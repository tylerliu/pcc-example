# doca-flow — PCC-informed RoCE path steering (BF3 eSwitch)

`doca_flow_steer` is the DOCA Flow half of the two-path PCC experiment. It runs on
the **BF3 eSwitch** over a **p0↔p1 200G DAC loopback**. Sender packets are
assigned per packet to one of two virtual paths using `parser_meta.random`; the
selected path is carried in an **ICRC-exempt DSCP bit**. On ingress, traffic is
CE-marked per path, then a stable full-24-bit-QPN hash assigns each flow to class
0 or class 1. ECN is retained only when the QPN class equals the packet path; it
is stripped otherwise. The DSCP marker is always cleared before SF delivery.
Because the marker is a DSCP bit, both classes may share one receiver IP.

## Why a DSCP bit and not the UDP port

The first design rewrote the RoCEv2 UDP destination port **4791→4792** as the wire
marker and restored it before delivery. **This breaks RoCE**: the UDP destination
port is an *invariant* field covered by the **RoCEv2 ICRC**, so even a
perfectly-paired rewrite/restore leaves the delivered packet failing ICRC → the NIC
silently drops it → `transport retry counter exceeded`. This was confirmed on
hardware: `--move-parity none` (no rewrite, CE-marking only) ran clean at 25M+
packets, while any UDP-port rewrite killed the moved QP.

The IP **ToS byte (DSCP + ECN) is a *variant* field excluded from the ICRC** — which
is exactly why CE-marking (an ECN write) is safe. So the path marker lives in a
single **DSCP bit**, set/cleared with a **masked modify** (`new = (old & ~mask) |
(val & mask)`) that leaves the ECN bits and the rest of the DSCP class untouched.
`PATH_DSCP_MASK` (default `0x04`, the DSCP LSB — 0 for common RoCE classes 24/26)
selects the bit; change it if your deployment uses a DSCP whose LSB is set.

## Topology and roles

On a single BF3 the sender and receiver are different SFs, usually on different PFs
(the sender egresses one uplink, the receiver ingests the other across the DAC). A
DOCA Flow `switch` instance bound to one PF controls only that PF's eSwitch
(uplink + its SF rep), so the two directions run as **two separate programs**
selected by `--role`:

```
  ── sender side (PF1, --role egress) ────────────────────────────────────────
  sender SF (e.g. pf1sf0) ─ PORT_DEMUX ─ EGRESS_ROCE_CHECK ─ EGRESS_CLASSIFY ─ p1 wire
                                           (RoCE only)       (random → DSCP path)
  wire ingress (returning ACK/CNP) ─ PORT_DEMUX ─ DELIVER_SF (untouched)

                                   p0 ══ 200G DAC ══ p1   (loopback)

  ── receiver side (PF0, --role ingress) ─────────────────────────────────────
  p0 wire ─ PORT_DEMUX ─ INGRESS_ROCE_CHECK ─ INGRESS_PATH_DEMUX ─ MARK/SAMPLE
                                                       ─ INGRESS_QPN_HASH ─ RESTORE_CLASS0/1 ─ receiver SF
  receiver SF egress (ACK/CNP) ─ PORT_DEMUX ─ DELIVER_WIRE (untouched)
```

`--role both` builds both halves in one instance (single-endpoint / whole-eSwitch
case). Logical flow-port ids: **0 = PF uplink (wire), 1 = SF representor**.

> **Link speed.** The DAC negotiates at **200G** — quote throughput against a 200G
> line rate.

## Pipeline

| Pipe | Built for role | Match | Action / fate |
|---|---|---|---|
| `PORT_DEMUX` (root) | all | `parser_meta` source port id | wire(0) → wire-target; SF(1) → sf-target; miss → drop |
| `EGRESS_ROCE_CHECK` | egress | IPv4 RoCEv2, UDP dst 4791 | hit → `EGRESS_CLASSIFY`; miss → `DELIVER_WIRE` unchanged |
| `EGRESS_CLASSIFY` | egress | `parser_meta.random` | two buckets write DSCP path 0/1; → `DELIVER_WIRE` |
| `INGRESS_ROCE_CHECK` | ingress | IPv4 RoCEv2, UDP dst 4791 | hit → `INGRESS_PATH_DEMUX`; miss → `DELIVER_SF` unchanged |
| `INGRESS_PATH_DEMUX` | ingress | DSCP path bit (`0x04`) | path 0/1 → its CE target; miss → `INGRESS_QPN_HASH` |
| `RANDOM_SAMPLE_P{0,1}` | ingress | `parser_meta.random` mask | optional per-path sampling; hit → mark, miss → QPN hash |
| `INGRESS_MARK` | ingress | DSCP path bit | masked ECN=CE write; → `INGRESS_QPN_HASH` |
| `INGRESS_QPN_HASH` | ingress | IPv4/RoCEv2 selectors + full 24-bit BTH `dest_qp` | stable two-bucket flow classification; bucket n → `RESTORE_CLASSn` |
| `INGRESS_RESTORE_CLASS{0,1}` | ingress | DSCP path bit only | class==path: clear marker and keep ECN; otherwise clear marker and strip ECN |
| `DELIVER_SF` / `DELIVER_WIRE` | all | all IPv4 (dscp wildcard) | forward to SF(1) / wire(0). On 3.x HWS a pipe's `fwd_miss` may not be a port, so port delivery goes through these `FWD_PIPE` targets. |

**Measure per path, signal per QPN class.** Marking occurs before QPN hashing, so
path counters measure the offered traffic on each virtual path. The full-QPN hash
is stable per flow. Each restore-class pipe retains CE only for its selected path,
preventing the other path from producing congestion feedback for that class.

## Build

Standalone (also linked into `doca_pcc`; see [`../pcc/README.md`](../pcc/README.md)):

```bash
cd /home/tylerliu/pcc_example/doca-flow
meson setup build
ninja -C build
```

### DOCA 2.9 / 3.x compatibility

Device discovery, port start, and the entry API differ between releases;
[`doca_flow_compat.h`](doca_flow_compat.h) and `#if DOCA_VERSION_MAJOR >= 3` gates in
[`steer.c`](steer.c) hide the differences:

| Concern | DOCA 2.9 | DOCA 3.x |
|---|---|---|
| device discovery | open by index + `representor=sfN` probe string | `doca_dpdk_port_probe_with_representors(dev, "dv_flow_en=2,fdb_def_rule_en=1", &dev_rep, 1)`; **no** `repr_matching_en` / `representor=` |
| flow mode | `switch,hws,isolated,disable_switch_rss` + `set_nr_counters` | `switch,hws` + `set_resource_mode(PORT)` |
| PF port start | `set_dev` + devargs string | `set_dev` + `set_port_id(0)` + `set_actions_mem_size` + `set_nr_resources(COUNTER,128)` |
| SF rep port start | `find_sf_representor_port_id()` by ethdev flag | `set_port_id(1)` + `set_dev_rep(dev_rep)` |
| add / update entry | `doca_flow_pipe_add_entry`, idx via `actions.action_idx` | `doca_flow_pipe_basic_add_entry(..., action_idx, ...)` |
| source-port match | `parser_meta.port_meta` (u32) | `parser_meta.port_id` (u16) |

Verified to **build+link cleanly on DOCA 3.4.0112** (the SDK installed here) and the
3.4 datapath is **hardware-validated**. The 2.9 branch follows the tutorial's
known-good 2.9 API but has not been compiled here (no 2.9 SDK on this box).

## Run

The BF3 device and SF representor are opened via DOCA argp device params (DOCA 3.x).
Run **two instances** — one per side — before driving traffic. Each inits EAL
independently with a role-specific DPDK `--file-prefix` (auto), so they coexist on
one host and need no `--`/`-a` on the CLI. See the tutorial's
`setup_roce_loopback.sh` for the SF/loopback/namespace setup.

```bash
# receiver side (PF0): mark by path, hash full QPN, keep/strip ECN by class
sudo ./build/doca_flow_steer -r pci/0000:03:00.0,pf0sf0 --role ingress

# sender side (PF1): randomly write DSCP path 0 or 1 per packet
sudo ./build/doca_flow_steer -r pci/0000:03:00.1,pf1sf0 --role egress
```

| Flag | Meaning | Default |
|---|---|---|
| `-r pci/<bdf>,<sf>[,dv_flow_en=2]` | SF representor device (DOCA 3.x, `DOCA_ARGP_TYPE_DEVICE_REP`) | required (3.x) |
| `-a pci/<bdf>[,...]` | optional explicit PF device | derived from `-r` |
| `--role egress\|ingress\|both` | which half of the pipeline to build | both |
| `--move-parity ...` | legacy option; ignored by the fixed random-hash egress pipe | auto |
| `--path0-percent` / `--path1-percent` | per-path CE-mark percentage (rounded down to a power-of-two fraction; 0 and 100 exact) | 100 / 100 |
| `--sf-num N` | receiver SF number (DOCA 2.9 discovery only) | 0 |

The two virtual paths are distinguished purely by the DSCP path bit; both may
share one receiver destination IP. The ingress instance prints per-path marking,
full-QPN hash buckets, and all four class/path restore counters once per second.

## Hash and restore validation

Ingress uses regular `HASH` over all 24 destination-QPN bits. The hash template
contains the IPv4 and RoCEv2 selectors but does not include UDP dst in the hash
key. Hardware testing with 16 QPNs produced an approximately 50/50 bucket split.
The earlier partial-QPN basic match and `IDENTITY` experiment have been removed;
two DSCP-only restore-class pipes are selected directly by the QPN hash buckets.

## Status

- **Hardware-validated on DOCA 3.4:** random DSCP path assignment, per-path CE marking,
  full-24-bit-QPN hashing across 16 QPs, and DSCP-only class restore construction.
- Standalone runs as two per-PF instances; the embedded `doca_pcc` path still needs
  `dev`/`dev_rep` provisioning (see below).
- On teardown you may see `EGRESS_CLASSIFY entry remove completed with failure` —
  cosmetic (during `doca_flow_destroy`); does not affect the run.

## Embedded in doca_pcc (live PCC-driven steering)

The same module is linked into the `doca_pcc` host process (see
[`../pcc/README.md`](../pcc/README.md)). The PCC rate-report trace handler calls
`steer_update_pcc_rate(qpn, rate)`; the host loop calls `steer_poll()` once/second;
the current egress hash buckets are fixed; PCC reports are logged but do not
reprogram the random distribution.

**Egress role, wired via `-r`.** `steer_start()` on 3.x needs `opts.dev` and
`opts.dev_rep`. `doca_pcc` now opens them from a `-r pci/<bdf>,<sf>` device param
(and optional `-a`) and calls `start_embedded_steering()` with `role=EGRESS`, since
the PCC RP and the sender's egress are the same PF. Builds and registers the option;
**not yet run on hardware** — the open risk is dual-opening the sender PF (PCC engine
+ DOCA Flow DPDK probe) in one process.

## Deferred / not yet done

- **PCC-host integration:** provide `dev`/`dev_rep` to `steer_start()` and confirm
  EAL/device coexistence with the PCC context in one process (see pcc README).
- **PCC-driven ratio control is deferred.** The current checkpoint uses a fixed
  two-bucket random egress distribution.
- **`PATH_DSCP_MASK` bit choice** assumes the path bit is free in your DSCP class.
