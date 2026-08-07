# doca-flow — PCC-informed RoCE path steering (BF3 eSwitch)

`doca_flow_steer` is the DOCA Flow half of the two-path PCC experiment. It runs on
the **BF3 eSwitch** over a **p0↔p1 200G DAC loopback** and splits the sender's two
RoCE QPs across two virtual paths by **QPN parity**. A flow can be *steered onto the
alternate path* by setting an **ICRC-exempt DSCP marker bit** on the wire; only
**native-path** (unmarked) traffic is CE-marked so CNP→QPN attribution stays
coherent; the marker is cleared again on wire-ingress before the receiver SF sees
the packet.

## Why a DSCP bit and not the UDP port

The first design rewrote the RoCEv2 UDP destination port **4791→4792** as the wire
marker and restored it before delivery. **This breaks RoCE**: the UDP destination
port is an *invariant* field covered by the **RoCEv2 ICRC**, so even a
perfectly-paired rewrite/restore leaves the delivered packet failing ICRC → the NIC
silently drops it → `transport retry counter exceeded`. This was confirmed on
hardware: `--move-parity none` (no rewrite, CE-marking only) ran clean at 25M+
packets, while any UDP-port rewrite killed the moved QP.

The IP **ToS byte (DSCP + ECN) is a *variant* field excluded from the ICRC** — which
is exactly why CE-marking (an ECN write) is safe. So the marker now lives in a
single **DSCP bit**, set/cleared with a **masked modify** (`new = (old & ~mask) |
(val & mask)`) that leaves the ECN bits and the rest of the DSCP class untouched.
`MOVED_DSCP_MASK` (default `0x04`, the DSCP LSB — 0 for common RoCE classes 24/26)
selects the bit; change it if your deployment uses a DSCP whose LSB is set.

## Topology and roles

On a single BF3 the sender and receiver are different SFs, usually on different PFs
(the sender egresses one uplink, the receiver ingests the other across the DAC). A
DOCA Flow `switch` instance bound to one PF controls only that PF's eSwitch
(uplink + its SF rep), so the two directions run as **two separate programs**
selected by `--role`:

```
  ── sender side (PF1, --role egress) ────────────────────────────────────────
  sender SF (e.g. pf1sf0) ─ PORT_DEMUX(SF egress) ─ EGRESS_EXEMPT ─ EGRESS_CLASSIFY ─ p1 wire
                                                     (QP0/1 bypass)  (parity → set DSCP marker)
  wire ingress (returning ACK/CNP) ─ PORT_DEMUX ─ DELIVER_SF (untouched)

                                   p0 ══ 200G DAC ══ p1   (loopback)

  ── receiver side (PF0, --role ingress) ─────────────────────────────────────
  p0 wire ─ PORT_DEMUX(wire) ─ INGRESS_PATH_DEMUX ─ INGRESS_MARK ─ INGRESS_RESTORE ─ receiver SF
            (by src port)      (by outer dst IP)   (CE on unmarked) (clear DSCP marker)
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
| `EGRESS_EXEMPT` | egress | RoCEv2 BTH `dest_qp` ∈ {0,1} (mask `0xFFFFFE`) | management QPs (SMI/GSI-CM) → `DELIVER_WIRE` unchanged; miss → `EGRESS_CLASSIFY` |
| `EGRESS_CLASSIFY` | egress | RoCEv2 BTH `dest_qp` LSB (parity) | moved parity: **masked set DSCP `0x04`** (idx0); other: passthrough (idx1); both → `DELIVER_WIRE` |
| `INGRESS_PATH_DEMUX` | ingress | outer IPv4 dst | path0/path1 → per-path CE target; miss → `INGRESS_RESTORE` |
| `RANDOM_SAMPLE_P{0,1}` | ingress | `parser_meta.random` mask | hit → `INGRESS_MARK`; miss → `INGRESS_RESTORE` (only when 0 < percent < 100) |
| `INGRESS_MARK` | ingress | outer IPv4 dst + UDP dst 4791 + **DSCP marker clear** | **masked set ECN=CE (0x03)**, per-path counter → `INGRESS_RESTORE`; miss (marked/moved) → `INGRESS_RESTORE` |
| `INGRESS_RESTORE` | ingress | **DSCP marker set (`0x04`)** | **masked clear** the marker → `DELIVER_SF`; miss (native) → `DELIVER_SF` |
| `DELIVER_SF` / `DELIVER_WIRE` | all | all IPv4 (dscp wildcard) | forward to SF(1) / wire(0). On 3.x HWS a pipe's `fwd_miss` may not be a port, so port delivery goes through these `FWD_PIPE` targets. |

**Why mark only unmarked (native) packets.** A moved flow's packets carry the DSCP
marker and must not be CE-marked: their CNPs would return to that flow's own QPN and
corrupt its PCC signal. Marking only native packets keeps each path's congestion
signal attributed to the QPN that represents it. (Re-crediting a moved flow's ECN to
the *other* path's representative QPN is deliberately **out of scope** for now.)

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
Run **two instances** — one per side — before driving traffic. See the tutorial's
`setup_roce_loopback.sh` for the SF/loopback/namespace setup.

```bash
# receiver side (PF0): CE-mark native + clear DSCP marker
sudo ./build/doca_flow_steer -a "" -- \
     -r pci/0000:03:00.0,pf0sf0 --role ingress --path0-ip 172.16.1.20

# sender side (PF1): set the DSCP marker on the moved parity
sudo ./build/doca_flow_steer -a "" -- \
     -r pci/0000:03:00.1,pf1sf0 --role egress --move-parity odd
```

Arguments after `--` are the program's; DOCA argp options (`-a`/`-r`) come before it.

| Flag | Meaning | Default |
|---|---|---|
| `-r pci/<bdf>,<sf>[,dv_flow_en=2]` | SF representor device (DOCA 3.x, `DOCA_ARGP_TYPE_DEVICE_REP`) | required (3.x) |
| `-a pci/<bdf>[,...]` | optional explicit PF device | derived from `-r` |
| `--role egress\|ingress\|both` | which half of the pipeline to build | both |
| `--move-parity none\|even\|odd\|all\|auto` | which QPN parity is steered onto the marked path (egress) | auto |
| `--path0-ip` / `--path1-ip` | per-path outer IPv4 dst to match (ingress) | 172.16.1.20 / 172.16.2.20 |
| `--path0-percent` / `--path1-percent` | per-path CE-mark percentage (rounded down to a power-of-two fraction; 0 and 100 exact) | 100 / 100 |
| `--sf-num N` | receiver SF number (DOCA 2.9 discovery only) | 0 |

`--move-parity all` moves both parities onto the marked path — a useful isolation
test (it exercises the full set/CE/clear round trip for every data QP). The ingress
instance prints per-path CE-marked and restored (marker-cleared) counts once/second.

## Status

- **Hardware-validated on DOCA 3.4:** device discovery, the role split, the DSCP
  marker set/CE/clear round trip, and QP0/1 exemption. `none`, `all`, and `odd`
  runs sustain full-rate RoCE with the expected counters.
- Standalone runs as two per-PF instances; the embedded `doca_pcc` path still needs
  `dev`/`dev_rep` provisioning (see below).
- On teardown you may see `EGRESS_CLASSIFY entry remove completed with failure` —
  cosmetic (during `doca_flow_destroy`); does not affect the run.

## Embedded in doca_pcc (live PCC-driven steering)

The same module is linked into the `doca_pcc` host process (see
[`../pcc/README.md`](../pcc/README.md)). The PCC rate-report trace handler calls
`steer_update_pcc_rate(qpn, rate)`; the host loop calls `steer_poll()` once/second;
in `STEER_MOVE_AUTO` mode `steer_poll()` moves the more-congested parity by
live-updating the `EGRESS_CLASSIFY` entries.

**Not yet functional on 3.x:** `steer_start()` now requires `opts.dev` and
`opts.dev_rep` (opened via DOCA device APIs). The embedded caller in
`../pcc/host/pcc.c` does not yet supply them, so `doca_pcc --steer-sf` will report
"opts->dev and opts->dev_rep are required" until the integration below is done.

## Deferred / not yet done

- **PCC-host integration:** provide `dev`/`dev_rep` to `steer_start()` and confirm
  EAL/device coexistence with the PCC context in one process (see pcc README).
- **AUTO policy is a placeholder.** `steer_decide()` moves the lower-rate parity
  once its rate drops below `auto_ratio_threshold` × the other's; to be refined.
- **Re-crediting a moved flow's ECN/CNP to the other path's representative QPN.**
- **`MOVED_DSCP_MASK` bit choice** assumes the marker bit is free in your DSCP class.
