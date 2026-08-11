# doca-flow — PCC-informed RoCE path steering (BF3 eSwitch)

`doca_flow_steer` is the DOCA Flow half of the two-path PCC experiment. It runs on
the **BF3 eSwitch** over a **p0↔p1 200G DAC loopback**. Sender packets are
assigned per packet to one of two virtual paths using `parser_meta.random`; the
selected path is carried in an **ICRC-exempt DSCP bit**. On ingress, the path is
selected first and then processed by an exact-QPN match pipe populated from
RDMA-CM. Path 0 marks even receiver QPNs and path 1 marks odd receiver QPNs. Unknown QPNs are never
artificially marked. The DSCP marker is always cleared before SF delivery.
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
  sender SF ─ PORT_DEMUX ─ QP1_CHECK_SF ─┬─ QP1_FLOOD_SF ─┬─ DELIVER_WIRE
                                         │                 └─ shared DPDK queue 0
                                         └─ EGRESS_ROCE_CHECK ─ EGRESS_CLASSIFY ─ p1 wire
  wire ingress ─ PORT_DEMUX ─ QP1_CHECK_WIRE ─┬─ QP1_FLOOD_WIRE ─┬─ DELIVER_SF
                                              │                   └─ shared DPDK queue 0
                                              └─ DELIVER_SF (ordinary ACK/CNP)

                                   p0 ══ 200G DAC ══ p1   (loopback)

  ── receiver side (PF0, --role ingress) ─────────────────────────────────────
  p0 wire ─ PORT_DEMUX ─ INGRESS_ROCE_CHECK ─ INGRESS_PATH_DEMUX
                                      ├─ PATH0_QPN_MATCH ─ even QPN ─ SAMPLE/MARK ─ receiver SF
                                      └─ PATH1_QPN_MATCH ─ odd QPN ─ SAMPLE/MARK ─ receiver SF
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
| `QP1_CHECK_{WIRE,SF}` | ingress, egress | IPv4 RoCEv2, full BTH `dest_qp == 1` | hit → direction-specific flooding clone; miss → existing direction pipeline |
| `QP1_FLOOD_{WIRE,SF}` | ingress, egress | flooding hash (two entries) | preserve original forwarding and clone to shared `QP1_RSS` |
| `QP1_RSS` | ingress, egress | cloned IPv4 packet | terminate clones from both directions in DPDK RX queue 0 |
| `EGRESS_CNP_COUNT` | egress | CNP opcode `0x81` + learned exact sender QPN | count unchanged returning CNPs per QP, grouped for diagnostics by mapped receiver-QPN LSB; miss → existing wire target |
| `EGRESS_ROCE_CHECK` | egress | IPv4 RoCEv2, UDP dst 4791 | hit → `EGRESS_CLASSIFY`; miss → `DELIVER_WIRE` unchanged |
| `EGRESS_CLASSIFY` | egress | `parser_meta.random` | two buckets write DSCP path 0/1; → `DELIVER_WIRE` |
| `INGRESS_ROCE_CHECK` | ingress | IPv4 RoCEv2, UDP dst 4791 | hit → `INGRESS_PATH_DEMUX`; miss → `DELIVER_SF` unchanged |
| `INGRESS_PATH_DEMUX` | ingress | DSCP path bit (`0x04`) | path n → `PATHn_QPN_MATCH`; miss → `INGRESS_CLEAR_PATH` |
| `PATH{0,1}_QPN_MATCH` | ingress | learned exact 24-bit receiver QPN | QPN LSB==path → sampling/marking; miss → `INGRESS_CLEAR_PATH` |
| `RANDOM_SAMPLE_P{0,1}` | ingress | `parser_meta.random` mask | optional selected-class sampling; hit → path marker, miss → `INGRESS_CLEAR_PATH` |
| `PATH{0,1}_CE_MARK` | ingress | selected class packets | set ECN=CE and clear DSCP path bit; → `DELIVER_SF` |
| `INGRESS_CLEAR_PATH` | ingress | all IPv4 | preserve ECN, clear DSCP path bit; → `DELIVER_SF` |
| `DELIVER_SF` / `DELIVER_WIRE` | all | all IPv4 (dscp wildcard) | forward to SF(1) / wire(0). On 3.x HWS a pipe's `fwd_miss` may not be a port, so port delivery goes through these `FWD_PIPE` targets. |

**Two independent ECN markers.** Path selection occurs before QPN matching. Each
path has an independent exact-QPN pipe and only its matching LSB class can enter
that path marker. The other class bypasses marking and preserves existing ECN.

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
# receiver side (PF0): choose path, run that paths QPN-class ECN marker
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
| `--path0-percent` / `--path1-percent` | intended CE percentage over all path traffic; selected-class sampling uses `min(2x, 100%)`, then rounds down to a supported power-of-two fraction | 100 / 100 |
| `--sf-num N` | receiver SF number (DOCA 2.9 discovery only) | 0 |

The two virtual paths are distinguished purely by the DSCP path bit; both may
share one receiver destination IP. The ingress instance prints both paths'
selected-class CE-mark counters and the shared
unmarked/path-bit-cleared counter once per second.

The egress role also clones IPv4 RoCEv2 packets addressed to QP1 in both
directions. The original QP1 packet bypasses data-path marking and continues to
the opposite port; its copy enters one shared DPDK queue. Logs identify the MAD
class/method/attribute. CM REQ logs include the initiator QPN and local
communication ID; CM REP logs include the responder QPN and both communication
IDs.

CM REQs are retained by `local_comm_id`; a CM REP completes the connection when
its `remote_comm_id` matches that REQ. This builds an initiator/sender-QPN to
responder/receiver-QPN mapping. PCC rate reports remain keyed by sender QPN, but
the grouping class is the mapped receiver QPN's LSB because that is the exact
BTH destination QPN classified by ingress. PCC flows without a completed
CM mapping are reported as `pending-map` and excluded from both group totals
instead of being assigned using the wrong QPN.

QP1 observation is installed through the standalone
`install_qp1_clone_paths()` facility. Its backend is intentionally isolated from
the ordinary steering topology: DOCA 3.x currently uses flooding hash pipes;
the DOCA 2.9 compatibility backend will use shared mirror resources.

## Per-path ECN-marker validation

Ingress first demultiplexes on the DSCP path bit, then sends each path through
its exact-QPN match pipe. CM REP parsing installs each receiver QPN only into
`PATH(qpn&1)_QPN_MATCH`. Unknown, opposite-class, and sampling-miss packets
bypass marking. Both outcomes clear only the private DSCP path bit before SF
delivery, preserving any pre-existing ECN on unmarked packets.

Because only the matching QPN class, approximately half of each path, is
eligible for new CE marking, its sampler runs at twice the configured intended
all-traffic rate. The selected-class rate is capped at 100%, so intended rates
above 50% cannot be fully realized by this class-selective design.

On egress, CM pairing maps every PCC sender QPN to its receiver QPN. Grouping
uses `receiver_qpn & 1` directly; no QPN hash profile or calc-hash operation is
used. The same mapping installs an exact sender-QPN entry in `EGRESS_CNP_COUNT`.
Its hardware counters report returning CNP packets as path 0 or path 1 according
to the mapped receiver QPN's LSB; this is diagnostic and does not modify CNPs.

The egress diagnostic also retains the latest PCC rate for each observed QPN and
prints a proposed 64-bucket path share once per host poll. QPNs at the full rate
(`1 << 20`) are excluded from reduced-rate sums. If both groups have reduced
flows, each path share is proportional to its group sum; if exactly one entire
group is full-rate, it receives 61 of 64 buckets. This result is logging-only:
the two-entry egress hash pipe and its 50/50 forwarding behavior are unchanged.

## Status

- **Previously hardware-validated on DOCA 3.4:** random DSCP path assignment and
  full-24-bit-QPN hashing across 16 QPs. The new path-first, two-marker ingress
  topology still requires hardware validation.
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
