# DOCA Flow two-path RoCE steering

This module implements the DOCA Flow datapath for a two-path PCC experiment on
a BlueField-3 eSwitch. Egress assigns every RoCEv2 packet to virtual path 0 or
1. The path is carried in IP ToS bit `0x04` (DSCP bit 0), which is outside the
RoCEv2 invariant CRC. Ingress applies the ECN policy for the selected path,
clears the private path bit, and delivers the packet to the receiver SF selected
by destination IPv4 address.

The UDP destination port is never used as a path marker. Rewriting 4791 breaks
RoCEv2 ICRC validation even if it is restored before SF delivery.

## Topology

The tested setup uses separate sender and receiver PFs connected through the
physical loopback. The receiver has one SF and destination IP per path.

```text
sender PF (--role egress)

 sender SF
    │
 PORT_DEMUX
    │
 EGRESS_ROCE_CHECK ── non-RoCE ───────────────┐
    │ RoCEv2                                  │
 EGRESS_CLASSIFY (64 random buckets)          │
    │ write path bit                          │
 DELIVER_WIRE ◀───────────────────────────────┘

 returning wire traffic
    │
 EGRESS_CNP_COUNT ── QP1 clone/CM parser ── DELIVER_SF


receiver PF (--role ingress)

 wire
  │
 PORT_DEMUX
  │
 INGRESS_ROCE_CHECK ── non-RoCE ──────────────┐
  │ RoCEv2                                    │
 INGRESS_PATH_DEMUX (DSCP path bit)           │
  ├─ path0 ─ PATH0_IP_MATCH ─ SAMPLE ─ CE_MARK│
  └─ path1 ─ PATH1_IP_MATCH ─ SAMPLE ─ CE_MARK│
                    misses ─ INGRESS_CLEAR_PATH
                              │
                       RECEIVER_IP_DEMUX
                         ├─ destination IP 0 ─ SF0
                         └─ destination IP 1 ─ SF1
```

QP1 packets are cloned in both directions to one DPDK RX queue. The host parses
RDMA-CM REQ packets to learn `(sender QPN, destination IP)`, which directly
assigns each PCC sender QPN to path 0 or path 1. REP parsing records the
responder QPN for diagnostics; it is not required for path grouping.

## Egress control

`EGRESS_CLASSIFY` is a basic exact-match pipe over the low six bits of
`parser_meta.random`. It has 64 live bucket rules and capacity for 128 rules;
the spare capacity is required because HWS temporarily allocates a replacement
rule during an entry update.

The initial assignment is 32 buckets per path. Once per host poll:

1. PCC rate reports are averaged per sender QPN over the complete interval.
2. RDMA-CM maps each QPN into its destination-IP path group.
3. Full-rate flows (`1 << 20`) are excluded from each reduced-rate sum.
4. When both paths contain reduced flows, path 0 receives
   `sum(path0) / (sum(path0) + sum(path1))` of the 64 buckets.
5. If exactly one path group is entirely full-rate, it receives 61 buckets and
   the constrained group receives the minimum 3 buckets.
6. Only rules crossing the old/new boundary are updated.

Flows without a known RDMA-CM mapping are reported as `pending-map` and excluded
from the calculation. Returning CNP counters are grouped using the same learned
sender-QPN path association.

## Ingress ECN marking

Path selection happens before two separate destination-IP marker chains. A
path's configured percentage describes the intended CE percentage over all
traffic on that path. Only the selected half of the random path/class space is
eligible, so the hardware sampler uses twice the requested percentage, capped
at 100%. Both marker hits and misses clear only the private DSCP path bit before
delivery; unrelated DSCP and existing ECN bits are preserved.

## Build

The module is built standalone and linked into `doca_pcc`:

```bash
meson setup build --reconfigure
ninja -C build
```

For standalone development:

```bash
meson setup /tmp/pcc-flow-check doca-flow
ninja -C /tmp/pcc-flow-check
```

DOCA 3.x is built and hardware-tested on 3.4.0112. Compatibility wrappers in
`doca_flow_compat.h` retain the DOCA 2.9 add/update and port-discovery API path;
QP1 cloning is isolated in `install_qp1_clone_paths()` so its 2.9 backend can use
mirror resources instead of the 3.x flooding hash pipe.

### Future DOCA 2.7/2.9 port

The legacy branches are scaffolding, not a validated 2.7/2.9 implementation.
Before using them on older SDKs, verify or replace the following:

- Representor discovery and switch-port startup (`open_and_probe_dev()`,
  `find_sf_representor_port_id()`, and the DOCA-version port configuration).
- Entry add/update semantics in `doca_flow_compat.h`. DOCA 3.x requires
  `DOCA_FLOW_ENTRY_FLAGS_NO_WAIT` for a submitted single-entry update; the
  current legacy wrapper assumes that omitting `DOCA_FLOW_WAIT_FOR_BATCH`
  submits immediately.
- QP1 cloning. DOCA 3.4 uses a two-entry flooding hash pipe; 2.7/2.9 should use
  the available shared mirror resource behind `install_qp1_clone_paths()`.
- Dual receiver-SF logical port ids and source-port metadata field widths.
- Dynamic classifier updates and teardown. On DOCA 3.4.0112, updated
  `EGRESS_CLASSIFY` entries can emit several
  `entry remove completed with failure` messages during pipe flush even after
  update completion and queue draining. Shutdown still completes. Re-test this
  behavior on the older SDK rather than carrying a version-specific workaround
  blindly.

Keep the application-level pipeline and PCC grouping unchanged while porting;
the intended compatibility boundary is `doca_flow_compat.h`, device/port setup,
and `install_qp1_clone_paths()`.

## Run

Receiver/ingress, with two representors and destination IPs:

```bash
sudo ./build/doca_flow_steer \
  -r pci/0000:03:00.0,pf0sf0 \
  -R pci/0000:03:00.0,pf0sf4 \
  --path0-ip 10.0.0.1 --path1-ip 10.0.0.11 \
  --role ingress --path0-percent 0.025 --path1-percent 0.05
```

Sender/egress standalone diagnostic:

```bash
sudo ./build/doca_flow_steer \
  -r pci/0000:03:00.1,pf1sf0 \
  --path0-ip 10.0.0.1 --path1-ip 10.0.0.11 \
  --role egress
```

The normal sender deployment embeds the egress role in `doca_pcc`; its PCC
trace handler calls `steer_update_pcc_rate()` and its host loop calls
`steer_poll()` once per second.

| Option | Meaning |
|---|---|
| `-r`, `--path0-rep` | sender SF for egress, or receiver path-0 SF for ingress |
| `-R`, `--path1-rep` | receiver path-1 SF; required for ingress |
| `--path0-ip`, `--path1-ip` | destination IPs used for receiver delivery and PCC grouping |
| `--role ingress\|egress\|both` | pipeline half to build |
| `--path0-percent`, `--path1-percent` | intended per-path all-traffic CE percentages |
| `--sf-num` | DOCA 2.9 representor discovery fallback |

## Shutdown

On exit, rate callbacks are quiesced first. The proxy port owns every pipe, so
one proxy flush removes the complete pipeline. The representor child ports are
then stopped before their proxy parent. Empty representor ports are not flushed
because that triggers a DOCA 3.4 dual-representor teardown failure.

### Unresolved future work: updated classifier teardown

On DOCA 3.4.0112, egress shutdown still logs several errors of this form after
the path share has been changed dynamically:

```text
pipe 'EGRESS_CLASSIFY' entry remove completed with failure (queue=0)
```

The process exits normally and the ports are released. The problem is isolated
to entries previously changed with `doca_flow_pipe_basic_update_entry()`; the
ingress pipeline and an egress classifier that was never updated tear down
cleanly. Explicit `NO_WAIT` update submission, processing each update
completion, draining the operation queue after a transition, draining again
before flush, removing per-entry counters, and child-before-parent port shutdown
do not eliminate the messages.

Treat this as unresolved SDK/update-lifecycle work. When revisiting it, test an
explicit classifier-pipe recreation strategy and compare behavior on the target
DOCA 2.7/2.9 SDK. Do not spend more time changing the general port teardown
order unless new evidence shows a port ownership failure.
