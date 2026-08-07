# PCC rate-report trace path

This PCC application reports per-flow rate information from the DPA to the host through the PCC trace stream. It is intended for observing the rate selected by the custom RTT-template / Pure-ECN algorithm; it does not alter the PCC rate-control path.

## Trace format

Format ID `6` is reserved in `common/device/pcc_rate_report.h`:

```c
#define PCC_RATE_REPORT_FORMAT_ID (6)
```

The DPA emits it with:

```c
doca_pcc_dev_trace_5(PCC_RATE_REPORT_FORMAT_ID,
                     qpn, results->rate, ev_type, rtt, now);
```

The five trace arguments are:

| Argument | Value |
| --- | --- |
| 1 | QPN |
| 2 | PCC rate, in FXP20 format |
| 3 | PCC event type |
| 4 | RTT value from the algorithm context |
| 5 | DPA low timer value, in microseconds |

For example, `1048576` (`1 << 20`) is the configured `NEW_FLOW_RATE` currently observed in the Pure-ECN test.

## Host decoding and aggregation

`pcc/host/pcc_core.c` registers `rate_report_trace_handler()` with `doca_pcc_register_trace_handler()`.

`struct doca_pcc_bin_report` is opaque in the public PCC API. Runtime validation on DOCA 3.4 showed that a PCC trace report is 64 bytes and has this effective layout:

```c
struct pcc_trace_report {
    uint32_t msg_number;
    uint32_t seq_number;
    uint64_t metadata;
    uint64_t internal_timestamp;
    uint64_t args[5];  /* trace_5 argument 1 through 5 */
};
```

This differs from FlexIO's `struct msg_bin_report`, whose `args` array begins at byte 16. Casting PCC reports to that FlexIO layout shifts the arguments and produces invalid QPN/rate values.

The host filters format ID 6 records and tracks up to 256 QPNs. For every QPN it keeps:

- cumulative rate sum;
- number of received rate reports;
- most recently received rate.

When a rate report arrives and at least one DPA-timer second has elapsed since the prior summary, the host prints a cumulative summary:

```text
--- Per-flow rate averages (received=129767 total=1427306) ---
  QPN 0x63f: avg_rate=1048576 last_rate=1048576 updates=713651
  QPN 0x640: avg_rate=1048576 last_rate=1048576 updates=713650
---
```

`received` is the number of accepted format-6 reports since the previous summary; `total` is the number accepted since PCC startup. `updates` is the cumulative count for that QPN.

The host prints only when rate reports are received. Consequently, a single flow that sends one startup report and has no later rate changes prints its startup summary once; it does not produce periodic output without later trace events.

## Validated test behavior

With BF3 as the PCC sender and CX7 as the receiver, `ib_write_bw` traffic assigned to custom slot 0 produces stable consecutive traffic QPNs. RTT probing is disabled in the current Pure-ECN algorithm, so the observed traffic is TX-only rather than polluted by RTT-probe QPs.

The trace route has been validated end to end:

1. DPA emits format-6 records.
2. `doca_pcc_dev_trace_flush()` delivers records to the host callback.
3. The host decodes QPN and FXP20 rate correctly.
4. The host aggregates reports and prints per-QPN averages once per second.

## Current limitation: DPA report volume

The current startup-detection experiment uses reserved RTT-template context words to tag the QPN that owns a cloned context. PCC context cloning/sharing can cause the tag to alternate between active QPNs. In a multi-flow run this currently causes a format-6 report and a startup flush on many TX events, yielding high report rates (for example, about 129k reports in one host summary interval).

This behavior is useful for validating the trace transport and host aggregation, but it is **not** the intended production stream rate. The next DPA-side refinement should reduce reporting to:

1. one initial report per real flow; and
2. one report for each actual PCC rate change.

Do not flush on every TX or every rate report in the production path: `doca_pcc_dev_trace_flush()` is intended to flush partial trace buffers and frequent calls can reduce DPA performance.

## Build

Rebuild both host and DPA code after changing DPA sources:

```bash
cd /home/tylerliu/pcc_example/build
meson setup --wipe ..
ninja
```

The DPA archive is regenerated during Meson setup through `pcc/build_device_code.sh` / `dpacc`.

## Embedded DOCA Flow path steering

For the BF3 experiment, the PCC executable can run the **DOCA Flow path-steering
module** (`../doca-flow/steer.c`) in the **same host process**. Enable it with
`--steer-sf <N>`, the receiver SF number:

```bash
./build/pcc/doca_pcc --device mlx5_0 --steer-sf 0
```

Drive traffic with two RoCE QPs (e.g. `ib_write_bw -q 2 ... -R`); the two QPNs are
consecutive, so their LSB parity identifies the two virtual paths.

There is no rate file, polling IPC, or manual QPN-to-path configuration. Each PCC
format-6 trace report calls `steer_update_pcc_rate(qpn, rate)` directly (a relaxed
atomic store into the per-parity rate slot). Once per second the host loop calls
`steer_poll()`, which — in AUTO mode — moves the more-congested parity onto the
alternate virtual path by live-updating the `EGRESS_CLASSIFY` entries, and prints
the per-path CE-mark / restore counters.

> **Marker mechanism.** The alternate path is marked on the wire with an
> ICRC-exempt **DSCP bit** (masked modify), *not* a UDP-port rewrite — rewriting the
> RoCEv2 UDP port breaks ICRC and drops the moved flow. See
> [`../doca-flow/README.md`](../doca-flow/README.md).

> **Status — embedded path is WIP on DOCA 3.x.** The standalone `doca_flow_steer`
> (run as two per-PF instances, `--role egress`/`--role ingress`) is
> hardware-validated. The embedded path is not yet functional on 3.x: `steer_start()`
> now requires a `doca_dev` + `doca_dev_rep`, and this host program does not yet open
> and pass them. `--steer-sf` will report *"opts->dev and opts->dev_rep are
> required"* until that wiring lands. Also note the sender's egress steering must run
> on the **sender's** PF, which is a separate concern from where the PCC RP context
> is opened.

The existing host-side per-QPN PCC rate summary is still printed at most once per
DPA-timer second and remains the primary visibility point for the trace feed:

```text
--- Per-flow rate averages (received=... total=...) ---
  QPN 0x63f: avg_rate=1048576 last_rate=1048576 updates=...
  QPN 0x640: avg_rate=786432 last_rate=786432 updates=...
---
```

The steering pipeline, options, and the DOCA 2.9/3.x compatibility notes are
documented in [`../doca-flow/README.md`](../doca-flow/README.md). The same module
also builds as a standalone `doca_flow_steer` binary there for testing.

> The former `peer_sim` sender/DRR component has been removed; the sender is now
> just a RoCE traffic generator (e.g. `ib_write_bw`), and DOCA Flow performs the
> PCC-informed path steering.
