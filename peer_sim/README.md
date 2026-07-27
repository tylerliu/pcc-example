# Two-path RDMA_WRITE workload with PCC and ECN

`peer_sim` is a two-path RoCE workload for testing a single logical stream sent from BF3 to CX7. It has two roles:

- **BF3 client:** creates one RDMA-CM RC QP per path, uses DRR to choose the next path, and performs the bulk transfer with one-sided `RDMA_WRITE`.
- **CX7 server:** creates the matching RDMA-CM connections, registers an RDMA-write target ring per path, and remains off the bulk data path.

PCC controls each QP's hardware transmit rate from CNP feedback. DRR controls which QP receives future writes. DOCA Flow remains responsible for the path-specific CE-marking profiles and counters.

## RDMA-CM, ECE, and PCC slot selection

Both paths use the standard RDMA-CM sequence:

```text
rdma_resolve_addr → rdma_resolve_route → rdma_create_qp
                  → rdma_connect / rdma_accept
```

No raw `ibv_modify_qp` connection setup is used. This is the same connection-establishment model as `ib_write_bw -R`: mlx5 Enhanced Connection Establishment (ECE) can negotiate the PCC slot for the BF3 QPs. Start the existing BF3 PCC host application and slot-0 DPA program before the client, then confirm `slot=0` in the PCC output for both traffic QPs.

ECE may extend RDMA-CM private data, so the program does not parse application data from that area. After each QP is established, CX7 sends a small in-band RC `SEND` control message containing the registered target's address, rkey, and slot size. BF3 waits for this message before issuing any writes.

## Bulk data path

For every path, CX7 registers a ring of `depth × wire_size` bytes with remote-write permission. BF3 writes each chunk to:

```text
remote_base + (sequence % depth) × wire_size
```

The write ring is deliberately a performance baseline:

- receiver CPU does not post, poll, or repost a WQE per bulk chunk;
- receiver does not receive an immediate notification per write;
- BF3 does not rewrite the whole payload for every chunk; it updates only the chunk header;
- BF3 links up to 32 RDMA-write WQEs into one `ibv_post_send()` call;
- BF3 requests one send CQE every 32 writes, plus a CQE when a queue must be drained or a finite run ends;
- an ordered RC completion retires all earlier unsignaled writes on that QP.

Consequently, **BF3 sender completion throughput is the authoritative bulk-throughput measurement**. CX7 only reports that its write targets are active; it cannot report per-write delivery bandwidth without adding `RDMA_WRITE_WITH_IMM` plus a credit/notification protocol. That richer receiver validation is intentionally deferred until after the write baseline is established.

## Build

Build this directory independently on both endpoints. It is not part of the top-level PCC/DPACC Meson build. **Use a release build for every throughput measurement**; Meson's default debug configuration uses `-O0` and is not a valid performance baseline.

```bash
cd /home/tylerliu/pcc_example/peer_sim
meson setup build --reconfigure -Dbuildtype=release
ninja -C build
```

Use a separate `build-debug` directory with `-Dbuildtype=debug` only when diagnosing failures.

## Run a continuous ECN experiment

The default is continuous operation. Omit `--chunks` (or use `--chunks 0`) so both QPs remain active while ECN profiles are changed. Stop an experiment with `Ctrl-C`.

Start CX7 first:

```bash
sudo ip netns exec remote ./build/peer_sim --server \
  --local0 172.16.1.20 --local1 172.16.2.20
```

Then run the BF3 client while the PCC application is already active:

```bash
./build/peer_sim --client \
  --local0 172.16.1.2 --peer0 172.16.1.20 \
  --local1 172.16.2.2 --peer1 172.16.2.20
```

`--local0` and `--local1` pin RDMA-CM route resolution to the intended BF3 source path. The two local CX7 addresses and RDMA-CM service ports identify the server paths independently. `peer_sim` does **not** choose an RDMA device by name: RDMA-CM selects the verbs device and port from each source/destination IP route.

Before a dual-path run, verify the mappings on BF3:

```bash
ip route get 172.16.1.20 from 172.16.1.2
ip route get 172.16.2.20 from 172.16.2.2
rdma link show
ibdev2netdev
```

Run the equivalent route and RDMA-link commands inside the CX7 receiver namespace when one is used:

```bash
sudo ip netns exec remote ip route get 172.16.1.2 from 172.16.1.20
sudo ip netns exec remote ip route get 172.16.2.2 from 172.16.2.20
sudo ip netns exec remote rdma link show
sudo ip netns exec remote ibdev2netdev
```

After connection, each established-QP log reports `device=<verbs-device> port=<N>`. The two paths must differ in that pair—normally two ports of one HCA or ports of different HCAs. If both logs show the same device and port, both QPs share one RDMA link regardless of the IP arguments; correct the address assignment or routes before interpreting throughput.

The default queue depth is 512, the default payload is 64 KiB, and BF3 links up to 32 writes per `ibv_post_send()` call. `--post-batch` controls that client-side maximum (1–64, and no greater than `--depth`). Start with the default; compare 16, 32, and 64 only after recording CPU usage and throughput. To reduce WQE/CQE rate further while testing the baseline, use the same data-ring settings on both endpoints, for example:

```bash
--chunk-size 262144 --depth 256 --post-batch 32
```

A finite test can stop after exactly `N` sender writes:

```bash
--chunks 100000
```

A finite count is a sender completion limit in RDMA-write mode; it is not an end-to-end receiver sequence verifier.

## Throughput output

In continuous mode BF3 prints a one-second interval summary:

```text
--- sender throughput (1000 ms interval) ---
  path 0: ... Gbps, interval_bytes=... total_bytes=...
  path 1: ... Gbps, interval_bytes=... total_bytes=...
  aggregate: ... Gbps
```

The path rate is based on successful RC RDMA-write completions. Compare this output with PCC trace rate reports, BF3/CX7 ECN/CNP counters, and the per-path DOCA Flow mark counters.

## Dynamic DRR weights

DRR begins at 50/50. The client can optionally poll a file containing two positive PCC FXP20 rates:

```text
<path0-fxp20-rate> <path1-fxp20-rate>
```

```bash
printf '1048576 1048576\n' > /run/peer_sim-rates
./build/peer_sim --client ... --rate-file /run/peer_sim-rates
```

The scheduler applies a 5% minimum probe share, 95% maximum share, and a 10-percentage-point-per-update slew limit. The existing PCC trace host does not yet publish this file automatically; that exporter is the next integration step.

## Expected ECN experiment

For direct BF3–CX7 links, BF3 egress DOCA Flow injects CE into actual RoCEv2 data packets for each path. It must match the specific path's outer IPv4 addresses and UDP destination port 4791, not all IPv4 traffic.

When path 1 has the more aggressive CE profile, expect:

```text
ECN marks(path 1) > ECN marks(path 0)
CNPs(path 1)      > CNPs(path 0)
PCC rate(path 1)  < PCC rate(path 0)
DRR share(path 1) < DRR share(path 0)
write throughput(path 1) < write throughput(path 0)
```

After CE marking is disabled, CNPs stop, PCC gradually recovers, and DRR can return work to that path. Swapping the two marking profiles should swap the behavior.

A direct link validates synthetic ECN → CNP → PCC → DRR dynamics. It does not create or measure a real intermediate switch queue; add independent switch/bottleneck queues later for queue-occupancy and WRED-threshold experiments.
