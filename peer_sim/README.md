# peer_sim — RoCE Peer Simulator for PCC RTT Probing

## Purpose

Simulates the remote end of a RoCE connection for a host running NVIDIA DOCA PCC
in RP (Reaction Point) mode. Because the peer NIC is not PCC-capable, it cannot
automatically reflect CCMAD probe packets. This DPDK application fills that role
while also injecting a configurable one-way network latency so the PCC algorithm
observes realistic (or artificially stressed) RTT values.

## Functional Requirements

### 1. CCMAD Probe Reflection
- Detect incoming CCMAD probe packets (RoCE/UDP, BTH opcode 0x51)
- Hold each probe in a latency queue for a configurable delay
- After the delay elapses, reflect the packet back (swap Ethernet/IP/UDP src↔dst)
- The delay simulates one-way propagation latency; the RP observes 2× delay as RTT

### 2. RoCE ACK Generation
- Detect incoming RoCE RC Send data packets (BTH opcode 0x00–0x02)
- Immediately send a RoCE ACK (BTH opcode 0x11 + AETH syndrome 0x00) with the
  matching destination QP and PSN
- Keeps the RP sender from stalling; without ACKs there is no traffic to rate-limit

### 3. Latency Model
- Single global configurable one-way delay (microseconds), set at startup via
  command-line argument `--latency <us>`
- Implemented as a software delay queue: each enqueued packet carries a
  `release_tsc` timestamp; the TX loop drains packets whose deadline has passed
- Default latency: 5 µs (yields ~10 µs RTT on a local link)

### 4. CNP Injection (optional, future)
- Not implemented in v1; can be added to stress-test the CNP decrease path

## Non-Requirements

- No RoCE connection setup (CM / MAD exchanges) — assumes QPs are already
  connected externally via the kernel RDMA stack or rdma-core
- No RDMA reliability retransmission — ACKs are best-effort
- No multi-port support — single DPDK port (port 0)

## Packet Formats

### CCMAD Probe (inbound, opcode 0x51)
```
Ethernet | IPv4 | UDP (dport=4791) | BTH (op=0x51, dqpn) | CCMAD payload
```

### Reflected Probe (outbound)
```
swap eth src↔dst, swap ip src↔dst, swap udp sport↔dport, same BTH+payload
```

### RoCE Data (inbound, opcode 0x00/0x01/0x02)
```
Ethernet | IPv4 | UDP (dport=4791) | BTH (op, dqpn, psn) | payload
```

### RoCE ACK (outbound)
```
Ethernet | IPv4 | UDP (dport=4791) | BTH (op=0x11, dqpn, psn) | AETH (syn=0x00)
```

## NIC Firmware Configuration (RP side, one-time)

Run on the **Arm SoC side** of the BF3:

```sh
sudo mlxconfig -d mlx5_0 -y s USER_PROGRAMMABLE_CC=1
```

Then reboot **both the Arm SoC and the x86 host**. Rebooting only the Arm side
is not sufficient — the PCIe link must be fully reset for the config to take effect.

## Build

Requires DPDK ≥ 22.11 and libibverbs.

```sh
meson setup build
cd build && ninja
```

## Run

```sh
./peer_sim -l 0-1 -n 4 -- --latency 10
```

- `-l 0-1`: use cores 0 and 1 (core 0 = RX, core 1 = TX)
- `--latency <us>`: simulated one-way delay in microseconds (default: 5)

## Design Notes

- RX and TX run on separate lcores to avoid head-of-line blocking
- The latency queue is a single-producer single-consumer ring between RX and TX
- TSC-based timing (`rte_rdtsc`) for sub-microsecond delay accuracy
- CCMAD reflection and RoCE ACK are the only two packet types generated; all
  other traffic is dropped
