# Bonus section: Path Steering with PCC

# Summary

Earlier parts of the tutorial introduced two complementary BlueField programming models:

- **DOCA Flow** programs packet classification, modification, forwarding, and hardware counters in the NIC data plane.
- **DOCA PCC** runs a congestion-control algorithm on the DPA and reacts to RoCE transport events for individual queue pairs (QPs).

This bonus section combines them into a closed-loop, two-path steering system.
PCC continues to calculate a congestion-derived value for each QP, but it does not apply that value as a NIC rate limit.
Instead, the DPA reports it to the host, where it becomes an input to the DOCA Flow controller.
The controller converts the relative congestion signals into a packet-splitting ratio and updates an existing hardware dispatch table while traffic is running.

The experiment runs on one BlueField-3 using a physical port loopback.
Two virtual paths share the same cable and are distinguished by a temporary DSCP bit.
Two parallel RDMA QPs act as path-specific congestion probes.
The sender pipeline randomly assigns packets to paths; the receiver pipeline emulates a different ECN policy for each path, removes the private marker, and delivers the two QPs to separate receiver SFs.

By the end of this section, you will understand how to:

1. preserve path identity when standard RoCE CNP feedback identifies only a QP;
2. build a random HASH classifier whose distribution can be changed without recreating the HASH pipe;
3. connect per-QP PCC reports to live DOCA Flow entry updates; and
4. validate the complete data and feedback loop using hardware counters and host-side diagnostics.

The implementation supports DOCA 2.7, 2.9, 3.1, and 3.4 through a shared compatibility layer.
The logical pipeline and command-line model remain the same; only the SDK-specific host, PCC-reporting, and DOCA Flow APIs differ.

# Part A: Scenario

## A.1 Why a single QP is not enough

Start with the intuitive design: one sender, one receiver, and a path multiplexer that distributes packets from one RDMA queue pair (QP) over two paths.

![A single-flow multi-path scenario](./simple-multi-path-topology.png)

The multiplexer can choose a path independently for every packet, but ordinary RoCE congestion feedback does not preserve that choice.
A receiver that sees an ECN-marked packet sends a Congestion Notification Packet (CNP) for the affected QP.
When the CNP reaches the sender, PCC can identify the QP, but it cannot tell whether the original data packet traversed path 0 or path 1.
Both paths have collapsed into one transport-level feedback stream.

This creates an observability problem.
Suppose path 0 is congested and path 1 is clear.
The sender may learn that the QP should slow down, but it has no path-specific signal from which to calculate a better packet-splitting ratio.
Changing the QP rate alone also reduces traffic on both paths, including the uncongested one.

The tutorial therefore separates two decisions:

1. PCC estimates congestion from transport feedback and exports a rate-like signal for each QP.
2. DOCA Flow uses those signals to change the fraction of packets assigned to each path.

PCC does not enforce the calculated rate in this example.
The DPA program returns `DOCA_PCC_DEV_MAX_RATE` to the NIC and reports its calculated value to the host as a steering signal.
DOCA Flow, rather than the normal PCC rate limiter, controls the traffic distribution.

## A.2 Paired QPs as path probes

To recover path identity, the application uses two parallel RDMA QPs with equal or comparable offered load.
We call them the blue QP and the green QP.

![A two-flow multi-path scenario](./paired-multi-path-topology.png)

The colors identify QPs, not paths.
Packets from either QP may be assigned to either virtual path by the sender-side multiplexer.
At the receiver-side path emulator, however, each path marks only its designated probe QP:

| Selected virtual path | QP eligible for ECN marking | Interpretation |
| --- | --- | --- |
| Path 0 | Blue QP | Blue-QP congestion represents path 0 |
| Path 1 | Green QP | Green-QP congestion represents path 1 |

Packets from the other QP still traverse and consume capacity on that path; they are simply not used as that path's congestion probe.
Because only roughly half of a paired workload is eligible for marking on a given path, the receiver-side sampler uses twice the requested all-traffic marking probability, capped at 100%.
For example, an intended 5% path marking rate becomes a 10% sampling probability for the designated QP.

This compensation assumes the paired QPs contribute similar traffic volumes.
If one QP is idle or substantially slower, its PCC signal is no longer a representative probe for the corresponding path.
That is a property of this tutorial construction, not a general requirement of multipath steering.

The two QPs use different receiver destination IP addresses.
The destination IP identifies blue versus green traffic and lets the receiver deliver each flow to its receiver SF.
It does **not** encode the packet's selected path; that is a separate per-packet marker.

## A.3 Mapping the scenario onto one BlueField-3

The tutorial emulates two paths using the two PF domains and one physical loopback cable on a single BlueField-3:

- The sender application uses a sender SF in the PF1 domain.
- PF1 runs the egress steering pipeline and sends traffic through physical port `p1`.
- A loopback cable carries the traffic from `p1` to `p0`.
- PF0 runs the ingress path-emulation pipeline.
- Two receiver SFs represent the blue and green receiver endpoints.

![Dual-flow data path in PCC path steering](./end-to-end-data-path-dual-flow.png)

Since both virtual paths share the same cable, the egress pipeline writes the selected path into IP ToS bit `0x04` (DSCP bit 0).
This bit is suitable for the experiment because the IPv4 DSCP/ECN byte is a RoCEv2 ICRC variant field.
The ingress pipeline reads the bit, applies the corresponding path policy, and clears only that private bit before delivering the packet.
Existing ECN bits and unrelated DSCP bits are preserved.

The UDP destination port is deliberately not used as a path marker.
UDP port 4791 is covered by the RoCEv2 invariant CRC; rewriting it causes the receiver to drop the packet even if a later rule restores the original value.

## A.4 Forward packet walk

For each outgoing RoCEv2 packet, the data plane performs the following steps:

1. The sender posts traffic on the blue or green RDMA QP through the sender SF.
2. PF1 admits RoCEv2 traffic to `EGRESS_CLASSIFY`.
   A 64-entry random HASH pipe selects a persistent bucket for the packet.
3. A metadata dispatch table maps that bucket to path 0 or path 1.
   Changing the number of buckets assigned to each path changes the steering ratio without rebuilding the HASH pipe.
4. The selected path-rewrite pipe writes DSCP path bit 0 or 1, and the packet is sent through the physical loopback.
5. PF0 reads the path bit first, then checks the destination IP.
   Only the probe QP designated for that path enters the path's probabilistic CE-marking stage.
6. PF0 clears the private path bit and uses the destination IP to deliver blue traffic to receiver SF0 and green traffic to receiver SF1.

Non-RoCE traffic bypasses the random classifier.

## A.5 Feedback and steering loop

Path selection is per packet, while congestion control and QP identification remain per transport flow.
The feedback and steering loop operates as follows:

1. PCC calculates a congestion-derived value for each sender QP on the DPA.
2. On DOCA 3.x, PCC binary trace reports deliver those per-QPN values directly to the host callback.
   On DOCA 2.7/2.9, the host retrieves the latest values from the PCC mailbox once per steering interval.
3. The host averages reports over the interval and applies a persistent EWMA.
   Flows that have not yet been associated with a path are reported as `pending-map` and do not influence the ratio.
4. The controller compares the aggregate reduced-rate signals for the two path groups and converts the result into a number of path-0 buckets out of 64.
5. Only dispatch entries whose assignment crosses the old/new boundary are updated.
   No HASH entries are added or removed while traffic is running.

At startup, 32 buckets are assigned to each path.
The controller retains at least three buckets for a constrained path in the one-sided full-rate case, so both paths continue receiving probe traffic.
The 64-bucket representation gives a steering granularity of 1/64, or approximately 1.56%.

## A.6 What the experiment demonstrates

This experiment demonstrates how PCC and DOCA Flow can form a closed-loop traffic-steering system.
PCC measures congestion for the probe QPs, and the host converts those measurements into a desired path share.
DOCA Flow applies that share by updating the bucket dispatch entries while traffic continues, without rebuilding the random HASH pipe.
Together, PCC provides the feedback signal and DOCA Flow enforces the resulting per-packet steering decision at line rate.
The single-card loopback emulates the two paths for the tutorial, but the same control and steering design can target two real next hops.

# Part B. Randomly assifying packets

Instruction on how to build the hash pipe for DOCA 2 and 3, with metadata writes.

# Part C. dynamically steer packets

Instruction on how to build the pipe after hash pipe, and modifying the pipe entries to steer packets.

# Part D. Testing