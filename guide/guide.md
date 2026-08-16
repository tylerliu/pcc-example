# Bonus section: Path Steering with PCC

# Summary

Previous part of the tutorial has introduced Packet Processing Programming using DOCA Flow and Transport Programming with Programmable Congestion Control(PCC). 
The tutorial combines the above components to perform programming of the transport in a more complex scenario, a multi-path packet steering scenario. 
In this scenario, instead of a per-flow congestion control decision, PCC's rate control on multiple paths is handed over to DOCA Flow, to perform packet rewrites and steering of the individual packets. 

# Part A: Scenario

We consider a Naïve multi-path Flow Scenario:

![A single-flow multi-path scenario](./simple-multi-path-topology.png)

In which a single RDMA QP, sending from Sender to Receiver, is being split by the path multiplexer to two different flows. 
The ratio of sending to two paths are controlled by the path multiplexer, which in our case, is built with PCC and DOCA Flow. 

However, one of the issue of this setup is distinguishing the traffic condition to these two paths. 
For example, if one of the packet is marked with ECN and the receiver generates a CNP, how can the sender know if it is from path 0 or path 1? 
PCC shares the same issue - it operates on each flow, but it only sees a single RDMA flow and cannot react to signals for different paths. 

Therefore, we use a second parallel flows, and have each carrying congestion information of each path: 

![A two-flow multi-path scenario](./paired-multi-path-topology.png)

Even though these two flows both sending from the same sender and "receiver", we can designate blue flow to carry only path 0 information and green flow to carry path 1 information. 
That is, for ECN marking, the switch on path 0 only marks the blue flow and path 1 only marks the green flow. 
As these two flows sending at the same rate, the switch will mark each of the blue/green flow packet it can mark with double the probability, to compensate for the fact that only half of the packets can be marked. 
And on PCC side, we can map CNPs for blue flow to conditions for path 0 and vice versa, allowing to function properly. 

Next, we can map this scenario into the single-card loopback topology in the tutorial: 

![dual-flow Datapath in PCC path Steering](./end-to-end-data-path-dual-flow.png)

As we only have a single physical link, we distinguish the two path by writing a bit into each packet, into the DSCP field in the IPv4 header. 
On the receiver side (PF0), which simulates the ECN marking for each path, we read this bit and flow destination, classifying packets before sampling and marking. 
... more description on how we have done the scenario. 

# Part B. Randomly assifying packets

Instruction on how to build the hash pipe for DOCA 2 and 3, with metadata writes. 

# Part C. dynamically steer packets

Instruction on how to build the pipe after hash pipe, and modifying the pipe entries to steer packets. 

# Part D. Testing