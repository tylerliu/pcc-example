#pragma once
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* Initialize latency ring and TSC calibration.
 * latency_us: one-way simulated delay in microseconds. */
int reflector_init(uint32_t latency_us);

/* Process a burst of received packets.
 * CCMAD probes are enqueued with a deadline; RoCE data packets get immediate ACKs. */
void reflector_rx(struct rte_mbuf **pkts, uint16_t n,
                  uint16_t port, struct rte_mempool *mp);

/* Drain any latency-queue entries whose deadline has passed and transmit them. */
void reflector_tx_drain(uint16_t port);
