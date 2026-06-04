#pragma once
#include <stdint.h>
#include <rte_byteorder.h>

/* RoCEv2 is UDP port 4791 */
#define ROCE_UDP_PORT 4791

/* BTH opcodes */
#define BTH_OP_SEND_FIRST   0x00
#define BTH_OP_SEND_MIDDLE  0x01
#define BTH_OP_SEND_LAST    0x02
#define BTH_OP_SEND_ONLY    0x04
#define BTH_OP_RC_ACK       0x11
#define BTH_OP_CNP          0x81
#define BTH_OP_CCMAD        0x51  /* PCC RTT probe */

/* Base Transport Header (BTH) — 12 bytes, network byte order */
struct bth {
    uint8_t    opcode;
    uint8_t    se_migreq_padcnt_tver;
    rte_be16_t pkey;
    rte_be32_t qpn_res;   /* [23:0] = dest QPN */
    rte_be32_t ack_psn;   /* [31] = ack_req, [23:0] = PSN */
} __attribute__((packed));

/* ACK Extended Transport Header (AETH) — 4 bytes */
struct aeth {
    rte_be32_t syn_msn;   /* [31:24] = syndrome (0x00 = ACK), [23:0] = MSN */
} __attribute__((packed));

static inline uint32_t bth_get_qpn(const struct bth *b)
{
    return rte_be_to_cpu_32(b->qpn_res) & 0x00FFFFFF;
}

static inline uint32_t bth_get_psn(const struct bth *b)
{
    return rte_be_to_cpu_32(b->ack_psn) & 0x00FFFFFF;
}
