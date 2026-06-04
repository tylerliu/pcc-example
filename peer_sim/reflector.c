#include "reflector.h"
#include "roce.h"

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <string.h>

/* Latency queue entry: packet + TSC deadline */
struct lat_entry {
    struct rte_mbuf *mbuf;
    uint64_t release_tsc;
};

#define LAT_RING_SIZE 4096

static struct rte_ring *lat_ring;
static uint64_t latency_tsc;

int reflector_init(uint32_t latency_us)
{
    lat_ring = rte_ring_create("lat_ring", LAT_RING_SIZE,
                               rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!lat_ring)
        return -1;
    latency_tsc = (uint64_t)latency_us * rte_get_tsc_hz() / 1000000ULL;
    return 0;
}

static void reflect_inplace(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr   *udp = (struct rte_udp_hdr *)(ip + 1);

    struct rte_ether_addr tmp_mac = eth->src_addr;
    eth->src_addr = eth->dst_addr;
    eth->dst_addr = tmp_mac;

    uint32_t tmp_ip = ip->src_addr;
    ip->src_addr    = ip->dst_addr;
    ip->dst_addr    = tmp_ip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    uint16_t tmp_port = udp->src_port;
    udp->src_port     = udp->dst_port;
    udp->dst_port     = tmp_port;
    udp->dgram_cksum  = 0;
}

static struct rte_mbuf *build_ack(struct rte_mbuf *data_pkt, struct rte_mempool *mp)
{
    struct rte_ether_hdr *rx_eth = rte_pktmbuf_mtod(data_pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *rx_ip  = (struct rte_ipv4_hdr *)(rx_eth + 1);
    struct rte_udp_hdr   *rx_udp = (struct rte_udp_hdr *)(rx_ip + 1);
    struct bth           *rx_bth = (struct bth *)(rx_udp + 1);

    size_t pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_udp_hdr) + sizeof(struct bth) + sizeof(struct aeth);

    struct rte_mbuf *ack = rte_pktmbuf_alloc(mp);
    if (!ack) return NULL;
    rte_pktmbuf_append(ack, pkt_len);

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(ack, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);
    struct rte_udp_hdr   *udp = (struct rte_udp_hdr *)(ip + 1);
    struct bth           *bth = (struct bth *)(udp + 1);
    struct aeth          *aeth = (struct aeth *)(bth + 1);

    eth->dst_addr   = rx_eth->src_addr;
    eth->src_addr   = rx_eth->dst_addr;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    ip->version_ihl     = 0x45;
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(pkt_len - sizeof(struct rte_ether_hdr));
    ip->packet_id       = 0;
    ip->fragment_offset = 0;
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->hdr_checksum    = 0;
    ip->src_addr        = rx_ip->dst_addr;
    ip->dst_addr        = rx_ip->src_addr;

    udp->src_port  = rx_udp->dst_port;
    udp->dst_port  = rx_udp->src_port;
    udp->dgram_len = rte_cpu_to_be_16(pkt_len - sizeof(struct rte_ether_hdr)
                                       - sizeof(struct rte_ipv4_hdr));
    udp->dgram_cksum = 0;

    bth->opcode               = BTH_OP_RC_ACK;
    bth->se_migreq_padcnt_tver = 0;
    bth->pkey                 = rte_cpu_to_be_16(0xFFFF);
    bth->qpn_res              = rx_bth->qpn_res;
    bth->ack_psn              = rx_bth->ack_psn;

    aeth->syn_msn = rte_cpu_to_be_32(bth_get_psn(rx_bth) & 0x00FFFFFF);

    ack->ol_flags = 0;
    ack->l2_len = sizeof(struct rte_ether_hdr);
    ack->l3_len = sizeof(struct rte_ipv4_hdr);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    return ack;
}

void reflector_rx(struct rte_mbuf **pkts, uint16_t n,
                  uint16_t port, struct rte_mempool *mp)
{
    static uint64_t rx_count = 0;
    static uint64_t last_print = 0;
    uint64_t now = rte_rdtsc();

    rx_count += n;
    if (now - last_print > rte_get_tsc_hz()) {
        printf("reflector: rx_total=%lu (batch=%u)\n", rx_count, n);
        last_print = now;
    }

    for (uint16_t i = 0; i < n; i++) {
        struct rte_mbuf *m = pkts[i];

        /* Dump first 10 packets raw */
        static int dumped = 0;
        if (dumped < 10) {
            uint8_t *raw = rte_pktmbuf_mtod(m, uint8_t *);
            int len = rte_pktmbuf_data_len(m);
            printf("reflector: pkt[%d] len=%d: ", dumped, len);
            for (int b = 0; b < (len < 80 ? len : 80); b++)
                printf("%02x", raw[b]);
            printf("\n");
            dumped++;
        }

        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
            goto drop;
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        if (ip->next_proto_id != IPPROTO_UDP)
            goto drop;
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
        if (rte_be_to_cpu_16(udp->dst_port) != ROCE_UDP_PORT)
            goto drop;
        struct bth *bth = (struct bth *)(udp + 1);

        /* Log first 10 RoCE packets */
        static int logged = 0;
        if (logged < 10) {
            printf("reflector: RoCE pkt opcode=0x%02x qpn=0x%06x\n",
                   bth->opcode, bth_get_qpn(bth));
            logged++;
        }

        if (bth->opcode == BTH_OP_CCMAD) {
            /* Print source QPN once so user can identify the RP */
            static int qpn_printed = 0;
            if (!qpn_printed) {
                printf("RP QPN=0x%06x\n", bth_get_qpn(bth));
                qpn_printed = 1;
            }
            reflect_inplace(m);
            struct lat_entry *e = rte_malloc(NULL, sizeof(*e), 0);
            if (!e) goto drop;
            e->mbuf        = m;
            e->release_tsc = now + latency_tsc;
            if (rte_ring_enqueue(lat_ring, e) != 0) {
                rte_free(e);
                goto drop;
            }
            continue;
        } else if (bth->opcode <= BTH_OP_SEND_ONLY) {
            struct rte_mbuf *ack = build_ack(m, mp);
            rte_pktmbuf_free(m);
            if (ack)
                rte_eth_tx_burst(port, 0, &ack, 1);
            continue;
        }
drop:
        rte_pktmbuf_free(m);
    }
}

void reflector_tx_drain(uint16_t port)
{
    /* One slot to hold a dequeued entry whose deadline hasn't arrived yet. */
    static struct lat_entry *pending = NULL;
    uint64_t now = rte_rdtsc();

    /* Check held entry first */
    if (pending) {
        if (now < pending->release_tsc)
            return; /* still waiting */
        rte_eth_tx_burst(port, 0, &pending->mbuf, 1);
        rte_free(pending);
        pending = NULL;
    }

    struct lat_entry *e;
    while (rte_ring_dequeue(lat_ring, (void **)&e) == 0) {
        if (now < e->release_tsc) {
            pending = e; /* hold and stop — ring is FIFO so nothing else is ready */
            break;
        }
        rte_eth_tx_burst(port, 0, &e->mbuf, 1);
        rte_free(e);
    }
}
