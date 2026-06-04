#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/wait.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_flow.h>

#include "reflector.h"

#define PORT_ID        0
#define RX_RING_SIZE   1024
#define TX_RING_SIZE   1024
#define MBUF_POOL_SIZE 8191
#define MBUF_CACHE     256
#define BURST_SIZE     32
#define DEFAULT_LATENCY_US 5

static volatile int running = 1;
static struct rte_mempool *mbuf_pool;
static pid_t bw_pid = -1;

/* CLI config */
static uint32_t latency_us = DEFAULT_LATENCY_US;
static char     ib_dev[64] = "";
static int      ib_port    = 1;

static void sig_handler(int sig) { (void)sig; running = 0; }

static void port_init(uint16_t port)
{
    struct rte_eth_conf conf = {0};
    struct rte_eth_dev_info info;
    rte_eth_dev_info_get(port, &info);

    struct rte_eth_rxconf rxconf = info.default_rxconf;
    struct rte_eth_txconf txconf = info.default_txconf;

    rte_eth_dev_configure(port, 1, 1, &conf);
    rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                           rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
    rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
                           rte_eth_dev_socket_id(port), &txconf);
    rte_eth_dev_start(port);
    rte_eth_promiscuous_enable(port);

    /* Steer all RoCE traffic (UDP dst port 4791) to DPDK RX queue 0 */
    struct rte_flow_attr attr = { .ingress = 1 };
    struct rte_flow_item_udp udp_spec = { .hdr.dst_port = rte_cpu_to_be_16(4791) };
    struct rte_flow_item_udp udp_mask = { .hdr.dst_port = 0xFFFF };
    struct rte_flow_item pattern[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH },
        { .type = RTE_FLOW_ITEM_TYPE_IPV4 },
        { .type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask },
        { .type = RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action_queue queue_action = { .index = 0 };
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue_action },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_error flow_err;
    struct rte_flow *flow = rte_flow_create(port, &attr, pattern, actions, &flow_err);
    if (!flow)
        printf("WARNING: flow rule failed: %s\n", flow_err.message);
    else
        printf("peer_sim: flow rule installed — steering UDP:4791 to DPDK\n");
}

static int tx_lcore(__rte_unused void *arg)
{
    printf("TX lcore %u started\n", rte_lcore_id());
    while (running)
        reflector_tx_drain(PORT_ID);
    return 0;
}

static void rx_loop(void)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    printf("RX lcore %u started\n", rte_lcore_id());
    while (running) {
        uint16_t n = rte_eth_rx_burst(PORT_ID, 0, pkts, BURST_SIZE);
        if (n)
            reflector_rx(pkts, n, PORT_ID, mbuf_pool);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [EAL opts] -- --device <ibdev> "
        "[--ib-port <n>] [--latency <us>]\n", prog);
}

static void parse_args(int argc, char **argv)
{
    static struct option opts[] = {
        {"device",  required_argument, 0, 'd'},
        {"latency", required_argument, 0, 'l'},
        {"ib-port", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (c) {
        case 'd': snprintf(ib_dev, sizeof(ib_dev), "%s", optarg); break;
        case 'l': latency_us = (uint32_t)atoi(optarg); break;
        case 'i': ib_port = atoi(optarg); break;
        default:  break;
        }
    }

    if (ib_dev[0] == '\0') {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
}

static pid_t start_ib_write_bw(void)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        /* Child: exec ib_write_bw as server */
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", ib_port);
        execlp("ib_write_bw", "ib_write_bw",
               "-d", ib_dev, "-i", port_str, "--run_infinitely",
               NULL);
        perror("execlp ib_write_bw");
        _exit(1);
    }
    printf("peer_sim: started ib_write_bw server (pid %d)\n", pid);
    return pid;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;

    parse_args(argc, argv);
    printf("peer_sim: device=%s ib_port=%d latency=%uus\n",
           ib_dev, ib_port, latency_us);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Start ib_write_bw as a subprocess (server mode) */
    bw_pid = start_ib_write_bw();
    if (bw_pid < 0)
        rte_exit(EXIT_FAILURE, "Failed to start ib_write_bw\n");

    /* Give it time to set up QP and start listening */
    sleep(1);

    /* Start DPDK */
    mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", MBUF_POOL_SIZE,
                                        MBUF_CACHE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No DPDK ports available\n");

    port_init(PORT_ID);

    if (reflector_init(latency_us) != 0)
        rte_exit(EXIT_FAILURE, "reflector_init failed\n");

    uint32_t tx_lcore_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    if (tx_lcore_id == RTE_MAX_LCORE)
        rte_exit(EXIT_FAILURE, "Need at least 2 lcores\n");
    rte_eal_remote_launch(tx_lcore, NULL, tx_lcore_id);

    rx_loop();

    rte_eal_mp_wait_lcore();
    rte_eth_dev_stop(PORT_ID);
    rte_eth_dev_close(PORT_ID);

    /* Kill ib_write_bw */
    if (bw_pid > 0) {
        kill(bw_pid, SIGTERM);
        waitpid(bw_pid, NULL, 0);
    }
    return 0;
}
