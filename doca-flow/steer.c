/*
 * PCC-informed RoCE path-steering demo (BF3, p0<->p1 DAC loopback).
 *
 * Runs on the BF3 eSwitch in switch,hws,isolated mode. Pipeline (all on BF3):
 *
 *   PORT_DEMUX (root, match source vport):
 *     port_meta == SF vport  (sender egress)  -> EGRESS_CLASSIFY
 *     port_meta == 0         (wire ingress)   -> INGRESS_MARK
 *     miss                                     -> DROP
 *
 *   EGRESS_CLASSIFY (non-root): match RoCEv2 BTH dest_qp LSB (QPN parity).
 *     A QP whose parity is selected for "move" has its UDP dst 4791->4792
 *     rewritten (marker that travels on the wire), then is forwarded to the
 *     p0 wire. Everything else is forwarded to the wire unchanged (dst 4791).
 *
 *   INGRESS_MARK (non-root): the packet has looped back over the DAC.
 *     Match UDP dst 4791 -> SET CE (0x03); this marks ONLY native-path packets
 *     so CNP->QPN attribution stays coherent (moved/4792 packets are exempt).
 *     Then -> INGRESS_RESTORE.
 *
 *   INGRESS_RESTORE (non-root): match UDP dst 4792 -> rewrite back to 4791,
 *     forward to the receiver SF. dst 4791 packets pass through unchanged.
 *     Disabling this pipe lets 4792 reach the receiver (only valid if the
 *     receiver tolerates it) -- kept separable on purpose.
 *
 * The "which parity/QPN to move" decision is a control-plane input. For now it
 * is a static CLI toggle (--move-parity); wiring it to the live PCC {qpn->rate}
 * feed (peer_sim_update_pcc_rate) is a later step.
 *
 * Modeled on the SIGCOMM tutorial doca_flow_ecn.c scaffold.
 */

#include <doca_dev.h>
#include <doca_dpdk.h>
#include <doca_flow.h>
#include <doca_log.h>
#include "doca_flow_compat.h"
#include "steer.h"
#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdatomic.h>

DOCA_LOG_REGISTER(FLOW_STEER);

#define NB_QUEUES 1
#define NB_COUNTERS 16

#define ROCE_UDP_PORT_NATIVE 4791
#define ROCE_UDP_PORT_MOVED 4792 /* legacy: UDP-port marker (breaks RoCEv2 ICRC; no longer used) */
#define IP4_DSCP_ECN_CE 0x03	 /* ECN=11 (CE); set masked so DSCP is preserved */
#define IP4_ECN_MASK 0x03	 /* the two ECN bits of the ToS byte */
/*
 * On-wire "moved-path" marker. The UDP destination port is covered by the
 * RoCEv2 ICRC, so rewriting it (even with a perfect restore) corrupts the
 * packet. The IP ToS byte (DSCP+ECN) is a *variant* field excluded from the
 * ICRC -- proven safe by CE-marking working -- so we mark the moved path with a
 * single DSCP bit, set/cleared with a masked modify that leaves ECN untouched.
 * ToS bit 2 (DSCP LSB) is 0 for common RoCE DSCP classes (e.g. 24/26); change
 * MOVED_DSCP_MASK if your deployment uses a DSCP whose LSB is set.
 */
#define MOVED_DSCP_MASK 0x04

#define NB_PATHS STEER_NB_PATHS
#define PATH0_DST_IP "172.16.1.20"
#define PATH1_DST_IP "172.16.2.20"

/*
 * parser_meta.random is a 16-bit HW per-packet value independent of packet
 * content. Masking it restricts marking to a power-of-two fraction of traffic
 * (same technique as the tutorial doca_flow_ecn.c / DOCA flow_random sample).
 */
#define RANDOM_FIELD_WIDTH 16

/* enum steer_move_parity and struct steer_opts are defined in steer.h */

/* Log at CRIT level and terminate if err != DOCA_SUCCESS -- mirrors rte_exit(). */
static __attribute__((format(printf, 2, 3))) void crash_if_unsuccessful(doca_error_t err, const char *fmt, ...)
{
	if (err == DOCA_SUCCESS)
		return;

	char msg[512];
	va_list args;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	DOCA_LOG_CRIT("%s: %s", msg, doca_error_get_descr(err));
	exit(EXIT_FAILURE);
}

/* DOCA Flow global entry-process callback -- updates a per-batch status struct. */
struct entry_batch_status {
	bool failure;
	uint32_t nb_processed;
};

static void entry_process_cb(struct doca_flow_pipe_entry *entry, uint16_t pipe_queue,
			     enum doca_flow_entry_status status, enum doca_flow_entry_op op, void *user_ctx)
{
	(void)entry;
	(void)pipe_queue;
	(void)op;
	struct entry_batch_status *s = user_ctx;

	if (s == NULL)
		return;
	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		s->failure = true;
	s->nb_processed++;
}

/*
 * Stable usr_ctx for the classify entries. A live steer_apply() updates those
 * entries, and the completion callback fires with the usr_ctx bound at add
 * time; a stack-local status would dangle, so use a static one.
 */
static struct entry_batch_status g_classify_batch;

/* Block until a just-added batch of `n` entries is processed, or crash. */
static void process_entries(struct doca_flow_port *port, struct entry_batch_status *status, uint32_t n, const char *label)
{
	doca_error_t err = doca_flow_entries_process(port, 0, 10000 /* us */, n);

	crash_if_unsuccessful(err, "doca_flow_entries_process (%s)", label);
	err = (status->failure || status->nb_processed != n) ? DOCA_ERROR_BAD_STATE : DOCA_SUCCESS;
	crash_if_unsuccessful(err, "%s: %u/%u entries processed", label, status->nb_processed, n);
}

/*
 * EAL callback: add a dummy -a allowlist entry so EAL does not auto-probe any
 * real PCI devices. The real device is attached via doca_dpdk_port_probe.
 */
doca_error_t steer_eal_init(int argc, char **argv)
{
	static char allow_flag[] = "-a";
	static char dummy_pci[] = "pci:00:00.0";
	char *new_argv[64];

	if (argc >= 62) {
		DOCA_LOG_ERR("Too many EAL arguments");
		return DOCA_ERROR_INVALID_VALUE;
	}
	for (int i = 0; i < argc; i++)
		new_argv[i] = argv[i];
	new_argv[argc] = allow_flag;
	new_argv[argc + 1] = dummy_pci;

	if (rte_eal_init(argc + 2, new_argv) < 0) {
		DOCA_LOG_ERR("EAL initialization failed");
		return DOCA_ERROR_DRIVER;
	}
	return DOCA_SUCCESS;
}

static uint32_t g_sf_num; /* used only on the DOCA 2.9 discovery path */

#if DOCA_VERSION_MAJOR >= 3

/*
 * DOCA 3.x: the PF doca_dev and SF doca_dev_rep are opened by the caller (DOCA
 * argp --device/--rep, or the embedding process) and probed into DPDK together.
 * devargs default: dv_flow_en=2 (HWS) + fdb_def_rule_en=1 (keep the kernel FDB
 * default for the other PF). NOTE: repr_matching_en and representor=sfN are NOT
 * valid probe keys on 3.x -- the representor is passed as a doca_dev_rep object.
 */
static void probe_device(struct doca_dev *dev, const char *devargs, struct doca_dev_rep *dev_rep)
{
	const char *args = (devargs && devargs[0]) ? devargs : "dv_flow_en=2,fdb_def_rule_en=1";
	doca_error_t err = doca_dpdk_port_probe_with_representors(dev, args, &dev_rep, 1);

	crash_if_unsuccessful(err, "doca_dpdk_port_probe_with_representors");
}

#else /* DOCA 2.9 */

/* Open the Nth DOCA device and probe it into DPDK with caller-supplied args. */
static struct doca_dev *open_and_probe_dev(uint32_t index, const char *probe_args)
{
	struct doca_devinfo **devinfo_list;
	uint32_t nb_devs;
	struct doca_dev *dev;
	doca_error_t err;

	err = doca_devinfo_create_list(&devinfo_list, &nb_devs);
	crash_if_unsuccessful(err, "doca_devinfo_create_list");

	if (index >= nb_devs) {
		DOCA_LOG_CRIT("Device index %u out of range (%u devices found)", index, nb_devs);
		exit(EXIT_FAILURE);
	}

	err = doca_dev_open(devinfo_list[index], &dev);
	crash_if_unsuccessful(err, "doca_dev_open");

	doca_devinfo_destroy_list(devinfo_list);

	err = doca_dpdk_port_probe(dev, probe_args);
	crash_if_unsuccessful(err, "doca_dpdk_port_probe (index=%u)", index);

	return dev;
}

#endif

/*
 * DPDK must be configured and started before DOCA Flow (HWS requirement), and
 * needs at least one RX queue to start. Isolated mode: no ingress goes to RSS
 * queues -- every packet is steered by flow rules alone.
 */
static void configure_and_start_dpdk_port(struct doca_dev *dev)
{
	uint16_t first_port_id;
	doca_error_t err = doca_dpdk_get_first_port_id(dev, &first_port_id);

	crash_if_unsuccessful(err, "doca_dpdk_get_first_port_id");

	struct rte_mempool *mp = rte_pktmbuf_pool_create("mbuf_pool", 8192, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
							 rte_eth_dev_socket_id(first_port_id));
	if (mp == NULL) {
		DOCA_LOG_CRIT("rte_pktmbuf_pool_create failed");
		exit(EXIT_FAILURE);
	}

	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id)
	{
		struct rte_eth_dev_info dev_info = {0};
		int ret = rte_eth_dev_info_get(port_id, &dev_info);

		if (ret < 0) {
			DOCA_LOG_CRIT("rte_eth_dev_info_get port %u failed (errno %d)", port_id, -ret);
			exit(EXIT_FAILURE);
		}

		struct rte_eth_conf eth_conf = {0};

		ret = rte_eth_dev_configure(port_id, NB_QUEUES, NB_QUEUES, &eth_conf);
		if (ret < 0) {
			DOCA_LOG_CRIT("rte_eth_dev_configure port %u failed (errno %d)", port_id, -ret);
			exit(EXIT_FAILURE);
		}

		struct rte_eth_txconf tx_conf = dev_info.default_txconf;

		for (int q = 0; q < NB_QUEUES; q++) {
			ret = rte_eth_rx_queue_setup(port_id, q, 512, rte_eth_dev_socket_id(port_id), NULL, mp);
			if (ret < 0) {
				DOCA_LOG_CRIT("rte_eth_rx_queue_setup port %u q%d failed (errno %d)", port_id, q,
					      -ret);
				exit(EXIT_FAILURE);
			}
			ret = rte_eth_tx_queue_setup(port_id, q, 512, rte_eth_dev_socket_id(port_id), &tx_conf);
			if (ret < 0) {
				DOCA_LOG_CRIT("rte_eth_tx_queue_setup port %u q%d failed (errno %d)", port_id, q,
					      -ret);
				exit(EXIT_FAILURE);
			}
		}

#if DOCA_VERSION_MAJOR < 3
		/* 2.9 used "switch,hws,isolated,disable_switch_rss"; isolated mode must
		 * be set before start. 3.x uses plain "switch,hws" and does not isolate. */
		struct rte_flow_error flow_err = {0};

		ret = rte_flow_isolate(port_id, 1, &flow_err);
		if (ret < 0) {
			DOCA_LOG_CRIT("rte_flow_isolate port %u failed (errno %d): %s", port_id, -ret,
				      flow_err.message ? flow_err.message : "no details");
			exit(EXIT_FAILURE);
		}
#endif

		ret = rte_eth_dev_start(port_id);
		if (ret < 0) {
			DOCA_LOG_CRIT("rte_eth_dev_start port %u failed (errno %d)", port_id, -ret);
			exit(EXIT_FAILURE);
		}
	}
}

static void initialize_doca_flow(void)
{
	struct doca_flow_cfg *cfg;
	doca_error_t err = doca_flow_cfg_create(&cfg);

	crash_if_unsuccessful(err, "doca_flow_cfg_create");

	err = doca_flow_cfg_set_pipe_queues(cfg, NB_QUEUES);
	crash_if_unsuccessful(err, "doca_flow_cfg_set_pipe_queues");

#if DOCA_VERSION_MAJOR >= 3
	err = doca_flow_cfg_set_mode_args(cfg, "switch,hws");
	crash_if_unsuccessful(err, "doca_flow_cfg_set_mode_args");

	/* Port-level resource mode (counters allocated per port via nr_resources). */
	err = doca_flow_cfg_set_resource_mode(cfg, DOCA_FLOW_RESOURCE_MODE_PORT);
	crash_if_unsuccessful(err, "doca_flow_cfg_set_resource_mode");
#else
	err = doca_flow_cfg_set_mode_args(cfg, "switch,hws,isolated,disable_switch_rss");
	crash_if_unsuccessful(err, "doca_flow_cfg_set_mode_args");

	err = doca_flow_cfg_set_nr_counters(cfg, NB_COUNTERS);
	crash_if_unsuccessful(err, "doca_flow_cfg_set_nr_counters");
#endif

	err = doca_flow_cfg_set_cb_entry_process(cfg, entry_process_cb);
	crash_if_unsuccessful(err, "doca_flow_cfg_set_cb_entry_process");

	err = doca_flow_init(cfg);
	crash_if_unsuccessful(err, "doca_flow_init");

	doca_flow_cfg_destroy(cfg);
}

static struct doca_flow_port *port_start(struct doca_dev *dev, uint16_t flow_port_id)
{
	struct doca_flow_port_cfg *cfg;
	doca_error_t err = doca_flow_port_cfg_create(&cfg);

	crash_if_unsuccessful(err, "doca_flow_port_cfg_create");

	err = doca_flow_port_cfg_set_dev(cfg, dev);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_dev");

	/* Logical port id 0 = PF uplink (also the parser_meta source-port value). */
	err = steer_port_cfg_set_port_id(cfg, flow_port_id);
	crash_if_unsuccessful(err, "steer_port_cfg_set_port_id (uplink %u)", flow_port_id);

#if DOCA_VERSION_MAJOR >= 3
	err = doca_flow_port_cfg_set_actions_mem_size(cfg, 16 * DOCA_FLOW_MAX_ENTRY_ACTIONS_MEM_SIZE);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_actions_mem_size");
	err = doca_flow_port_cfg_set_nr_resources(cfg, DOCA_FLOW_RESOURCE_COUNTER, 128);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_nr_resources (counter)");
#else
	{
		char port_id_str[8];

		snprintf(port_id_str, sizeof(port_id_str), "%u", flow_port_id);
		err = doca_flow_port_cfg_set_devargs(cfg, port_id_str);
		crash_if_unsuccessful(err, "doca_flow_port_cfg_set_devargs");
	}
#endif

	struct doca_flow_port *port;

	err = doca_flow_port_start(cfg, &port);
	crash_if_unsuccessful(err, "doca_flow_port_start");

	doca_flow_port_cfg_destroy(cfg);
	return port;
}

#if DOCA_VERSION_MAJOR < 3
/* Find the DPDK port id of the SF representor (2.9: probed via "representor=sfN"). */
static uint16_t find_sf_representor_port_id(void)
{
	uint16_t port_id;
	uint16_t nb_ports = 0;

	RTE_ETH_FOREACH_DEV(port_id)
	{
		struct rte_eth_dev_info dev_info = {0};

		nb_ports++;
		if (rte_eth_dev_info_get(port_id, &dev_info) < 0)
			continue;
		if (dev_info.dev_flags != NULL && (*dev_info.dev_flags & RTE_ETH_DEV_REPRESENTOR) != 0) {
			DOCA_LOG_INFO("SF representor found on DPDK port %u", port_id);
			return port_id;
		}
	}

	DOCA_LOG_CRIT("No SF representor ethdev found (%u DPDK port(s) probed).", nb_ports);
	DOCA_LOG_CRIT("Probed 'representor=sf%u'; run 'sudo mlnx-sf -a show' and pass --sf-num <N>.", g_sf_num);
	exit(EXIT_FAILURE);
}
#endif

#if DOCA_VERSION_MAJOR >= 3
/* 3.x: start the SF representor as a DOCA Flow port (logical id 1) via its doca_dev_rep. */
static struct doca_flow_port *rep_port_start(uint16_t flow_port_id, struct doca_dev_rep *dev_rep)
{
	struct doca_flow_port_cfg *cfg;
	doca_error_t err = doca_flow_port_cfg_create(&cfg);

	crash_if_unsuccessful(err, "doca_flow_port_cfg_create (rep port %u)", flow_port_id);

	err = doca_flow_port_cfg_set_port_id(cfg, flow_port_id);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_port_id (rep port %u)", flow_port_id);

	err = doca_flow_port_cfg_set_dev_rep(cfg, dev_rep);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_dev_rep (rep port %u)", flow_port_id);

	err = doca_flow_port_cfg_set_actions_mem_size(cfg, 16 * DOCA_FLOW_MAX_ENTRY_ACTIONS_MEM_SIZE);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_actions_mem_size (rep port %u)", flow_port_id);

	struct doca_flow_port *port;

	err = doca_flow_port_start(cfg, &port);
	crash_if_unsuccessful(err, "doca_flow_port_start (rep port %u)", flow_port_id);

	doca_flow_port_cfg_destroy(cfg);
	return port;
}
#else
static struct doca_flow_port *rep_port_start(uint16_t dpdk_port_id)
{
	struct doca_flow_port_cfg *cfg;
	char port_id_str[8];

	snprintf(port_id_str, sizeof(port_id_str), "%u", dpdk_port_id);

	doca_error_t err = doca_flow_port_cfg_create(&cfg);

	crash_if_unsuccessful(err, "doca_flow_port_cfg_create (rep port %u)", dpdk_port_id);

	err = doca_flow_port_cfg_set_devargs(cfg, port_id_str);
	crash_if_unsuccessful(err, "doca_flow_port_cfg_set_devargs (rep port %u)", dpdk_port_id);

	struct doca_flow_port *port;

	err = doca_flow_port_start(cfg, &port);
	crash_if_unsuccessful(err, "doca_flow_port_start (rep port %u)", dpdk_port_id);

	doca_flow_port_cfg_destroy(cfg);
	return port;
}
#endif

/* Port ids in the eSwitch: 0 = p0 wire uplink, 1 = SF representor (receiver). */
#define WIRE_PORT_ID 0
#define SF_PORT_ID 1

/*
 * DELIVER pipe: forward-only basic pipe whose HIT fate is a port. On 3.x HWS a
 * pipe's fwd_miss may not be a port (only a pipe or drop), so pipes that need to
 * "deliver to a port on miss" point their fwd/fwd_miss at one of these via
 * FWD_PIPE instead. Matches all IPv4 (dscp_ecn wildcarded); non-IPv4 misses ->
 * NULL fwd_miss (mirrors the tutorial create_fwd_pipe).
 */
static struct doca_flow_pipe *create_deliver_pipe(struct doca_flow_port *port, const char *name, uint16_t dest_port_id)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PORT, .port_id = dest_port_id};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct entry_batch_status status = {0};
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dscp_ecn = 0xFF;      /* variable -> non-empty HWS template */
	match_mask.outer.ip4.dscp_ecn = 0x00; /* wildcard: all IPv4 */

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (%s)", name);
	err = doca_flow_pipe_cfg_set_name(cfg, name);
	crash_if_unsuccessful(err, "pipe_cfg_set_name (%s)", name);
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (%s)", name);
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (%s)", name);
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (%s)", name);
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (%s)", name);
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (%s)", name);

	err = doca_flow_pipe_create(cfg, &fwd, NULL, &pipe);
	crash_if_unsuccessful(err, "pipe_create (%s)", name);
	doca_flow_pipe_cfg_destroy(cfg);

	struct doca_flow_match ematch = {0};

	err = steer_pipe_add_entry(0, pipe, &ematch, 0, NULL, NULL, NULL, 0, &status, &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (%s)", name);
	process_entries(port, &status, 1, name);
	DOCA_LOG_INFO("%s ready: deliver IPv4 -> port %u", name, dest_port_id);
	return pipe;
}

/*
 * INGRESS_RESTORE (non-root): rewrite UDP dst 4792 -> 4791, then deliver to the
 * receiver SF via deliver_sf. Packets already on 4791 miss and also go to
 * deliver_sf (fwd_miss must be a pipe, not a port, on 3.x HWS).
 * Returns the pipe; the entry is added by add_restore_entry().
 */
static struct doca_flow_pipe *create_restore_pipe(struct doca_flow_port *port, struct doca_flow_pipe *deliver_sf)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_actions actions = {0}, *actions_arr[1] = {&actions};
	struct doca_flow_actions actions_mask = {0}, *actions_masks_arr[1] = {&actions_mask};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_sf};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_sf};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;	 /* marker bit set (moved path) */
	match_mask.outer.ip4.dscp_ecn = MOVED_DSCP_MASK; /* only the marker bit */

	actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.outer.ip4.dscp_ecn = 0x00;		 /* clear marker (masked -> ECN preserved) */
	actions_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions_mask.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (restore)");
	err = doca_flow_pipe_cfg_set_name(cfg, "INGRESS_RESTORE");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (restore)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (restore)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (restore)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (restore)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (restore)");
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (restore)");
	err = doca_flow_pipe_cfg_set_actions(cfg, actions_arr, actions_masks_arr, NULL, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_actions (restore)");
	err = doca_flow_pipe_cfg_set_monitor(cfg, &monitor);
	crash_if_unsuccessful(err, "pipe_cfg_set_monitor (restore)");

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (restore)");
	doca_flow_pipe_cfg_destroy(cfg);
	return pipe;
}

static struct doca_flow_pipe_entry *add_restore_entry(struct doca_flow_pipe *pipe, struct doca_flow_port *port)
{
	struct doca_flow_match match = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct entry_batch_status status = {0};
	struct doca_flow_pipe_entry *entry;
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;
	actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.outer.ip4.dscp_ecn = 0x00;

	err = steer_pipe_add_entry(0, pipe, &match, 0, &actions, &monitor, NULL, 0, &status, &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (restore)");
	process_entries(port, &status, 1, "restore entry");
	DOCA_LOG_INFO("Restore pipe ready: clear DSCP marker (0x%02x) before SF delivery", MOVED_DSCP_MASK);
	return entry;
}

/*
 * Mask-based random matching supports only negative-power-of-two percentages
 * (50, 25, 12.5, ...): rounds the request down to the nearest supported one.
 * Same technique as the tutorial doca_flow_ecn.c / DOCA flow_random sample.
 */
static uint16_t get_random_mask(double percentage)
{
	double next_supported = 50.0;
	uint8_t i;

	for (i = 1; i <= RANDOM_FIELD_WIDTH; ++i) {
		if (percentage >= next_supported)
			break;
		next_supported /= 2;
	}
	if (percentage > next_supported)
		DOCA_LOG_WARN("Requested %.4g%% not supported (power-of-2 only); using %.4g%%", percentage,
			      next_supported);
	return (uint16_t)((1u << i) - 1);
}

/*
 * RANDOM_SAMPLE (non-root): match only parser_meta.random with a mask, so a
 * power-of-two fraction of a path's packets reaches hit_pipe (the mark pipe)
 * and the rest go to miss_pipe (restore, i.e. delivered unmarked). Used per
 * path when 0 < percent < 100. Combining a random match with a header-modify
 * action in one HWS entry is not supported, hence a separate action-free pipe.
 */
static struct doca_flow_pipe *create_random_sample_pipe(struct doca_flow_port *port, const char *name,
							struct doca_flow_pipe *hit_pipe,
							struct doca_flow_pipe *miss_pipe, uint16_t random_mask)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = hit_pipe};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = miss_pipe};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct entry_batch_status status = {0};
	doca_error_t err;

	match.parser_meta.random = 0;
	match_mask.parser_meta.random = random_mask;

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (%s)", name);
	err = doca_flow_pipe_cfg_set_name(cfg, name);
	crash_if_unsuccessful(err, "pipe_cfg_set_name (%s)", name);
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (%s)", name);
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (%s)", name);
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (%s)", name);
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (%s)", name);
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (%s)", name);

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (%s)", name);
	doca_flow_pipe_cfg_destroy(cfg);

	err = steer_pipe_add_entry(0, pipe, &match, 0, NULL, NULL, NULL, 0, &status, &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (%s)", name);
	process_entries(port, &status, 1, name);
	DOCA_LOG_INFO("%s ready: mask 0x%04x", name, random_mask);
	return pipe;
}

/*
 * INGRESS_MARK (non-root): the looped-back packet. Match the specific path's
 * outer IPv4 dst + UDP dst 4791 -> SET CE, then forward to restore. Moved
 * packets (dst 4792) and non-native traffic miss and go straight to restore,
 * so only native-path packets are CE-marked. One entry per path -> per-path
 * counters; the mark decision is per path via its own CE profile upstream.
 */
static struct doca_flow_pipe *create_mark_pipe(struct doca_flow_port *port, struct doca_flow_pipe *restore_pipe)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_actions actions = {0}, *actions_arr[1] = {&actions};
	struct doca_flow_actions actions_mask = {0}, *actions_masks_arr[1] = {&actions_mask};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = restore_pipe};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = restore_pipe};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dst_ip = 0xFFFFFFFF;	/* variable per entry (path dst IP) */
	match.outer.ip4.dscp_ecn = 0xFF;	/* variable field -> non-empty template */
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.udp.l4_port.dst_port = RTE_BE16(ROCE_UDP_PORT_NATIVE);
	match_mask.outer.ip4.dst_ip = 0xFFFFFFFF;	 /* exact dst IP */
	match_mask.outer.ip4.dscp_ecn = MOVED_DSCP_MASK; /* mark only native (marker bit clear) */
	match_mask.outer.udp.l4_port.dst_port = RTE_BE16(0xFFFF);

	actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.outer.ip4.dscp_ecn = 0xFF; /* variable -- exact value per entry */
	actions_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions_mask.outer.ip4.dscp_ecn = IP4_ECN_MASK; /* set only ECN (CE); preserve DSCP+marker */

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (mark)");
	err = doca_flow_pipe_cfg_set_name(cfg, "INGRESS_MARK");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (mark)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (mark)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (mark)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (mark)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, NB_PATHS);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (mark)");
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (mark)");
	err = doca_flow_pipe_cfg_set_actions(cfg, actions_arr, actions_masks_arr, NULL, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_actions (mark)");
	err = doca_flow_pipe_cfg_set_monitor(cfg, &monitor);
	crash_if_unsuccessful(err, "pipe_cfg_set_monitor (mark)");

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (mark)");
	doca_flow_pipe_cfg_destroy(cfg);
	return pipe;
}

/* One CE-mark entry per path (matched by outer dst IP + UDP 4791). */
static void add_mark_entries(struct doca_flow_pipe *pipe, struct doca_flow_port *port,
			     const struct steer_opts *cfg, struct doca_flow_pipe_entry *entries[NB_PATHS])
{
	struct entry_batch_status status = {0};
	doca_error_t err;

	for (int i = 0; i < NB_PATHS; i++) {
		struct doca_flow_match match = {0};
		struct doca_flow_actions actions = {0};
		struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
		uint32_t flags = (i == NB_PATHS - 1) ? 0 : STEER_WAIT_FOR_BATCH;

		match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
		match.outer.ip4.dst_ip = cfg->path_dst_ip[i];
		match.outer.udp.l4_port.dst_port = RTE_BE16(ROCE_UDP_PORT_NATIVE);
		actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
		actions.outer.ip4.dscp_ecn = IP4_DSCP_ECN_CE;

		err = steer_pipe_add_entry(0, pipe, &match, 0, &actions, &monitor, NULL, flags, &status, &entries[i]);
		crash_if_unsuccessful(err, "pipe_add_entry (mark path %d)", i);
	}
	process_entries(port, &status, NB_PATHS, "mark entries");
	DOCA_LOG_INFO("Mark pipe ready: CE on native (UDP 4791) per-path wire-ingress");
}

/*
 * INGRESS_PATH_DEMUX (non-root): classify looped-back wire ingress by outer
 * IPv4 dst into the two paths' CE targets (mark pipe directly at 100%, or a
 * per-path RANDOM_SAMPLE pre-filter, or restore at 0%). Non-path traffic
 * misses and is delivered (restored if it is a stray 4792).
 */
static struct doca_flow_pipe *create_path_demux_pipe(struct doca_flow_port *port, const struct steer_opts *cfg,
						     struct doca_flow_pipe *target[NB_PATHS],
						     struct doca_flow_pipe *restore_pipe)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_CHANGEABLE};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = restore_pipe};
	struct doca_flow_pipe_cfg *cfg_pipe;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dst_ip = 0xFFFFFFFF;
	match_mask.outer.ip4.dst_ip = 0xFFFFFFFF;

	err = doca_flow_pipe_cfg_create(&cfg_pipe, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (path demux)");
	err = doca_flow_pipe_cfg_set_name(cfg_pipe, "INGRESS_PATH_DEMUX");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (path demux)");
	err = doca_flow_pipe_cfg_set_type(cfg_pipe, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (path demux)");
	err = doca_flow_pipe_cfg_set_domain(cfg_pipe, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (path demux)");
	err = doca_flow_pipe_cfg_set_is_root(cfg_pipe, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (path demux)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg_pipe, NB_PATHS);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (path demux)");
	err = doca_flow_pipe_cfg_set_match(cfg_pipe, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (path demux)");

	err = doca_flow_pipe_create(cfg_pipe, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (path demux)");
	doca_flow_pipe_cfg_destroy(cfg_pipe);

	struct entry_batch_status status = {0};

	for (int i = 0; i < NB_PATHS; i++) {
		struct doca_flow_match entry_match = {0};
		struct doca_flow_fwd entry_fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = target[i]};
		struct doca_flow_pipe_entry *entry;
		uint32_t flags = (i == NB_PATHS - 1) ? 0 : STEER_WAIT_FOR_BATCH;

		entry_match.outer.ip4.dst_ip = cfg->path_dst_ip[i];
		err = steer_pipe_add_entry(0, pipe, &entry_match, 0, NULL, NULL, &entry_fwd, flags, &status, &entry);
		crash_if_unsuccessful(err, "pipe_add_entry (path demux %d)", i);
	}
	process_entries(port, &status, NB_PATHS, "path demux entries");
	DOCA_LOG_INFO("Path demux ready: per-path CE targets by outer dst IP");
	return pipe;
}

/*
 * EGRESS_CLASSIFY (non-root): match RoCEv2 BTH dest_qp LSB (QPN parity). The
 * selected parity is rewritten UDP 4791->4792 (moved); the other parity is
 * forwarded unchanged. Both fates forward to the p0 wire. Two entries.
 */
static struct doca_flow_pipe *create_classify_pipe(struct doca_flow_port *port, struct doca_flow_pipe *deliver_wire)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_actions rewrite = {0}, passthru = {0};
	struct doca_flow_actions rewrite_mask = {0}, passthru_mask = {0};
	struct doca_flow_actions *actions_arr[2] = {&rewrite, &passthru};
	struct doca_flow_actions *actions_masks_arr[2] = {&rewrite_mask, &passthru_mask};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_wire};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_wire};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	/* Match on RoCEv2 BTH dest_qp; parity is selected per entry via the mask. */
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match.outer.roce_v2.bth.dest_qp[2] = 0xFF; /* LSB byte -- variable */
	match_mask.outer.roce_v2.bth.dest_qp[2] = 0x01; /* only the parity bit */

	/* action[0]: set the ICRC-exempt DSCP marker bit (masked -> ECN and the rest
	 * of the DSCP class are preserved). The UDP port is left untouched. */
	rewrite.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	rewrite.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;
	rewrite_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	rewrite_mask.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;
	/* action[1]: no header change (native parity passthrough) */

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (classify)");
	err = doca_flow_pipe_cfg_set_name(cfg, "EGRESS_CLASSIFY");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (classify)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (classify)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (classify)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (classify)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 2);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (classify)");
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (classify)");
	err = doca_flow_pipe_cfg_set_actions(cfg, actions_arr, actions_masks_arr, NULL, 2);
	crash_if_unsuccessful(err, "pipe_cfg_set_actions (classify)");
	err = doca_flow_pipe_cfg_set_monitor(cfg, &monitor);
	crash_if_unsuccessful(err, "pipe_cfg_set_monitor (classify)");

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (classify)");
	doca_flow_pipe_cfg_destroy(cfg);
	return pipe;
}

/*
 * Two entries: the "moved" parity rewrites 4791->4792 (action_idx 0), the other
 * parity passes through (action_idx 1). When move_parity == MOVE_NONE both
 * entries pass through (pure per-path CE-mark demo, no wire rewrite).
 */
static void add_classify_entries(struct doca_flow_pipe *pipe, struct doca_flow_port *port, int move_parity,
				 struct doca_flow_pipe_entry *entries[NB_PATHS])
{
	doca_error_t err;

	memset(&g_classify_batch, 0, sizeof(g_classify_batch));

	for (int parity = 0; parity <= 1; parity++) {
		struct doca_flow_match match = {0};
		struct doca_flow_actions actions = {0};
		struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
		bool move = (move_parity == STEER_MOVE_ALL) || (parity == move_parity);
		uint32_t flags = (parity == 0) ? STEER_WAIT_FOR_BATCH : 0;
		uint8_t aidx;

		match.outer.roce_v2.bth.dest_qp[2] = (uint8_t)parity;

		if (move) {
			aidx = 0; /* set DSCP marker bit (masked) */
			actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
			actions.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;
		} else {
			aidx = 1; /* passthrough */
		}

		err = steer_pipe_add_entry(0, pipe, &match, aidx, &actions, &monitor, NULL, flags, &g_classify_batch,
					   &entries[parity]);
		crash_if_unsuccessful(err, "pipe_add_entry (classify parity=%d)", parity);
	}
	process_entries(port, &g_classify_batch, 2, "classify entries");
	DOCA_LOG_INFO("Classify pipe ready: move_parity=%d (dest_qp LSB -> DSCP marker 0x%02x)", move_parity,
		      MOVED_DSCP_MASK);
}

/*
 * EGRESS_EXEMPT (non-root): management QPs must never be steered onto the moved
 * (UDP 4792) path. QP1 is the GSI QP that carries rdma_cm connection MADs (the
 * RoCEv2 -R handshake); rewriting it to 4792 breaks connection setup. This pipe
 * matches dest_qp in {0,1} (high 23 bits zero, parity bit wildcarded) and sends
 * them straight to the wire unchanged; every other QPN misses to EGRESS_CLASSIFY.
 */
static struct doca_flow_pipe *create_exempt_pipe(struct doca_flow_port *port, struct doca_flow_pipe *deliver_wire,
						 struct doca_flow_pipe *classify_pipe)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_wire};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = classify_pipe};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct entry_batch_status status = {0};
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match.outer.roce_v2.bth.dest_qp[0] = 0xFF;
	match.outer.roce_v2.bth.dest_qp[1] = 0xFF;
	match.outer.roce_v2.bth.dest_qp[2] = 0xFF;
	match_mask.outer.roce_v2.bth.dest_qp[0] = 0xFF;
	match_mask.outer.roce_v2.bth.dest_qp[1] = 0xFF;
	match_mask.outer.roce_v2.bth.dest_qp[2] = 0xFE; /* ignore the parity bit */

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (exempt)");
	err = doca_flow_pipe_cfg_set_name(cfg, "EGRESS_EXEMPT");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (exempt)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (exempt)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (exempt)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (exempt)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (exempt)");
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (exempt)");

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (exempt)");
	doca_flow_pipe_cfg_destroy(cfg);

	struct doca_flow_match ematch = {0}; /* dest_qp == 0 (mask 0xFFFFFE -> {0,1}) */

	err = steer_pipe_add_entry(0, pipe, &ematch, 0, NULL, NULL, NULL, 0, &status, &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (exempt qp0/1)");
	process_entries(port, &status, 1, "exempt entry");
	DOCA_LOG_INFO("Exempt pipe ready: dest_qp 0/1 (SMI/GSI-CM) bypass rewrite");
	return pipe;
}

/*
 * PORT_DEMUX (root): demux by source vport.
 *   port_meta == SF_PORT_ID (sender egress) -> classify_pipe
 *   port_meta == 0          (wire ingress)  -> mark_pipe
 *   miss -> DROP
 */
static void create_port_demux_pipe(struct doca_flow_port *port, struct doca_flow_pipe *sf_target,
				   struct doca_flow_pipe *wire_target)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_CHANGEABLE};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_DROP};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	match.parser_meta.STEER_PARSER_PORT = STEER_PORT_ALL;
	match_mask.parser_meta.STEER_PARSER_PORT = STEER_PORT_ALL;

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (demux)");
	err = doca_flow_pipe_cfg_set_name(cfg, "PORT_DEMUX");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (demux)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (demux)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (demux)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, true);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (demux)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 2);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (demux)");
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (demux)");

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (demux)");
	doca_flow_pipe_cfg_destroy(cfg);

	struct doca_flow_match entry_match = {0};
	struct doca_flow_fwd entry_fwd;
	struct entry_batch_status status = {0};
	struct doca_flow_pipe_entry *entry;

	/* wire ingress (port 0) -> wire_target (ingress path demux / mark chain) */
	entry_match.parser_meta.STEER_PARSER_PORT = WIRE_PORT_ID;
	memset(&entry_fwd, 0, sizeof(entry_fwd));
	entry_fwd.type = DOCA_FLOW_FWD_PIPE;
	entry_fwd.next_pipe = wire_target;
	err = steer_pipe_add_entry(0, pipe, &entry_match, 0, NULL, NULL, &entry_fwd, STEER_WAIT_FOR_BATCH, &status,
				   &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (demux wire->target)");

	/* SF egress (port 1) -> sf_target (classify on sender, plain deliver on receiver) */
	entry_match.parser_meta.STEER_PARSER_PORT = SF_PORT_ID;
	memset(&entry_fwd, 0, sizeof(entry_fwd));
	entry_fwd.type = DOCA_FLOW_FWD_PIPE;
	entry_fwd.next_pipe = sf_target;
	err = steer_pipe_add_entry(0, pipe, &entry_match, 0, NULL, NULL, &entry_fwd, 0, &status, &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (demux sf->target)");

	process_entries(port, &status, 2, "demux entries");
	DOCA_LOG_INFO("Port demux ready: wire-ingress and SF-egress routed per role");
}

/* CLI parsing lives in the standalone main (doca_flow_steer.c). */

/* Choose a path's ingress CE target: mark (100%), random pre-filter (0<p<100), or restore (0%). */
static struct doca_flow_pipe *path_ce_target(struct doca_flow_port *port, int idx, double percent,
					     struct doca_flow_pipe *mark_pipe, struct doca_flow_pipe *restore_pipe)
{
	char name[32];

	if (percent >= 100.0)
		return mark_pipe;
	if (percent <= 0.0)
		return restore_pipe;
	snprintf(name, sizeof(name), "RANDOM_SAMPLE_P%d", idx);
	return create_random_sample_pipe(port, name, mark_pipe, restore_pipe, get_random_mask(percent));
}

/* ------------------------------------------------------------------ *
 *  Module state + public API (see steer.h)                            *
 * ------------------------------------------------------------------ */

struct steer_state {
	bool started;
	struct steer_opts opts;
	struct doca_flow_port *port;
	struct doca_flow_port *sf_rep_port;
	struct doca_flow_pipe *classify_pipe;
	struct doca_flow_pipe_entry *classify_entry[NB_PATHS];
	struct doca_flow_pipe_entry *mark_entry[NB_PATHS];
	struct doca_flow_pipe_entry *restore_entry;
	_Atomic uint32_t rate[NB_PATHS]; /* per-parity PCC rate (FXP20) */
	int applied_move;		 /* enum steer_move_parity currently programmed */
};

static struct steer_state g_steer;

void steer_default_opts(struct steer_opts *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->sf_num = 0;
	opts->role = STEER_ROLE_BOTH;
	opts->move_parity = STEER_MOVE_AUTO;
	opts->path_percent[0] = 100.0;
	opts->path_percent[1] = 100.0;
	opts->auto_ratio_threshold = 0.5;
	/* Defaults are string literals, so inet_pton cannot fail here. */
	(void)inet_pton(AF_INET, PATH0_DST_IP, &opts->path_dst_ip[0]);
	(void)inet_pton(AF_INET, PATH1_DST_IP, &opts->path_dst_ip[1]);
}

/*
 * Resolve the effective "moved" parity. Fixed configs return opts.move_parity.
 * STEER_MOVE_AUTO derives it from per-parity PCC rate: the more-congested parity
 * (lower rate) is moved onto the alternate (4792) path once its rate falls below
 * auto_ratio_threshold * the other parity's rate.
 *
 * NOTE: this AUTO policy is a first, deliberately simple placeholder; the exact
 * PCC-driven policy is intended to be refined later.
 */
static int steer_decide(void)
{
	if (g_steer.opts.move_parity != STEER_MOVE_AUTO)
		return g_steer.opts.move_parity;

	uint32_t r_even = atomic_load_explicit(&g_steer.rate[0], memory_order_relaxed);
	uint32_t r_odd = atomic_load_explicit(&g_steer.rate[1], memory_order_relaxed);

	if (r_even == 0 || r_odd == 0)
		return STEER_MOVE_NONE; /* no rate yet for one path */

	double thr = g_steer.opts.auto_ratio_threshold;

	if ((double)r_even < (double)r_odd * thr)
		return STEER_MOVE_EVEN;
	if ((double)r_odd < (double)r_even * thr)
		return STEER_MOVE_ODD;
	return STEER_MOVE_NONE;
}

/* Reprogram the classify entries so `move_parity` is rewritten 4791->4792. */
static void steer_apply(int move_parity)
{
	memset(&g_classify_batch, 0, sizeof(g_classify_batch));

	for (int parity = 0; parity < NB_PATHS; parity++) {
		struct doca_flow_actions actions = {0};
		struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
		uint8_t aidx;
		doca_error_t err;

		if (parity == move_parity || move_parity == STEER_MOVE_ALL) {
			aidx = 0;
			actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
			actions.outer.ip4.dscp_ecn = MOVED_DSCP_MASK;
		} else {
			aidx = 1;
		}
		err = steer_pipe_update_entry(0, g_steer.classify_pipe, aidx, &actions, &monitor, NULL, 0,
					      g_steer.classify_entry[parity]);
		crash_if_unsuccessful(err, "classify update (parity=%d)", parity);
	}
	process_entries(g_steer.port, &g_classify_batch, NB_PATHS, "classify update");
	g_steer.applied_move = move_parity;
	DOCA_LOG_INFO("steer decision applied: move_parity=%d", move_parity);
}

doca_error_t steer_start(const struct steer_opts *opts)
{
	if (g_steer.started)
		return DOCA_ERROR_BAD_STATE;

	g_steer.opts = *opts;
	g_sf_num = opts->sf_num;
	for (int i = 0; i < NB_PATHS; i++)
		atomic_store_explicit(&g_steer.rate[i], 0, memory_order_relaxed);

#if DOCA_VERSION_MAJOR >= 3
	if (opts->dev == NULL || opts->dev_rep == NULL) {
		DOCA_LOG_CRIT("steer_start: opts->dev and opts->dev_rep are required on DOCA 3.x "
			      "(open them via --device/--rep or DOCA device APIs)");
		return DOCA_ERROR_INVALID_VALUE;
	}
	struct doca_dev *dev = opts->dev;

	probe_device(dev, opts->devargs, opts->dev_rep);
	configure_and_start_dpdk_port(dev);
	initialize_doca_flow();

	g_steer.port = port_start(dev, WIRE_PORT_ID);
	g_steer.sf_rep_port = rep_port_start(SF_PORT_ID, opts->dev_rep);
#else
	char probe_args[128];

	snprintf(probe_args, sizeof(probe_args), "dv_flow_en=2,fdb_def_rule_en=1,representor=sf%u", opts->sf_num);
	struct doca_dev *dev = open_and_probe_dev(0, probe_args);

	configure_and_start_dpdk_port(dev);
	initialize_doca_flow();

	g_steer.port = port_start(dev, WIRE_PORT_ID);
	g_steer.sf_rep_port = rep_port_start(find_sf_representor_port_id());
#endif

	/* Deliver pipes: fwd_miss cannot be a port on 3.x HWS, so port delivery is
	 * done via these FWD_PIPE targets. Both roles need both. */
	struct doca_flow_pipe *deliver_sf = create_deliver_pipe(g_steer.port, "DELIVER_SF", SF_PORT_ID);
	struct doca_flow_pipe *deliver_wire = create_deliver_pipe(g_steer.port, "DELIVER_WIRE", WIRE_PORT_ID);

	const bool do_ingress = (g_steer.opts.role != STEER_ROLE_EGRESS);
	const bool do_egress = (g_steer.opts.role != STEER_ROLE_INGRESS);

	/* PORT_DEMUX targets default to plain delivery; the active role overrides. */
	struct doca_flow_pipe *wire_target = deliver_sf;  /* wire-ingress fate */
	struct doca_flow_pipe *sf_target = deliver_wire;  /* SF-egress fate */

	if (do_ingress) {
		/* Ingress (receiver): deliver_sf <- restore <- mark <- CE target <- path demux. */
		struct doca_flow_pipe *restore_pipe = create_restore_pipe(g_steer.port, deliver_sf);

		g_steer.restore_entry = add_restore_entry(restore_pipe, g_steer.port);

		struct doca_flow_pipe *mark_pipe = create_mark_pipe(g_steer.port, restore_pipe);

		add_mark_entries(mark_pipe, g_steer.port, &g_steer.opts, g_steer.mark_entry);

		struct doca_flow_pipe *ce_target[NB_PATHS];

		for (int i = 0; i < NB_PATHS; i++)
			ce_target[i] = path_ce_target(g_steer.port, i, g_steer.opts.path_percent[i], mark_pipe,
						      restore_pipe);

		wire_target = create_path_demux_pipe(g_steer.port, &g_steer.opts, ce_target, restore_pipe);
	}

	if (do_egress) {
		/* Egress (sender): QPN-parity classify (+ optional 4791->4792) -> deliver_wire. */
		g_steer.classify_pipe = create_classify_pipe(g_steer.port, deliver_wire);

		/* AUTO starts as NONE until per-path rates arrive. */
		int initial_move = (g_steer.opts.move_parity == STEER_MOVE_AUTO) ? STEER_MOVE_NONE
										 : g_steer.opts.move_parity;

		add_classify_entries(g_steer.classify_pipe, g_steer.port, initial_move, g_steer.classify_entry);
		g_steer.applied_move = initial_move;

		/* Management QPs (QP0/QP1, incl. the GSI QP for rdma_cm) bypass the
		 * rewrite; everything else falls through to the parity classifier. */
		sf_target = create_exempt_pipe(g_steer.port, deliver_wire, g_steer.classify_pipe);
	}

	create_port_demux_pipe(g_steer.port, sf_target, wire_target);

	g_steer.started = true;
	DOCA_LOG_INFO("steer started (role=%s, move_parity=%d, path0=%.4g%% path1=%.4g%%)",
		      g_steer.opts.role == STEER_ROLE_EGRESS ? "egress"
		      : g_steer.opts.role == STEER_ROLE_INGRESS ? "ingress" : "both",
		      g_steer.opts.move_parity, g_steer.opts.path_percent[0], g_steer.opts.path_percent[1]);
	return DOCA_SUCCESS;
}

void steer_update_pcc_rate(uint32_t qpn, uint32_t rate)
{
	/* Path identity is QPN parity (the two peer QPs differ in the LSB). */
	atomic_store_explicit(&g_steer.rate[qpn & 1], rate, memory_order_relaxed);
}

void steer_poll(void)
{
	if (!g_steer.started)
		return;

	if (g_steer.classify_pipe) {
		int want = steer_decide();

		if (want != g_steer.applied_move)
			steer_apply(want);
	}

	struct doca_flow_resource_query q;

	for (int i = 0; i < NB_PATHS; i++) {
		if (g_steer.mark_entry[i] &&
		    doca_flow_resource_query_entry(g_steer.mark_entry[i], &q) == DOCA_SUCCESS)
			DOCA_LOG_INFO("path%d CE-marked (native 4791): %lu pkts  [rate=%u]", i, q.counter.total_pkts,
				      atomic_load_explicit(&g_steer.rate[i], memory_order_relaxed));
	}
	if (g_steer.restore_entry &&
	    doca_flow_resource_query_entry(g_steer.restore_entry, &q) == DOCA_SUCCESS)
		DOCA_LOG_INFO("restored (cleared DSCP marker): %lu pkts (move_parity=%d)", q.counter.total_pkts,
			      g_steer.applied_move);
}

void steer_stop(void)
{
	if (!g_steer.started)
		return;
	if (g_steer.sf_rep_port)
		doca_flow_port_stop(g_steer.sf_rep_port);
	if (g_steer.port)
		doca_flow_port_stop(g_steer.port);
	doca_flow_destroy();
	g_steer.started = false;
}
