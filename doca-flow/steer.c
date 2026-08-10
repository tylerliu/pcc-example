/* PCC-informed RoCE path-steering demo (BF3 p0<->p1 DAC loopback).
 *
 * Egress admits IPv4 RoCEv2/UDP 4791 and uses parser_meta.random to write a
 * two-way DSCP path marker. Ingress first demuxes by path, then runs one
 * full-QPN hash marker per path. Only class==path may be newly CE-marked; all
 * branches clear the private path marker before SF delivery.
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
#define PCC_FULL_RATE (1u << 20)
#define MAX_RATE_FLOWS 256u
#define PATH_SHARE_BUCKETS 64u
#define PATH_SHARE_MIN_BUCKETS 3u

#define ROCE_UDP_PORT_NATIVE 4791
#define ROCE_UDP_PORT_MOVED 4792 /* legacy: UDP-port marker (breaks RoCEv2 ICRC; no longer used) */
#define IP4_DSCP_ECN_CE 0x03	 /* ECN=11 (CE); set masked so DSCP is preserved */
#define IP4_ECN_MASK 0x03	 /* the two ECN bits of the ToS byte */
/*
 * On-wire "current-path" marker. The two virtual paths are distinguished purely
 * by one bit of the IP ToS byte (DSCP+ECN is a *variant* field excluded from the
 * RoCEv2 ICRC -- proven safe by CE-marking working -- so writing it is
 * transparent to RoCE, unlike the UDP destination port which the ICRC covers).
 *
 * Egress randomly writes the current-path bit per packet. Ingress uses the QPN
 * classification together with that bit to decide whether marked ECN is kept.
 * Ingress demuxes on this bit alone (no dst-IP needed, so both QPs may share one
 * receiver IP), marks per path, then clears the bit before SF delivery. ToS bit
 * 2 (DSCP LSB) is 0 for common RoCE DSCP classes (e.g. 24/26); change
 * PATH_DSCP_MASK if your deployment uses a DSCP whose LSB is set.
 */
#define PATH_DSCP_MASK 0x04
/* path id (0/1) -> ToS value for the masked write, and back */
#define PATH_DSCP_VAL(path) ((uint8_t)((path) ? PATH_DSCP_MASK : 0x00))

/* EGRESS_CLASSIFY distributes packets independently of QPN. Hashing the HW
 * parser random value gives a per-packet 50/50 choice between the two buckets,
 * following the DOCA 3.4 flow_random sample. */

#define NB_PATHS STEER_NB_PATHS

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

/* A stable, role-specific DPDK --file-prefix so the egress and ingress steering
 * primaries (and doca_pcc's embedded egress) never share a runtime config dir. */
const char *steer_eal_prefix_for_role(int role)
{
	switch (role) {
	case STEER_ROLE_EGRESS:
		return "pcc-egress";
	case STEER_ROLE_INGRESS:
		return "pcc-ingress";
	default:
		return "pcc-steer";
	}
}

/*
 * EAL init for the steering datapath. Appends a dummy -a allowlist entry (so EAL
 * does not auto-probe real PCI devices; the device is attached later via
 * doca_dpdk_port_probe*) and a unique --file-prefix so this DPDK primary does not
 * collide with another primary on the host ("Cannot create lock on
 * /var/run/dpdk/<prefix>/config"). Pass steer_eal_prefix_for_role(role).
 */
doca_error_t steer_eal_init(int argc, char **argv, const char *file_prefix)
{
	static char allow_flag[] = "-a";
	/* A well-formed but nonexistent PCI address puts EAL in allowlist mode so it
	 * auto-probes nothing; the real device is attached later via
	 * doca_dpdk_port_probe*. (An empty "-a \"\"" does NOT enable allowlist mode, so
	 * EAL auto-probes the NIC and the explicit probe then fails with
	 * "cmd_fd mismatch / Probe again".) */
	static char allow_none[] = "pci:00:00.0";
	static char allow_aux_none[] = "auxiliary:mlx5_core.sf.4294967295";
	static char prefix_flag[] = "--file-prefix";
	char *new_argv[64];

	if (argc >= 57) {
		DOCA_LOG_ERR("Too many EAL arguments");
		return DOCA_ERROR_INVALID_VALUE;
	}
	for (int i = 0; i < argc; i++)
		new_argv[i] = argv[i];
	new_argv[argc] = allow_flag;
	new_argv[argc + 1] = allow_none;
	new_argv[argc + 2] = allow_flag;
	new_argv[argc + 3] = allow_aux_none;
	new_argv[argc + 4] = prefix_flag;
	new_argv[argc + 5] = (char *)((file_prefix && file_prefix[0]) ? file_prefix : "pcc-steer");

	if (rte_eal_init(argc + 6, new_argv) < 0) {
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
	err = doca_flow_port_cfg_set_actions_mem_size(cfg, 256 * DOCA_FLOW_MAX_ENTRY_ACTIONS_MEM_SIZE);
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

	err = doca_flow_port_cfg_set_actions_mem_size(cfg, 256 * DOCA_FLOW_MAX_ENTRY_ACTIONS_MEM_SIZE);
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
 * and the rest go to miss_pipe (clear and deliver unmarked). Used per
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
 * INGRESS_PATH_DEMUX (non-root): classify looped-back wire ingress by the DSCP
 * path bit (written at egress) into two independent path-specific QPN hash markers.
 * Non-IPv4 misses go to the shared clear-and-deliver pipe.
 */
static struct doca_flow_pipe *create_path_demux_pipe(struct doca_flow_port *port,
						     struct doca_flow_pipe *target[NB_PATHS],
						     struct doca_flow_pipe *clear_pipe)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_CHANGEABLE};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = clear_pipe};
	struct doca_flow_pipe_cfg *cfg_pipe;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dscp_ecn = 0xFF;		/* changeable: path bit value is per entry */
	match_mask.outer.ip4.dscp_ecn = PATH_DSCP_MASK; /* match only the path bit */

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

		entry_match.outer.ip4.dscp_ecn = PATH_DSCP_VAL(i);
		err = steer_pipe_add_entry(0, pipe, &entry_match, 0, NULL, NULL, &entry_fwd, flags, &status, &entry);
		crash_if_unsuccessful(err, "pipe_add_entry (path demux %d)", i);
	}
	process_entries(port, &status, NB_PATHS, "path demux entries");
	DOCA_LOG_INFO("Path demux ready: path0->PATH0_QPN_HASH path1->PATH1_QPN_HASH by DSCP bit 0x%02x",
	              PATH_DSCP_MASK);
	return pipe;
}

/* Current path of a QP: home path = parity (even->0, odd->1); flipped when this
 * parity is "moved" (or under MOVE_ALL) onto the other path. */
static int current_path(int parity, int move_parity)
{
	bool moved = (move_parity == STEER_MOVE_ALL) || (parity == move_parity);

	return moved ? (parity ^ 1) : parity;
}

/* EGRESS_CLASSIFY (HASH pipe): parser_meta.random selects one of two buckets
 * per packet. Each bucket writes its DSCP path bit and forwards to the wire. */
static struct doca_flow_pipe *create_classify_pipe(struct doca_flow_port *port, struct doca_flow_pipe *deliver_wire)
{
	struct doca_flow_match match_mask = {0};
	struct doca_flow_actions set0 = {0}, set1 = {0};
	struct doca_flow_actions set0_mask = {0}, set1_mask = {0};
	struct doca_flow_actions *actions_arr[2] = {&set0, &set1};
	struct doca_flow_actions *actions_masks_arr[2] = {&set0_mask, &set1_mask};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_wire};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	/* Per-packet random distribution, independent of all flow fields. */
	match_mask.parser_meta.random = RTE_BE16(UINT16_MAX);

	/* Two masked-write templates; entry (bucket) idx selects idx0=path0, idx1=path1. */
	set0.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	set0.outer.ip4.dscp_ecn = PATH_DSCP_VAL(0);
	set0_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	set0_mask.outer.ip4.dscp_ecn = PATH_DSCP_MASK;
	set1.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	set1.outer.ip4.dscp_ecn = PATH_DSCP_VAL(1);
	set1_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	set1_mask.outer.ip4.dscp_ecn = PATH_DSCP_MASK;

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (classify)");
	err = doca_flow_pipe_cfg_set_name(cfg, "EGRESS_CLASSIFY");
	crash_if_unsuccessful(err, "pipe_cfg_set_name (classify)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_HASH);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (classify)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (classify)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (classify)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, NB_PATHS); /* 2 buckets (power of 2) */
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (classify)");
	err = doca_flow_pipe_cfg_set_match(cfg, NULL, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (classify)");
	err = doca_flow_pipe_cfg_set_actions(cfg, actions_arr, actions_masks_arr, NULL, 2);
	crash_if_unsuccessful(err, "pipe_cfg_set_actions (classify)");
	err = doca_flow_pipe_cfg_set_monitor(cfg, &monitor);
	crash_if_unsuccessful(err, "pipe_cfg_set_monitor (classify)");

	err = doca_flow_pipe_create(cfg, &fwd, NULL, &pipe);
	crash_if_unsuccessful(err, "pipe_create (classify)");
	doca_flow_pipe_cfg_destroy(cfg);
	return pipe;
}

/*
 * Add the two random-distribution buckets; bucket i writes DSCP path bit i.
 */
static void add_classify_entries(struct doca_flow_pipe *pipe, struct doca_flow_port *port, int move_parity,
				 struct doca_flow_pipe_entry *entries[NB_PATHS])
{
	doca_error_t err;

	(void)move_parity; /* hash bucket = native path; no move on this pipe */
	memset(&g_classify_batch, 0, sizeof(g_classify_batch));

	for (uint32_t idx = 0; idx < NB_PATHS; idx++) {
		struct doca_flow_actions actions = {0};
		struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
		uint32_t flags = (idx == 0) ? STEER_WAIT_FOR_BATCH : 0;

		actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
		actions.outer.ip4.dscp_ecn = PATH_DSCP_VAL(idx);

		err = doca_flow_pipe_hash_add_entry(0, pipe, idx, (uint8_t)idx, &actions, &monitor, NULL, flags,
						    &g_classify_batch, &entries[idx]);
		crash_if_unsuccessful(err, "pipe_hash_add_entry (bucket=%u)", idx);
	}
	process_entries(port, &g_classify_batch, NB_PATHS, "classify (hash) entries");
	DOCA_LOG_INFO("Classify hash pipe ready: bucket0->path0 bucket1->path1 using parser_meta.random");
}

/* EGRESS_ROCE_CHECK (non-root): admit only IPv4 RoCEv2 on UDP 4791 to
 * the random path classifier. All other SF-egress traffic bypasses
 * the hash pipe and is delivered to the wire unchanged. */
static struct doca_flow_pipe *create_roce_check_pipe(struct doca_flow_port *port, const char *name,
                                                     struct doca_flow_pipe *roce_target,
                                                     struct doca_flow_pipe *bypass_target)
{
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = roce_target};
	struct doca_flow_fwd fwd_miss = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = bypass_target};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct entry_batch_status status = {0};
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match.outer.roce_v2.udp.l4_port.dst_port = RTE_BE16(ROCE_UDP_PORT_NATIVE);
	match_mask.outer.roce_v2.udp.l4_port.dst_port = RTE_BE16(0xFFFF);

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (RoCE check)");
	err = doca_flow_pipe_cfg_set_name(cfg, name);
	crash_if_unsuccessful(err, "pipe_cfg_set_name (RoCE check)");
	err = doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC);
	crash_if_unsuccessful(err, "pipe_cfg_set_type (RoCE check)");
	err = doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
	crash_if_unsuccessful(err, "pipe_cfg_set_domain (RoCE check)");
	err = doca_flow_pipe_cfg_set_is_root(cfg, false);
	crash_if_unsuccessful(err, "pipe_cfg_set_is_root (RoCE check)");
	err = doca_flow_pipe_cfg_set_nr_entries(cfg, 1);
	crash_if_unsuccessful(err, "pipe_cfg_set_nr_entries (RoCE check)");
	err = doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask);
	crash_if_unsuccessful(err, "pipe_cfg_set_match (RoCE check)");

	err = doca_flow_pipe_create(cfg, &fwd, &fwd_miss, &pipe);
	crash_if_unsuccessful(err, "pipe_create (RoCE check)");
	doca_flow_pipe_cfg_destroy(cfg);

	struct doca_flow_match entry_match = {0};

	err = steer_pipe_add_entry(0, pipe, &entry_match, 0, NULL, NULL, NULL, 0, &status, &entry);
	crash_if_unsuccessful(err, "pipe_add_entry (RoCE check)");
	process_entries(port, &status, 1, "RoCE check entry");
	DOCA_LOG_INFO("%s ready: IPv4 RoCEv2 UDP %u admitted; other traffic bypasses", name,
	              ROCE_UDP_PORT_NATIVE);
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

/* Final ingress bypass action: remove only the private DSCP path marker and
 * preserve the packets existing ECN bits. Selected-class sampling misses and
 * non-selected QPN classes both terminate here. */
static struct doca_flow_pipe *create_clear_path_pipe(struct doca_flow_port *port,
					      struct doca_flow_pipe *deliver_sf,
					      struct doca_flow_pipe_entry **entry_out)
{
	struct doca_flow_match match = {0}, match_mask = {0}, entry_match = {0};
	struct doca_flow_actions actions = {0}, actions_mask = {0};
	struct doca_flow_actions *actions_arr[1] = {&actions};
	struct doca_flow_actions *actions_masks_arr[1] = {&actions_mask};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_sf};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct entry_batch_status status = {0};
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dscp_ecn = 0xFF;
	match_mask.outer.ip4.dscp_ecn = 0; /* all IPv4 */
	actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.outer.ip4.dscp_ecn = 0;
	actions_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions_mask.outer.ip4.dscp_ecn = PATH_DSCP_MASK;

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_name(cfg, "INGRESS_CLEAR_PATH"),
	                      "pipe_cfg_set_name (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC),
	                      "pipe_cfg_set_type (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT),
	                      "pipe_cfg_set_domain (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_is_root(cfg, false),
	                      "pipe_cfg_set_is_root (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_nr_entries(cfg, 1),
	                      "pipe_cfg_set_nr_entries (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask),
	                      "pipe_cfg_set_match (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_actions(cfg, actions_arr, actions_masks_arr, NULL, 1),
	                      "pipe_cfg_set_actions (clear path)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_monitor(cfg, &monitor),
	                      "pipe_cfg_set_monitor (clear path)");
	err = doca_flow_pipe_create(cfg, &fwd, NULL, &pipe);
	crash_if_unsuccessful(err, "pipe_create (clear path)");
	doca_flow_pipe_cfg_destroy(cfg);

	err = steer_pipe_add_entry(0, pipe, &entry_match, 0, &actions, &monitor, NULL, 0,
	                           &status, entry_out);
	crash_if_unsuccessful(err, "pipe_add_entry (clear path)");
	process_entries(port, &status, 1, "clear path entry");
	DOCA_LOG_INFO("Ingress clear-path ready: preserve ECN, clear DSCP path bit");
	return pipe;
}

/* Per-path selected-class marker. Packets reach this pipe only after that
 * paths QPN hash selected its matching class and optional sampling hit. */
static struct doca_flow_pipe *create_selected_mark_pipe(struct doca_flow_port *port, int path,
						 struct doca_flow_pipe *deliver_sf,
						 struct doca_flow_pipe_entry **entry_out)
{
	struct doca_flow_match match = {0}, match_mask = {0}, entry_match = {0};
	struct doca_flow_actions actions = {0}, actions_mask = {0};
	struct doca_flow_actions *actions_arr[1] = {&actions};
	struct doca_flow_actions *actions_masks_arr[1] = {&actions_mask};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_PIPE, .next_pipe = deliver_sf};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct entry_batch_status status = {0};
	char name[32];
	doca_error_t err;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dscp_ecn = 0xFF;
	match_mask.outer.ip4.dscp_ecn = 0;
	actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions.outer.ip4.dscp_ecn = IP4_DSCP_ECN_CE;
	actions_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	actions_mask.outer.ip4.dscp_ecn = PATH_DSCP_MASK | IP4_ECN_MASK;
	snprintf(name, sizeof(name), "PATH%d_CE_MARK", path);

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_name(cfg, name), "pipe_cfg_set_name (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_BASIC), "pipe_cfg_set_type (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), "pipe_cfg_set_domain (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_is_root(cfg, false), "pipe_cfg_set_is_root (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_nr_entries(cfg, 1), "pipe_cfg_set_nr_entries (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_match(cfg, &match, &match_mask), "pipe_cfg_set_match (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_actions(cfg, actions_arr, actions_masks_arr, NULL, 1),
	                      "pipe_cfg_set_actions (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_monitor(cfg, &monitor), "pipe_cfg_set_monitor (%s)", name);
	err = doca_flow_pipe_create(cfg, &fwd, NULL, &pipe);
	crash_if_unsuccessful(err, "pipe_create (%s)", name);
	doca_flow_pipe_cfg_destroy(cfg);

	err = steer_pipe_add_entry(0, pipe, &entry_match, 0, &actions, &monitor, NULL, 0,
	                           &status, entry_out);
	crash_if_unsuccessful(err, "pipe_add_entry (%s)", name);
	process_entries(port, &status, 1, name);
	DOCA_LOG_INFO("%s ready: set CE and clear DSCP path bit", name);
	return pipe;
}

/* One independent full-QPN hash marker per virtual path. Only bucket `path`
 * enters that paths sampler/marker; the other bucket bypasses marking. */
static struct doca_flow_pipe *create_path_qpn_hash_pipe(struct doca_flow_port *port, int path,
						 struct doca_flow_pipe *selected_target,
						 struct doca_flow_pipe *clear_target,
						 struct doca_flow_pipe_entry **entries)
{
	struct doca_flow_match match_mask = {0};
	struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_CHANGEABLE};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	struct entry_batch_status status = {0};
	char name[32];
	doca_error_t err;

	match_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	memset(match_mask.outer.roce_v2.bth.dest_qp, 0xFF,
	       sizeof(match_mask.outer.roce_v2.bth.dest_qp));
	snprintf(name, sizeof(name), "PATH%d_QPN_HASH", path);

	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_name(cfg, name), "pipe_cfg_set_name (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_HASH), "pipe_cfg_set_type (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT), "pipe_cfg_set_domain (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_is_root(cfg, false), "pipe_cfg_set_is_root (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_nr_entries(cfg, NB_PATHS), "pipe_cfg_set_nr_entries (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_hash_map_algorithm(cfg, DOCA_FLOW_PIPE_HASH_MAP_ALGORITHM_HASH),
	                      "pipe_cfg_set_hash_map_algorithm (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_match(cfg, NULL, &match_mask), "pipe_cfg_set_match (%s)", name);
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_monitor(cfg, &monitor), "pipe_cfg_set_monitor (%s)", name);
	err = doca_flow_pipe_create(cfg, &fwd, NULL, &pipe);
	crash_if_unsuccessful(err, "pipe_create (%s)", name);
	doca_flow_pipe_cfg_destroy(cfg);

	for (uint32_t bucket = 0; bucket < NB_PATHS; bucket++) {
		struct doca_flow_monitor entry_monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};
		struct doca_flow_fwd entry_fwd = {
			.type = DOCA_FLOW_FWD_PIPE,
			.next_pipe = ((int)bucket == path) ? selected_target : clear_target,
		};
		uint32_t flags = (bucket == 0) ? STEER_WAIT_FOR_BATCH : 0;
		err = doca_flow_pipe_hash_add_entry(0, pipe, bucket, 0, NULL, &entry_monitor, &entry_fwd,
		                                    flags, &status, &entries[bucket]);
		crash_if_unsuccessful(err, "pipe_hash_add_entry (%s bucket=%u)", name, bucket);
	}
	process_entries(port, &status, NB_PATHS, name);
	DOCA_LOG_INFO("%s ready: class%d selected for ECN marking", name, path);
	return pipe;
}

/* Create an egress-only full-QPN hash profile for doca_flow_pipe_calc_hash().
 * It is not reachable from the packet pipeline and has no entries. */
static struct doca_flow_pipe *create_qpn_calc_pipe(struct doca_flow_port *port)
{
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_DROP};
	struct doca_flow_pipe_cfg *cfg;
	struct doca_flow_pipe *pipe;
	doca_error_t err;

	match_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match_mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	memset(match_mask.outer.roce_v2.bth.dest_qp, 0xFF,
	       sizeof(match_mask.outer.roce_v2.bth.dest_qp));
	err = doca_flow_pipe_cfg_create(&cfg, port);
	crash_if_unsuccessful(err, "pipe_cfg_create (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_name(cfg, "EGRESS_QPN_HASH_CALC"),
	                      "pipe_cfg_set_name (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_type(cfg, DOCA_FLOW_PIPE_HASH),
	                      "pipe_cfg_set_type (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_domain(cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT),
	                      "pipe_cfg_set_domain (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_is_root(cfg, false),
	                      "pipe_cfg_set_is_root (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_nr_entries(cfg, NB_PATHS),
	                      "pipe_cfg_set_nr_entries (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_hash_map_algorithm(
	                         cfg, DOCA_FLOW_PIPE_HASH_MAP_ALGORITHM_HASH),
	                      "pipe_cfg_set_hash_map_algorithm (QPN calc)");
	crash_if_unsuccessful(doca_flow_pipe_cfg_set_match(cfg, NULL, &match_mask),
	                      "pipe_cfg_set_match (QPN calc)");
	err = doca_flow_pipe_create(cfg, &fwd, NULL, &pipe);
	crash_if_unsuccessful(err, "pipe_create (QPN calc)");
	doca_flow_pipe_cfg_destroy(cfg);
	DOCA_LOG_INFO("Egress QPN calc-hash profile ready");
	return pipe;
}

/* Compensate for the unmarkable half of each path: the configured percentage
 * is the intended fraction over all path traffic, while only class==path can
 * enter this sampler. The selected-class rate is therefore doubled and capped. */
static struct doca_flow_pipe *path_ce_target(struct doca_flow_port *port, int idx, double intended_percent,
					     struct doca_flow_pipe *mark_pipe, struct doca_flow_pipe *clear_pipe)
{
	char name[32];
	double selected_percent = intended_percent * 2.0;

	if (selected_percent > 100.0)
		selected_percent = 100.0;
	DOCA_LOG_INFO("Path%d CE sampling: intended all-traffic=%.4g%% selected-class=%.4g%%",
	              idx, intended_percent, selected_percent);
	if (intended_percent > 50.0)
		DOCA_LOG_WARN("Path%d intended CE rate %.4g%% exceeds the approximately 50%% maximum "
		              "with class-selective marking", idx, intended_percent);

	if (selected_percent >= 100.0)
		return mark_pipe;
	if (selected_percent <= 0.0)
		return clear_pipe;
	snprintf(name, sizeof(name), "RANDOM_SAMPLE_P%d", idx);
	return create_random_sample_pipe(port, name, mark_pipe, clear_pipe, get_random_mask(selected_percent));
}

/* ------------------------------------------------------------------ *
 *  Module state + public API (see steer.h)                            *
 * ------------------------------------------------------------------ */

struct rate_flow_state {
	uint32_t qpn;
	uint32_t latest_rate;
	uint8_t qpn_class;
};

struct steer_state {
	bool started;
	struct steer_opts opts;
	struct doca_flow_port *port;
	struct doca_flow_port *sf_rep_port;
	struct doca_flow_pipe *classify_pipe;
	struct doca_flow_pipe *qpn_calc_pipe;
	bool classify_is_hash; /* classify is a HASH pipe (fixed buckets, no live move) */
	struct doca_flow_pipe_entry *classify_entry[NB_PATHS];
	struct doca_flow_pipe_entry *mark_entry[NB_PATHS];
	struct doca_flow_pipe_entry *qpn_hash_entry[NB_PATHS * NB_PATHS]; /* [path*NB_PATHS + class] */
	struct doca_flow_pipe_entry *clear_path_entry;
	struct rate_flow_state rate_flow[MAX_RATE_FLOWS];
	uint32_t rate_flow_count;
	atomic_flag rate_lock;
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
	doca_error_t err = DOCA_SUCCESS;

	memset(&g_classify_batch, 0, sizeof(g_classify_batch));

	for (int parity = 0; parity < NB_PATHS; parity++) {
		struct doca_flow_actions actions = {0};
		struct doca_flow_monitor monitor = {.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED};

		/* action_idx = current path under `move_parity` (0 or 1); the template
		 * for that idx writes the DSCP path bit accordingly. */
		uint8_t aidx = (uint8_t)current_path(parity, move_parity);

		actions.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
		actions.outer.ip4.dscp_ecn = PATH_DSCP_VAL(aidx);

		err = steer_pipe_update_entry(0, g_steer.classify_pipe, aidx, &actions, &monitor, NULL, 0,
					      g_steer.classify_entry[parity]);
		if (err != DOCA_SUCCESS)
			break;
	}

	/* A live-update failure (e.g. transient HWS pool pressure) must not kill the
	 * embedding process. Leave applied_move unchanged so the next poll retries. */
	if (err != DOCA_SUCCESS) {
		DOCA_LOG_WARN("classify update failed (%s); keeping move_parity=%d, will retry",
			      doca_error_get_descr(err), g_steer.applied_move);
		return;
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
	atomic_flag_clear(&g_steer.rate_lock);

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
		/* Ingress: choose the virtual path first, then run that paths
		 * independent full-QPN ECN marker. Only class==path may be marked. */
		struct doca_flow_pipe *clear_path =
			create_clear_path_pipe(g_steer.port, deliver_sf, &g_steer.clear_path_entry);
		struct doca_flow_pipe *path_hash[NB_PATHS];
		for (int path = 0; path < NB_PATHS; path++) {
			struct doca_flow_pipe *mark =
				create_selected_mark_pipe(g_steer.port, path, deliver_sf,
				                          &g_steer.mark_entry[path]);
			struct doca_flow_pipe *selected =
				path_ce_target(g_steer.port, path, g_steer.opts.path_percent[path],
				               mark, clear_path);
			path_hash[path] =
				create_path_qpn_hash_pipe(g_steer.port, path, selected, clear_path,
				                          &g_steer.qpn_hash_entry[path * NB_PATHS]);
		}

		struct doca_flow_pipe *path_demux =
			create_path_demux_pipe(g_steer.port, path_hash, clear_path);
		wire_target = create_roce_check_pipe(g_steer.port, "INGRESS_ROCE_CHECK",
		                                     path_demux, deliver_sf);
	}

	if (do_egress) {
		g_steer.qpn_calc_pipe = create_qpn_calc_pipe(g_steer.port);
		/* Egress (sender): hash-pipe classify by dest_qp -> native path DSCP bit. */
		g_steer.classify_pipe = create_classify_pipe(g_steer.port, deliver_wire);
		g_steer.classify_is_hash = true;

		/* AUTO starts as NONE until per-path rates arrive. */
		int initial_move = (g_steer.opts.move_parity == STEER_MOVE_AUTO) ? STEER_MOVE_NONE
										 : g_steer.opts.move_parity;

		add_classify_entries(g_steer.classify_pipe, g_steer.port, initial_move, g_steer.classify_entry);
		g_steer.applied_move = initial_move;

		/* All admitted RoCE traffic is randomly assigned a DSCP path bit. */
		sf_target = create_roce_check_pipe(g_steer.port, "EGRESS_ROCE_CHECK",
		                                   g_steer.classify_pipe, deliver_wire);
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
	/* Existing rate storage is retained until the dynamic controller replaces it. */
	atomic_store_explicit(&g_steer.rate[qpn & 1], rate, memory_order_relaxed);

	if (g_steer.qpn_calc_pipe == NULL)
		return;
	qpn &= 0x00FFFFFFu;
	if (qpn <= 1)
		return;

	while (atomic_flag_test_and_set_explicit(&g_steer.rate_lock, memory_order_acquire))
		;
	struct rate_flow_state *flow = NULL;
	for (uint32_t i = 0; i < g_steer.rate_flow_count; i++) {
		if (g_steer.rate_flow[i].qpn == qpn) {
			flow = &g_steer.rate_flow[i];
			break;
		}
	}
	if (flow == NULL && g_steer.rate_flow_count < MAX_RATE_FLOWS) {
		struct doca_flow_match match = {0};
		uint32_t hash;
		match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
		match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
		match.outer.roce_v2.bth.dest_qp[0] = (uint8_t)(qpn >> 16);
		match.outer.roce_v2.bth.dest_qp[1] = (uint8_t)(qpn >> 8);
		match.outer.roce_v2.bth.dest_qp[2] = (uint8_t)qpn;

		doca_error_t err = doca_flow_pipe_calc_hash(g_steer.qpn_calc_pipe, &match, &hash);
		if (err == DOCA_SUCCESS) {
			flow = &g_steer.rate_flow[g_steer.rate_flow_count++];
			flow->qpn = qpn;
			flow->qpn_class = (uint8_t)(hash % NB_PATHS);
			DOCA_LOG_INFO("egress calc_hash: PCC QPN 0x%06x rate=%u hash=%u bucket=%u",
			              qpn, rate, hash, flow->qpn_class);
		} else {
			DOCA_LOG_WARN("calc_hash failed for PCC QPN 0x%06x: %s", qpn,
			              doca_error_get_descr(err));
		}
	}
	if (flow != NULL)
		flow->latest_rate = rate;
	atomic_flag_clear_explicit(&g_steer.rate_lock, memory_order_release);
}

void steer_poll(void)
{
	if (!g_steer.started)
		return;

	if (g_steer.qpn_calc_pipe != NULL) {
		uint64_t reduced_sum[NB_PATHS] = {0};
		uint32_t total[NB_PATHS] = {0}, full[NB_PATHS] = {0}, reduced[NB_PATHS] = {0};
		while (atomic_flag_test_and_set_explicit(&g_steer.rate_lock, memory_order_acquire))
			;
		for (uint32_t i = 0; i < g_steer.rate_flow_count; i++) {
			const struct rate_flow_state *flow = &g_steer.rate_flow[i];
			uint8_t c = flow->qpn_class;
			total[c]++;
			if (flow->latest_rate == PCC_FULL_RATE)
				full[c]++;
			else {
				reduced[c]++;
				reduced_sum[c] += flow->latest_rate;
			}
		}
		atomic_flag_clear_explicit(&g_steer.rate_lock, memory_order_release);

		uint32_t path0 = PATH_SHARE_BUCKETS / 2;
		bool all_full0 = total[0] > 0 && full[0] == total[0];
		bool all_full1 = total[1] > 0 && full[1] == total[1];
		if (total[0] > 0 && total[1] > 0) {
			if (all_full0 && !all_full1 && reduced[1] > 0)
				path0 = PATH_SHARE_BUCKETS - PATH_SHARE_MIN_BUCKETS;
			else if (all_full1 && !all_full0 && reduced[0] > 0)
				path0 = PATH_SHARE_MIN_BUCKETS;
			else if (!all_full0 && !all_full1 && reduced[0] > 0 && reduced[1] > 0) {
				uint64_t sum = reduced_sum[0] + reduced_sum[1];
				if (sum > 0)
					path0 = (uint32_t)((reduced_sum[0] * PATH_SHARE_BUCKETS + sum / 2) / sum);
				if (path0 < PATH_SHARE_MIN_BUCKETS)
					path0 = PATH_SHARE_MIN_BUCKETS;
				if (path0 > PATH_SHARE_BUCKETS - PATH_SHARE_MIN_BUCKETS)
					path0 = PATH_SHARE_BUCKETS - PATH_SHARE_MIN_BUCKETS;
			}
		}
		DOCA_LOG_INFO("PCC path-share diagnostic: c0 total=%u full=%u reduced=%u sum=%lu; "
		              "c1 total=%u full=%u reduced=%u sum=%lu; proposed path0=%u/64 path1=%u/64 (not applied)",
		              total[0], full[0], reduced[0], reduced_sum[0], total[1], full[1], reduced[1],
		              reduced_sum[1], path0, PATH_SHARE_BUCKETS - path0);
	}

	if (g_steer.classify_pipe && !g_steer.classify_is_hash) {
		int want = steer_decide();

		if (want != g_steer.applied_move)
			steer_apply(want);
	}

	struct doca_flow_resource_query q;

	for (int path = 0; path < NB_PATHS; path++) {
		for (int bucket = 0; bucket < NB_PATHS; bucket++) {
			struct doca_flow_pipe_entry *e = g_steer.qpn_hash_entry[path * NB_PATHS + bucket];
			if (e && doca_flow_resource_query_entry(e, &q) == DOCA_SUCCESS)
				DOCA_LOG_INFO("ingress: path%d QPN class%d (%s): %lu pkts", path, bucket,
				              path == bucket ? "selected" : "not selected", q.counter.total_pkts);
		}
	}

	/* Egress (sender) role: per-bucket classify counts (bucket i -> native path i). */
	for (int i = 0; g_steer.classify_pipe && i < NB_PATHS; i++) {
		if (g_steer.classify_entry[i] &&
		    doca_flow_resource_query_entry(g_steer.classify_entry[i], &q) == DOCA_SUCCESS)
			DOCA_LOG_INFO("egress: bucket%d -> path%d: %lu pkts", i, i, q.counter.total_pkts);
	}

	for (int i = 0; i < NB_PATHS; i++) {
		if (g_steer.mark_entry[i] &&
		    doca_flow_resource_query_entry(g_steer.mark_entry[i], &q) == DOCA_SUCCESS)
			DOCA_LOG_INFO("path%d selected-class CE marked: %lu pkts  [rate=%u]", i,
				      q.counter.total_pkts,
				      atomic_load_explicit(&g_steer.rate[i], memory_order_relaxed));
	}
	if (g_steer.clear_path_entry &&
	    doca_flow_resource_query_entry(g_steer.clear_path_entry, &q) == DOCA_SUCCESS)
		DOCA_LOG_INFO("ingress: unmarked/path-bit-cleared: %lu pkts", q.counter.total_pkts);
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
