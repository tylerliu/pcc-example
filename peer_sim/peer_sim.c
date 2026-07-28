/*
 * Two-path RoCE workload for PCC/ECN experiments.
 *
 * Both paths are established with standard RDMA CM.  QPs are deliberately
 * created with rdma_create_qp() and connected with rdma_connect()/rdma_accept()
 * so mlx5 ECE negotiation can select the PCC algorithm slot.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <poll.h>
#include <rdma/rdma_cma.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "peer_sim.h"

#define PEER_PATHS 2
#define PEER_MAGIC UINT64_C(0x5043434452523031) /* "PCCDRR01" */
#define PEER_REGION_MAGIC UINT64_C(0x5043435245473031) /* "PCCREG01" */
#define CM_MAGIC UINT32_C(0x50434d31)            /* "PCM1" */
#define CM_VERSION 1
#define DEFAULT_CM_PORT0 18515
#define DEFAULT_CM_PORT1 18516
#define DEFAULT_CHUNKS 0 /* zero means run until SIGINT/SIGTERM */
#define DEFAULT_PAYLOAD_SIZE (64 * 1024)
#define DEFAULT_DEPTH 512
#define DEFAULT_WEIGHT_PERIOD_MS 200
#define MIN_PROBE_SHARE 0.05
#define MAX_PROBE_SHARE 0.95
#define MAX_WEIGHT_STEP 0.10
#define THROUGHPUT_INTERVAL_MS 1000
#define SIGNAL_INTERVAL 32
#define DEFAULT_POST_BATCH 32
#define MAX_POST_BATCH 64
#define CONTROL_WR_ID UINT64_MAX
#define CONNECT_TIMEOUT_MS 5000
#define CM_EVENT_POLL_MS 100
#define MIN_PROBE_QUANTUM_FACTOR 20

struct peer_chunk_header {
	uint64_t magic;
	uint64_t sequence;
	uint32_t payload_length;
	uint16_t path_id;
	uint16_t reserved;
} __attribute__((packed));

struct cm_hello {
	uint32_t magic;
	uint16_t version;
	uint16_t path_id;
} __attribute__((packed));

/* Exchanged over the established RC QP, never through ECE-owned CM data. */
struct peer_region_info {
	uint64_t magic;
	uint64_t address;
	uint32_t rkey;
	uint32_t wire_size;
} __attribute__((packed));

enum peer_role {
	PEER_ROLE_UNSET,
	PEER_ROLE_CLIENT,
	PEER_ROLE_SERVER,
};

struct peer_config {
	enum peer_role role;
	struct sockaddr_in local[PEER_PATHS];
	struct sockaddr_in peer[PEER_PATHS];
	bool have_local[PEER_PATHS];
	bool have_peer[PEER_PATHS];
	uint16_t cm_port[PEER_PATHS];
	uint64_t chunks;
	uint32_t payload_size;
	uint32_t depth;
	uint32_t post_batch;
	uint32_t weight_period_ms;
};

struct path_ctx {
	unsigned int path_id;
	struct rdma_event_channel *channel;
	struct rdma_cm_id *listen_id;
	struct rdma_cm_id *id;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_mr *mr;
	uint8_t *buffer;
	bool *slot_busy;
	uint64_t *slot_order;
	size_t wire_size;
	uint32_t depth;
	uint32_t outstanding;
	uint32_t unsignaled_writes;
	uint64_t next_post_order;
	uint64_t remote_address;
	uint32_t remote_rkey;
	uint32_t remote_wire_size;
	uint64_t assigned_chunks;
	uint64_t assigned_bytes;
	uint64_t completed_chunks;
	uint64_t completed_bytes;
	uint64_t received_chunks;
	uint64_t received_bytes;
};

static volatile sig_atomic_t stop_requested;
static _Atomic uint32_t tracked_pcc_qpns[PEER_PATHS];
static _Atomic uint32_t tracked_pcc_rates[PEER_PATHS];

void peer_sim_track_pcc_qpns(uint32_t path0_qpn, uint32_t path1_qpn)
{
	atomic_store_explicit(&tracked_pcc_rates[0], 0, memory_order_relaxed);
	atomic_store_explicit(&tracked_pcc_rates[1], 0, memory_order_relaxed);
	atomic_store_explicit(&tracked_pcc_qpns[0], path0_qpn, memory_order_relaxed);
	atomic_store_explicit(&tracked_pcc_qpns[1], path1_qpn, memory_order_relaxed);
}

void peer_sim_update_pcc_rate(uint32_t qpn, uint32_t rate)
{
	if (qpn == atomic_load_explicit(&tracked_pcc_qpns[0], memory_order_relaxed))
		atomic_store_explicit(&tracked_pcc_rates[0], rate, memory_order_relaxed);
	if (qpn == atomic_load_explicit(&tracked_pcc_qpns[1], memory_order_relaxed))
		atomic_store_explicit(&tracked_pcc_rates[1], rate, memory_order_relaxed);
}

static void on_signal(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static uint64_t monotonic_msec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s --server --local0 <ip> --local1 <ip> [options]\n"
		"  %s --client --local0 <ip> --peer0 <ip> --local1 <ip> --peer1 <ip> [options]\n\n"
		"Both modes establish one standard RDMA-CM RC connection per path.\n"
		"This is required for mlx5 ECE/PCC algorithm-slot negotiation.\n\n"
		"Options:\n"
		"  --cm-port0 <port>        RDMA-CM service port for path 0 (default %u)\n"
		"  --cm-port1 <port>        RDMA-CM service port for path 1 (default %u)\n"
		"  --chunks <count>         Finite stream length; 0 runs until signal (default %u)\n"
		"  --chunk-size <bytes>     Payload bytes per chunk (default %u)\n"
		"  --depth <count>          Per-QP send/receive depth (default %u)\n"
		"  --post-batch <count>     Linked RDMA writes per post (default %u; max %u)\n"
		"  --weight-period-ms <ms>  In-process PCC rate refresh period (default %u)\n"
		"  --help                    Show this help\n",
		program, program, DEFAULT_CM_PORT0, DEFAULT_CM_PORT1,
		DEFAULT_CHUNKS, DEFAULT_PAYLOAD_SIZE, DEFAULT_DEPTH, DEFAULT_POST_BATCH,
		MAX_POST_BATCH, DEFAULT_WEIGHT_PERIOD_MS);
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno != 0 || end == text || *end != '\0')
		return -1;
	*value = parsed;
	return 0;
}

static int parse_u32(const char *text, uint32_t *value)
{
	uint64_t parsed;

	if (parse_u64(text, &parsed) != 0 || parsed > UINT32_MAX)
		return -1;
	*value = (uint32_t)parsed;
	return 0;
}

static int parse_u16(const char *text, uint16_t *value)
{
	uint64_t parsed;

	if (parse_u64(text, &parsed) != 0 || parsed == 0 || parsed > UINT16_MAX)
		return -1;
	*value = (uint16_t)parsed;
	return 0;
}

static int parse_ipv4(const char *text, struct sockaddr_in *address)
{
	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
	if (inet_pton(AF_INET, text, &address->sin_addr) != 1) {
		fprintf(stderr, "Invalid IPv4 address: %s\n", text);
		return -1;
	}
	return 0;
}

static const char *format_address(const struct sockaddr_in *address, char output[INET_ADDRSTRLEN])
{
	if (inet_ntop(AF_INET, &address->sin_addr, output, INET_ADDRSTRLEN) == NULL)
		return "<invalid>";
	return output;
}

static int parse_args(int argc, char **argv, struct peer_config *config)
{
	enum {
		OPT_LOCAL0 = 1000,
		OPT_LOCAL1,
		OPT_PEER0,
		OPT_PEER1,
		OPT_CM_PORT0,
		OPT_CM_PORT1,
		OPT_CHUNKS,
		OPT_CHUNK_SIZE,
		OPT_DEPTH,
		OPT_POST_BATCH,
		OPT_WEIGHT_PERIOD,
	};
	static const struct option options[] = {
		{"server", no_argument, NULL, 's'},
		{"client", no_argument, NULL, 'c'},
		{"local0", required_argument, NULL, OPT_LOCAL0},
		{"local1", required_argument, NULL, OPT_LOCAL1},
		{"peer0", required_argument, NULL, OPT_PEER0},
		{"peer1", required_argument, NULL, OPT_PEER1},
		{"cm-port0", required_argument, NULL, OPT_CM_PORT0},
		{"cm-port1", required_argument, NULL, OPT_CM_PORT1},
		{"chunks", required_argument, NULL, OPT_CHUNKS},
		{"chunk-size", required_argument, NULL, OPT_CHUNK_SIZE},
		{"depth", required_argument, NULL, OPT_DEPTH},
		{"post-batch", required_argument, NULL, OPT_POST_BATCH},
		{"weight-period-ms", required_argument, NULL, OPT_WEIGHT_PERIOD},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};
	int option;

	memset(config, 0, sizeof(*config));
	config->cm_port[0] = DEFAULT_CM_PORT0;
	config->cm_port[1] = DEFAULT_CM_PORT1;
	config->chunks = DEFAULT_CHUNKS;
	config->payload_size = DEFAULT_PAYLOAD_SIZE;
	config->depth = DEFAULT_DEPTH;
	config->post_batch = DEFAULT_POST_BATCH;
	config->weight_period_ms = DEFAULT_WEIGHT_PERIOD_MS;

	while ((option = getopt_long(argc, argv, "sch", options, NULL)) != -1) {
		switch (option) {
		case 's':
			config->role = PEER_ROLE_SERVER;
			break;
		case 'c':
			config->role = PEER_ROLE_CLIENT;
			break;
		case OPT_LOCAL0:
			if (parse_ipv4(optarg, &config->local[0]) != 0)
				return -1;
			config->have_local[0] = true;
			break;
		case OPT_LOCAL1:
			if (parse_ipv4(optarg, &config->local[1]) != 0)
				return -1;
			config->have_local[1] = true;
			break;
		case OPT_PEER0:
			if (parse_ipv4(optarg, &config->peer[0]) != 0)
				return -1;
			config->have_peer[0] = true;
			break;
		case OPT_PEER1:
			if (parse_ipv4(optarg, &config->peer[1]) != 0)
				return -1;
			config->have_peer[1] = true;
			break;
		case OPT_CM_PORT0:
			if (parse_u16(optarg, &config->cm_port[0]) != 0)
				return -1;
			break;
		case OPT_CM_PORT1:
			if (parse_u16(optarg, &config->cm_port[1]) != 0)
				return -1;
			break;
		case OPT_CHUNKS:
			if (parse_u64(optarg, &config->chunks) != 0)
				return -1;
			break;
		case OPT_CHUNK_SIZE:
			if (parse_u32(optarg, &config->payload_size) != 0 || config->payload_size == 0)
				return -1;
			break;
		case OPT_DEPTH:
			if (parse_u32(optarg, &config->depth) != 0 || config->depth == 0 || config->depth > 4096)
				return -1;
			break;
		case OPT_POST_BATCH:
			if (parse_u32(optarg, &config->post_batch) != 0 || config->post_batch == 0 ||
			    config->post_batch > MAX_POST_BATCH)
				return -1;
			break;
		case OPT_WEIGHT_PERIOD:
			if (parse_u32(optarg, &config->weight_period_ms) != 0 || config->weight_period_ms == 0)
				return -1;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		default:
			return -1;
		}
	}

	if (config->role == PEER_ROLE_UNSET || !config->have_local[0] || !config->have_local[1]) {
		fprintf(stderr, "A role and both --localN addresses are required\n");
		return -1;
	}
	if (config->role == PEER_ROLE_CLIENT && (!config->have_peer[0] || !config->have_peer[1])) {
		fprintf(stderr, "Client mode requires both --peerN addresses\n");
		return -1;
	}
	if (config->post_batch > config->depth) {
		fprintf(stderr, "--post-batch must not exceed --depth\n");
		return -1;
	}
	if ((uint64_t)config->payload_size + sizeof(struct peer_chunk_header) > UINT32_MAX) {
		fprintf(stderr, "Chunk size is too large\n");
		return -1;
	}
	return 0;
}

static int wait_for_event(struct rdma_event_channel *channel, enum rdma_cm_event_type expected,
			  struct rdma_cm_id **id_output)
{
	struct pollfd descriptor = {
		.fd = channel->fd,
		.events = POLLIN,
	};
	struct rdma_cm_event *event = NULL;
	enum rdma_cm_event_type actual;
	int status;

	while (!stop_requested) {
		int poll_result = poll(&descriptor, 1, CM_EVENT_POLL_MS);

		if (poll_result == 0)
			continue;
		if (poll_result < 0) {
			if (errno == EINTR)
				continue;
			perror("poll RDMA-CM event channel");
			return -1;
		}
		if (rdma_get_cm_event(channel, &event) != 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			perror("rdma_get_cm_event");
			return -1;
		}
		actual = event->event;
		status = event->status;
		if (id_output != NULL)
			*id_output = event->id;
		if (rdma_ack_cm_event(event) != 0) {
			perror("rdma_ack_cm_event");
			return -1;
		}
		if (actual != expected || status != 0) {
			fprintf(stderr, "Unexpected RDMA-CM event: got %s status=%d, expected %s\n",
				rdma_event_str(actual), status, rdma_event_str(expected));
			return -1;
		}
		return 0;
	}
	return -1;
}

static void log_ece(const struct path_ctx *path, const char *side)
{
	struct ibv_ece ece = {0};
	const char *device_name = "<unknown>";
	uint8_t port_num = 0;

	if (path->id == NULL || path->id->qp == NULL)
		return;
	if (path->id->verbs != NULL) {
		port_num = path->id->port_num;
		if (path->id->verbs->device != NULL)
			device_name = path->id->verbs->device->name;
	}
	if (ibv_query_ece(path->id->qp, &ece) != 0) {
		fprintf(stderr, "%s path %u: RDMA-CM established on %s port %u; unable to query accepted ECE: %s\n",
			side, path->path_id, device_name, port_num, strerror(errno));
		return;
	}
	printf("%s path %u: RDMA-CM established, device=%s port=%u QPN=0x%x, "
	       "ECE vendor=0x%x options=0x%x\n", side, path->path_id, device_name, port_num,
	       path->id->qp->qp_num, ece.vendor_id, ece.options);
}

static int post_receive(struct path_ctx *path, uint32_t slot)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)(path->buffer + (size_t)slot * path->wire_size),
		.length = (uint32_t)path->wire_size,
		.lkey = path->mr->lkey,
	};
	struct ibv_recv_wr receive = {
		.wr_id = slot,
		.sg_list = &sge,
		.num_sge = 1,
	};
	struct ibv_recv_wr *bad_receive = NULL;

	if (ibv_post_recv(path->id->qp, &receive, &bad_receive) != 0) {
		fprintf(stderr, "path %u: ibv_post_recv failed: %s\n", path->path_id, strerror(errno));
		return -1;
	}
	return 0;
}

static int setup_resources(struct path_ctx *path, uint32_t depth, size_t wire_size,
			   uint32_t control_receives)
{
	struct ibv_qp_init_attr qp_attr = {0};
	uint32_t slot;

	path->depth = depth;
	path->wire_size = wire_size;
	path->pd = ibv_alloc_pd(path->id->verbs);
	if (path->pd == NULL) {
		perror("ibv_alloc_pd");
		return -1;
	}
	path->cq = ibv_create_cq(path->id->verbs, (int)(depth * 2), path, NULL, 0);
	if (path->cq == NULL) {
		perror("ibv_create_cq");
		return -1;
	}
	path->buffer = calloc(depth, wire_size);
	path->slot_busy = calloc(depth, sizeof(*path->slot_busy));
	path->slot_order = calloc(depth, sizeof(*path->slot_order));
	if (path->buffer == NULL || path->slot_busy == NULL || path->slot_order == NULL) {
		perror("calloc");
		return -1;
	}
	path->mr = ibv_reg_mr(path->pd, path->buffer, (size_t)depth * wire_size,
			      IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	if (path->mr == NULL) {
		perror("ibv_reg_mr");
		return -1;
	}

	qp_attr.send_cq = path->cq;
	qp_attr.recv_cq = path->cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.sq_sig_all = 0;
	qp_attr.cap.max_send_wr = depth;
	qp_attr.cap.max_recv_wr = control_receives == 0 ? 1 : control_receives;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	if (rdma_create_qp(path->id, path->pd, &qp_attr) != 0) {
		perror("rdma_create_qp");
		return -1;
	}

	for (slot = 0; slot < control_receives; slot++) {
		if (post_receive(path, slot) != 0)
			return -1;
	}
	return 0;
}

static void cleanup_path(struct path_ctx *path)
{
	if (path->id != NULL && path->id->qp != NULL)
		rdma_destroy_qp(path->id);
	if (path->mr != NULL)
		ibv_dereg_mr(path->mr);
	if (path->cq != NULL)
		ibv_destroy_cq(path->cq);
	if (path->pd != NULL)
		ibv_dealloc_pd(path->pd);
	free(path->slot_order);
	free(path->slot_busy);
	free(path->buffer);
	if (path->id != NULL)
		rdma_destroy_id(path->id);
	if (path->listen_id != NULL)
		rdma_destroy_id(path->listen_id);
	if (path->channel != NULL)
		rdma_destroy_event_channel(path->channel);
	memset(path, 0, sizeof(*path));
}

static int wait_for_control_send(struct path_ctx *path)
{
	for (;;) {
		struct ibv_wc completion;
		int count = ibv_poll_cq(path->cq, 1, &completion);

		if (count < 0) {
			fprintf(stderr, "path %u: control CQ poll failed\n", path->path_id);
			return -1;
		}
		if (count == 0) {
			usleep(10);
			continue;
		}
		if (completion.status != IBV_WC_SUCCESS || completion.opcode != IBV_WC_SEND ||
		    completion.wr_id != CONTROL_WR_ID) {
			fprintf(stderr, "path %u: control send completion error status=%s opcode=%d wr_id=%" PRIu64 "\n",
				path->path_id, ibv_wc_status_str(completion.status), completion.opcode,
				completion.wr_id);
			return -1;
		}
		return 0;
	}
}

static int send_region_info(struct path_ctx *path)
{
	struct peer_region_info region = {
		.magic = htobe64(PEER_REGION_MAGIC),
		.address = htobe64((uint64_t)(uintptr_t)path->buffer),
		.rkey = htonl(path->mr->rkey),
		.wire_size = htonl((uint32_t)path->wire_size),
	};
	struct ibv_sge sge = {
		.addr = (uintptr_t)path->buffer,
		.length = sizeof(region),
		.lkey = path->mr->lkey,
	};
	struct ibv_send_wr send = {
		.wr_id = CONTROL_WR_ID,
		.sg_list = &sge,
		.num_sge = 1,
		.opcode = IBV_WR_SEND,
		.send_flags = IBV_SEND_SIGNALED,
	};
	struct ibv_send_wr *bad_send = NULL;

	memcpy(path->buffer, &region, sizeof(region));
	if (ibv_post_send(path->id->qp, &send, &bad_send) != 0) {
		fprintf(stderr, "server path %u: failed to send region info: %s\n",
			path->path_id, strerror(errno));
		return -1;
	}
	if (wait_for_control_send(path) != 0)
		return -1;
	printf("server path %u: exported RDMA write target addr=%#" PRIx64 " rkey=%#x size=%zu\n",
	       path->path_id, (uint64_t)(uintptr_t)path->buffer, path->mr->rkey, path->wire_size);
	return 0;
}

static int receive_region_info(struct path_ctx *path)
{
	for (;;) {
		struct ibv_wc completion;
		struct peer_region_info region;
		int count = ibv_poll_cq(path->cq, 1, &completion);

		if (count < 0) {
			fprintf(stderr, "client path %u: control CQ poll failed\n", path->path_id);
			return -1;
		}
		if (count == 0) {
			usleep(10);
			continue;
		}
		if (completion.status != IBV_WC_SUCCESS || completion.opcode != IBV_WC_RECV || completion.wr_id != 0 ||
		    completion.byte_len != sizeof(region)) {
			fprintf(stderr, "client path %u: region receive error status=%s opcode=%d wr_id=%" PRIu64
				" bytes=%u\n", path->path_id, ibv_wc_status_str(completion.status),
				completion.opcode, completion.wr_id, completion.byte_len);
			return -1;
		}
		memcpy(&region, path->buffer, sizeof(region));
		if (be64toh(region.magic) != PEER_REGION_MAGIC || ntohl(region.wire_size) != path->wire_size) {
			fprintf(stderr, "client path %u: invalid remote region info\n", path->path_id);
			return -1;
		}
		path->remote_address = be64toh(region.address);
		path->remote_rkey = ntohl(region.rkey);
		path->remote_wire_size = ntohl(region.wire_size);
		printf("client path %u: imported RDMA write target addr=%#" PRIx64 " rkey=%#x size=%u\n",
		       path->path_id, path->remote_address, path->remote_rkey, path->remote_wire_size);
		return 0;
	}
}

static int connect_client_path(struct path_ctx *path, const struct peer_config *config)
{
	struct cm_hello hello = {
		.magic = htonl(CM_MAGIC),
		.version = htons(CM_VERSION),
		.path_id = htons((uint16_t)path->path_id),
	};
	struct rdma_conn_param parameter = {
		.private_data = &hello,
		.private_data_len = sizeof(hello),
		.responder_resources = 1,
		.initiator_depth = 1,
		.retry_count = 7,
		.rnr_retry_count = 7,
	};
	struct sockaddr_in local = config->local[path->path_id];
	struct sockaddr_in remote = config->peer[path->path_id];
	char local_text[INET_ADDRSTRLEN], remote_text[INET_ADDRSTRLEN];

	remote.sin_port = htons(config->cm_port[path->path_id]);
	path->channel = rdma_create_event_channel();
	if (path->channel == NULL) {
		perror("rdma_create_event_channel");
		return -1;
	}
	if (rdma_create_id(path->channel, &path->id, path, RDMA_PS_TCP) != 0) {
		perror("rdma_create_id");
		return -1;
	}
	printf("client path %u: resolving %s -> %s:%u through RDMA CM\n", path->path_id,
	       format_address(&local, local_text), format_address(&remote, remote_text),
	       config->cm_port[path->path_id]);
	if (rdma_resolve_addr(path->id, (struct sockaddr *)&local, (struct sockaddr *)&remote,
			      CONNECT_TIMEOUT_MS) != 0) {
		perror("rdma_resolve_addr");
		return -1;
	}
	if (wait_for_event(path->channel, RDMA_CM_EVENT_ADDR_RESOLVED, NULL) != 0)
		return -1;
	if (rdma_resolve_route(path->id, CONNECT_TIMEOUT_MS) != 0) {
		perror("rdma_resolve_route");
		return -1;
	}
	if (wait_for_event(path->channel, RDMA_CM_EVENT_ROUTE_RESOLVED, NULL) != 0)
		return -1;
	if (setup_resources(path, config->depth, sizeof(struct peer_chunk_header) + config->payload_size, 1) != 0)
		return -1;

	/* Standard RDMA-CM QP setup triggers mlx5's automatic ECE handshake. */
	if (rdma_connect(path->id, &parameter) != 0) {
		perror("rdma_connect");
		return -1;
	}
	if (wait_for_event(path->channel, RDMA_CM_EVENT_ESTABLISHED, NULL) != 0)
		return -1;
	log_ece(path, "client");
	return receive_region_info(path);
}

static int prepare_server_listener(struct path_ctx *path, const struct peer_config *config)
{
	struct sockaddr_in local = config->local[path->path_id];
	char local_text[INET_ADDRSTRLEN];

	local.sin_port = htons(config->cm_port[path->path_id]);
	path->channel = rdma_create_event_channel();
	if (path->channel == NULL) {
		perror("rdma_create_event_channel");
		return -1;
	}
	if (rdma_create_id(path->channel, &path->listen_id, path, RDMA_PS_TCP) != 0) {
		perror("rdma_create_id");
		return -1;
	}
	if (rdma_bind_addr(path->listen_id, (struct sockaddr *)&local) != 0) {
		perror("rdma_bind_addr");
		return -1;
	}
	if (rdma_listen(path->listen_id, 1) != 0) {
		perror("rdma_listen");
		return -1;
	}
	printf("server path %u: listening with RDMA CM on %s:%u\n", path->path_id,
	       format_address(&local, local_text), config->cm_port[path->path_id]);
	return 0;
}

static int accept_server_path(struct path_ctx *path, const struct peer_config *config)
{
	struct rdma_conn_param parameter = {
		.responder_resources = 1,
		.initiator_depth = 1,
		.rnr_retry_count = 7,
	};

	/*
	 * mlx5 ECE may extend connection-request private data. Do not parse it:
	 * the listener's local IP and RDMA-CM service port identify the path.
	 */
	if (wait_for_event(path->channel, RDMA_CM_EVENT_CONNECT_REQUEST, &path->id) != 0)
		return -1;
	printf("server path %u: accepted CONNECT_REQUEST\n", path->path_id);
	if (setup_resources(path, config->depth, sizeof(struct peer_chunk_header) + config->payload_size, 0) != 0)
		return -1;

	/* rdma_accept completes standard ECE negotiation for this RDMA-CM QP. */
	if (rdma_accept(path->id, &parameter) != 0) {
		perror("rdma_accept");
		return -1;
	}
	if (wait_for_event(path->channel, RDMA_CM_EVENT_ESTABLISHED, NULL) != 0)
		return -1;
	log_ece(path, "server");
	return send_region_info(path);
}

static int post_chunk_batch(struct path_ctx *path, uint32_t count, uint64_t first_sequence,
			    uint32_t payload_size, bool force_final_signal)
{
	struct ibv_sge sges[MAX_POST_BATCH] = {0};
	struct ibv_send_wr sends[MAX_POST_BATCH] = {0};
	struct ibv_send_wr *bad_send = NULL;
	uint32_t slots[MAX_POST_BATCH];
	uint32_t selected = 0;
	uint32_t outstanding = path->outstanding;
	uint32_t unsignaled = path->unsignaled_writes;
	uint32_t candidate;

	if (count == 0 || count > MAX_POST_BATCH || count > path->depth - path->outstanding) {
		fprintf(stderr, "path %u: invalid RDMA_WRITE batch size %u\n", path->path_id, count);
		return -1;
	}

	/* Select distinct local slots before making any state visible to the QP. */
	for (candidate = 0; candidate < path->depth && selected < count; candidate++) {
		if (!path->slot_busy[candidate])
			slots[selected++] = candidate;
	}
	if (selected != count) {
		fprintf(stderr, "path %u: unable to allocate %u local send slots\n", path->path_id, count);
		return -1;
	}

	for (uint32_t index = 0; index < count; index++) {
		uint32_t slot = slots[index];
		uint64_t sequence = first_sequence + index;
		struct peer_chunk_header *header =
			(struct peer_chunk_header *)(path->buffer + (size_t)slot * path->wire_size);
		bool signal = (force_final_signal && index + 1 == count) ||
			unsignaled + 1 >= SIGNAL_INTERVAL || outstanding + 1 >= path->depth;

		/* The data pattern is intentionally not rewritten for every chunk. */
		header->magic = htobe64(PEER_MAGIC);
		header->sequence = htobe64(sequence);
		header->payload_length = htonl(payload_size);
		header->path_id = htons((uint16_t)path->path_id);
		header->reserved = 0;

		sges[index].addr = (uintptr_t)header;
		sges[index].length = (uint32_t)path->wire_size;
		sges[index].lkey = path->mr->lkey;
		sends[index].wr_id = slot;
		sends[index].sg_list = &sges[index];
		sends[index].num_sge = 1;
		sends[index].opcode = IBV_WR_RDMA_WRITE;
		sends[index].wr.rdma.remote_addr =
			path->remote_address + (sequence % path->depth) * path->wire_size;
		sends[index].wr.rdma.rkey = path->remote_rkey;
		sends[index].next = index + 1 < count ? &sends[index + 1] : NULL;
		if (signal)
			sends[index].send_flags = IBV_SEND_SIGNALED;
		if (signal)
			unsignaled = 0;
		else
			unsignaled++;
		outstanding++;
	}

	if (ibv_post_send(path->id->qp, &sends[0], &bad_send) != 0) {
		fprintf(stderr, "path %u: ibv_post_send RDMA_WRITE batch failed: %s\n", path->path_id,
			strerror(errno));
		return -1;
	}
	for (uint32_t index = 0; index < count; index++) {
		uint32_t slot = slots[index];

		path->slot_busy[slot] = true;
		path->slot_order[slot] = ++path->next_post_order;
	}
	path->outstanding = outstanding;
	path->unsignaled_writes = unsignaled;
	path->assigned_chunks += count;
	path->assigned_bytes += (uint64_t)count * path->wire_size;
	return 0;
}

static int poll_sender_completions(struct path_ctx *path)
{
	struct ibv_wc completions[32];
	int count, index, retired = 0;

	count = ibv_poll_cq(path->cq, 32, completions);
	if (count < 0) {
		fprintf(stderr, "path %u: ibv_poll_cq failed\n", path->path_id);
		return -1;
	}
	for (index = 0; index < count; index++) {
		uint64_t slot = completions[index].wr_id;
		uint64_t completed_order;

		if (completions[index].status != IBV_WC_SUCCESS || completions[index].opcode != IBV_WC_RDMA_WRITE ||
		    slot >= path->depth || !path->slot_busy[slot]) {
			fprintf(stderr, "path %u: RDMA_WRITE completion error status=%s opcode=%d wr_id=%" PRIu64 "\n",
				path->path_id, ibv_wc_status_str(completions[index].status),
				completions[index].opcode, slot);
			return -1;
		}
		completed_order = path->slot_order[slot];
		/* RC QP ordering guarantees every prior WQE completed with this CQE. */
		for (uint32_t candidate = 0; candidate < path->depth; candidate++) {
			if (path->slot_busy[candidate] && path->slot_order[candidate] <= completed_order) {
				path->slot_busy[candidate] = false;
				path->outstanding--;
				path->completed_chunks++;
				path->completed_bytes += path->wire_size;
				retired++;
			}
		}
	}
	return retired;
}

static void update_weights(const struct peer_config *config, double weights[PEER_PATHS])
{
	uint32_t path0_rate;
	uint32_t path1_rate;
	double target, delta;

	(void)config;
	path0_rate = atomic_load_explicit(&tracked_pcc_rates[0], memory_order_relaxed);
	path1_rate = atomic_load_explicit(&tracked_pcc_rates[1], memory_order_relaxed);
	if (path0_rate == 0 || path1_rate == 0)
		return;
	target = (double)path0_rate / ((double)path0_rate + (double)path1_rate);
	if (target < MIN_PROBE_SHARE)
		target = MIN_PROBE_SHARE;
	if (target > MAX_PROBE_SHARE)
		target = MAX_PROBE_SHARE;
	delta = target - weights[0];
	if (delta > MAX_WEIGHT_STEP)
		delta = MAX_WEIGHT_STEP;
	if (delta < -MAX_WEIGHT_STEP)
		delta = -MAX_WEIGHT_STEP;
	weights[0] += delta;
	weights[1] = 1.0 - weights[0];
}

static void report_throughput(const char *role, const struct path_ctx paths[PEER_PATHS], bool sender,
			      uint64_t last_bytes[PEER_PATHS], uint64_t *last_report)
{
	uint64_t now = monotonic_msec();
	uint64_t elapsed = now - *last_report;
	uint64_t aggregate_delta = 0;

	if (elapsed < THROUGHPUT_INTERVAL_MS)
		return;
	printf("--- %s throughput (%" PRIu64 " ms interval) ---\n", role, elapsed);
	for (unsigned int i = 0; i < PEER_PATHS; i++) {
		uint64_t total = sender ? paths[i].completed_bytes : paths[i].received_bytes;
		uint64_t delta = total - last_bytes[i];
		double gbps = ((double)delta * 8.0) / ((double)elapsed * 1000000.0);

		printf("  path %u: %.3f Gbps, interval_bytes=%" PRIu64 " total_bytes=%" PRIu64 "\n",
		       i, gbps, delta, total);
		last_bytes[i] = total;
		aggregate_delta += delta;
	}
	printf("  aggregate: %.3f Gbps\n", ((double)aggregate_delta * 8.0) /
	       ((double)elapsed * 1000000.0));
	fflush(stdout);
	*last_report = now;
}

static int run_sender(struct path_ctx paths[PEER_PATHS], const struct peer_config *config)
{
	const bool finite_run = config->chunks != 0;
	uint64_t deficits[PEER_PATHS] = {0};
	double weights[PEER_PATHS] = {0.5, 0.5};
	uint64_t last_weight_update = 0;
	uint64_t posted = 0, completed = 0;
	uint64_t started = monotonic_msec();
	uint64_t last_report = started;
	uint64_t last_bytes[PEER_PATHS] = {0};
	uint64_t wire_size = sizeof(struct peer_chunk_header) + config->payload_size;
	uint64_t quantum = wire_size * config->post_batch * PEER_PATHS;
	uint64_t minimum_probe_quantum = wire_size * MIN_PROBE_QUANTUM_FACTOR;
	uint64_t maximum_deficit;

	if (quantum < minimum_probe_quantum)
		quantum = minimum_probe_quantum;
	maximum_deficit = (uint64_t)config->depth * wire_size;
	if (maximum_deficit < quantum)
		maximum_deficit = quantum;

	while ((!finite_run || completed < config->chunks) && !stop_requested) {
		bool progress = false;
		unsigned int path_index;

		if (monotonic_msec() - last_weight_update >= config->weight_period_ms) {
			last_weight_update = monotonic_msec();
			update_weights(config, weights);
		}
		for (path_index = 0; path_index < PEER_PATHS &&
		     (!finite_run || posted < config->chunks); path_index++) {
			struct path_ctx *path = &paths[path_index];
			uint64_t credit = (uint64_t)(quantum * weights[path_index]);

			if (credit >= maximum_deficit - deficits[path_index])
				deficits[path_index] = maximum_deficit;
			else
				deficits[path_index] += credit;
			while ((!finite_run || posted < config->chunks) &&
			       deficits[path_index] >= path->wire_size && path->outstanding < path->depth) {
				uint64_t remaining = finite_run ? config->chunks - posted : UINT64_MAX;
				uint32_t batch = config->post_batch;
				uint64_t credit_chunks = deficits[path_index] / path->wire_size;
				uint32_t available = path->depth - path->outstanding;

				if ((uint64_t)batch > credit_chunks)
					batch = (uint32_t)credit_chunks;
				if (batch > available)
					batch = available;
				if ((uint64_t)batch > remaining)
					batch = (uint32_t)remaining;
				if (batch == 0)
					break;
				if (post_chunk_batch(path, batch, posted, config->payload_size,
						     finite_run && (uint64_t)batch == remaining) != 0)
					return -1;
				deficits[path_index] -= (uint64_t)batch * path->wire_size;
				posted += batch;
				progress = true;
			}
		}
		for (path_index = 0; path_index < PEER_PATHS; path_index++) {
			int result = poll_sender_completions(&paths[path_index]);

			if (result < 0)
				return -1;
			if (result > 0) {
				completed += (uint64_t)result;
				progress = true;
			}
		}
		if (!finite_run)
			report_throughput("sender", paths, true, last_bytes, &last_report);
		if (!progress)
			usleep(10);
	}
	printf("sender: %s after %" PRIu64 " chunks in %" PRIu64 " ms\n",
	       stop_requested ? "stopped" : "completed", completed, monotonic_msec() - started);
	for (unsigned int i = 0; i < PEER_PATHS; i++) {
		printf("sender path %u: assigned=%" PRIu64 " chunks / %" PRIu64
		       " bytes, completed=%" PRIu64 " chunks\n",
		       i, paths[i].assigned_chunks, paths[i].assigned_bytes, paths[i].completed_chunks);
	}
	return stop_requested && finite_run ? -1 : 0;
}

static int run_write_target(const struct path_ctx paths[PEER_PATHS])
{
	printf("receiver: RDMA write targets are active; bulk bytes are measured at the BF3 sender\n");
	while (!stop_requested) {
		if (poll(NULL, 0, CM_EVENT_POLL_MS) < 0 && errno != EINTR) {
			perror("poll receiver shutdown");
			return -1;
		}
	}
	for (unsigned int i = 0; i < PEER_PATHS; i++)
		printf("receiver path %u: target addr=%#" PRIx64 " rkey=%#x size=%zu\n", i,
		       (uint64_t)(uintptr_t)paths[i].buffer, paths[i].mr->rkey, paths[i].wire_size);
	return 0;
}

static void disconnect_client_paths(struct path_ctx paths[PEER_PATHS])
{
	for (unsigned int i = 0; i < PEER_PATHS; i++) {
		if (paths[i].id == NULL)
			continue;
		if (rdma_disconnect(paths[i].id) != 0 && errno != ENOTCONN)
			fprintf(stderr, "path %u: rdma_disconnect failed: %s\n", paths[i].path_id,
				strerror(errno));
		if (!stop_requested)
			(void)wait_for_event(paths[i].channel, RDMA_CM_EVENT_DISCONNECTED, NULL);
	}
}

int peer_sim_main(int argc, char **argv)
{
	struct peer_config config;
	struct path_ctx paths[PEER_PATHS] = {0};
	int result = EXIT_FAILURE;

	stop_requested = 0;
	optind = 1;
	if (parse_args(argc, argv, &config) != 0) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	if (signal(SIGINT, on_signal) == SIG_ERR || signal(SIGTERM, on_signal) == SIG_ERR) {
		perror("signal");
		return EXIT_FAILURE;
	}
	for (unsigned int i = 0; i < PEER_PATHS; i++)
		paths[i].path_id = i;

	if (config.role == PEER_ROLE_CLIENT) {
		if (connect_client_path(&paths[0], &config) != 0 ||
		    connect_client_path(&paths[1], &config) != 0)
			goto cleanup;
		peer_sim_track_pcc_qpns(paths[0].id->qp->qp_num, paths[1].id->qp->qp_num);
		if (run_sender(paths, &config) != 0)
			goto cleanup;
		disconnect_client_paths(paths);
		result = EXIT_SUCCESS;
	} else {
		if (prepare_server_listener(&paths[0], &config) != 0 ||
		    prepare_server_listener(&paths[1], &config) != 0)
			goto cleanup;
		if (accept_server_path(&paths[0], &config) != 0 ||
		    accept_server_path(&paths[1], &config) != 0)
			goto cleanup;
		if (run_write_target(paths) != 0)
			goto cleanup;
		result = EXIT_SUCCESS;
	}

cleanup:
	for (unsigned int i = 0; i < PEER_PATHS; i++)
		cleanup_path(&paths[i]);
	return result;
}

#ifndef PEER_SIM_NO_MAIN
int main(int argc, char **argv)
{
	return peer_sim_main(argc, argv);
}
#endif
