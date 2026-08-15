/*
 * DOCA Flow 2.9 <-> 3.x source compatibility shim for doca_flow_steer.c.
 *
 * The DOCA Flow entry API changed between 2.9 and 3.x:
 *   - 2.9: doca_flow_pipe_add_entry(queue, pipe, match, actions, monitor, fwd,
 *          flags, usr, entry); the action-template index is a struct member,
 *          actions->action_idx. Source vport match field is parser_meta.port_meta.
 *          Batch flag is DOCA_FLOW_WAIT_FOR_BATCH.
 *   - 3.4+: doca_flow_pipe_basic_add_entry(queue, pipe, match, action_idx, actions,
 *          monitor, fwd, flags, usr, entry); action_idx is an explicit parameter.
 *          Source vport match field is parser_meta.port_id (set via
 *          doca_flow_port_cfg_set_port_id). Batch flag is
 *          DOCA_FLOW_ENTRY_FLAGS_WAIT_FOR_BATCH.
 *
 * This header hides those behind steer_* wrappers/macros so one source builds on
 *   - 3.0-3.3 retain the old basic-entry API and flags, while using the 3.x
 *     device/representor and parser-port APIs. Hash-entry action_idx also only
 *     becomes an explicit argument in 3.4.
 *
 * These distinctions are kept here rather than at pipeline call sites. The
 * DOCA 2.x branch is porting
 * scaffolding only; see README.md "Future DOCA 2.7/2.9 port" before relying on
 * it with an older SDK.
 */

#ifndef DOCA_FLOW_COMPAT_H_
#define DOCA_FLOW_COMPAT_H_

#include <doca_flow.h>
#include <doca_version.h>

#define STEER_DOCA_VERSION_GE(major, minor) \
	((DOCA_VERSION_MAJOR > (major)) || \
	 (DOCA_VERSION_MAJOR == (major) && DOCA_VERSION_MINOR >= (minor)))

/* Basic/hash entry APIs gained an explicit action_idx in DOCA 3.4. */
#define STEER_HAS_EXPLICIT_ACTION_IDX STEER_DOCA_VERSION_GE(3, 4)

/* 3.x has the native RANDOM HASH algorithm used by EGRESS_CLASSIFY. Keep the
 * old parser_meta.random BASIC implementation compiled for the 2.7/2.9 backend. */
#define STEER_USE_RANDOM_HASH_CLASSIFIER (DOCA_VERSION_MAJOR >= 3)

/* Native RoCEv2/BTH items and HASH forwarding were added in DOCA Flow 3.x. */
#define STEER_HAS_ROCE_MATCH (DOCA_VERSION_MAJOR >= 3)
#define STEER_HAS_HASH_FWD (DOCA_VERSION_MAJOR >= 3)

/* Counter allocation moved from the global Flow cfg to individual ports in 3.2. */
#define STEER_HAS_PORT_RESOURCE_MODE STEER_DOCA_VERSION_GE(3, 2)

#if STEER_HAS_EXPLICIT_ACTION_IDX

#define STEER_WAIT_FOR_BATCH DOCA_FLOW_ENTRY_FLAGS_WAIT_FOR_BATCH
#define STEER_NO_WAIT DOCA_FLOW_ENTRY_FLAGS_NO_WAIT
#else
#define STEER_WAIT_FOR_BATCH DOCA_FLOW_WAIT_FOR_BATCH
#define STEER_NO_WAIT DOCA_FLOW_NO_WAIT
#endif

#if DOCA_VERSION_MAJOR >= 3
/* parser_meta source-port field name (used as .parser_meta.STEER_PARSER_PORT). */
#define STEER_PARSER_PORT port_id
/* All-ones wildcard sized to the source-port field (uint16_t on 3.x). */
#define STEER_PORT_ALL 0xFFFFu

static inline doca_error_t steer_port_cfg_set_port_id(struct doca_flow_port_cfg *cfg, uint16_t port_id)
{
	return doca_flow_port_cfg_set_port_id(cfg, port_id);
}

#else /* DOCA 2.x */

#define STEER_PARSER_PORT port_meta
/* All-ones wildcard sized to the source-port field (uint32_t on 2.9). */
#define STEER_PORT_ALL 0xFFFFFFFFu

static inline doca_error_t steer_port_cfg_set_port_id(struct doca_flow_port_cfg *cfg, uint16_t port_id)
{
	/* 2.9 matches the intrinsic source vport via parser_meta.port_meta; no
	 * explicit logical-port-id assignment is required. */
	(void)cfg;
	(void)port_id;
	return DOCA_SUCCESS;
}

#endif

/* RSS forwarding was flattened in 2.x and moved below an rss member in 3.x. */
static inline void steer_fwd_set_rss(struct doca_flow_fwd *fwd, uint16_t *queues,
                                      uint16_t nr_queues, uint32_t flags)
{
	fwd->type = DOCA_FLOW_FWD_RSS;
#if DOCA_VERSION_MAJOR >= 3
	fwd->rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	fwd->rss.queues_array = queues;
	fwd->rss.nr_queues = nr_queues;
	fwd->rss.inner_flags = flags;
#else
	fwd->rss_queues = queues;
	fwd->num_of_queues = nr_queues;
	fwd->rss_outer_flags = flags;
#endif
}

/* RoCEv2 is ordinary IPv4/UDP 4791 to the 2.x public Flow parser. */
static inline void steer_set_roce_udp_match(struct doca_flow_match *match,
                                             struct doca_flow_match *mask,
                                             doca_be16_t dst_port)
{
#if STEER_HAS_ROCE_MATCH
	match->outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match->outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ROCE_V2;
	match->outer.roce_v2.udp.l4_port.dst_port = dst_port;
	mask->outer.roce_v2.udp.l4_port.dst_port = UINT16_MAX;
#else
	/* DOCA 2.x selects IPv4/UDP through parser metadata. Keep UDP 4791
	 * fixed in the template; marking it changeable with only a mask creates
	 * an invalid protocol-only HWS item. */
	match->parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match->parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
	match->outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match->outer.udp.l4_port.dst_port = dst_port;
	(void)mask;
#endif
}

/* DOCA 2.x treats even an all-zero parser-meta mask as an explicit ptype
 * mask, which HWS does not support. Protocol and UDP-port values are fixed in
 * the pipe template there, so no mask is required. */
static inline struct doca_flow_match *steer_roce_udp_match_mask(
	struct doca_flow_match *mask)
{
#if STEER_HAS_ROCE_MATCH
	return mask;
#else
	(void)mask;
	return NULL;
#endif
}

#if DOCA_VERSION_MAJOR < 3
/* DOCA 2.7 requires the mirror resource to carry the original-packet
 * destination. DOCA 2.9 rejects that field and falls back to the pipe entry
 * forwarding instead. */
static inline void steer_mirror_set_original_fwd(
	struct doca_flow_shared_resource_cfg *cfg,
	const struct doca_flow_fwd *original_fwd)
{
#if DOCA_VERSION_MINOR < 9
	cfg->mirror_cfg.fwd = *original_fwd;
#else
	(void)cfg;
	(void)original_fwd;
#endif
}
#endif

struct steer_resource_query {
	uint64_t total_bytes;
	uint64_t total_pkts;
};

static inline doca_error_t steer_shared_resource_set_cfg(
	enum doca_flow_shared_resource_type type, uint32_t id,
	struct doca_flow_shared_resource_cfg *cfg)
{
#if STEER_DOCA_VERSION_GE(2, 8)
	return doca_flow_shared_resource_set_cfg(type, id, cfg);
#else
	return doca_flow_shared_resource_cfg(type, id, cfg);
#endif
}

static inline doca_error_t steer_query_entry(struct doca_flow_pipe_entry *entry,
                                              struct steer_resource_query *query)
{
#if STEER_DOCA_VERSION_GE(2, 8)
	struct doca_flow_resource_query sdk_query = {0};
	doca_error_t err = doca_flow_resource_query_entry(entry, &sdk_query);

	query->total_bytes = sdk_query.counter.total_bytes;
	query->total_pkts = sdk_query.counter.total_pkts;
	return err;
#else
	struct doca_flow_query sdk_query = {0};
	doca_error_t err = doca_flow_query_entry(entry, &sdk_query);

	query->total_bytes = sdk_query.total_bytes;
	query->total_pkts = sdk_query.total_pkts;
	return err;
#endif
}

/*
 * Unified add-entry. action_idx selects the action template slot provided at pipe
 * creation. actions may be NULL (fate-only entries). On 2.9 the index is written
 * into the (non-const) actions struct; on 3.x it is passed as a parameter.
 */
static inline doca_error_t steer_pipe_add_entry(uint16_t queue, struct doca_flow_pipe *pipe,
						const struct doca_flow_match *match, uint8_t action_idx,
						struct doca_flow_actions *actions,
						const struct doca_flow_monitor *monitor,
						const struct doca_flow_fwd *fwd, uint32_t flags, void *usr_ctx,
						struct doca_flow_pipe_entry **entry)
{
#if STEER_HAS_EXPLICIT_ACTION_IDX
	return doca_flow_pipe_basic_add_entry(queue, pipe, match, action_idx, actions, monitor, fwd, flags, usr_ctx,
					      entry);
#else
	if (actions != NULL)
		actions->action_idx = action_idx;
	return doca_flow_pipe_add_entry(queue, pipe, (struct doca_flow_match *)match, actions,
					(struct doca_flow_monitor *)monitor, (struct doca_flow_fwd *)fwd, flags,
					usr_ctx, entry);
#endif
}

/*
 * Unified entry update (used for live steering re-decision). action_idx selects
 * the action template slot; actions may be NULL.
 */
static inline doca_error_t steer_pipe_update_entry(uint16_t queue, struct doca_flow_pipe *pipe, uint8_t action_idx,
						   struct doca_flow_actions *actions,
						   const struct doca_flow_monitor *monitor,
						   const struct doca_flow_fwd *fwd, uint32_t flags,
						   struct doca_flow_pipe_entry *entry)
{
#if STEER_HAS_EXPLICIT_ACTION_IDX
	return doca_flow_pipe_basic_update_entry(queue, pipe, action_idx, actions, monitor, fwd, flags, entry);
#else
	/* Fate-only pipes have no action template, so preserve a NULL actions
	 * pointer when only their changeable forward is being updated. */
	if (actions != NULL)
		actions->action_idx = action_idx;
	return doca_flow_pipe_update_entry(queue, pipe, actions, (struct doca_flow_monitor *)monitor,
					   (struct doca_flow_fwd *)fwd, flags, entry);
#endif
}

/* Unified hash-entry add. DOCA 3.1 has flooding hash, but its hash-entry API
 * still carries action_idx inside actions rather than as a separate argument. */
static inline doca_error_t steer_pipe_hash_add_entry(uint16_t queue, struct doca_flow_pipe *pipe,
					      uint32_t entry_index, uint8_t action_idx,
					      struct doca_flow_actions *actions,
					      const struct doca_flow_monitor *monitor,
					      const struct doca_flow_fwd *fwd, uint32_t flags,
					      void *usr_ctx, struct doca_flow_pipe_entry **entry)
{
#if STEER_HAS_EXPLICIT_ACTION_IDX
	return doca_flow_pipe_hash_add_entry(queue, pipe, entry_index, action_idx, actions, monitor, fwd, flags,
					     usr_ctx, entry);
#else
	if (actions != NULL)
		actions->action_idx = action_idx;
	return doca_flow_pipe_hash_add_entry(queue, pipe, entry_index, actions,
					     (struct doca_flow_monitor *)monitor, (struct doca_flow_fwd *)fwd,
					     flags, usr_ctx, entry);
#endif
}

static inline doca_error_t steer_pipe_remove_entry(uint16_t queue, uint32_t flags,
                                                   struct doca_flow_pipe_entry *entry)
{
#if DOCA_VERSION_MAJOR < 3 && DOCA_VERSION_MINOR < 9
	return doca_flow_pipe_rm_entry(queue, flags, entry);
#else
	return doca_flow_pipe_remove_entry(queue, flags, entry);
#endif
}

#endif /* DOCA_FLOW_COMPAT_H_ */
