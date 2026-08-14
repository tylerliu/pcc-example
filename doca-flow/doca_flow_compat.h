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
 * old parser_meta.random BASIC implementation compiled only for the future
 * 2.7/2.9 port. */
#define STEER_USE_RANDOM_HASH_CLASSIFIER (DOCA_VERSION_MAJOR >= 3)

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

#else /* DOCA 2.9 */

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

#endif /* DOCA_FLOW_COMPAT_H_ */
