/*
 * DOCA Flow 2.9 <-> 3.x source compatibility shim for doca_flow_steer.c.
 *
 * The DOCA Flow entry API changed between 2.9 and 3.x:
 *   - 2.9: doca_flow_pipe_add_entry(queue, pipe, match, actions, monitor, fwd,
 *          flags, usr, entry); the action-template index is a struct member,
 *          actions->action_idx. Source vport match field is parser_meta.port_meta.
 *          Batch flag is DOCA_FLOW_WAIT_FOR_BATCH.
 *   - 3.x: doca_flow_pipe_basic_add_entry(queue, pipe, match, action_idx, actions,
 *          monitor, fwd, flags, usr, entry); action_idx is an explicit parameter.
 *          Source vport match field is parser_meta.port_id (set via
 *          doca_flow_port_cfg_set_port_id). Batch flag is
 *          DOCA_FLOW_ENTRY_FLAGS_WAIT_FOR_BATCH.
 *
 * This header hides those behind steer_* wrappers/macros so one source builds on
 * both. Version-gated on DOCA_VERSION_MAJOR. The legacy branch is porting
 * scaffolding only; see README.md "Future DOCA 2.7/2.9 port" before relying on
 * it with an older SDK.
 */

#ifndef DOCA_FLOW_COMPAT_H_
#define DOCA_FLOW_COMPAT_H_

#include <doca_flow.h>
#include <doca_version.h>

#if DOCA_VERSION_MAJOR >= 3

#define STEER_WAIT_FOR_BATCH DOCA_FLOW_ENTRY_FLAGS_WAIT_FOR_BATCH
#define STEER_NO_WAIT DOCA_FLOW_ENTRY_FLAGS_NO_WAIT
/* parser_meta source-port field name (used as .parser_meta.STEER_PARSER_PORT). */
#define STEER_PARSER_PORT port_id
/* All-ones wildcard sized to the source-port field (uint16_t on 3.x). */
#define STEER_PORT_ALL 0xFFFFu

static inline doca_error_t steer_port_cfg_set_port_id(struct doca_flow_port_cfg *cfg, uint16_t port_id)
{
	return doca_flow_port_cfg_set_port_id(cfg, port_id);
}

#else /* DOCA 2.9 */

#define STEER_WAIT_FOR_BATCH DOCA_FLOW_WAIT_FOR_BATCH
/* The legacy API submits immediately when WAIT_FOR_BATCH is absent. */
#define STEER_NO_WAIT 0
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
#if DOCA_VERSION_MAJOR >= 3
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
#if DOCA_VERSION_MAJOR >= 3
	return doca_flow_pipe_basic_update_entry(queue, pipe, action_idx, actions, monitor, fwd, flags, entry);
#else
	if (actions != NULL)
		actions->action_idx = action_idx;
	return doca_flow_pipe_update_entry(queue, pipe, actions, (struct doca_flow_monitor *)monitor,
					   (struct doca_flow_fwd *)fwd, flags, entry);
#endif
}

#endif /* DOCA_FLOW_COMPAT_H_ */
