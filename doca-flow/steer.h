/*
 * Embeddable PCC-informed RoCE path-steering module (BF3 eSwitch, DOCA Flow).
 *
 * This is the "switching" component: it builds and owns the DOCA Flow pipeline
 * (see README.md) and exposes a small API so it can run either standalone
 * (doca_flow_steer) or embedded in the doca_pcc host process. In the embedded
 * case doca_pcc's PCC trace handler calls steer_update_pcc_rate() with each
 * per-QPN rate; the module maps the rate to a path (by QPN parity) and, in AUTO
 * mode, adjusts which flow is steered onto the "moved" (UDP 4792) virtual path.
 *
 * Lifecycle (embedded):
 *   steer_eal_init(argc, argv, steer_eal_prefix_for_role(role)); // before other EAL users
 *   steer_start(&opts);           // build the pipeline
 *   ... per PCC trace: steer_update_pcc_rate(qpn, rate);
 *   ... periodically:  steer_poll();   // apply decision + log counters
 *   steer_stop();
 */

#ifndef STEER_H_
#define STEER_H_

#include <doca_error.h>
#include <doca_dev.h>
#include <doca_flow.h> /* doca_be32_t */
#include <stdint.h>

#define STEER_NB_PATHS 2

/* Which QPN parity is steered onto the moved (UDP 4792) virtual path. */
enum steer_move_parity {
	STEER_MOVE_NONE = -1, /* never rewrite: pure per-path CE-mark demo */
	STEER_MOVE_EVEN = 0,  /* dest_qp LSB == 0 -> 4792 */
	STEER_MOVE_ODD = 1,   /* dest_qp LSB == 1 -> 4792 */
	STEER_MOVE_AUTO = 2,  /* PCC-rate-driven (see auto_ratio_threshold) */
	STEER_MOVE_ALL = 3,   /* both parities -> 4792 (isolation test) */
};

/*
 * Which half of the pipeline this instance builds. On a single BF3 with a
 * p0<->p1 DAC loopback the sender and receiver are different SFs (usually on
 * different PFs), so the two directions run as two separate programs:
 *
 *   STEER_ROLE_EGRESS  (sender side, e.g. pf1sf0): SF-egress -> EGRESS_CLASSIFY
 *                       does the parity 4791->4792 rewrite -> wire. Wire-ingress
 *                       (returning ACK/CNP) is delivered straight to the SF.
 *   STEER_ROLE_INGRESS (receiver side, e.g. pf0sf0): wire-ingress -> MARK (CE on
 *                       native 4791) + RESTORE (4792->4791) -> SF. SF-egress
 *                       (receiver ACK/CNP) is delivered straight to the wire.
 *   STEER_ROLE_BOTH    both halves in one eSwitch instance (single-endpoint /
 *                       whole-eSwitch case).
 */
enum steer_role {
	STEER_ROLE_INGRESS = 0,
	STEER_ROLE_EGRESS = 1,
	STEER_ROLE_BOTH = 2,
};

struct steer_opts {
	uint32_t sf_num;			      /* receiver SF number (DOCA 2.9 discovery only) */
	int role;				      /* enum steer_role */
	int move_parity;			      /* enum steer_move_parity */
	double path_percent[STEER_NB_PATHS];	      /* per-path CE-mark percentage [0,100] */
	double auto_ratio_threshold;		      /* AUTO: move parity p when rate[p] < rate[other]*thr */
	/* DOCA 3.x device discovery: caller opens these (argp --device/--rep or DOCA APIs). */
	struct doca_dev *dev;			      /* PF device */
	struct doca_dev_rep *dev_rep;		      /* SF representor */
	const char *devargs;			      /* optional probe devargs (default dv_flow_en=2,fdb_def_rule_en=1) */
};

/* Fill opts with defaults (the two peer paths, 100% CE, AUTO threshold 0.5). */
void steer_default_opts(struct steer_opts *opts);

/*
 * Initialize DPDK EAL for the steering datapath. `file_prefix` becomes the DPDK
 * --file-prefix so this primary process does not collide with another DPDK
 * primary on the host (e.g. the peer role's steering instance); pass
 * steer_eal_prefix_for_role(role). Call once, before any other EAL user in the
 * process.
 */
doca_error_t steer_eal_init(int argc, char **argv, const char *file_prefix);

/* A stable, role-specific DPDK --file-prefix ("pcc-egress" / "pcc-ingress" / "pcc-steer"). */
const char *steer_eal_prefix_for_role(int role);

/* Build the eSwitch pipeline. EAL must already be initialized. */
doca_error_t steer_start(const struct steer_opts *opts);

/*
 * Feed one per-QPN PCC rate (FXP20). Safe to call from the PCC trace handler.
 * The path is identified by QPN parity (qpn & 1). Lock-free: stores only.
 */
void steer_update_pcc_rate(uint32_t qpn, uint32_t rate);

/* Apply the current (AUTO) steering decision if changed, and log counters. */
void steer_poll(void);

/* Tear down the pipeline and DOCA Flow. */
void steer_stop(void);

#endif /* STEER_H_ */
