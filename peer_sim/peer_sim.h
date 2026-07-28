#ifndef PEER_SIM_H_
#define PEER_SIM_H_

#include <stdint.h>

/*
 * Direct in-process PCC feedback bridge. The sender registers its established
 * client QPNs before posting traffic; the PCC trace handler pushes only matching
 * FXP20 rates. Readers may observe an older complete rate, which is valid DRR
 * control behavior.
 */
void peer_sim_track_pcc_qpns(uint32_t path0_qpn, uint32_t path1_qpn);
void peer_sim_update_pcc_rate(uint32_t qpn, uint32_t rate);

/* Reusable client/server entrypoint. argv[0] is used only in diagnostics. */
int peer_sim_main(int argc, char **argv);

#endif /* PEER_SIM_H_ */
