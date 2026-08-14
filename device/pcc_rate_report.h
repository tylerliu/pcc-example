/*
 * Copyright (c) 2025 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Shared definitions for DPA-to-Host per-flow rate reporting via the PCC trace
 * infrastructure (built on flexio_msg_stream tracer mode).
 *
 * Device side: calls doca_pcc_dev_trace_5(PCC_RATE_REPORT_FORMAT_ID, ...)
 * Host side:   filters incoming trace reports by format_id == PCC_RATE_REPORT_FORMAT_ID
 */

#ifndef PCC_DEVICE_RATE_REPORT_H_
#define PCC_DEVICE_RATE_REPORT_H_

/*
 * Trace format ID for per-flow rate reports.
 * Must not collide with existing format IDs (0..9 are used by the app).
 */
#define PCC_RATE_REPORT_FORMAT_ID (6)

/*
 * Trace arguments layout (5 x 64-bit):
 *   arg1 = flow QPN
 *   arg2 = new rate (FXP20 format, same as results->rate)
 *   arg3 = event type that caused the rate change
 *   arg4 = current RTT (nanoseconds)
 *   arg5 = timestamp (doca_pcc_dev_get_timer_lo)
 */

#endif /* PCC_DEVICE_RATE_REPORT_H_ */
