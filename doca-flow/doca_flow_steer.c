/*
 * Standalone runner for the steering module (steer.c). Parses CLI, initializes
 * EAL via DOCA argp, starts the pipeline, and polls once per second. The same
 * steer_* API is used embedded in doca_pcc (see ../pcc), where the PCC trace
 * handler drives steer_update_pcc_rate() instead of this static CLI.
 */

#include <doca_argp.h>
#include <doca_error.h>
#include <doca_log.h>
#include "steer.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

DOCA_LOG_REGISTER(FLOW_STEER_MAIN);

static volatile bool g_running = true;

static void on_signal(int s)
{
	if (s == SIGINT || s == SIGTERM)
		g_running = false;
}

#define CRASH(err, msg)                                                                    \
	do {                                                                               \
		doca_error_t _e = (err);                                                   \
		if (_e != DOCA_SUCCESS) {                                                  \
			DOCA_LOG_CRIT("%s: %s", (msg), doca_error_get_descr(_e));          \
			exit(EXIT_FAILURE);                                                \
		}                                                                          \
	} while (0)

static doca_error_t sf_num_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	long v = atol((const char *)param);

	if (v < 0 || v > UINT16_MAX) {
		DOCA_LOG_ERR("--sf-num must be in [0, %u]", UINT16_MAX);
		return DOCA_ERROR_INVALID_VALUE;
	}
	o->sf_num = (uint32_t)v;
	return DOCA_SUCCESS;
}

static doca_error_t move_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	const char *s = (const char *)param;

	if (strcmp(s, "none") == 0)
		o->move_parity = STEER_MOVE_NONE;
	else if (strcmp(s, "even") == 0 || strcmp(s, "0") == 0)
		o->move_parity = STEER_MOVE_EVEN;
	else if (strcmp(s, "odd") == 0 || strcmp(s, "1") == 0)
		o->move_parity = STEER_MOVE_ODD;
	else if (strcmp(s, "auto") == 0)
		o->move_parity = STEER_MOVE_AUTO;
	else if (strcmp(s, "all") == 0)
		o->move_parity = STEER_MOVE_ALL;
	else {
		DOCA_LOG_ERR("--move-parity must be none|even|odd|auto|all (got '%s')", s);
		return DOCA_ERROR_INVALID_VALUE;
	}
	return DOCA_SUCCESS;
}

static doca_error_t role_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	const char *s = (const char *)param;

	if (strcmp(s, "egress") == 0 || strcmp(s, "sender") == 0)
		o->role = STEER_ROLE_EGRESS;
	else if (strcmp(s, "ingress") == 0 || strcmp(s, "receiver") == 0)
		o->role = STEER_ROLE_INGRESS;
	else if (strcmp(s, "both") == 0)
		o->role = STEER_ROLE_BOTH;
	else {
		DOCA_LOG_ERR("--role must be egress|ingress|both (got '%s')", s);
		return DOCA_ERROR_INVALID_VALUE;
	}
	return DOCA_SUCCESS;
}

static doca_error_t p0ip_cb(void *param, void *config)
{
	struct steer_opts *o = config;

	if (inet_pton(AF_INET, (const char *)param, &o->path_dst_ip[0]) != 1)
		return DOCA_ERROR_INVALID_VALUE;
	return DOCA_SUCCESS;
}

static doca_error_t p1ip_cb(void *param, void *config)
{
	struct steer_opts *o = config;

	if (inet_pton(AF_INET, (const char *)param, &o->path_dst_ip[1]) != 1)
		return DOCA_ERROR_INVALID_VALUE;
	return DOCA_SUCCESS;
}

static doca_error_t p0pct_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	double v = atof((const char *)param);

	if (v < 0.0 || v > 100.0)
		return DOCA_ERROR_INVALID_VALUE;
	o->path_percent[0] = v;
	return DOCA_SUCCESS;
}

static doca_error_t p1pct_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	double v = atof((const char *)param);

	if (v < 0.0 || v > 100.0)
		return DOCA_ERROR_INVALID_VALUE;
	o->path_percent[1] = v;
	return DOCA_SUCCESS;
}

#if DOCA_VERSION_MAJOR >= 3
static doca_error_t device_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	struct doca_argp_device_ctx *dev_ctx = param;

	o->dev = dev_ctx->dev;
	if (dev_ctx->devargs)
		o->devargs = dev_ctx->devargs;
	return DOCA_SUCCESS;
}

static doca_error_t rep_cb(void *param, void *config)
{
	struct steer_opts *o = config;
	struct doca_argp_device_rep_ctx *rep_ctx = param;

	o->dev = rep_ctx->dev_ctx.dev;
	o->dev_rep = rep_ctx->dev_rep;
	if (rep_ctx->dev_ctx.devargs)
		o->devargs = rep_ctx->dev_ctx.devargs;
	return DOCA_SUCCESS;
}

static void reg_dev(const char *shortn, const char *longn, const char *desc, doca_argp_param_cb_t cb, int type)
{
	struct doca_argp_param *pm;

	CRASH(doca_argp_param_create(&pm), "argp_param_create");
	doca_argp_param_set_short_name(pm, shortn);
	doca_argp_param_set_long_name(pm, longn);
	doca_argp_param_set_description(pm, desc);
	doca_argp_param_set_callback(pm, cb);
	doca_argp_param_set_type(pm, type);
	CRASH(doca_argp_register_param(pm), "argp_register_param");
}
#endif

static void reg(const char *name, const char *desc, doca_argp_param_cb_t cb)
{
	struct doca_argp_param *pm;

	CRASH(doca_argp_param_create(&pm), "argp_param_create");
	doca_argp_param_set_long_name(pm, name);
	doca_argp_param_set_description(pm, desc);
	doca_argp_param_set_callback(pm, cb);
	doca_argp_param_set_type(pm, DOCA_ARGP_TYPE_STRING);
	CRASH(doca_argp_register_param(pm), "argp_register_param");
}

int main(int argc, char **argv)
{
	struct doca_log_backend *sdk_log;

	CRASH(doca_log_backend_create_standard(), "doca_log_backend_create_standard");
	CRASH(doca_log_backend_create_with_file_sdk(stderr, &sdk_log), "doca_log_backend_create_with_file_sdk");
	doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);

	struct steer_opts opts;

	steer_default_opts(&opts);
	opts.move_parity = STEER_MOVE_NONE; /* standalone default: static, no rewrite */

	CRASH(doca_argp_init("doca_flow_steer", &opts), "doca_argp_init");
	doca_argp_set_dpdk_program(steer_eal_init);
	reg("sf-num", "Receiver SF number (en3f0pf0sf<N>). Default: 0", sf_num_cb);
	reg("move-parity", "QPN parity moved to the 4792 path: none|even|odd|auto. Default: none", move_cb);
	reg("path0-ip", "Path 0 outer IPv4 dst. Default: 172.16.1.20", p0ip_cb);
	reg("path1-ip", "Path 1 outer IPv4 dst. Default: 172.16.2.20", p1ip_cb);
	reg("path0-percent", "Path 0 CE-mark percent [0,100]. Default: 100", p0pct_cb);
	reg("path1-percent", "Path 1 CE-mark percent [0,100]. Default: 100", p1pct_cb);
	reg("role", "Which half to build: egress (sender) | ingress (receiver) | both. Default: both", role_cb);
#if DOCA_VERSION_MAJOR >= 3
	reg_dev("a", "device", "DOCA device, e.g. pci/0000:03:00.0,dv_flow_en=2", device_cb, DOCA_ARGP_TYPE_DEVICE);
	reg_dev("r", "rep", "SF representor, e.g. pci/0000:03:00.0,sf0", rep_cb, DOCA_ARGP_TYPE_DEVICE_REP);
#endif
	CRASH(doca_argp_start(argc, argv), "doca_argp_start");

#if DOCA_VERSION_MAJOR >= 3
	if (opts.dev == NULL || opts.dev_rep == NULL) {
		DOCA_LOG_CRIT("Specify the SF representor via -r (e.g. -r pci/0000:03:00.0,sf0,dv_flow_en=2)");
		return EXIT_FAILURE;
	}
#endif

	CRASH(steer_start(&opts), "steer_start");

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	DOCA_LOG_INFO("doca_flow_steer running -- Ctrl-C to stop");

	while (g_running) {
		sleep(1);
		steer_poll();
	}

	steer_stop();
	doca_argp_destroy();
	return EXIT_SUCCESS;
}
