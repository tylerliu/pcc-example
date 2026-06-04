#include "qp_setup.h"
#include <stdio.h>
#include <string.h>

#define CQ_DEPTH  64

int qp_setup_init(const char *dev_name, uint8_t ib_port, int gid_index,
                  struct qp_ctx *out)
{
    memset(out, 0, sizeof(*out));
    out->ib_port = ib_port;
    out->gid_index = gid_index;

    int num_devs;
    struct ibv_device **devs = ibv_get_device_list(&num_devs);
    if (!devs) { perror("ibv_get_device_list"); return -1; }

    struct ibv_device *dev = NULL;
    for (int i = 0; i < num_devs; i++) {
        if (strcmp(ibv_get_device_name(devs[i]), dev_name) == 0) {
            dev = devs[i];
            break;
        }
    }
    if (!dev) {
        fprintf(stderr, "qp_setup: device '%s' not found\n", dev_name);
        ibv_free_device_list(devs);
        return -1;
    }

    out->ctx = ibv_open_device(dev);
    ibv_free_device_list(devs);
    if (!out->ctx) { perror("ibv_open_device"); return -1; }

    if (ibv_query_gid(out->ctx, ib_port, gid_index, (union ibv_gid *)out->gid)) {
        fprintf(stderr, "qp_setup: ibv_query_gid failed\n");
        goto err_ctx;
    }

    out->pd = ibv_alloc_pd(out->ctx);
    if (!out->pd) { perror("ibv_alloc_pd"); goto err_ctx; }

    out->cq = ibv_create_cq(out->ctx, CQ_DEPTH, NULL, NULL, 0);
    if (!out->cq) { perror("ibv_create_cq"); goto err_pd; }

    /* Allocate buffer and register MR for RDMA WRITE target */
    size_t buf_size = 65536;
    out->buf = malloc(buf_size);
    if (!out->buf) { perror("malloc"); goto err_cq; }
    out->mr = ibv_reg_mr(out->pd, out->buf, buf_size,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                         IBV_ACCESS_REMOTE_READ);
    if (!out->mr) { perror("ibv_reg_mr"); goto err_buf; }
    out->rkey  = out->mr->rkey;
    out->vaddr = (uint64_t)(uintptr_t)out->buf;

    struct ibv_qp_init_attr init = {
        .send_cq = out->cq,
        .recv_cq = out->cq,
        .qp_type = IBV_QPT_RC,
        .cap     = { .max_send_wr=64, .max_recv_wr=64,
                     .max_send_sge=1, .max_recv_sge=1 },
    };
    out->qp = ibv_create_qp(out->pd, &init);
    if (!out->qp) { perror("ibv_create_qp"); goto err_cq; }
    out->qpn = out->qp->qp_num;

    struct ibv_qp_attr attr = {
        .qp_state        = IBV_QPS_INIT,
        .pkey_index      = 0,
        .port_num        = ib_port,
        .qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ,
    };
    if (ibv_modify_qp(out->qp, &attr,
                      IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                      IBV_QP_PORT  | IBV_QP_ACCESS_FLAGS)) {
        perror("ibv_modify_qp INIT"); goto err_qp;
    }

    printf("qp_setup: local QPN=0x%06x GID=%02x%02x:...:%02x%02x\n",
           out->qpn, out->gid[0], out->gid[1], out->gid[14], out->gid[15]);
    return 0;

err_qp:  ibv_destroy_qp(out->qp);
err_cq:  ibv_destroy_cq(out->cq);
err_pd:  ibv_dealloc_pd(out->pd);
err_ctx: ibv_close_device(out->ctx);
    return -1;
}

int qp_setup_connect(struct qp_ctx *ctx, uint32_t remote_qpn,
                     const uint8_t remote_gid[16])
{
    /* INIT -> RTR */
    struct ibv_qp_attr attr = {
        .qp_state           = IBV_QPS_RTR,
        .path_mtu           = IBV_MTU_4096,
        .dest_qp_num        = remote_qpn,
        .rq_psn             = 0,
        .max_dest_rd_atomic = 1,
        .min_rnr_timer      = 12,
        .ah_attr = {
            .is_global  = 1,
            .port_num   = ctx->ib_port,
            .grh        = { .hop_limit=64, .sgid_index=ctx->gid_index },
        },
    };
    memcpy(attr.ah_attr.grh.dgid.raw, remote_gid, 16);

    if (ibv_modify_qp(ctx->qp, &attr,
                      IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                      IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                      IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER)) {
        perror("ibv_modify_qp RTR"); return -1;
    }

    /* RTR -> RTS */
    memset(&attr, 0, sizeof(attr));
    attr.qp_state      = IBV_QPS_RTS;
    attr.timeout       = 14;
    attr.retry_cnt     = 7;
    attr.rnr_retry     = 7;
    attr.sq_psn        = 0;
    attr.max_rd_atomic = 1;

    if (ibv_modify_qp(ctx->qp, &attr,
                      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                      IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC)) {
        perror("ibv_modify_qp RTS"); return -1;
    }

    printf("qp_setup: connected — remote QPN=0x%06x, state=RTS\n", remote_qpn);
    return 0;
}

void qp_setup_destroy(struct qp_ctx *ctx)
{
    if (ctx->qp)  ibv_destroy_qp(ctx->qp);
    if (ctx->cq)  ibv_destroy_cq(ctx->cq);
    if (ctx->pd)  ibv_dealloc_pd(ctx->pd);
    if (ctx->ctx) ibv_close_device(ctx->ctx);
}
