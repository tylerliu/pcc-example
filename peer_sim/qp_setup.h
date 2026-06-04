#pragma once
#include <stdint.h>
#include <infiniband/verbs.h>

struct qp_ctx {
    struct ibv_context *ctx;
    struct ibv_pd      *pd;
    struct ibv_cq      *cq;
    struct ibv_qp      *qp;
    struct ibv_mr      *mr;
    void               *buf;
    uint32_t            qpn;
    uint32_t            rkey;
    uint64_t            vaddr;
    uint8_t             gid[16];
    uint8_t             ib_port;
    int                 gid_index;
};

int qp_setup_init(const char *dev_name, uint8_t ib_port, int gid_index,
                  struct qp_ctx *out);

int qp_setup_connect(struct qp_ctx *ctx, uint32_t remote_qpn,
                     const uint8_t remote_gid[16]);

void qp_setup_destroy(struct qp_ctx *ctx);
