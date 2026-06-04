#pragma once
#include <stdint.h>
#include <infiniband/verbs.h>

struct perftest_dest {
    int      lid;
    int      out_reads;
    int      qpn;
    int      psn;
    uint32_t rkey;
    uint64_t vaddr;
    uint8_t  gid[16];
    uint32_t srqn;
};

/*
 * Listen on TCP port, exchange QP info with perftest client.
 * Fills rem_dest with remote side info.
 * Returns 0 on success.
 */
int perftest_server_exchange(int port,
                             struct perftest_dest *my_dest,
                             struct perftest_dest *rem_dest);

/*
 * After test completes, do the final sync (close exchange).
 * sock is the connected socket fd returned internally.
 */
int perftest_server_sync(int sock);
