#include "perftest_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/*
 * Perftest TCP exchange (ethernet mode, server side):
 * Each ctx_xchg_data: server reads N, then writes N.
 *
 * Sequence:
 * 1. exchange_versions:  16 bytes
 * 2. check_sys_data:     4 bytes (cycle_buffer) + 4 bytes (cache_line_size)
 * 3. negotiate_params:   sizeof(perftest_parameters_negotiate) — platform-dependent
 * 4. check_mtu:          2 bytes
 * 5. ctx_hand_shake:     KEY_MSG_SIZE_GID (108) bytes
 */

#define MAX_VERSION     16
#define KEY_MSG_SIZE_GID 108
#define VERSION_STRING  "6.26"

static int read_full(int fd, void *buf, int len)
{
    int total = 0;
    while (total < len) {
        int r = read(fd, (char *)buf + total, len - total);
        if (r <= 0) return -1;
        total += r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, int len)
{
    int total = 0;
    while (total < len) {
        int w = write(fd, (const char *)buf + total, len - total);
        if (w <= 0) return -1;
        total += w;
    }
    return 0;
}

/* Echo: read N bytes, write same N bytes back */
static int echo_exchange(int fd, int size, const char *label)
{
    char buf[1024];
    if (size > (int)sizeof(buf)) {
        fprintf(stderr, "perftest_compat: %s too large (%d)\n", label, size);
        return -1;
    }
    if (read_full(fd, buf, size) < 0) {
        fprintf(stderr, "perftest_compat: %s read failed\n", label);
        return -1;
    }
    if (write_full(fd, buf, size) < 0) {
        fprintf(stderr, "perftest_compat: %s write failed\n", label);
        return -1;
    }
    printf("perftest_compat: %s OK (%d bytes)\n", label, size);
    return 0;
}

static int encode_key(char *buf, const struct perftest_dest *d)
{
    return sprintf(buf,
        "%04x:%04x:%06x:%06x:%08x:%016llx:"
        "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
        "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%08x:",
        d->lid, d->out_reads, d->qpn, d->psn, d->rkey,
        (unsigned long long)d->vaddr,
        d->gid[0],  d->gid[1],  d->gid[2],  d->gid[3],
        d->gid[4],  d->gid[5],  d->gid[6],  d->gid[7],
        d->gid[8],  d->gid[9],  d->gid[10], d->gid[11],
        d->gid[12], d->gid[13], d->gid[14], d->gid[15],
        d->srqn);
}

static int decode_key(const char *buf, struct perftest_dest *d)
{
    unsigned int gid[16];
    unsigned long long vaddr;
    int n = sscanf(buf,
        "%x:%x:%x:%x:%x:%llx:"
        "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
        "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%x:",
        &d->lid, &d->out_reads, &d->qpn, &d->psn, &d->rkey, &vaddr,
        &gid[0],  &gid[1],  &gid[2],  &gid[3],
        &gid[4],  &gid[5],  &gid[6],  &gid[7],
        &gid[8],  &gid[9],  &gid[10], &gid[11],
        &gid[12], &gid[13], &gid[14], &gid[15],
        &d->srqn);
    d->vaddr = vaddr;
    for (int i = 0; i < 16; i++)
        d->gid[i] = (uint8_t)gid[i];
    return (n == 23) ? 0 : -1;
}

static int g_sock = -1;

int perftest_server_exchange(int port,
                             struct perftest_dest *my_dest,
                             struct perftest_dest *rem_dest)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_fd); return -1;
    }
    listen(listen_fd, 1);
    printf("perftest_compat: listening on port %d, waiting for client...\n", port);

    int fd = accept(listen_fd, NULL, NULL);
    close(listen_fd);
    if (fd < 0) { perror("accept"); return -1; }

    /* Disable Nagle for cleaner exchanges */
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    printf("perftest_compat: client connected\n");

    /* Step 1: exchange_versions (16 bytes) */
    {
        char ver_in[MAX_VERSION] = {0};
        char ver_out[MAX_VERSION] = {0};
        if (read_full(fd, ver_in, MAX_VERSION) < 0) {
            fprintf(stderr, "perftest_compat: version read failed\n");
            goto fail;
        }
        printf("perftest_compat: client version: %s\n", ver_in);
        snprintf(ver_out, MAX_VERSION, "%s", VERSION_STRING);
        if (write_full(fd, ver_out, MAX_VERSION) < 0) goto fail;
    }

    /* Step 2: check_sys_data — 2 exchanges of 4 bytes each */
    if (echo_exchange(fd, 4, "sys_data[cycle_buffer]") < 0) goto fail;
    if (echo_exchange(fd, 4, "sys_data[cache_line]") < 0) goto fail;

    /* Step 3: check_mtu (2 bytes) */
    if (echo_exchange(fd, 2, "mtu") < 0) goto fail;

    /* Step 5: ctx_hand_shake — key exchange (108 bytes) */
    {
        char key_buf[KEY_MSG_SIZE_GID + 1];
        memset(key_buf, 0, sizeof(key_buf));
        if (read_full(fd, key_buf, KEY_MSG_SIZE_GID) < 0) {
            fprintf(stderr, "perftest_compat: key read failed\n");
            goto fail;
        }
        if (decode_key(key_buf, rem_dest) < 0) {
            fprintf(stderr, "perftest_compat: decode failed: %.108s\n", key_buf);
            goto fail;
        }
        printf("perftest_compat: remote QPN=0x%06x PSN=0x%06x RKey=0x%08x\n",
               rem_dest->qpn, rem_dest->psn, rem_dest->rkey);

        memset(key_buf, 0, sizeof(key_buf));
        encode_key(key_buf, my_dest);
        if (write_full(fd, key_buf, KEY_MSG_SIZE_GID) < 0) goto fail;
        printf("perftest_compat: local  QPN=0x%06x PSN=0x%06x\n",
               my_dest->qpn, my_dest->psn);
    }

    printf("perftest_compat: exchange complete\n");
    g_sock = fd;
    return 0;

fail:
    close(fd);
    return -1;
}

int perftest_server_sync(int sock)
{
    (void)sock;
    if (g_sock >= 0) {
        char buf[KEY_MSG_SIZE_GID] = {0};
        read(g_sock, buf, KEY_MSG_SIZE_GID);
        write(g_sock, buf, KEY_MSG_SIZE_GID);
        close(g_sock);
        g_sock = -1;
        printf("perftest_compat: connection closed\n");
    }
    return 0;
}
