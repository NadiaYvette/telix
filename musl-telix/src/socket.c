/* BSD socket API for Telix - routes to uds_srv (AF_UNIX), net_srv (AF_INET),
 * or ip6_srv (AF_INET6). */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/socket.h>

/* Pack up to 16 bytes into two u64 words (little-endian). */
static void pack16(const unsigned char *buf, int len, uint64_t *w0, uint64_t *w1) {
    *w0 = 0; *w1 = 0;
    if (len > 16) len = 16;
    for (int i = 0; i < len && i < 8; i++)
        *w0 |= (uint64_t)buf[i] << (i * 8);
    for (int i = 8; i < len; i++)
        *w1 |= (uint64_t)buf[i] << ((i - 8) * 8);
}

/* Unpack up to 16 bytes from two u64 words. */
static int unpack16(uint64_t w0, uint64_t w1, unsigned char *buf, int maxlen) {
    int n = maxlen > 16 ? 16 : maxlen;
    for (int i = 0; i < n && i < 8; i++)
        buf[i] = (unsigned char)(w0 >> (i * 8));
    for (int i = 8; i < n; i++)
        buf[i] = (unsigned char)(w1 >> ((i - 8) * 8));
    return n;
}

/* Unpack up to 24 bytes from three u64 words (for TCP recv). */
static int unpack24(uint64_t w0, uint64_t w1, uint64_t w2, unsigned char *buf, int maxlen) {
    int n = maxlen > 24 ? 24 : maxlen;
    for (int i = 0; i < n && i < 8; i++)
        buf[i] = (unsigned char)(w0 >> (i * 8));
    for (int i = 8; i < n && i < 16; i++)
        buf[i] = (unsigned char)(w1 >> ((i - 8) * 8));
    for (int i = 16; i < n; i++)
        buf[i] = (unsigned char)(w2 >> ((i - 16) * 8));
    return n;
}

static int my_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* Pack IPv6 address (16 bytes) into two u64s (little-endian byte order). */
static void pack_ip6(const uint8_t *addr, uint64_t *d0, uint64_t *d1) {
    *d0 = 0; *d1 = 0;
    for (int i = 0; i < 8; i++) *d0 |= (uint64_t)addr[i] << (i * 8);
    for (int i = 0; i < 8; i++) *d1 |= (uint64_t)addr[8 + i] << (i * 8);
}

/* Unpack IPv6 address from two u64s. */
static void unpack_ip6(uint64_t d0, uint64_t d1, uint8_t *addr) {
    for (int i = 0; i < 8; i++) addr[i] = (uint8_t)(d0 >> (i * 8));
    for (int i = 0; i < 8; i++) addr[8 + i] = (uint8_t)(d1 >> (i * 8));
}

/* ntohs: network (big-endian) to host byte order. */
static uint16_t my_ntohs(uint16_t net) {
    return (uint16_t)((net >> 8) | (net << 8));
}

/* IPC helper (call/reply): for servers using sys_call/sys_reply (uds_srv). */
static int ipc_call(uint32_t server_port, uint64_t tag,
                    uint64_t d0, uint64_t d1, uint64_t d2,
                    uint64_t d3, struct telix_msg *reply) {
    return telix_call(server_port, tag, d0, d1, d2, d3, reply);
}

/* IPC helper (fire-and-forget + reply port): reply port in d2 high 32 bits. */
static int ipc_request(uint32_t server_port, uint64_t tag,
                       uint64_t d0, uint64_t d1, uint64_t d2_low,
                       uint64_t d3, struct telix_msg *reply) {
    uint32_t rp = telix_port_create();
    uint64_t d2 = d2_low | ((uint64_t)rp << 32);
    telix_send(server_port, tag, d0, d1, d2, d3);
    int ok = telix_recv_msg(rp, reply);
    telix_port_destroy(rp);
    return ok;
}

/* IPC helper: reply port in d1 high 32 bits. */
static int ipc_request_d1rp(uint32_t server_port, uint64_t tag,
                            uint64_t d0, uint64_t d1_low,
                            uint64_t d2, uint64_t d3,
                            struct telix_msg *reply) {
    uint32_t rp = telix_port_create();
    uint64_t d1 = d1_low | ((uint64_t)rp << 32);
    telix_send(server_port, tag, d0, d1, d2, d3);
    int ok = telix_recv_msg(rp, reply);
    telix_port_destroy(rp);
    return ok;
}

/* ------------------------------------------------------------------ */
/* socket()                                                            */
/* ------------------------------------------------------------------ */

int socket(int domain, int type, int protocol) {
    (void)protocol;
    uint32_t srv;
    if (domain == AF_UNIX)
        srv = __telix_uds_port;
    else if (domain == AF_INET)
        srv = __telix_net_port;
    else if (domain == AF_INET6)
        srv = __telix_ip6_port;
    else
        return -1;
    if (srv == 0xFFFFFFFF) return -1;

    if (domain == AF_INET) {
        int fd = telix_fd_alloc(srv, 0xFFFF, FD_TYPE_SOCKET, AF_INET);
        if (fd >= 0) telix_fd_get(fd)->sock_type = type;
        return fd;
    }

    if (domain == AF_INET6) {
        /* AF_INET6: allocate fd, store sock_type.
         * server_handle = 0xFFFF (unbound) until bind/connect. */
        int fd = telix_fd_alloc(srv, 0xFFFF, FD_TYPE_SOCKET, AF_INET6);
        if (fd >= 0) telix_fd_get(fd)->sock_type = type;
        return fd;
    }

    /* AF_UNIX: call server to create socket. */
    struct telix_msg reply;
    int ok = ipc_call(srv, UDS_SOCKET, (uint64_t)(unsigned)type, 0, 0, 0, &reply);
    if (ok != 0 || reply.tag != UDS_OK) return -1;

    uint32_t handle = (uint32_t)reply.data[0];
    int fd = telix_fd_alloc(srv, handle, FD_TYPE_SOCKET, domain);
    if (fd >= 0) telix_fd_get(fd)->sock_type = type;
    return fd;
}

/* ------------------------------------------------------------------ */
/* bind()                                                              */
/* ------------------------------------------------------------------ */

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint16_t port = my_ntohs(sin->sin_port);
        struct telix_msg reply;
        int ok = ipc_request(fde->server_port, NET_TCP_BIND,
                             (uint64_t)port, 0, 0, 0, &reply);
        if (ok != 0 || reply.tag != NET_TCP_BIND_OK) return -1;
        fde->server_handle = port;
        return 0;
    }

    if (fde->domain == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        uint16_t port = my_ntohs(sin6->sin6_port);

        if (fde->sock_type == SOCK_DGRAM) {
            /* UDP6_BIND: data[0] = port(low16) | reply_port(high48) */
            uint32_t rp = telix_port_create();
            uint64_t d0 = (uint64_t)port | ((uint64_t)rp << 16);
            telix_send(fde->server_port, UDP6_BIND, d0, 0, 0, 0);
            struct telix_msg reply;
            int ok = telix_recv_msg(rp, &reply);
            telix_port_destroy(rp);
            if (ok != 0 || reply.tag != UDP6_BIND_OK) return -1;
            fde->server_handle = (uint32_t)reply.data[0]; /* bind_id */
            return 0;
        }

        /* TCP6_BIND: data[0]=port, data[1]=reply_port<<32 */
        struct telix_msg reply;
        int ok = ipc_request_d1rp(fde->server_port, TCP6_BIND,
                                  (uint64_t)port, 0, 0, 0, &reply);
        if (ok != 0 || reply.tag != TCP6_BIND_OK) return -1;
        fde->server_handle = port;
        return 0;
    }

    if (fde->domain == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        int namelen = my_strlen(un->sun_path);
        if (namelen > 16) namelen = 16;
        uint64_t n0, n1;
        pack16((const unsigned char *)un->sun_path, namelen, &n0, &n1);

        struct telix_msg reply;
        int ok = ipc_call(fde->server_port, UDS_BIND,
                          (uint64_t)fde->server_handle, n0,
                          (uint64_t)namelen, n1, &reply);
        if (ok != 0 || reply.tag != UDS_OK) return -1;
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* listen()                                                            */
/* ------------------------------------------------------------------ */

int listen(int sockfd, int backlog) {
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        uint16_t port = (uint16_t)fde->server_handle;
        struct telix_msg reply;
        int ok = ipc_request(fde->server_port, NET_TCP_LISTEN,
                             (uint64_t)port, (uint64_t)backlog, 0, 0, &reply);
        if (ok != 0 || reply.tag != NET_TCP_LISTEN_OK) return -1;
        return 0;
    }

    if (fde->domain == AF_INET6) {
        /* TCP6_LISTEN: data[0]=port, data[2]=reply_port<<32 */
        uint16_t port = (uint16_t)fde->server_handle;
        uint32_t rp = telix_port_create();
        uint64_t d2 = (uint64_t)rp << 32;
        telix_send(fde->server_port, TCP6_LISTEN, (uint64_t)port, 0, d2, 0);
        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0 || reply.tag != TCP6_LISTEN_OK) return -1;
        return 0;
    }

    struct telix_msg reply;
    int ok = ipc_call(fde->server_port, UDS_LISTEN,
                      (uint64_t)fde->server_handle, (uint64_t)backlog,
                      0, 0, &reply);
    if (ok != 0 || reply.tag != UDS_OK) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* accept()                                                            */
/* ------------------------------------------------------------------ */

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)addr; (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        uint16_t port = (uint16_t)fde->server_handle;
        struct telix_msg reply;
        int ok = ipc_request_d1rp(fde->server_port, NET_TCP_ACCEPT,
                                  (uint64_t)port, 0, 0, 0, &reply);
        if (ok != 0 || reply.tag != NET_TCP_ACCEPT_OK) return -1;
        uint32_t conn_id = (uint32_t)reply.data[0];
        int fd = telix_fd_alloc(fde->server_port, conn_id, FD_TYPE_SOCKET, AF_INET);
        if (fd >= 0) telix_fd_get(fd)->sock_type = SOCK_STREAM;
        return fd;
    }

    if (fde->domain == AF_INET6) {
        /* TCP6_ACCEPT: data[0]=port, data[1]=reply_port<<32 */
        uint16_t port = (uint16_t)fde->server_handle;
        struct telix_msg reply;
        int ok = ipc_request_d1rp(fde->server_port, TCP6_ACCEPT,
                                  (uint64_t)port, 0, 0, 0, &reply);
        if (ok != 0 || reply.tag != TCP6_ACCEPT_OK) return -1;
        uint32_t conn_id = (uint32_t)reply.data[0];
        int fd = telix_fd_alloc(fde->server_port, conn_id, FD_TYPE_SOCKET, AF_INET6);
        if (fd >= 0) telix_fd_get(fd)->sock_type = SOCK_STREAM;
        return fd;
    }

    struct telix_msg reply;
    int ok = ipc_call(fde->server_port, UDS_ACCEPT,
                      (uint64_t)fde->server_handle, 0, 0, 0, &reply);
    if (ok != 0 || reply.tag != UDS_OK) return -1;

    uint32_t new_handle = (uint32_t)reply.data[0];
    int fd = telix_fd_alloc(fde->server_port, new_handle, FD_TYPE_SOCKET, fde->domain);
    if (fd >= 0) telix_fd_get(fd)->sock_type = SOCK_STREAM;
    return fd;
}

/* ------------------------------------------------------------------ */
/* connect()                                                           */
/* ------------------------------------------------------------------ */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t ip_be = sin->sin_addr;
        uint16_t port = my_ntohs(sin->sin_port);

        uint32_t rp = telix_port_create();
        uint64_t d1 = (uint64_t)port | ((uint64_t)rp << 16);
        telix_send(fde->server_port, NET_TCP_CONNECT, (uint64_t)ip_be, d1, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0 || reply.tag != NET_TCP_CONNECTED) return -1;
        fde->server_handle = (uint32_t)reply.data[0];
        return 0;
    }

    if (fde->domain == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        uint16_t port = my_ntohs(sin6->sin6_port);
        uint64_t a0, a1;
        pack_ip6(sin6->sin6_addr, &a0, &a1);

        if (fde->sock_type == SOCK_DGRAM) {
            /* UDP6: "connect" just stores the destination for send(). We don't
             * actually send a connect message to ip6_srv. Store addr info
             * in file_offset/file_size fields (reused for UDP peer addr). */
            fde->file_offset = a0;
            fde->file_size = a1;
            fde->fs_aspace = port; /* Store connected peer port. */
            return 0;
        }

        /* TCP6_CONNECT: data[0..1]=dst_ip6, data[2]=port(low16)|reply_port(high48) */
        uint32_t rp = telix_port_create();
        uint64_t d2 = (uint64_t)port | ((uint64_t)rp << 16);
        telix_send(fde->server_port, TCP6_CONNECT, a0, a1, d2, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0 || reply.tag != TCP6_CONNECTED) return -1;
        fde->server_handle = (uint32_t)reply.data[0];
        return 0;
    }

    if (fde->domain == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        int namelen = my_strlen(un->sun_path);
        if (namelen > 16) namelen = 16;
        uint64_t n0, n1;
        pack16((const unsigned char *)un->sun_path, namelen, &n0, &n1);

        uint64_t pid = __telix_syscall0(SYS_GETPID);
        uint64_t uid = __telix_syscall0(SYS_GETUID);
        uint64_t d3 = (pid & 0xFFFFFFFF) | (uid << 32);

        struct telix_msg reply;
        int ok = ipc_call(fde->server_port, UDS_CONNECT,
                          n0, n1, (uint64_t)namelen, d3, &reply);
        if (ok != 0 || reply.tag != UDS_OK) return -1;
        fde->server_handle = (uint32_t)reply.data[0];
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* send()                                                              */
/* ------------------------------------------------------------------ */

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    (void)flags;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        const unsigned char *p = (const unsigned char *)buf;
        size_t remaining = len;
        size_t total = 0;

        while (remaining > 0) {
            int chunk = (remaining > 16) ? 16 : (int)remaining;
            uint64_t w0 = 0, w1 = 0;
            pack16(p, chunk, &w0, &w1);

            uint32_t rp = telix_port_create();
            uint64_t d0 = (uint64_t)fde->server_handle;
            uint64_t d1 = (uint64_t)chunk | ((uint64_t)rp << 16);
            telix_send(fde->server_port, NET_TCP_SEND, d0, d1, w0, w1);

            struct telix_msg reply;
            int ok = telix_recv_msg(rp, &reply);
            telix_port_destroy(rp);

            if (ok != 0 || reply.tag != NET_TCP_SEND_OK) {
                return total > 0 ? (ssize_t)total : -1;
            }
            total += chunk;
            p += chunk;
            remaining -= chunk;
        }
        return (ssize_t)total;
    }

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_STREAM) {
        /* TCP6_SEND: chunks data 16 bytes at a time. */
        const unsigned char *p = (const unsigned char *)buf;
        size_t remaining = len;
        size_t total = 0;

        while (remaining > 0) {
            int chunk = (remaining > 16) ? 16 : (int)remaining;
            uint64_t w0 = 0, w1 = 0;
            pack16(p, chunk, &w0, &w1);

            uint32_t rp = telix_port_create();
            uint64_t d0 = (uint64_t)fde->server_handle;
            uint64_t d1 = (uint64_t)chunk | ((uint64_t)rp << 16);
            telix_send(fde->server_port, TCP6_SEND, d0, d1, w0, w1);

            struct telix_msg reply;
            int ok = telix_recv_msg(rp, &reply);
            telix_port_destroy(rp);

            if (ok != 0 || reply.tag != TCP6_SEND_OK) {
                return total > 0 ? (ssize_t)total : -1;
            }
            total += chunk;
            p += chunk;
            remaining -= chunk;
        }
        return (ssize_t)total;
    }

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_DGRAM) {
        /* Connected UDP6: send to the stored peer address.
         * UDP6_SEND: data[0..1]=dst_ip6, data[2]=port|bind_id|rp, data[3]=len|payload */
        uint64_t a0 = fde->file_offset;  /* Peer IPv6 low */
        uint64_t a1 = fde->file_size;    /* Peer IPv6 high */
        uint16_t port = (uint16_t)fde->fs_aspace; /* Peer port */
        uint32_t bind_id = fde->server_handle;

        const unsigned char *p = (const unsigned char *)buf;
        int chunk = (len > 7) ? 7 : (int)len;

        uint32_t rp = telix_port_create();
        uint64_t d2 = (uint64_t)port | ((uint64_t)(bind_id & 0xFFFF) << 16) | ((uint64_t)rp << 32);
        uint64_t d3 = (uint64_t)chunk;
        for (int i = 0; i < chunk; i++)
            d3 |= (uint64_t)p[i] << ((i + 1) * 8);

        telix_send(fde->server_port, UDP6_SEND, a0, a1, d2, d3);
        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0 || reply.tag != UDP6_SEND_OK) return -1;
        return (ssize_t)chunk;
    }

    /* AF_UNIX path. */
    const unsigned char *p = (const unsigned char *)buf;
    size_t remaining = len;
    size_t total = 0;

    while (remaining > 0) {
        int chunk = (remaining > 16) ? 16 : (int)remaining;
        uint64_t w0, w1;
        pack16(p, chunk, &w0, &w1);

        struct telix_msg reply;
        int ok = ipc_call(fde->server_port, UDS_SEND,
                          (uint64_t)fde->server_handle, w0,
                          (uint64_t)chunk, w1, &reply);
        if (ok != 0 || reply.tag != UDS_OK) {
            return total > 0 ? (ssize_t)total : -1;
        }
        int written = (int)reply.data[0];
        total += written;
        p += written;
        remaining -= written;
        if (written < chunk) break;
    }
    return (ssize_t)total;
}

/* ------------------------------------------------------------------ */
/* recv()                                                              */
/* ------------------------------------------------------------------ */

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    (void)flags;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        uint32_t rp = telix_port_create();
        uint64_t d0 = (uint64_t)fde->server_handle;
        uint64_t d1 = ((uint64_t)rp << 16);
        telix_send(fde->server_port, NET_TCP_RECV, d0, d1, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0) return -1;
        if (reply.tag == NET_TCP_CLOSED) return 0;
        if (reply.tag != NET_TCP_DATA) return -1;

        int n = (int)reply.data[0];
        if (n > 24) n = 24;
        if (n > (int)len) n = (int)len;
        unpack24(reply.data[1], reply.data[2], reply.data[3],
                 (unsigned char *)buf, n);
        return (ssize_t)n;
    }

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_STREAM) {
        /* TCP6_RECV: data[0]=conn_id, data[1]=reply_port<<16 */
        uint32_t rp = telix_port_create();
        uint64_t d0 = (uint64_t)fde->server_handle;
        uint64_t d1 = ((uint64_t)rp << 16);
        telix_send(fde->server_port, TCP6_RECV, d0, d1, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0) return -1;
        if (reply.tag == TCP6_CLOSED) return 0;
        if (reply.tag != TCP6_DATA) return -1;

        int n = (int)reply.data[0];
        if (n > 16) n = 16;
        if (n > (int)len) n = (int)len;
        unpack16(reply.data[1], reply.data[2], (unsigned char *)buf, n);
        return (ssize_t)n;
    }

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_DGRAM) {
        /* UDP6_RECV: data[0]=bind_id|reply_port<<32 */
        uint32_t rp = telix_port_create();
        uint64_t d0 = (uint64_t)fde->server_handle | ((uint64_t)rp << 32);
        telix_send(fde->server_port, UDP6_RECV, d0, 0, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0) return -1;
        if (reply.tag == UDP6_RECV_NONE) return 0;
        if (reply.tag != UDP6_DATA6) return -1;

        /* UDP6_DATA: data[0]=plen|(src_port<<16), data[1..2]=src_ip, data[3]=payload */
        int plen = (int)(reply.data[0] & 0xFFFF);
        if (plen > 8) plen = 8;
        if (plen > (int)len) plen = (int)len;
        uint64_t payload = reply.data[3];
        unsigned char *dst = (unsigned char *)buf;
        for (int i = 0; i < plen; i++)
            dst[i] = (unsigned char)(payload >> (i * 8));
        return (ssize_t)plen;
    }

    /* AF_UNIX path. */
    struct telix_msg reply;
    int ok = ipc_call(fde->server_port, UDS_RECV,
                      (uint64_t)fde->server_handle, 0, 0, 0, &reply);
    if (ok != 0) return -1;
    if (reply.tag == UDS_EOF) return 0;
    if (reply.tag != UDS_OK) return -1;

    int n = (int)reply.data[2];
    if (n > 16) n = 16;
    if (n > (int)len) n = (int)len;
    unpack16(reply.data[0], reply.data[1], (unsigned char *)buf, n);
    return (ssize_t)n;
}

/* ------------------------------------------------------------------ */
/* sendto() — primarily for SOCK_DGRAM (UDP)                          */
/* ------------------------------------------------------------------ */

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    (void)flags; (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    /* For SOCK_STREAM, sendto with NULL dest_addr is equivalent to send(). */
    if (fde->sock_type == SOCK_STREAM || dest_addr == 0)
        return send(sockfd, buf, len, flags);

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_DGRAM) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)dest_addr;
        uint16_t port = my_ntohs(sin6->sin6_port);
        uint64_t a0, a1;
        pack_ip6(sin6->sin6_addr, &a0, &a1);

        uint32_t bind_id = fde->server_handle;
        const unsigned char *p = (const unsigned char *)buf;
        int chunk = (len > 7) ? 7 : (int)len;

        uint32_t rp = telix_port_create();
        uint64_t d2 = (uint64_t)port | ((uint64_t)(bind_id & 0xFFFF) << 16) | ((uint64_t)rp << 32);
        uint64_t d3 = (uint64_t)chunk;
        for (int i = 0; i < chunk; i++)
            d3 |= (uint64_t)p[i] << ((i + 1) * 8);

        telix_send(fde->server_port, UDP6_SEND, a0, a1, d2, d3);
        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0 || reply.tag != UDP6_SEND_OK) return -1;
        return (ssize_t)chunk;
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/* recvfrom() — primarily for SOCK_DGRAM (UDP)                        */
/* ------------------------------------------------------------------ */

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    (void)flags;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    /* For SOCK_STREAM or when src_addr is NULL, fall back to recv(). */
    if (fde->sock_type == SOCK_STREAM)
        return recv(sockfd, buf, len, flags);

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_DGRAM) {
        /* UDP6_RECV: data[0]=bind_id|reply_port<<32 */
        uint32_t rp = telix_port_create();
        uint64_t d0 = (uint64_t)fde->server_handle | ((uint64_t)rp << 32);
        telix_send(fde->server_port, UDP6_RECV, d0, 0, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0) return -1;
        if (reply.tag == UDP6_RECV_NONE) return 0;
        if (reply.tag != UDP6_DATA6) return -1;

        /* UDP6_DATA: data[0]=plen|(src_port<<16), data[1..2]=src_ip6, data[3]=payload */
        int plen = (int)(reply.data[0] & 0xFFFF);
        uint16_t src_port = (uint16_t)(reply.data[0] >> 16);
        if (plen > 8) plen = 8;
        if (plen > (int)len) plen = (int)len;

        uint64_t payload = reply.data[3];
        unsigned char *dst = (unsigned char *)buf;
        for (int i = 0; i < plen; i++)
            dst[i] = (unsigned char)(payload >> (i * 8));

        /* Fill in source address if requested. */
        if (src_addr && addrlen && *addrlen >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src_addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = my_ntohs(src_port); /* Store as network byte order */
            sin6->sin6_flowinfo = 0;
            unpack_ip6(reply.data[1], reply.data[2], sin6->sin6_addr);
            sin6->sin6_scope_id = 0;
            *addrlen = sizeof(struct sockaddr_in6);
        }
        return (ssize_t)plen;
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/* recv_nb() — non-blocking TCP recv (internal extension)             */
/* ------------------------------------------------------------------ */

ssize_t recv_nb(int sockfd, void *buf, size_t len) {
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        uint32_t rp = telix_port_create();
        uint64_t d0 = (uint64_t)fde->server_handle;
        uint64_t d1 = ((uint64_t)rp << 16);
        telix_send(fde->server_port, NET_TCP_RECV_NB, d0, d1, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0) return -1;
        if (reply.tag == NET_TCP_CLOSED) return 0;
        if (reply.tag == NET_TCP_RECV_NONE) return -2;
        if (reply.tag != NET_TCP_DATA) return -1;

        int n = (int)reply.data[0];
        if (n > 24) n = 24;
        if (n > (int)len) n = (int)len;
        unpack24(reply.data[1], reply.data[2], reply.data[3],
                 (unsigned char *)buf, n);
        return (ssize_t)n;
    }

    if (fde->domain == AF_INET6 && fde->sock_type == SOCK_STREAM) {
        uint32_t rp = telix_port_create();
        uint64_t d0 = (uint64_t)fde->server_handle;
        uint64_t d1 = ((uint64_t)rp << 16);
        telix_send(fde->server_port, TCP6_RECV_NB, d0, d1, 0, 0);

        struct telix_msg reply;
        int ok = telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        if (ok != 0) return -1;
        if (reply.tag == TCP6_CLOSED) return 0;
        if (reply.tag == TCP6_RECV_NONE) return -2;
        if (reply.tag != TCP6_DATA) return -1;

        int n = (int)reply.data[0];
        if (n > 16) n = 16;
        if (n > (int)len) n = (int)len;
        unpack16(reply.data[1], reply.data[2], (unsigned char *)buf, n);
        return (ssize_t)n;
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/* shutdown() / close()                                                */
/* ------------------------------------------------------------------ */

int shutdown(int sockfd, int how) {
    (void)how;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_INET) {
        uint32_t rp = telix_port_create();
        telix_send(fde->server_port, NET_TCP_CLOSE,
                   (uint64_t)fde->server_handle, (uint64_t)rp, 0, 0);
        struct telix_msg reply;
        telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        telix_fd_close(sockfd);
        return 0;
    }

    if (fde->domain == AF_INET6) {
        uint32_t rp = telix_port_create();
        if (fde->sock_type == SOCK_DGRAM) {
            /* UDP6_CLOSE: data[0]=bind_id|reply_port<<32 */
            uint64_t d0 = (uint64_t)fde->server_handle | ((uint64_t)rp << 32);
            telix_send(fde->server_port, UDP6_CLOSE, d0, 0, 0, 0);
        } else {
            /* TCP6_CLOSE: data[0]=conn_id, data[1]=reply_port */
            telix_send(fde->server_port, TCP6_CLOSE,
                       (uint64_t)fde->server_handle, (uint64_t)rp, 0, 0);
        }
        struct telix_msg reply;
        telix_recv_msg(rp, &reply);
        telix_port_destroy(rp);
        telix_fd_close(sockfd);
        return 0;
    }

    struct telix_msg reply;
    ipc_call(fde->server_port, UDS_CLOSE,
             (uint64_t)fde->server_handle, 0, 0, 0, &reply);
    telix_fd_close(sockfd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Stubs                                                               */
/* ------------------------------------------------------------------ */

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return 0; /* Stub. */
}

int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0; /* Stub - no-op. */
}

int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0; /* Stub - no-op. */
}
