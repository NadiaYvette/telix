/* BSD socket API for Telix — routes to uds_srv (AF_UNIX) or net_srv (AF_INET). */
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

static int my_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* IPC helper: send request and receive reply on a temporary port. */
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

int socket(int domain, int type, int protocol) {
    (void)protocol;
    uint32_t srv;
    if (domain == AF_UNIX)
        srv = __telix_uds_port;
    else if (domain == AF_INET)
        srv = __telix_net_port;
    else
        return -1;
    if (srv == 0xFFFFFFFF) return -1;

    struct telix_msg reply;
    int ok = ipc_request(srv, UDS_SOCKET, (uint64_t)(unsigned)type, 0, 0, 0, &reply);
    if (ok != 0 || reply.tag != UDS_OK) return -1;

    uint32_t handle = (uint32_t)reply.data[0];
    return telix_fd_alloc(srv, handle, FD_TYPE_SOCKET, domain);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        int namelen = my_strlen(un->sun_path);
        if (namelen > 16) namelen = 16;
        uint64_t n0, n1;
        pack16((const unsigned char *)un->sun_path, namelen, &n0, &n1);

        struct telix_msg reply;
        int ok = ipc_request(fde->server_port, UDS_BIND,
                             (uint64_t)fde->server_handle, n0,
                             (uint64_t)namelen, n1, &reply);
        if (ok != 0 || reply.tag != UDS_OK) return -1;
        return 0;
    }
    return -1;
}

int listen(int sockfd, int backlog) {
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    struct telix_msg reply;
    int ok = ipc_request(fde->server_port, UDS_LISTEN,
                         (uint64_t)fde->server_handle, (uint64_t)backlog,
                         0, 0, &reply);
    if (ok != 0 || reply.tag != UDS_OK) return -1;
    return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    if (fde->domain == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
        int namelen = my_strlen(un->sun_path);
        if (namelen > 16) namelen = 16;
        uint64_t n0, n1;
        pack16((const unsigned char *)un->sun_path, namelen, &n0, &n1);

        /* Pack pid|(uid<<32) in d3 for SCM_CREDENTIALS. */
        uint64_t pid = __telix_syscall0(SYS_GETPID);
        uint64_t uid = __telix_syscall0(SYS_GETUID);
        uint64_t d3 = (pid & 0xFFFFFFFF) | (uid << 32);

        struct telix_msg reply;
        int ok = ipc_request(fde->server_port, UDS_CONNECT,
                             n0, n1, (uint64_t)namelen, d3, &reply);
        if (ok != 0 || reply.tag != UDS_OK) return -1;

        /* Update handle to the new client-end handle. */
        fde->server_handle = (uint32_t)reply.data[0];
        return 0;
    }
    return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)addr; (void)addrlen;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    struct telix_msg reply;
    int ok = ipc_request(fde->server_port, UDS_ACCEPT,
                         (uint64_t)fde->server_handle, 0, 0, 0, &reply);
    if (ok != 0 || reply.tag != UDS_OK) return -1;

    uint32_t new_handle = (uint32_t)reply.data[0];
    return telix_fd_alloc(fde->server_port, new_handle, FD_TYPE_SOCKET, fde->domain);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    (void)flags;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    const unsigned char *p = (const unsigned char *)buf;
    size_t remaining = len;
    size_t total = 0;

    while (remaining > 0) {
        int chunk = (remaining > 16) ? 16 : (int)remaining;
        uint64_t w0, w1;
        pack16(p, chunk, &w0, &w1);

        struct telix_msg reply;
        int ok = ipc_request(fde->server_port, UDS_SEND,
                             (uint64_t)fde->server_handle, w0,
                             (uint64_t)chunk, w1, &reply);
        if (ok != 0 || reply.tag != UDS_OK) {
            return total > 0 ? (ssize_t)total : -1;
        }
        int written = (int)reply.data[0];
        total += written;
        p += written;
        remaining -= written;
        if (written < chunk) break; /* Buffer full. */
    }
    return (ssize_t)total;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    (void)flags;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    struct telix_msg reply;
    int ok = ipc_request(fde->server_port, UDS_RECV,
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

int shutdown(int sockfd, int how) {
    (void)how;
    struct telix_fd_entry *fde = telix_fd_get(sockfd);
    if (!fde || fde->fd_type != FD_TYPE_SOCKET) return -1;

    struct telix_msg reply;
    ipc_request(fde->server_port, UDS_CLOSE,
                (uint64_t)fde->server_handle, 0, 0, 0, &reply);
    telix_fd_close(sockfd);
    return 0;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return 0; /* Stub. */
}

int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0; /* Stub — no-op. */
}

int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0; /* Stub — no-op. */
}
