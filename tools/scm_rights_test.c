/* Wayland compositor port Step 1: SCM_RIGHTS + memfd round-trip test.
 *
 * Per docs/wayland-compositor-port-plan.md §4 priority 1: validates the
 * most critical compositor-bridge ABI before the wlroots/cage build chain.
 * Every wl_shm buffer transfer between a Wayland client and compositor
 * rides on:
 *   1. memfd_create + ftruncate (compositor's shared buffer)
 *   2. mmap MAP_SHARED on both sides (sender writes, receiver reads)
 *   3. sendmsg(SCM_RIGHTS) to pass the memfd over a UDS
 *   4. recvmsg on the peer to receive the fd
 *
 * This test exercises that full round-trip with a known byte pattern.
 * If [scm_rights] PASS prints, the linux_srv handlers at
 * linux_srv.rs:10248 (sendmsg SCM_RIGHTS) and ~10480 (recvmsg) are
 * functional and the compositor port is unblocked on this front.
 *
 * Pattern: writer fills 4096 bytes with the sequence (i & 0xFF) for i in
 * 0..4096; reader verifies every byte after mmap MAP_SHARED of the
 * received fd.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define BUFSZ 4096

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n > 0) {
        ssize_t r = write(fd, p, n);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

/* memfd_create wrapper — glibc may not have it in older headers. */
static int memfd_create_compat(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

/* Send fd_to_send over `sock` using SCM_RIGHTS. */
static int send_fd(int sock, int fd_to_send) {
    char placeholder = 'F';
    struct iovec iov = { .iov_base = &placeholder, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_u;
    memset(&cmsg_u, 0, sizeof(cmsg_u));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_u.buf,
        .msg_controllen = sizeof(cmsg_u.buf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    ssize_t r = sendmsg(sock, &msg, 0);
    return r < 0 ? -1 : 0;
}

/* Receive an fd from `sock`. */
static int recv_fd(int sock) {
    char placeholder = 0;
    struct iovec iov = { .iov_base = &placeholder, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_u;
    memset(&cmsg_u, 0, sizeof(cmsg_u));

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_u.buf,
        .msg_controllen = sizeof(cmsg_u.buf),
    };
    ssize_t r = recvmsg(sock, &msg, 0);
    if (r < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET
              || cmsg->cmsg_type != SCM_RIGHTS) {
        return -2;
    }
    int recv_fd;
    memcpy(&recv_fd, CMSG_DATA(cmsg), sizeof(int));
    return recv_fd;
}

static const char *fail_with(const char *step) {
    char m[128];
    int n = snprintf(m, sizeof(m), "[scm_rights] FAIL at %s (errno=%d)\n",
                     step, (int)errno);
    write(1, m, (size_t)n);
    return step;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    const char start[] = "[scm_rights] start\n";
    write(1, start, sizeof(start) - 1);

    /* Step A: create memfd, size it, fill with pattern. */
    int memfd = memfd_create_compat("scm_test", 0);
    if (memfd < 0) { fail_with("memfd_create"); return 1; }
    if (ftruncate(memfd, BUFSZ) < 0) { fail_with("ftruncate"); return 1; }

    /* Map MAP_SHARED on the writer side and stamp the pattern. */
    void *wmap = mmap(NULL, BUFSZ, PROT_READ | PROT_WRITE,
                      MAP_SHARED, memfd, 0);
    if (wmap == MAP_FAILED) { fail_with("mmap-writer"); return 1; }
    uint8_t *wbytes = wmap;
    for (size_t i = 0; i < BUFSZ; i++) wbytes[i] = (uint8_t)(i & 0xFF);

    /* Step B: socketpair for SCM_RIGHTS. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fail_with("socketpair"); return 1;
    }

    /* Step C: send memfd via SCM_RIGHTS on sv[0]. */
    if (send_fd(sv[0], memfd) < 0) { fail_with("send_fd"); return 1; }

    /* Step D: recv fd on sv[1]. */
    int rxfd = recv_fd(sv[1]);
    if (rxfd < 0) { fail_with("recv_fd"); return 1; }

    /* Step E: mmap the RECEIVED fd MAP_SHARED, verify pattern. */
    void *rmap = mmap(NULL, BUFSZ, PROT_READ, MAP_SHARED, rxfd, 0);
    if (rmap == MAP_FAILED) { fail_with("mmap-reader"); return 1; }
    const uint8_t *rbytes = rmap;
    for (size_t i = 0; i < BUFSZ; i++) {
        if (rbytes[i] != (uint8_t)(i & 0xFF)) {
            char m[160];
            int n = snprintf(m, sizeof(m),
                "[scm_rights] FAIL pattern mismatch at offset %zu: got 0x%02x want 0x%02x\n",
                i, rbytes[i], (uint8_t)(i & 0xFF));
            write(1, m, (size_t)n);
            return 1;
        }
    }

    /* Step F: writer modifies pattern; reader observes new pattern
     * (sanity check that MAP_SHARED is genuinely shared, not COW). */
    wbytes[0] = 0xAA;
    wbytes[BUFSZ - 1] = 0x55;
    if (rbytes[0] != 0xAA || rbytes[BUFSZ - 1] != 0x55) {
        const char m[] = "[scm_rights] FAIL MAP_SHARED not shared (write not visible to peer)\n";
        write(1, m, sizeof(m) - 1);
        return 1;
    }

    /* Cleanup */
    munmap(wmap, BUFSZ);
    munmap(rmap, BUFSZ);
    close(memfd);
    close(rxfd);
    close(sv[0]);
    close(sv[1]);

    const char done[] = "[scm_rights] PASS\n";
    write(1, done, sizeof(done) - 1);
    return 0;
}
