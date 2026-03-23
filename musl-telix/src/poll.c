/* POSIX-like poll() for Telix — queries each FD's server for readiness. */
#include <telix/poll.h>
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>

/* Server poll tags. */
#define PIPE_POLL_TAG   0x5050
#define UDS_POLL_TAG    0x8090
#define CON_POLL_TAG    0x3110
#define PIPE_OK_TAG2    0x5100
#define UDS_OK_TAG2     0x8100
#define CON_POLL_OK_TAG 0x3111

static inline uint64_t get_cycles(void) {
    return __telix_syscall0(SYS_GET_CYCLES);
}
static inline uint64_t get_timer_freq(void) {
    return __telix_syscall0(SYS_GET_TIMER_FREQ);
}
static inline void yield_now(void) {
    __telix_syscall0(SYS_YIELD);
}

static short poll_check_fd(struct telix_fd_entry *fde, short events) {
    if (fde->fd_type == FD_TYPE_CONSOLE) {
        short rev = 0;
        if (events & POLLOUT) rev |= POLLOUT;
        return rev;
    }

    if (fde->fd_type == FD_TYPE_FILE) {
        short rev = 0;
        if (events & POLLIN)  rev |= POLLIN;
        if (events & POLLOUT) rev |= POLLOUT;
        return rev;
    }

    if (fde->fd_type == FD_TYPE_PIPE) {
        uint32_t rp = telix_port_create();
        uint64_t d2 = (uint64_t)((unsigned short)events) | ((uint64_t)rp << 32);
        telix_send(fde->server_port, PIPE_POLL_TAG,
                   (uint64_t)fde->server_handle, 0, d2, 0);
        struct telix_msg msg;
        short rev = POLLERR;
        if (telix_recv_msg(rp, &msg) == 0 && msg.tag == PIPE_OK_TAG2) {
            rev = (short)(msg.data[0] & 0xFFFF);
        }
        telix_port_destroy(rp);
        return rev;
    }

    if (fde->fd_type == FD_TYPE_SOCKET) {
        uint32_t rp = telix_port_create();
        uint64_t d2 = (uint64_t)((unsigned short)events) | ((uint64_t)rp << 32);
        telix_send(fde->server_port, UDS_POLL_TAG,
                   (uint64_t)fde->server_handle, 0, d2, 0);
        struct telix_msg msg;
        short rev = POLLERR;
        if (telix_recv_msg(rp, &msg) == 0 && msg.tag == UDS_OK_TAG2) {
            rev = (short)(msg.data[0] & 0xFFFF);
        }
        telix_port_destroy(rp);
        return rev;
    }

    return 0;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    uint64_t start = get_cycles();
    uint64_t freq  = get_timer_freq();
    uint64_t timeout_cycles = 0;
    if (timeout > 0) {
        timeout_cycles = (uint64_t)timeout * freq / 1000;
    }

    for (;;) {
        int ready = 0;
        for (nfds_t i = 0; i < nfds; i++) {
            fds[i].revents = 0;
            struct telix_fd_entry *fde = telix_fd_get(fds[i].fd);
            if (!fde) {
                fds[i].revents = POLLNVAL;
                ready++;
                continue;
            }
            short rev = poll_check_fd(fde, fds[i].events);
            fds[i].revents = rev & (fds[i].events | POLLERR | POLLHUP | POLLNVAL);
            if (fds[i].revents)
                ready++;
        }

        if (ready > 0 || timeout == 0)
            return ready;

        if (timeout > 0) {
            uint64_t elapsed = get_cycles() - start;
            if (elapsed >= timeout_cycles)
                return 0;
        }

        yield_now();
    }
}
