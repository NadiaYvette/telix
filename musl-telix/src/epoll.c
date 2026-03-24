/* epoll implementation for Telix — built on port sets.
 *
 * Each epoll instance is a port_set. epoll_ctl(ADD) sends a POLL_SUBSCRIBE
 * message to the fd's server, which sends notifications to a per-fd port
 * that is added to the port set. epoll_wait uses port_set_recv_timeout.
 */
#include <sys/epoll.h>
#include <telix/syscall.h>
#include <telix/fd.h>
#include <telix/ipc.h>
#include <string.h>

#define MAX_EPOLL_INSTANCES 8
#define MAX_EPOLL_FDS 16

struct epoll_fd_entry {
    int fd;
    uint32_t notify_port;
    uint32_t events;
    epoll_data_t data;
    int active;
};

struct epoll_instance {
    int active;
    uint32_t port_set;
    int fd_num;  /* FD table slot for this epoll instance */
    struct epoll_fd_entry fds[MAX_EPOLL_FDS];
};

static struct epoll_instance epoll_instances[MAX_EPOLL_INSTANCES];

/* POLL_SUBSCRIBE tag sent to servers (pipe_srv, event_srv). */
#define POLL_SUBSCRIBE   0xF010
#define POLL_UNSUBSCRIBE 0xF020
#define POLL_NOTIFY      0xF030

#define FD_TYPE_EPOLL 5

int epoll_create(int size) {
    (void)size;
    return epoll_create1(0);
}

int epoll_create1(int flags) {
    (void)flags;

    /* Find free instance. */
    int idx = -1;
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!epoll_instances[i].active) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return -1;

    uint64_t ps = __telix_syscall0(SYS_PORT_SET_CREATE);
    if (ps == (uint64_t)-1) return -1;

    epoll_instances[idx].active = 1;
    epoll_instances[idx].port_set = (uint32_t)ps;
    memset(epoll_instances[idx].fds, 0, sizeof(epoll_instances[idx].fds));

    /* Allocate FD for this epoll instance. */
    int efd = telix_fd_alloc((uint32_t)ps, (uint32_t)idx, FD_TYPE_EPOLL, 0);
    if (efd < 0) {
        epoll_instances[idx].active = 0;
        return -1;
    }
    epoll_instances[idx].fd_num = efd;
    return efd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    /* Look up epoll instance from fd. */
    struct telix_fd_entry *fde = telix_fd_get(epfd);
    if (!fde || fde->fd_type != FD_TYPE_EPOLL) return -1;
    uint32_t handle = fde->server_handle;
    if (handle >= MAX_EPOLL_INSTANCES) return -1;
    struct epoll_instance *inst = &epoll_instances[handle];
    if (!inst->active) return -1;

    if (op == EPOLL_CTL_ADD) {
        /* Find free slot. */
        int slot = -1;
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (!inst->fds[i].active) { slot = i; break; }
        }
        if (slot < 0) return -1;

        /* Create a notify port and add it to the port set. */
        uint32_t np = (uint32_t)__telix_syscall0(SYS_PORT_CREATE);
        __telix_syscall2(SYS_PORT_SET_ADD, (uint64_t)inst->port_set, (uint64_t)np);

        /* Send POLL_SUBSCRIBE to the fd's server. */
        struct telix_fd_entry *target_fde = telix_fd_get(fd);
        if (target_fde) {
            telix_send(target_fde->server_port, POLL_SUBSCRIBE,
                       (uint64_t)target_fde->server_handle, (uint64_t)np,
                       event ? event->events : (uint32_t)EPOLLIN, 0);
        }

        inst->fds[slot].fd = fd;
        inst->fds[slot].notify_port = np;
        inst->fds[slot].events = event ? event->events : (uint32_t)EPOLLIN;
        inst->fds[slot].data = event ? event->data : (epoll_data_t){.fd = fd};
        inst->fds[slot].active = 1;
    } else if (op == EPOLL_CTL_DEL) {
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (inst->fds[i].active && inst->fds[i].fd == fd) {
                struct telix_fd_entry *target_fde = telix_fd_get(fd);
                if (target_fde) {
                    telix_send(target_fde->server_port, POLL_UNSUBSCRIBE,
                               (uint64_t)target_fde->server_handle,
                               (uint64_t)inst->fds[i].notify_port, 0, 0);
                }
                __telix_syscall1(SYS_PORT_DESTROY, (uint64_t)inst->fds[i].notify_port);
                inst->fds[i].active = 0;
                break;
            }
        }
    }
    return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    struct telix_fd_entry *fde = telix_fd_get(epfd);
    if (!fde || fde->fd_type != FD_TYPE_EPOLL) return -1;
    uint32_t handle = fde->server_handle;
    if (handle >= MAX_EPOLL_INSTANCES) return -1;
    struct epoll_instance *inst = &epoll_instances[handle];
    if (!inst->active) return -1;

    int count = 0;
    uint64_t timeout_us = (timeout < 0) ? 0xFFFFFFFFFFFFFFFFULL : (uint64_t)timeout * 1000;

    /* Use port_set_recv_timeout. */
    while (count < maxevents) {
        uint64_t result = __telix_syscall2(SYS_PORT_SET_RECV_TIMEOUT,
            (uint64_t)inst->port_set, timeout_us);

        if (result == (uint64_t)-1) break; /* timeout */

        /* result encodes the port that received the notification. */
        uint32_t src_port = (uint32_t)result;

        /* Find which fd this notification is for. */
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (inst->fds[i].active && inst->fds[i].notify_port == src_port) {
                events[count].events = EPOLLIN;
                events[count].data = inst->fds[i].data;
                count++;
                break;
            }
        }
        /* After first event, don't wait again — poll for more. */
        timeout_us = 0;
    }
    return count;
}
