/* GHC RTS shim: I/O Manager for Telix.
 *
 * Uses epoll (Phase 75) for async I/O event notification.
 * GHC's threaded RTS polls for I/O events between scheduler cycles.
 */
#include <sys/epoll.h>
#include <stdint.h>

static int epoll_fd = -1;

void ioManagerStart(void) {
    epoll_fd = epoll_create1(0);
}

void ioManagerStop(void) {
    /* Close epoll fd — cleanup. */
    epoll_fd = -1;
}

int ioManagerAddFd(int fd, uint32_t events) {
    if (epoll_fd < 0) return -1;
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

int ioManagerPoll(struct epoll_event *events, int maxevents, int timeout_ms) {
    if (epoll_fd < 0) return 0;
    return epoll_wait(epoll_fd, events, maxevents, timeout_ms);
}
