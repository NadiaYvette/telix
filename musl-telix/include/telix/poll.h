/* POSIX-like poll() for Telix. */
#ifndef TELIX_POLL_H
#define TELIX_POLL_H

#define POLLIN   0x0001
#define POLLPRI  0x0002
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020

struct pollfd {
    int   fd;
    short events;
    short revents;
};

typedef unsigned int nfds_t;

/* Poll an array of file descriptors for readiness.
 * timeout: -1 = block forever, 0 = non-blocking, >0 = timeout in ms.
 * Returns number of FDs with non-zero revents, or 0 on timeout. */
int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif /* TELIX_POLL_H */
