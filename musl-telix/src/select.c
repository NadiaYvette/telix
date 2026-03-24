/* select() for Telix — simple "all ready" implementation. */
#include <sys/select.h>
#include <telix/fd.h>

/*
 * Minimal select implementation: returns immediately with all requested fds
 * marked as ready.  This is valid POSIX behaviour (spurious wakeup model)
 * and allows programs that use select() to compile and link without
 * requiring full epoll/poll integration through the C library.
 */
int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout) {
    (void)timeout;

    int count = 0;

    for (int fd = 0; fd < nfds && fd < FD_SETSIZE; fd++) {
        struct telix_fd_entry *fde = telix_fd_get(fd);
        int active = (fde != NULL);

        if (readfds && FD_ISSET(fd, readfds)) {
            if (active)
                count++;
            else
                FD_CLR(fd, readfds);
        }
        if (writefds && FD_ISSET(fd, writefds)) {
            if (active)
                count++;
            else
                FD_CLR(fd, writefds);
        }
        if (exceptfds) {
            /* No exceptional conditions — always clear. */
            FD_CLR(fd, exceptfds);
        }
    }

    return count;
}
