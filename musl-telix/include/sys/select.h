#ifndef SYS_SELECT_H
#define SYS_SELECT_H

#include <telix/types.h>

#define FD_SETSIZE 64

/* Bits per word. */
#define __NFDBITS (8 * (int)sizeof(unsigned long))

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / __NFDBITS];
} fd_set;

#define FD_ZERO(set) \
    do { \
        unsigned long *__p = (set)->fds_bits; \
        for (int __i = 0; __i < FD_SETSIZE / __NFDBITS; __i++) \
            __p[__i] = 0; \
    } while (0)

#define FD_SET(fd, set) \
    ((set)->fds_bits[(fd) / __NFDBITS] |= (1UL << ((fd) % __NFDBITS)))

#define FD_CLR(fd, set) \
    ((set)->fds_bits[(fd) / __NFDBITS] &= ~(1UL << ((fd) % __NFDBITS)))

#define FD_ISSET(fd, set) \
    (((set)->fds_bits[(fd) / __NFDBITS] & (1UL << ((fd) % __NFDBITS))) != 0)

struct timeval {
    long tv_sec;
    long tv_usec;
};

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout);

#endif
