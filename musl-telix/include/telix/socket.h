/* BSD socket API definitions for Telix. */
#ifndef TELIX_SOCKET_H
#define TELIX_SOCKET_H

#include <stdint.h>

typedef long ssize_t;
typedef unsigned long size_t;
typedef unsigned int socklen_t;

/* Address families. */
#define AF_UNIX   1
#define AF_LOCAL  AF_UNIX
#define AF_INET   2

/* Socket types. */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

/* Socket options. */
#define SOL_SOCKET    1
#define SO_REUSEADDR  2

/* Shutdown modes. */
#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2

struct sockaddr {
    uint16_t sa_family;
    char     sa_data[14];
};

struct sockaddr_un {
    uint16_t sun_family;
    char     sun_path[108];
};

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char     sin_zero[8];
};

int     socket(int domain, int type, int protocol);
int     bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int     listen(int sockfd, int backlog);
int     accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int     connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
int     shutdown(int sockfd, int how);
int     getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int     setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int     getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

/* Internal: server ports set during init. */
extern uint32_t __telix_uds_port;
extern uint32_t __telix_net_port;

#endif /* TELIX_SOCKET_H */
