#ifndef _NETDB_H
#define _NETDB_H

#include <stdint.h>
#include <stddef.h>

/* Address families. */
#define AF_UNSPEC 0
#define AF_INET   2

/* Socket types. */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

/* AI flags. */
#define AI_PASSIVE     0x01
#define AI_NUMERICHOST 0x04
#define AI_NUMERICSERV 0x400

/* Error codes. */
#define EAI_NONAME -2
#define EAI_MEMORY -10
#define EAI_SYSTEM -11
#define EAI_AGAIN  -3

struct sockaddr {
    uint16_t sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char sin_zero[8];
};

struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
const char *gai_strerror(int errcode);

/* htons/ntohs helpers. */
static inline uint16_t htons(uint16_t x) {
    return (uint16_t)((x >> 8) | (x << 8));
}
static inline uint16_t ntohs(uint16_t x) {
    return htons(x);
}
static inline uint32_t htonl(uint32_t x) {
    return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) |
           ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000u);
}
static inline uint32_t ntohl(uint32_t x) {
    return htonl(x);
}

#endif /* _NETDB_H */
