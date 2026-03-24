/* Byte order and IP address conversion functions. */
#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <stdint.h>

static inline uint16_t htons(uint16_t x) {
    return (uint16_t)((x >> 8) | (x << 8));
}

static inline uint16_t ntohs(uint16_t x) {
    return htons(x);
}

static inline uint32_t htonl(uint32_t x) {
    return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) |
           ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000);
}

static inline uint32_t ntohl(uint32_t x) {
    return htonl(x);
}

/* Convert dotted-quad string to network byte order uint32_t. Returns 1 on success. */
int inet_aton(const char *cp, uint32_t *addr);

/* Convert network byte order uint32_t to dotted-quad string. */
const char *inet_ntoa(uint32_t addr);

#endif /* ARPA_INET_H */
