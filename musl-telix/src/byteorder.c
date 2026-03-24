/* Byte order and IP address conversion. */
#include <arpa/inet.h>

int inet_aton(const char *cp, uint32_t *addr) {
    uint32_t parts[4] = {0,0,0,0};
    int n = 0;
    const char *p = cp;
    while (*p && n < 4) {
        uint32_t val = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            p++;
        }
        parts[n++] = val;
        if (*p == '.') p++;
        else break;
    }
    if (n != 4) return 0;
    *addr = htonl((parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3]);
    return 1;
}

static char inet_ntoa_buf[16];

const char *inet_ntoa(uint32_t addr) {
    uint32_t h = ntohl(addr);
    char *p = inet_ntoa_buf;
    for (int i = 3; i >= 0; i--) {
        uint32_t octet = (h >> (i*8)) & 0xFF;
        if (octet >= 100) { *p++ = '0' + octet/100; octet %= 100; *p++ = '0' + octet/10; octet %= 10; }
        else if (octet >= 10) { *p++ = '0' + octet/10; octet %= 10; }
        *p++ = '0' + octet;
        if (i > 0) *p++ = '.';
    }
    *p = '\0';
    return inet_ntoa_buf;
}
