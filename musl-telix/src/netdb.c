/* DNS resolver / getaddrinfo for Telix. */
#include <netdb.h>
#include <string.h>
#include <telix/syscall.h>

/* Simple numeric IP parser: "a.b.c.d" → network-order u32.  Returns 0 on failure. */
static int parse_ipv4(const char *s, uint32_t *out) {
    uint32_t parts[4];
    int pi = 0;
    uint32_t cur = 0;
    int digits = 0;

    for (int i = 0; ; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + (uint32_t)(c - '0');
            digits++;
            if (cur > 255) return 0;
        } else if (c == '.' || c == '\0') {
            if (digits == 0 || pi >= 4) return 0;
            parts[pi++] = cur;
            cur = 0;
            digits = 0;
            if (c == '\0') break;
        } else {
            return 0;
        }
    }
    if (pi != 4) return 0;
    /* Store in network byte order. */
    *out = (parts[0]) | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
    return 1;
}

/* Simple atoi for port numbers. */
static int parse_port(const char *s) {
    int val = 0;
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return val;
}

/* Minimal malloc from our malloc.c */
extern void *malloc(unsigned long size);
extern void free(void *ptr);

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    uint32_t addr = 0;
    int family = AF_INET;
    int socktype = SOCK_STREAM;
    uint16_t port = 0;

    if (hints) {
        if (hints->ai_family != AF_UNSPEC) family = hints->ai_family;
        if (hints->ai_socktype) socktype = hints->ai_socktype;
    }

    if (node == 0 || node[0] == '\0') {
        /* AI_PASSIVE: bind to INADDR_ANY. */
        addr = 0;
    } else if (!parse_ipv4(node, &addr)) {
        /* Non-numeric — DNS resolution would go here.
         * For now, return EAI_NONAME for non-numeric hosts. */
        return EAI_NONAME;
    }

    if (service) {
        port = (uint16_t)parse_port(service);
    }

    /* Allocate result. */
    struct addrinfo *ai = (struct addrinfo *)malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
    if (!ai) return EAI_MEMORY;

    struct sockaddr_in *sa = (struct sockaddr_in *)(ai + 1);
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = (uint16_t)family;
    sa->sin_port = htons(port);
    sa->sin_addr = addr;

    ai->ai_flags = 0;
    ai->ai_family = family;
    ai->ai_socktype = socktype;
    ai->ai_protocol = (socktype == SOCK_DGRAM) ? 17 : 6;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_addr = (struct sockaddr *)sa;
    ai->ai_canonname = 0;
    ai->ai_next = 0;

    *res = ai;
    return 0;
}

void freeaddrinfo(struct addrinfo *res) {
    while (res) {
        struct addrinfo *next = res->ai_next;
        free(res);
        res = next;
    }
}

const char *gai_strerror(int errcode) {
    switch (errcode) {
    case 0: return "Success";
    case EAI_NONAME: return "Name or service not known";
    case EAI_MEMORY: return "Memory allocation failure";
    case EAI_AGAIN: return "Temporary failure in name resolution";
    default: return "Unknown error";
    }
}
