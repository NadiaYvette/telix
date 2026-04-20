/* Phase 58b test: AF_INET6 socket API (TCP6 + UDP6 via ip6_srv). */
#include <stdint.h>
#include <telix/ipc.h>
#include <telix/socket.h>

ssize_t write(int fd, const void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count);
void _exit(int status) __attribute__((noreturn));

static void my_memset(void *p, int c, int n) {
    unsigned char *d = (unsigned char *)p;
    for (int i = 0; i < n; i++) d[i] = (unsigned char)c;
}

static void my_memcpy(char *dst, const char *src, int n) {
    for (int i = 0; i < n; i++) dst[i] = src[i];
}

/* htons: host to network byte order (16-bit). */
static uint16_t my_htons(uint16_t h) {
    return (uint16_t)((h >> 8) | (h << 8));
}

/* Query ip6_srv for our link-local IPv6 address via IPC. */
extern uint32_t __telix_ip6_port;

static int get_our_ip6(uint8_t *addr) {
    uint32_t rp = telix_port_create();
    /* IP6_STATUS = 0x6000 */
    telix_send(__telix_ip6_port, 0x6000, (uint64_t)rp, 0, 0, 0);
    struct telix_msg reply;
    if (telix_recv_msg(rp, &reply) != 0 || reply.tag != 0x6001) {
        telix_port_destroy(rp);
        return -1;
    }
    /* data[0..1] = link-local IPv6 in LE byte packing. Use global instead.
     * For the loopback test, link-local is fine. */
    for (int i = 0; i < 8; i++) addr[i] = (uint8_t)(reply.data[0] >> (i * 8));
    for (int i = 0; i < 8; i++) addr[8 + i] = (uint8_t)(reply.data[1] >> (i * 8));
    telix_port_destroy(rp);
    return 0;
}

int main(uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    (void)arg0; (void)arg1; (void)arg2;

    /* Check ip6_srv is available. */
    if (__telix_ip6_port == 0xFFFFFFFF) {
        write(1, "SKIP: no ip6\n", 13);
        _exit(0);
    }

    /* Get our link-local address for loopback tests. */
    uint8_t our_ip6[16];
    if (get_our_ip6(our_ip6) < 0) {
        write(1, "FAIL: get ip6\n", 14);
        _exit(1);
    }

    /* --- TCP6 Test: bind, listen, connect, accept, send, recv, close --- */
    {
        int srv = socket(AF_INET6, SOCK_STREAM, 0);
        if (srv < 0) { write(1, "FAIL: tcp6 socket srv\n", 22); _exit(2); }

        struct sockaddr_in6 saddr;
        my_memset(&saddr, 0, sizeof(saddr));
        saddr.sin6_family = AF_INET6;
        saddr.sin6_port = my_htons(8877);
        /* Bind to any (all-zeros) - ip6_srv interprets as our addr. */

        if (bind(srv, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            write(1, "FAIL: tcp6 bind\n", 16); _exit(3);
        }
        if (listen(srv, 4) < 0) {
            write(1, "FAIL: tcp6 listen\n", 18); _exit(4);
        }

        /* Connect to our own address (loopback). */
        int cli = socket(AF_INET6, SOCK_STREAM, 0);
        if (cli < 0) { write(1, "FAIL: tcp6 socket cli\n", 22); _exit(5); }

        struct sockaddr_in6 caddr;
        my_memset(&caddr, 0, sizeof(caddr));
        caddr.sin6_family = AF_INET6;
        caddr.sin6_port = my_htons(8877);
        my_memcpy((char *)caddr.sin6_addr, (const char *)our_ip6, 16);

        if (connect(cli, (struct sockaddr *)&caddr, sizeof(caddr)) < 0) {
            write(1, "FAIL: tcp6 connect\n", 19); _exit(6);
        }

        int acc = accept(srv, (struct sockaddr *)0, (socklen_t *)0);
        if (acc < 0) { write(1, "FAIL: tcp6 accept\n", 18); _exit(7); }

        /* Client sends "v6!", server recvs. */
        if (send(cli, "v6!", 3, 0) != 3) {
            write(1, "FAIL: tcp6 send\n", 16); _exit(8);
        }

        char buf[16];
        ssize_t n = recv(acc, buf, 16, 0);
        if (n != 3 || buf[0] != 'v' || buf[1] != '6' || buf[2] != '!') {
            write(1, "FAIL: tcp6 recv\n", 16); _exit(9);
        }

        shutdown(cli, SHUT_RDWR);
        shutdown(acc, SHUT_RDWR);
        shutdown(srv, SHUT_RDWR);
    }

    /* --- UDP6 Test: bind, sendto, recvfrom --- */
    {
        int sock = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0) { write(1, "FAIL: udp6 socket\n", 18); _exit(10); }

        struct sockaddr_in6 baddr;
        my_memset(&baddr, 0, sizeof(baddr));
        baddr.sin6_family = AF_INET6;
        baddr.sin6_port = my_htons(7766);

        if (bind(sock, (struct sockaddr *)&baddr, sizeof(baddr)) < 0) {
            write(1, "FAIL: udp6 bind\n", 16); _exit(11);
        }

        /* sendto our own address on same port. */
        struct sockaddr_in6 dest;
        my_memset(&dest, 0, sizeof(dest));
        dest.sin6_family = AF_INET6;
        dest.sin6_port = my_htons(7766);
        my_memcpy((char *)dest.sin6_addr, (const char *)our_ip6, 16);

        ssize_t sent = sendto(sock, "Udp6", 4, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent != 4) {
            write(1, "FAIL: udp6 sendto\n", 18); _exit(12);
        }

        /* recvfrom should get our packet back. */
        char buf[16];
        struct sockaddr_in6 from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sock, buf, 16, 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n != 4 || buf[0] != 'U' || buf[1] != 'd' || buf[2] != 'p' || buf[3] != '6') {
            write(1, "FAIL: udp6 recvfrom\n", 20); _exit(13);
        }

        shutdown(sock, SHUT_RDWR);
    }

    write(1, "Phase 58b socket6 API: OK\n", 26);
    _exit(0);
}
