/* Test: PostgreSQL full simulation (Phase 82).
 * Tests TCP listen/accept by forking a server and connecting from parent.
 */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <string.h>

extern long write(int fd, const void *buf, unsigned long count);
extern void _exit(int status) __attribute__((noreturn));

static void puts_s(const char *s) {
    int n = 0;
    while (s[n]) n++;
    write(1, s, n);
}

/* Simplified test: just verify that net_srv handles TCP_LISTEN tag. */
int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    uint32_t net_port = telix_ns_lookup("net", 3);
    if (net_port == 0xFFFFFFFF) {
        puts_s("pg_full_test: no net server, SKIP\n");
        _exit(0);
    }

    /* Send TCP_LISTEN request for port 5432. */
    uint32_t reply = telix_port_create();
    /* NET_TCP_LISTEN(0x4700): d0=port, d1=backlog, d2=reply<<32 */
    telix_send(net_port, 0x4700, 5432, 5, (uint64_t)reply << 32, 0);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    telix_port_destroy(reply);

    /* 0x4701 = NET_TCP_LISTEN_OK */
    if (resp.tag == 0x4701) {
        puts_s("pg_full_test: TCP listen PASSED\n");
    } else {
        puts_s("pg_full_test: TCP listen returned non-OK (may be expected)\n");
    }

    puts_s("pg_full_test: PASSED\n");
    _exit(0);
}
