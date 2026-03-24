/* Test: postmaster simulation (Phase 81).
 * Tests shared memory setup + buffer pool via shm_open/mmap.
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

/* Simplified shm_open/mmap test — just tests that shm_srv IPC works. */
int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    /* Look up shm server. */
    uint32_t shm_port = telix_ns_lookup("shm", 3);
    if (shm_port == 0xFFFFFFFF) {
        puts_s("postmaster_test: no shm server, SKIP\n");
        _exit(0);
    }

    /* SHM_CREATE: create a 4-page shared region. */
    uint32_t reply = telix_port_create();
    /* tag=0x5000 (SHM_CREATE), d0=pages, d1=reply<<32 */
    telix_send(shm_port, 0x5000, 4, (uint64_t)reply << 32, 0, 0);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    telix_port_destroy(reply);

    if (resp.tag == 0x5100) { /* SHM_OK */
        puts_s("postmaster_test: PASSED\n");
        _exit(0);
    }

    puts_s("postmaster_test: shm create FAIL\n");
    _exit(1);
}
