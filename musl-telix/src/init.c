/* C runtime initialization for Telix.
 * Called before main() to set up the FD table and locate servers.
 */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>

/* Server ports (defined here, declared extern in various headers). */
uint32_t __telix_uds_port = 0xFFFFFFFF;
uint32_t __telix_net_port = 0xFFFFFFFF;
uint32_t __telix_pipe_port = 0xFFFFFFFF;
uint32_t __telix_vfs_port = 0xFFFFFFFF;

/* Trace helper — only prints for late-boot tasks (tid > 1000). */
static void _trace(const char *msg, int len) {
    uint64_t tid = __telix_syscall0(8 /* SYS_GETTID */);
    if (tid > 1000)
        __telix_syscall2(14 /* SYS_DEBUG_PUTS */, (uint64_t)(unsigned long)msg, (uint64_t)len);
}

/* Called from crt_start.S before main(). */
void __telix_init(void) {
    telix_fd_init();

    _trace("[init] ns:con..\n", 16);
    uint32_t con_port = telix_ns_lookup("console", 7);
    if (con_port != 0xFFFFFFFF) {
        telix_fd_set(0, con_port, 0);
        telix_fd_set(1, con_port, 0);
        telix_fd_set(2, con_port, 0);
    }

    _trace("[init] ns:uds..\n", 16);
    __telix_uds_port = telix_ns_lookup("uds", 3);

    _trace("[init] ns:net..\n", 16);
    __telix_net_port = telix_ns_lookup("net", 3);

    _trace("[init] ns:pipe.\n", 16);
    __telix_pipe_port = telix_ns_lookup("pipe", 4);

    _trace("[init] ns:vfs..\n", 16);
    __telix_vfs_port = telix_ns_lookup("vfs", 3);

    _trace("[init] done\n", 12);
}
