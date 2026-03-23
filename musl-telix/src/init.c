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

/* Called from crt_start.S before main(). */
void __telix_init(void) {
    telix_fd_init();

    /* Look up the console server and map fd 0/1/2 to it. */
    uint32_t con_port = telix_ns_lookup("console", 7);
    if (con_port != 0xFFFFFFFF) {
        telix_fd_set(0, con_port, 0);  /* stdin */
        telix_fd_set(1, con_port, 0);  /* stdout */
        telix_fd_set(2, con_port, 0);  /* stderr */
    }

    /* Look up socket servers. */
    __telix_uds_port = telix_ns_lookup("uds", 3);
    __telix_net_port = telix_ns_lookup("net", 3);

    /* Look up pipe server. */
    __telix_pipe_port = telix_ns_lookup("pipe", 4);

    /* Look up VFS server. */
    __telix_vfs_port = telix_ns_lookup("vfs", 3);
}
