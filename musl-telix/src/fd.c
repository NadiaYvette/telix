/* Per-process file descriptor table. */
#include <telix/fd.h>

static struct telix_fd_entry fd_table[TELIX_MAX_FDS];

void telix_fd_init(void) {
    for (int i = 0; i < TELIX_MAX_FDS; i++) {
        fd_table[i].active = 0;
        fd_table[i].server_port = 0xFFFFFFFF;
        fd_table[i].server_handle = 0;
    }
}

int telix_fd_set(int fd, uint32_t port, uint32_t handle) {
    if (fd < 0 || fd >= TELIX_MAX_FDS) return -1;
    fd_table[fd].server_port = port;
    fd_table[fd].server_handle = handle;
    fd_table[fd].active = 1;
    return 0;
}

struct telix_fd_entry *telix_fd_get(int fd) {
    if (fd < 0 || fd >= TELIX_MAX_FDS) return 0;
    if (!fd_table[fd].active) return 0;
    return &fd_table[fd];
}
