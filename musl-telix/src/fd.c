/* Per-process file descriptor table. */
#include <telix/fd.h>

static struct telix_fd_entry fd_table[TELIX_MAX_FDS];

void telix_fd_init(void) {
    for (int i = 0; i < TELIX_MAX_FDS; i++) {
        fd_table[i].active = 0;
        fd_table[i].server_port = 0xFFFFFFFF;
        fd_table[i].server_handle = 0;
        fd_table[i].fd_type = FD_TYPE_FREE;
        fd_table[i].domain = 0;
    }
}

int telix_fd_set(int fd, uint32_t port, uint32_t handle) {
    return telix_fd_set_typed(fd, port, handle, FD_TYPE_CONSOLE, 0);
}

int telix_fd_set_typed(int fd, uint32_t port, uint32_t handle, int fd_type, int domain) {
    if (fd < 0 || fd >= TELIX_MAX_FDS) return -1;
    fd_table[fd].server_port = port;
    fd_table[fd].server_handle = handle;
    fd_table[fd].active = 1;
    fd_table[fd].fd_type = fd_type;
    fd_table[fd].domain = domain;
    return 0;
}

struct telix_fd_entry *telix_fd_get(int fd) {
    if (fd < 0 || fd >= TELIX_MAX_FDS) return 0;
    if (!fd_table[fd].active) return 0;
    return &fd_table[fd];
}

int telix_fd_alloc(uint32_t port, uint32_t handle, int fd_type, int domain) {
    for (int i = 3; i < TELIX_MAX_FDS; i++) {
        if (!fd_table[i].active) {
            telix_fd_set_typed(i, port, handle, fd_type, domain);
            return i;
        }
    }
    return -1;
}

int telix_fd_close(int fd) {
    if (fd < 0 || fd >= TELIX_MAX_FDS) return -1;
    if (!fd_table[fd].active) return -1;
    fd_table[fd].active = 0;
    fd_table[fd].fd_type = FD_TYPE_FREE;
    fd_table[fd].server_port = 0xFFFFFFFF;
    fd_table[fd].server_handle = 0;
    fd_table[fd].domain = 0;
    return 0;
}
