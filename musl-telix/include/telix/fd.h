/* Per-process file descriptor table. */
#ifndef TELIX_FD_H
#define TELIX_FD_H

#include <stdint.h>

#define TELIX_MAX_FDS 32

struct telix_fd_entry {
    uint32_t server_port;  /* IPC port of the server owning this fd */
    uint32_t server_handle; /* server-side handle (unused for console) */
    int      active;
};

void     telix_fd_init(void);
int      telix_fd_set(int fd, uint32_t port, uint32_t handle);
struct telix_fd_entry *telix_fd_get(int fd);

#endif /* TELIX_FD_H */
