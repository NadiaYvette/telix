/* Per-process file descriptor table. */
#ifndef TELIX_FD_H
#define TELIX_FD_H

#include <stdint.h>

#define TELIX_MAX_FDS 32

/* FD type tags. */
#define FD_TYPE_FREE    0
#define FD_TYPE_CONSOLE 1
#define FD_TYPE_SOCKET  2
#define FD_TYPE_FILE    3

struct telix_fd_entry {
    uint32_t server_port;  /* IPC port of the server owning this fd */
    uint32_t server_handle; /* server-side handle */
    int      active;
    int      fd_type;      /* FD_TYPE_* */
    int      domain;       /* AF_UNIX, AF_INET, etc. (sockets only) */
};

void     telix_fd_init(void);
int      telix_fd_set(int fd, uint32_t port, uint32_t handle);
int      telix_fd_set_typed(int fd, uint32_t port, uint32_t handle, int fd_type, int domain);
struct telix_fd_entry *telix_fd_get(int fd);
int      telix_fd_alloc(uint32_t port, uint32_t handle, int fd_type, int domain);
int      telix_fd_close(int fd);

#endif /* TELIX_FD_H */
