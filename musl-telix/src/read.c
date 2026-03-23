/* POSIX read() for Telix — dispatches by fd type. */
#include <telix/fd.h>
#include <telix/socket.h>

ssize_t read(int fd, void *buf, size_t count) {
    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (!fde) return -1;

    if (fde->fd_type == FD_TYPE_SOCKET)
        return recv(fd, buf, count, 0);

    /* Console read not yet implemented. */
    return -1;
}
