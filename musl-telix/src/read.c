/* POSIX read() for Telix — dispatches by fd type. */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/socket.h>

/* Like POSIX read(): returns as soon as any data is available (short read). */
static ssize_t read_pipe(struct telix_fd_entry *fde,
                          unsigned char *p, size_t count) {
    uint32_t reply_port = telix_port_create();
    uint64_t d2 = (uint64_t)reply_port << 32;
    telix_send(fde->server_port, PIPE_READ_TAG,
               (uint64_t)fde->server_handle, 0, d2, 0);

    struct telix_msg msg;
    if (!telix_recv_msg(reply_port, &msg)) {
        telix_port_destroy(reply_port);
        return -1;
    }
    telix_port_destroy(reply_port);

    if (msg.tag == PIPE_EOF_TAG)
        return 0;
    if (msg.tag != PIPE_OK_TAG)
        return -1;

    int n = (int)(msg.data[2] & 0xFFFF);
    if (n > 16) n = 16;

    int copy = n;
    if ((size_t)copy > count)
        copy = (int)count;
    for (int i = 0; i < copy; i++) {
        int wi = i / 8;
        int bi = i % 8;
        uint64_t word = (wi == 0) ? msg.data[0] : msg.data[1];
        p[i] = (unsigned char)(word >> (bi * 8));
    }
    return (ssize_t)copy;
}

ssize_t read(int fd, void *buf, size_t count) {
    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (!fde) return -1;

    if (fde->fd_type == FD_TYPE_SOCKET)
        return recv(fd, buf, count, 0);

    if (fde->fd_type == FD_TYPE_PIPE)
        return read_pipe(fde, (unsigned char *)buf, count);

    /* Console read not yet implemented. */
    return -1;
}
