/* POSIX read() for Telix — dispatches by fd type. */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/socket.h>
#include <telix/vfs.h>

/* Like POSIX read(): returns as soon as any data is available (short read). */
static ssize_t read_pipe(struct telix_fd_entry *fde,
                          unsigned char *p, size_t count) {
    uint32_t reply_port = telix_port_create();
    uint64_t d2 = (uint64_t)reply_port << 32;
    telix_send(fde->server_port, PIPE_READ_TAG,
               (uint64_t)fde->server_handle, 0, d2, 0);

    struct telix_msg msg;
    if (telix_recv_msg(reply_port, &msg) != 0) {
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

/* Console line-buffered read via CON_READ (0x3000).
 * CON_READ: data[0] = reply_port << 32
 * CON_READ_OK: data[0] = line_len, data[1..3] = bytes (up to 24) */
static ssize_t read_console(struct telix_fd_entry *fde,
                             unsigned char *p, size_t count) {
    uint32_t reply_port = telix_port_create();
    uint64_t d0 = (uint64_t)reply_port << 32;
    telix_send(fde->server_port, CON_READ, d0, 0, 0, 0);

    struct telix_msg msg;
    if (telix_recv_msg(reply_port, &msg) != 0) {
        telix_port_destroy(reply_port);
        return -1;
    }
    telix_port_destroy(reply_port);

    if (msg.tag != CON_READ_OK)
        return -1;

    int line_len = (int)(msg.data[0] & 0xFFFF);
    if (line_len > 24) line_len = 24;

    int copy = line_len;
    if ((size_t)copy > count)
        copy = (int)count;

    /* Bytes are packed in data[1], data[2], data[3] (8 bytes each). */
    for (int i = 0; i < copy; i++) {
        int wi = i / 8;       /* word index: 0,1,2 */
        int bi = i % 8;       /* byte within word */
        uint64_t word = msg.data[1 + wi];
        p[i] = (unsigned char)(word >> (bi * 8));
    }
    return (ssize_t)copy;
}

/* File read via FS_READ (0x2100).
 * FS_READ: data[0] = handle, data[1] = offset, data[2] = count | (reply_port << 32)
 * FS_READ_OK: data[0] = bytes[0..7], data[1] = bytes[8..15], data[2] = actual_len */
static ssize_t read_file(struct telix_fd_entry *fde,
                          unsigned char *p, size_t count) {
    if (fde->file_offset >= fde->file_size)
        return 0; /* EOF */

    size_t remaining = fde->file_size - fde->file_offset;
    if (count > remaining) count = remaining;

    size_t total_read = 0;
    while (total_read < count) {
        size_t chunk = count - total_read;
        if (chunk > 16) chunk = 16;

        uint32_t reply_port = telix_port_create();
        uint64_t d2 = (uint64_t)(uint32_t)chunk | ((uint64_t)reply_port << 32);

        telix_send(fde->server_port, FS_READ,
                   (uint64_t)fde->server_handle,
                   fde->file_offset,
                   d2, 0);

        struct telix_msg msg;
        if (telix_recv_msg(reply_port, &msg) != 0) {
            telix_port_destroy(reply_port);
            break;
        }
        telix_port_destroy(reply_port);

        if (msg.tag != FS_READ_OK)
            break;

        /* FS_READ_OK: data[0]=count, data[1]=bytes[0..7], data[2]=bytes[8..15] */
        int n = (int)(msg.data[0] & 0xFFFF);
        if (n <= 0) break;
        if (n > 16) n = 16;

        for (int i = 0; i < n; i++) {
            int wi = i / 8;
            int bi = i % 8;
            uint64_t word = (wi == 0) ? msg.data[1] : msg.data[2];
            p[total_read + i] = (unsigned char)(word >> (bi * 8));
        }

        total_read += n;
        fde->file_offset += n;

        if (n < (int)chunk) break; /* short read = EOF */
    }
    return (ssize_t)total_read;
}

/* PTY read: send PTY_READ(0x9020) to pty_srv.
 * PTY_READ: d0=handle, d2=reply_port<<32
 * PTY_READ_OK: d0=bytes[0..7], d1=bytes[8..15], d2=count */
static ssize_t read_pty(struct telix_fd_entry *fde,
                         unsigned char *p, size_t count) {
    uint32_t reply_port = telix_port_create();
    uint64_t d2 = (uint64_t)reply_port << 32;
    telix_send(fde->server_port, 0x9020 /* PTY_READ */,
               (uint64_t)fde->server_handle, 0, d2, 0);

    struct telix_msg msg;
    if (telix_recv_msg(reply_port, &msg) != 0) {
        telix_port_destroy(reply_port);
        return -1;
    }
    telix_port_destroy(reply_port);

    if (msg.tag == 0x90FF /* PTY_EOF */)
        return 0;
    if (msg.tag != 0x9021 /* PTY_READ_OK */)
        return -1;

    int n = (int)(msg.data[2] & 0xFFFF);
    if (n > 16) n = 16;
    int copy = n;
    if ((size_t)copy > count) copy = (int)count;

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

    if (fde->fd_type == FD_TYPE_CONSOLE)
        return read_console(fde, (unsigned char *)buf, count);

    if (fde->fd_type == FD_TYPE_FILE)
        return read_file(fde, (unsigned char *)buf, count);

    if (fde->fd_type == FD_TYPE_PTY)
        return read_pty(fde, (unsigned char *)buf, count);

    return -1;
}
