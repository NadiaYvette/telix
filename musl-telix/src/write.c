/* POSIX write() for Telix — dispatches by fd type. */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/socket.h>
#include <telix/vfs.h>

/*
 * CON_WRITE protocol (from console_srv.rs):
 *   tag    = 0x3100
 *   data[0] = inline bytes 0..7
 *   data[1] = inline bytes 8..15
 *   data[2] = len (low 32) | reply_port (high 32)
 *   data[3] = inline bytes 16..23
 *
 * Max 24 bytes per message. We chunk larger writes.
 * reply_port = 0xFFFFFFFF means fire-and-forget (no ack).
 */

static uint64_t pack_bytes(const unsigned char *buf, int count) {
    uint64_t w = 0;
    for (int i = 0; i < count && i < 8; i++) {
        w |= (uint64_t)buf[i] << (i * 8);
    }
    return w;
}

static ssize_t write_console(struct telix_fd_entry *fde,
                              const unsigned char *p, size_t count) {
    size_t remaining = count;
    size_t written = 0;

    while (remaining > 0) {
        int chunk = (remaining > 24) ? 24 : (int)remaining;

        /* Pack bytes into data words. */
        uint64_t d0 = 0, d1 = 0, d3 = 0;
        if (chunk > 0)  d0 = pack_bytes(p, chunk > 8 ? 8 : chunk);
        if (chunk > 8)  d1 = pack_bytes(p + 8, chunk > 16 ? 8 : chunk - 8);
        if (chunk > 16) d3 = pack_bytes(p + 16, chunk - 16);

        /* data[2] = len | (reply_port << 32). Fire-and-forget. */
        uint64_t d2 = (uint64_t)(uint32_t)chunk | ((uint64_t)0xFFFFFFFF << 32);

        telix_send(fde->server_port, CON_WRITE, d0, d1, d2, d3);

        p += chunk;
        remaining -= chunk;
        written += chunk;
    }
    return (ssize_t)written;
}

static ssize_t write_pipe(struct telix_fd_entry *fde,
                           const unsigned char *p, size_t count) {
    size_t remaining = count;
    size_t written = 0;

    while (remaining > 0) {
        int chunk = (remaining > 16) ? 16 : (int)remaining;

        uint64_t d0 = 0, d1 = 0;
        if (chunk > 0)  d0 = pack_bytes(p, chunk > 8 ? 8 : chunk);
        if (chunk > 8)  d1 = pack_bytes(p + 8, chunk - 8);

        /* d2 = len | (reply_port << 32). Fire-and-forget. */
        uint64_t d2 = (uint64_t)(uint32_t)chunk | ((uint64_t)0xFFFFFFFF << 32);

        telix_send(fde->server_port, PIPE_WRITE_TAG,
                   (uint64_t)fde->server_handle, d0, d2, d1);

        p += chunk;
        remaining -= chunk;
        written += chunk;
    }
    return (ssize_t)written;
}

/* File write via FS_WRITE (0x2600).
 * FS_WRITE: data[0] = handle, data[1] = offset | (len << 32),
 *           data[2] = reply_port << 32, data[3] = inline bytes (up to 16)
 *
 * Actually, let's use the inline data approach:
 * data[0] = handle, data[1] = bytes[0..7], data[2] = len | (reply_port << 32),
 * data[3] = bytes[8..15], plus offset packed somewhere.
 *
 * Looking at ext2_srv FS_WRITE handler:
 * data[0] = handle, data[1] = length(low32) | reply_port(high32),
 * data[2] = grant_va, ... This is grant-based.
 *
 * For small inline writes, we'll use a simpler protocol:
 * Send FS_WRITE with data[0]=handle, data[1]=offset,
 * data[2]=len(low16)|reply(high32), data[3..5]=inline bytes.
 *
 * Actually, for v1 we'll just do fire-and-forget small writes to tmpfs.
 * The tmpfs_srv and ext2_srv use grant-based writes which is complex.
 * For now, implement inline console/pipe writes only for file writes.
 */
static ssize_t write_file(struct telix_fd_entry *fde,
                           const unsigned char *p, size_t count) {
    /* For now, file write is not implemented — files are read-only in C libc.
     * The Rust userlib handles writes via grant pages. */
    (void)fde; (void)p; (void)count;
    return -1;
}

ssize_t write(int fd, const void *buf, size_t count) {
    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (!fde) return -1;

    if (fde->fd_type == FD_TYPE_SOCKET)
        return send(fd, buf, count, 0);

    if (fde->fd_type == FD_TYPE_PIPE)
        return write_pipe(fde, (const unsigned char *)buf, count);

    if (fde->fd_type == FD_TYPE_FILE)
        return write_file(fde, (const unsigned char *)buf, count);

    /* Default: console write. */
    return write_console(fde, (const unsigned char *)buf, count);
}
