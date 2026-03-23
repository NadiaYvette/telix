/* File operations for Telix: open, close, stat, lseek via VFS/FS IPC. */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/vfs.h>
#include <string.h>

/* Defined in init.c */
extern uint32_t __telix_vfs_port;

int open(const char *path, int flags) {
    if (__telix_vfs_port == 0xFFFFFFFF)
        return -1;

    int pathlen = (int)strlen(path);
    if (pathlen > 16) pathlen = 16;

    /* Pack path into two u64 words (little-endian). */
    uint64_t w0 = 0, w1 = 0;
    for (int i = 0; i < pathlen && i < 8; i++)
        w0 |= (uint64_t)(unsigned char)path[i] << (i * 8);
    for (int i = 8; i < pathlen && i < 16; i++)
        w1 |= (uint64_t)(unsigned char)path[i] << ((i - 8) * 8);

    uint32_t reply = telix_port_create();
    /* d2 = pathlen(low16) | flags(next16) | reply_port(high32) */
    uint64_t d2 = (uint64_t)(uint32_t)pathlen
                | ((uint64_t)(uint32_t)flags << 16)
                | ((uint64_t)reply << 32);

    telix_send(__telix_vfs_port, VFS_OPEN, w0, w1, d2, 0);

    struct telix_msg msg;
    int ok = telix_recv_msg(reply, &msg);
    telix_port_destroy(reply);

    if (ok != 0 || msg.tag != VFS_OPEN_OK)
        return -1;

    /* VFS_OPEN_OK: data[0]=fs_port, data[1]=handle, data[2]=size, data[3]=fs_aspace */
    uint32_t fs_port   = (uint32_t)msg.data[0];
    uint32_t handle    = (uint32_t)msg.data[1];
    uint64_t file_size = msg.data[2];
    uint32_t fs_aspace = (uint32_t)msg.data[3];

    /* Allocate an FD. */
    int fd = telix_fd_alloc(fs_port, handle, FD_TYPE_FILE, 0);
    if (fd < 0) return -1;

    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (fde) {
        fde->file_offset = 0;
        fde->file_size = file_size;
        fde->fs_aspace = fs_aspace;
    }
    return fd;
}

int close(int fd) {
    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (!fde) return -1;

    if (fde->fd_type == FD_TYPE_FILE) {
        /* Send FS_CLOSE to the filesystem server. */
        uint32_t reply = telix_port_create();
        uint64_t d2 = (uint64_t)reply << 32;
        telix_send(fde->server_port, FS_CLOSE,
                   (uint64_t)fde->server_handle, 0, d2, 0);

        struct telix_msg msg;
        telix_recv_msg(reply, &msg);
        telix_port_destroy(reply);
    } else if (fde->fd_type == FD_TYPE_PIPE) {
        /* Send PIPE_CLOSE to pipe server. */
        uint32_t reply = telix_port_create();
        uint64_t d2 = (uint64_t)reply << 32;
        telix_send(fde->server_port, 0x5040 /* PIPE_CLOSE_TAG */,
                   (uint64_t)fde->server_handle, 0, d2, 0);
        struct telix_msg msg;
        telix_recv_msg(reply, &msg);
        telix_port_destroy(reply);
    }

    telix_fd_close(fd);
    return 0;
}

int stat(const char *path, struct stat *buf) {
    if (__telix_vfs_port == 0xFFFFFFFF)
        return -1;

    int pathlen = (int)strlen(path);
    if (pathlen > 16) pathlen = 16;

    uint64_t w0 = 0, w1 = 0;
    for (int i = 0; i < pathlen && i < 8; i++)
        w0 |= (uint64_t)(unsigned char)path[i] << (i * 8);
    for (int i = 8; i < pathlen && i < 16; i++)
        w1 |= (uint64_t)(unsigned char)path[i] << ((i - 8) * 8);

    uint32_t reply = telix_port_create();
    uint64_t d2 = (uint64_t)(uint32_t)pathlen | ((uint64_t)reply << 32);

    telix_send(__telix_vfs_port, VFS_STAT, w0, w1, d2, 0);

    struct telix_msg msg;
    int ok = telix_recv_msg(reply, &msg);
    telix_port_destroy(reply);

    if (ok != 0 || msg.tag != VFS_STAT_OK)
        return -1;

    /* VFS_STAT_OK: data[0]=size, data[1]=mode, data[2]=uid|(gid<<16), data[3]=inode */
    if (buf) {
        buf->st_size = msg.data[0];
        buf->st_mode = (mode_t)msg.data[1];
        buf->st_uid  = (uid_t)(msg.data[2] & 0xFFFF);
        buf->st_gid  = (gid_t)((msg.data[2] >> 16) & 0xFFFF);
        buf->st_ino  = (uint32_t)msg.data[3];
    }
    return 0;
}

off_t lseek(int fd, off_t offset, int whence) {
    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (!fde || fde->fd_type != FD_TYPE_FILE) return -1;

    int64_t newoff;
    switch (whence) {
    case 0: /* SEEK_SET */ newoff = offset; break;
    case 1: /* SEEK_CUR */ newoff = (int64_t)fde->file_offset + offset; break;
    case 2: /* SEEK_END */ newoff = (int64_t)fde->file_size + offset; break;
    default: return -1;
    }
    if (newoff < 0) return -1;
    fde->file_offset = (uint64_t)newoff;
    return (off_t)newoff;
}
