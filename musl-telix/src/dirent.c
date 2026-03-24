/* Directory enumeration for Telix. */
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/vfs.h>

/* Internal DIR structure. */
struct _DIR {
    int            fd;
    int            pos;
    struct dirent  current;
    int            done;
};

extern uint32_t __telix_vfs_port;

DIR *opendir(const char *name) {
    int fd = open(name, O_RDONLY);
    if (fd < 0)
        return NULL;

    DIR *dir = (DIR *)malloc(sizeof(DIR));
    if (!dir) {
        close(fd);
        return NULL;
    }

    dir->fd   = fd;
    dir->pos  = 0;
    dir->done = 0;
    memset(&dir->current, 0, sizeof(dir->current));
    return dir;
}

struct dirent *readdir(DIR *dir) {
    if (!dir || dir->done)
        return NULL;

    struct telix_fd_entry *fde = telix_fd_get(dir->fd);
    if (!fde)
        return NULL;

    uint32_t reply_port = telix_port_create();

    /* VFS_READDIR: d0=handle, d1=index, d2=reply_port<<32 */
    uint64_t d2 = (uint64_t)reply_port << 32;
    telix_send(fde->server_port, VFS_READDIR,
               (uint64_t)fde->server_handle,
               (uint64_t)dir->pos,
               d2, 0);

    struct telix_msg msg;
    int ok = telix_recv_msg(reply_port, &msg);
    telix_port_destroy(reply_port);

    if (ok != 0 || msg.tag == VFS_READDIR_END) {
        dir->done = 1;
        return NULL;
    }

    if (msg.tag != VFS_READDIR_OK)
        return NULL;

    /*
     * VFS_READDIR_OK reply format:
     *   d0 = name bytes [0..7]
     *   d1 = name bytes [8..15]
     *   d2 = name bytes [16..23]
     *   d3 = d_type(low8) | d_ino(bits 8..31) | name_len(bits 32..47)
     */
    int name_len = (int)((msg.data[3] >> 32) & 0xFFFF);
    if (name_len > 255) name_len = 255;

    dir->current.d_type = (unsigned char)(msg.data[3] & 0xFF);
    dir->current.d_ino  = (unsigned long)((msg.data[3] >> 8) & 0xFFFFFF);

    /* Unpack name from three 8-byte words (up to 24 chars). */
    memset(dir->current.d_name, 0, sizeof(dir->current.d_name));
    for (int i = 0; i < name_len && i < 24; i++) {
        int wi = i / 8;
        int bi = i % 8;
        uint64_t word;
        if      (wi == 0) word = msg.data[0];
        else if (wi == 1) word = msg.data[1];
        else              word = msg.data[2];
        dir->current.d_name[i] = (char)(unsigned char)(word >> (bi * 8));
    }
    dir->current.d_name[name_len] = '\0';

    dir->pos++;
    return &dir->current;
}

int closedir(DIR *dir) {
    if (!dir)
        return -1;
    close(dir->fd);
    free(dir);
    return 0;
}

void rewinddir(DIR *dir) {
    if (!dir)
        return;
    dir->pos  = 0;
    dir->done = 0;
}
