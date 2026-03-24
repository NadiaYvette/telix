/* VFS and filesystem protocol for Telix. */
#ifndef TELIX_VFS_H
#define TELIX_VFS_H

#include <telix/types.h>
#include <stdint.h>

/* VFS protocol tags. */
#define VFS_MOUNT       0x6000
#define VFS_UNMOUNT     0x6001
#define VFS_OPEN        0x6010
#define VFS_STAT        0x6020
#define VFS_READDIR     0x6030
#define VFS_OK          0x6100
#define VFS_OPEN_OK     0x6110
#define VFS_STAT_OK     0x6120
#define VFS_READDIR_OK  0x6130
#define VFS_READDIR_END 0x6131
#define VFS_MKDIR       0x6040
#define VFS_MKDIR_OK    0x6140
#define VFS_UNLINK      0x6050
#define VFS_UNLINK_OK   0x6150
#define VFS_RENAME      0x6060
#define VFS_RENAME_OK   0x6160
#define VFS_ERROR       0x6F00

/* Underlying FS protocol tags. */
#define FS_OPEN         0x2000
#define FS_OPEN_OK      0x2001
#define FS_READ         0x2100
#define FS_READ_OK      0x2101
#define FS_READDIR_FS   0x2200
#define FS_READDIR_FS_OK 0x2201
#define FS_READDIR_FS_END 0x2202
#define FS_STAT_FS      0x2300
#define FS_STAT_FS_OK   0x2301
#define FS_CLOSE        0x2400
#define FS_CREATE       0x2500
#define FS_CREATE_OK    0x2501
#define FS_WRITE        0x2600
#define FS_WRITE_OK     0x2601
#define FS_DELETE        0x2700
#define FS_DELETE_OK     0x2701
#define FS_MKDIR        0x2A00
#define FS_MKDIR_OK     0x2A01
#define FS_UNLINK       0x2A20
#define FS_UNLINK_OK    0x2A21
#define FS_FSYNC        0x2B00
#define FS_FSYNC_OK     0x2B01
#define FS_ERROR        0x2F00

/* Console read protocol. */
#define CON_READ        0x3000
#define CON_READ_OK     0x3001

/* Minimal stat structure. */
struct stat {
    mode_t   st_mode;
    uid_t    st_uid;
    gid_t    st_gid;
    uint64_t st_size;
    uint32_t st_ino;
};

/* VFS port (set up by init.c). */
extern uint32_t __telix_vfs_port;

/* File operations. */
int     open(const char *path, int flags);
int     close(int fd);
int     stat(const char *path, struct stat *buf);
off_t   lseek(int fd, off_t offset, int whence);
int     mkdir(const char *path, int mode);
int     unlink(const char *path);
int     rename(const char *oldpath, const char *newpath);
int     fsync(int fd);
int     ftruncate(int fd, off_t length);

#endif /* TELIX_VFS_H */
