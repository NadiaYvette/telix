#ifndef SYS_STAT_H
#define SYS_STAT_H

#include <telix/types.h>

/* Permission bits */
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

/* File type bits (already in types.h but also here) */
#ifndef S_IFMT
#define S_IFMT   0170000
#define S_IFDIR  0040000
#define S_IFREG  0100000
#define S_IFLNK  0120000
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif

struct stat {
    unsigned long st_dev;
    unsigned long st_ino;
    mode_t        st_mode;
    unsigned long st_nlink;
    uid_t         st_uid;
    gid_t         st_gid;
    unsigned long st_rdev;
    off_t         st_size;
    long          st_blksize;
    long          st_blocks;
    long          st_atime;
    long          st_mtime;
    long          st_ctime;
};

int stat(const char *path, struct stat *buf);
int fstat(int fd, struct stat *buf);
int lstat(const char *path, struct stat *buf);
int chmod(const char *path, mode_t mode);
int fchmod(int fd, mode_t mode);
mode_t umask(mode_t mask);
int mkdir(const char *path, mode_t mode);

#endif
