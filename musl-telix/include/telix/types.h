/* Common POSIX-ish types and constants for Telix. */
#ifndef TELIX_TYPES_H
#define TELIX_TYPES_H

#include <stdint.h>

typedef int64_t  ssize_t;
typedef uint64_t size_t;
typedef int32_t  pid_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint32_t mode_t;
typedef int64_t  off_t;
typedef unsigned int nfds_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

/* open() flags. */
#define O_RDONLY   0x0000
#define O_WRONLY   0x0001
#define O_RDWR     0x0002
#define O_CREAT    0x0040
#define O_TRUNC    0x0200
#define O_APPEND   0x0400

/* File mode bits. */
#define S_IFMT   0170000
#define S_IFDIR  0040000
#define S_IFREG  0100000
#define S_IFLNK  0120000
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)

/* lseek whence. */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* Errno values. */
#define ENOENT  2
#define EIO     5
#define EBADF   9
#define ENOMEM 12
#define EACCES 13
#define EINVAL 22
#define ENOSPC 28
#define EAGAIN 11

#endif /* TELIX_TYPES_H */
