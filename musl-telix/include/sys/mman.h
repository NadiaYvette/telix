#ifndef _SYS_MMAN_H
#define _SYS_MMAN_H

#include <stddef.h>
#include <stdint.h>

#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS

#define MAP_FAILED ((void *)-1)

#define MADV_NORMAL    0
#define MADV_RANDOM    1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED  3
#define MADV_DONTNEED  4

void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
int munmap(void *addr, size_t length);
int madvise(void *addr, size_t length, int advice);
int mprotect(void *addr, size_t len, int prot);

#endif /* _SYS_MMAN_H */
