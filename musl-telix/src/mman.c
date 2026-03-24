/* Memory management wrappers for Telix. */
#include <sys/mman.h>
#include <telix/syscall.h>
#include <stdint.h>

#define SYS_MMAP_ANON 16
#define SYS_MUNMAP    17
#define SYS_MPROTECT  60
#define SYS_MADVISE   90

void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset) {
    (void)fd; (void)offset; (void)flags;

    /* Convert POSIX prot to Telix prot: 0=RO, 1=RW, 2=RX, 3=RWX. */
    int telix_prot = 0;
    if (prot & PROT_WRITE) telix_prot |= 1;
    if (prot & PROT_EXEC)  telix_prot |= 2;

    /* Page count: Telix pages are 64K. */
    size_t page_size = 0x10000;
    size_t pages = (length + page_size - 1) / page_size;

    uint64_t result = __telix_syscall4(SYS_MMAP_ANON,
        (uint64_t)(uintptr_t)addr, pages, (uint64_t)telix_prot, 0);

    if (result == (uint64_t)-1) return MAP_FAILED;
    return (void *)(uintptr_t)result;
}

int munmap(void *addr, size_t length) {
    (void)length;
    __telix_syscall1(SYS_MUNMAP, (uint64_t)(uintptr_t)addr);
    return 0;
}

int madvise(void *addr, size_t length, int advice) {
    uint64_t result = __telix_syscall3(SYS_MADVISE,
        (uint64_t)(uintptr_t)addr, (uint64_t)length, (uint64_t)advice);
    return (int)result;
}

int mprotect(void *addr, size_t len, int prot) {
    int telix_prot = 0;
    if (prot & PROT_WRITE) telix_prot |= 1;
    if (prot & PROT_EXEC)  telix_prot |= 2;

    uint64_t result = __telix_syscall3(SYS_MPROTECT,
        (uint64_t)(uintptr_t)addr, (uint64_t)len, (uint64_t)telix_prot);
    return (int)result;
}
