/* GHC RTS shim: MBlock allocator for Telix.
 *
 * GHC allocates memory in "megablocks" (1 MiB aligned).
 * getMBlocks → mmap, freeMBlocks → madvise(MADV_DONTNEED).
 */
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>

#define MBLOCK_SIZE (1 << 20)  /* 1 MiB */
#define MBLOCK_MASK (MBLOCK_SIZE - 1)

void *getMBlocks(uint32_t n) {
    size_t size = (size_t)n * MBLOCK_SIZE;
    /* Allocate with extra space for alignment. */
    size_t alloc_size = size + MBLOCK_SIZE;
    void *p = mmap(0, alloc_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;

    /* Align to MBLOCK_SIZE boundary. */
    uintptr_t addr = (uintptr_t)p;
    uintptr_t aligned = (addr + MBLOCK_MASK) & ~(uintptr_t)MBLOCK_MASK;
    return (void *)aligned;
}

void freeMBlocks(void *addr, uint32_t n) {
    /* Use MADV_DONTNEED to release physical pages without unmapping.
     * The VMA stays intact — next access triggers zero-fill fault. */
    size_t size = (size_t)n * MBLOCK_SIZE;
    madvise(addr, size, MADV_DONTNEED);
}

void releaseMBlocks(void *addr, uint32_t n) {
    freeMBlocks(addr, n);
}
