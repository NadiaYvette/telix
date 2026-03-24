/* Simple bump allocator with free-list for Telix.
 * Uses SYS_MMAP_ANON to acquire pages. */
#include <stdlib.h>
#include <string.h>
#include <telix/syscall.h>

#define HEAP_BASE  0x400000000ULL
#define PAGE_SIZE  65536  /* Must match kernel allocation page size */

/* Each allocation has an 8-byte header storing the usable size. */
#define HDR_SIZE 8

/* Free list: small number of size classes (power-of-2 buckets). */
#define NUM_BUCKETS 16  /* covers 8 .. 256K */

static void *free_lists[NUM_BUCKETS];
static uint64_t heap_top = HEAP_BASE;
static int heap_inited = 0;

static int bucket_for(size_t sz) {
    int b = 0;
    size_t s = 8;
    while (s < sz && b < NUM_BUCKETS - 1) { s <<= 1; b++; }
    return b;
}

static size_t bucket_size(int b) {
    return (size_t)8 << b;
}

static void *alloc_pages(size_t bytes) {
    size_t pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t va = heap_top;
    /* SYS_MMAP_ANON(16): args = va, page_count, prot(1=RW) */
    uint64_t result = __telix_syscall3(SYS_MMAP_ANON, va, pages, 1);
    if (result == 0 || result == (uint64_t)-1)
        return NULL;
    heap_top += pages * PAGE_SIZE;
    return (void *)va;
}

void *malloc(size_t size) {
    if (size == 0) size = 1;

    size_t total = size + HDR_SIZE;
    int b = bucket_for(total);
    size_t bsz = bucket_size(b);

    /* Check free list first. */
    if (free_lists[b]) {
        void *block = free_lists[b];
        free_lists[b] = *(void **)block;
        /* Header stores usable size. */
        *(uint64_t *)block = bsz - HDR_SIZE;
        return (char *)block + HDR_SIZE;
    }

    /* Allocate fresh pages. */
    void *block = alloc_pages(bsz);
    if (!block) return NULL;
    *(uint64_t *)block = bsz - HDR_SIZE;
    return (char *)block + HDR_SIZE;
}

void free(void *ptr) {
    if (!ptr) return;
    char *block = (char *)ptr - HDR_SIZE;
    size_t usable = *(uint64_t *)block;
    size_t total = usable + HDR_SIZE;
    int b = bucket_for(total);

    /* Push onto free list. */
    *(void **)block = free_lists[b];
    free_lists[b] = block;
}

void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *p = malloc(total);
    if (p) memset(p, 0, total);
    return p;
}


int abs(int x) { return x < 0 ? -x : x; }
