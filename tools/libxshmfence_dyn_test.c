/* Tier-0 Xwayland porting smoke test: dynamically link Fedora's
 * libxshmfence.so.1 and exercise alloc → map → unmap to verify the
 * full ld.so + libc + memfd path.
 *
 * xshmfence_alloc_shm calls memfd_create + ftruncate + fcntl(F_ADD_SEALS).
 * Telix supports all three (Phase 46 POSIX shm + memfd sealing).  If
 * any of them fail we still surface the symbol resolution, just with a
 * non-zero exit.
 *
 * PASS: exit 0, fd printed.
 * FAIL: ld.so couldn't resolve a symbol, or memfd path is broken.
 *
 * Headers inlined to avoid a build-host dep on libxshmfence-devel.
 */
#include <stdio.h>
#include <unistd.h>

struct xshmfence;

extern int xshmfence_alloc_shm(void);
extern struct xshmfence *xshmfence_map_shm(int fd);
extern void xshmfence_unmap_shm(struct xshmfence *f);

int main(void)
{
    int fd = xshmfence_alloc_shm();
    if (fd < 0) {
        fprintf(stderr, "[xshmfence] alloc_shm failed: %d\n", fd);
        fflush(stderr);
        _exit(1);
    }
    struct xshmfence *f = xshmfence_map_shm(fd);
    if (!f) {
        fprintf(stderr, "[xshmfence] map_shm failed for fd=%d\n", fd);
        fflush(stderr);
        _exit(1);
    }
    printf("[xshmfence] alloc+map OK, fd=%d\n", fd);
    fflush(stdout);
    xshmfence_unmap_shm(f);
    _exit(0);
}
