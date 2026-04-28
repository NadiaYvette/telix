/* Tier-0 Xwayland porting smoke test: dynamically link Fedora's
 * libdrm.so.2 and call drmGetLibVersion(-1) to verify ld.so + libc
 * resolve a libdrm entry point.
 *
 * drmGetLibVersion does a single malloc and sets struct fields — no
 * ioctl, no /dev/dri open, no driver-specific code path.  Pure
 * symbol-resolution + glibc-malloc test.
 *
 * PASS: exit 0 with version line printed.
 * FAIL: any non-zero exit or pre-_exit fault.
 *
 * Headers are inlined so we don't need libdrm-devel on the build
 * host.  Binary is built with -l:libdrm.so.2 and -lc-before to keep
 * libc.so.6 ahead in the DT_NEEDED list (same workaround as
 * libxcvt_dyn_test for the version_r ordering bug).
 */
#include <stdio.h>
#include <unistd.h>

typedef struct _drmVersion {
    int     version_major;
    int     version_minor;
    int     version_patchlevel;
    int     name_len;
    char   *name;
    int     date_len;
    char   *date;
    int     desc_len;
    char   *desc;
} drmVersion, *drmVersionPtr;

extern drmVersionPtr drmGetLibVersion(int fd);
extern void drmFreeVersion(drmVersionPtr v);

int main(void)
{
    drmVersionPtr v = drmGetLibVersion(-1);
    if (!v) {
        fprintf(stderr, "[drm] drmGetLibVersion returned NULL\n");
        fflush(stderr);
        _exit(1);
    }
    printf("[drm] libdrm %d.%d.%d\n",
           v->version_major, v->version_minor, v->version_patchlevel);
    fflush(stdout);
    drmFreeVersion(v);
    _exit(0);
}
