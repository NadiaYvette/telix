/* Tier-0 Xwayland porting smoke test: link against Fedora's libxcvt.so.0
 * (dynamically) and call its only exported function,
 * libxcvt_gen_mode_info(), to verify that Telix's ld.so integration can
 * load an additional Fedora .so beyond glibc.
 *
 * PASS: exit 0, print computed dot_clock for 1920x1080@60.
 * FAIL: exit non-zero or segfault during ld.so resolution.
 *
 * Bypass libc atexit cleanup via _exit() — Telix's libc cleanup
 * (specifically __intl_freemem in the libc internationalization
 * subsystem) currently SIGSEGVs at CR2=0x8 on this environment.  That
 * cleanup is unrelated to the symbol-resolution path we're testing,
 * so use _exit() to skip atexit and report the actual test outcome.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <libxcvt/libxcvt.h>

int main(void)
{
    struct libxcvt_mode_info *m =
        libxcvt_gen_mode_info(1920, 1080, 60.0f, false, false);
    if (!m) {
        fprintf(stderr, "[xcvt] libxcvt_gen_mode_info returned NULL\n");
        fflush(stderr);
        _exit(1);
    }
    printf("[xcvt] %ux%u@%.0f dot_clock=%lu htotal=%u vtotal=%u\n",
           m->hdisplay, m->vdisplay, (double)m->vrefresh,
           (unsigned long)m->dot_clock, m->htotal, m->vtotal);
    fflush(stdout);
    free(m);
    _exit(0);
}
