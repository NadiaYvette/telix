/* Tier-2 Xwayland porting smoke test: dynamically link Fedora's
 * libwayland-client.so.0 and call wl_display_connect(NULL) to verify
 * ld.so resolves a libwayland entry point.
 *
 * wl_display_connect(NULL) reads WAYLAND_DISPLAY (we don't set it) /
 * tries "wayland-0" under XDG_RUNTIME_DIR / /run/user/uid/.  In the
 * Step-H-debug skip-set timeline Step G is skipped, so no compositor
 * is running — wl_display_connect should return NULL cleanly.  The
 * test passes either way: NULL means clean lookup failure, non-NULL
 * means we accidentally have a compositor up (also fine).
 *
 * Pulls in libwayland-client → libffi (DT_NEEDED) → libc.
 */
#include <stdio.h>
#include <unistd.h>

struct wl_display;

extern struct wl_display *wl_display_connect(const char *name);
extern void wl_display_disconnect(struct wl_display *display);

int main(void)
{
    struct wl_display *d = wl_display_connect(0);
    if (d) {
        printf("[wayland] wl_display_connect OK (compositor up)\n");
        fflush(stdout);
        wl_display_disconnect(d);
    } else {
        printf("[wayland] wl_display_connect=NULL (expected when no compositor)\n");
        fflush(stdout);
    }
    _exit(0);
}
