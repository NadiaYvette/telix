/* Tier-3 Xwayland porting smoke test: dynamically link Fedora's
 * libX11.so.6 and call XOpenDisplay(NULL) to verify ld.so resolves
 * a libX11 entry point.
 *
 * XOpenDisplay(NULL) reads $DISPLAY and tries to connect.  We don't
 * set DISPLAY, so it returns NULL — clean expected outcome.
 *
 * Pulls in a 4-level dep tree:
 *   binary → libX11 → libxcb → libXau → libc
 * (libX11 also needs libxcb's libXdmcp transitively)
 */
#include <stdio.h>
#include <unistd.h>

struct _XDisplay;
typedef struct _XDisplay Display;

extern Display *XOpenDisplay(const char *display_name);
extern int XCloseDisplay(Display *display);

int main(void)
{
    Display *d = XOpenDisplay(0);
    if (d) {
        printf("[X11] XOpenDisplay OK (DISPLAY connected)\n");
        fflush(stdout);
        XCloseDisplay(d);
    } else {
        printf("[X11] XOpenDisplay=NULL (expected when DISPLAY unset)\n");
        fflush(stdout);
    }
    _exit(0);
}
