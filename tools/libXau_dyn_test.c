/* Tier-1 Xwayland porting smoke test: dynamically link Fedora's
 * libXau.so.6 and call XauFileName() to verify ld.so resolves a
 * libXau entry point.
 *
 * XauFileName checks $XAUTHORITY and $HOME via getenv + malloc.  No
 * syscalls beyond brk; pure symbol-resolution test.  It returns NULL
 * if neither env var is set, which is the expected outcome on Telix
 * (we don't pass either).  PASS criterion is "function returned
 * without faulting", regardless of NULL-vs-string return.
 */
#include <stdio.h>
#include <unistd.h>

extern char *XauFileName(void);

int main(void)
{
    char *p = XauFileName();
    if (p) {
        printf("[Xau] XauFileName=%s\n", p);
    } else {
        printf("[Xau] XauFileName=NULL (expected when XAUTHORITY/HOME unset)\n");
    }
    fflush(stdout);
    _exit(0);
}
