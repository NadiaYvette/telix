/* Tier-1 Xwayland porting smoke test: dynamically link Fedora's
 * libpixman-1.so.0 and call pixman_version_string() / pixman_version().
 *
 * Both are pure constant-pointer / constant-int returns — no malloc,
 * no syscalls.  Heaviest of the Tier-1 leaves at ~700 KiB so this
 * exercises a much larger ld.so relocation pass than the 11-20 KiB
 * libs we've smoke-tested so far.
 */
#include <stdio.h>
#include <unistd.h>

extern const char *pixman_version_string(void);
extern int pixman_version(void);

int main(void)
{
    const char *s = pixman_version_string();
    int v = pixman_version();
    printf("[pixman] version=%d string=%s\n", v, s ? s : "(null)");
    fflush(stdout);
    _exit(0);
}
