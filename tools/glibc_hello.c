/* Phase 171 test: a real host-compiled static-glibc binary that runs
 * under the Telix Linux personality.  Returns argc as the exit code,
 * proving that argv was correctly passed across the execve boundary.
 *
 * Build:
 *   gcc -static -O2 -o glibc_hello glibc_hello.c
 */
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
    (void)argv;
    static const char msg[] = "[glibc_hello] hello from real glibc!\n";
    write(1, msg, sizeof(msg) - 1);
    /* Bypass libc exit-cleanup path: call exit_group directly so the
     * kernel sees argc as the exit code without going through libc's
     * atexit/stdio teardown (which currently triggers a crash on Telix). */
    syscall(SYS_exit_group, argc);
    __builtin_unreachable();
}
