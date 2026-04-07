/* Phase 171 test: a real host-compiled static-glibc binary that runs
 * under the Telix Linux personality.  Returns argc as the exit code,
 * proving that argv was correctly passed across the execve boundary.
 *
 * Build:
 *   gcc -static -O2 -o glibc_hello glibc_hello.c
 */
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argv;
    static const char msg[] = "[glibc_hello] hello from real glibc!\n";
    write(1, msg, sizeof(msg) - 1);
    return argc;
}
