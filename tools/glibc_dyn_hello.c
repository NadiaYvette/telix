/* Phase 172 test: dynamically-linked glibc binary.
 *
 * Goal: exercise the kernel ELF PT_INTERP path end-to-end with a real
 * glibc ld-linux-x86-64.so.2 + libc.so.6 loaded from initramfs/lib64/.
 *
 * Uses only the tiniest possible libc surface (write, _exit) to minimize
 * the number of syscalls ld.so / libc startup triggers.  Returning argc
 * gives a PASS signal visible in the Phase 171 waitpid harness.
 */
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argv;
    static const char msg[] = "[glibc_dyn_hello] hello from dynamically-linked glibc!\n";
    write(1, msg, sizeof(msg) - 1);
    _exit(argc);
}
