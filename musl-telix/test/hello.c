/* Phase 52 test: C program that writes to stdout via CON_WRITE IPC.
 * Phase 67: also tests argc/argv passing — exits with argc as status. */
#include <stdint.h>

/* Provided by musl-telix. */
typedef long ssize_t;
typedef unsigned long size_t;
ssize_t write(int fd, const void *buf, size_t count);
void _exit(int status) __attribute__((noreturn));

static int my_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

int main(int argc, char **argv, char **envp) {
    (void)argv; (void)envp;
    const char *msg = "Hello from C on Telix!\n";
    write(1, msg, my_strlen(msg));
    /* Exit with argc so the parent can verify argv was passed. */
    return argc;
}
