/* Phase 52 test: C program that writes to stdout via CON_WRITE IPC. */
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

int main(uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    (void)arg0; (void)arg1; (void)arg2;
    const char *msg = "Hello from C on Telix!\n";
    write(1, msg, my_strlen(msg));
    return 0;
}
