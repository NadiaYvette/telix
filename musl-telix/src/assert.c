/* assert failure handler for Telix. */
#include <telix/types.h>

extern ssize_t write(int fd, const void *buf, size_t count);
extern void _exit(int status) __attribute__((noreturn));

static size_t _strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void _write_str(const char *s) {
    write(2, s, _strlen(s));
}

static void _write_int(int val) {
    char buf[12];
    int i = 0;
    if (val < 0) { write(2, "-", 1); val = -val; }
    if (val == 0) { write(2, "0", 1); return; }
    while (val > 0) { buf[i++] = '0' + (val % 10); val /= 10; }
    while (--i >= 0) write(2, &buf[i], 1);
}

void __assert_fail(const char *expr, const char *file, int line, const char *func) {
    _write_str("Assertion failed: ");
    _write_str(expr);
    _write_str(", file ");
    _write_str(file);
    _write_str(", line ");
    _write_int(line);
    if (func) {
        _write_str(", function ");
        _write_str(func);
    }
    _write_str("\n");
    _exit(134); /* 128 + SIGABRT(6) */
}
