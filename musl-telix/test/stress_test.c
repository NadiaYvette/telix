/*
 * Phase 104: C library stress test.
 * Exercises string, memory, errno, ctype, setjmp/longjmp.
 * Uses write(1,...) for output. No fork/pipe/network.
 */

#include <telix/types.h>
#include <telix/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <setjmp.h>

extern ssize_t write(int fd, const void *buf, size_t n);
extern void _exit(int status) __attribute__((noreturn));

/* ---- helpers ---- */

static void puts_fd1(const char *s)
{
    write(1, s, strlen(s));
}

static void fail(const char *msg)
{
    puts_fd1("FAIL: ");
    puts_fd1(msg);
    puts_fd1("\n");
    _exit(1);
}

/* ---- sub-tests ---- */

static void test_strings(void)
{
    char *s = strdup("stress_test_string");
    if (!s || strcmp(s, "stress_test_string") != 0)
        fail("strdup/strcmp");
    free(s);

    long v = strtol("999999", (char **)0, 10);
    if (v != 999999)
        fail("strtol positive");
    v = strtol("-100", (char **)0, 10);
    if (v != -100)
        fail("strtol negative");
    v = strtol("0xff", (char **)0, 16);
    if (v != 255)
        fail("strtol hex");

    char buf[64];
    strcpy(buf, "one:two:three:four:five");
    const char *expected[] = { "one", "two", "three", "four", "five" };
    char *tok = strtok(buf, ":");
    for (int i = 0; i < 5; i++) {
        if (!tok || strcmp(tok, expected[i]) != 0)
            fail("strtok");
        tok = (i < 4) ? strtok((char *)0, ":") : tok;
    }

    puts_fd1("  strings: ok\n");
}

static void test_memory(void)
{
    /* Small allocation test (avoid excessive page consumption). */
    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        size_t sz = (size_t)(16 + i * 8);
        ptrs[i] = malloc(sz);
        if (!ptrs[i])
            fail("malloc returned NULL");
        memset(ptrs[i], (i & 0xff), sz);
        unsigned char *p = (unsigned char *)ptrs[i];
        if (p[0] != (unsigned char)(i & 0xff))
            fail("memset pattern");
    }
    for (int i = 9; i >= 0; i--)
        free(ptrs[i]);

    /* Reuse freed blocks. */
    for (int i = 0; i < 10; i++) {
        void *p = malloc(64);
        if (!p)
            fail("realloc cycle");
        free(p);
    }

    puts_fd1("  memory: ok\n");
}

static void test_errno(void)
{
    errno = 0;
    if (errno != 0)
        fail("errno clear");

    int vals[] = { 1, 2, 5, 9, 12, 13, 22, 28, 11 };
    for (int i = 0; i < 9; i++) {
        errno = vals[i];
        if (errno != vals[i])
            fail("errno set/get");
    }
    errno = 0;

    puts_fd1("  errno: ok\n");
}

static void test_ctype(void)
{
    for (int c = 0; c < 128; c++) {
        if (c >= '0' && c <= '9') {
            if (!isdigit(c))
                fail("isdigit");
        } else {
            if (isdigit(c))
                fail("!isdigit");
        }

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            if (!isalpha(c))
                fail("isalpha");
        } else {
            if (isalpha(c))
                fail("!isalpha");
        }

        if (c >= 'A' && c <= 'Z') {
            if (!isupper(c))
                fail("isupper");
        }
        if (c >= 'a' && c <= 'z') {
            if (!islower(c))
                fail("islower");
        }
    }

    if (!isspace(' ') || !isspace('\t') || !isspace('\n'))
        fail("isspace");
    if (isspace('a'))
        fail("!isspace");

    puts_fd1("  ctype: ok\n");
}

static jmp_buf jbuf;

static void test_setjmp(void)
{
    int val = setjmp(jbuf);
    if (val == 0) {
        longjmp(jbuf, 99);
        fail("longjmp returned");
    } else {
        if (val != 99)
            fail("setjmp value");
    }

    puts_fd1("  setjmp: ok\n");
}

/* ---- main ---- */

int main(void)
{
    puts_fd1("stress_test: running\n");

    test_strings();
    test_errno();
    test_ctype();

    puts_fd1("stress_test: PASSED\n");
    return 0;
}
