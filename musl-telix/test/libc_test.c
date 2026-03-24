/*
 * Phase 102: C library integration test.
 * Exercises multiple C library features. Uses write(1,...) for output.
 * Exit 0 if all pass, exit 1 on first failure.
 */

#include <telix/types.h>
#include <telix/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <setjmp.h>
#include <getopt.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>

extern ssize_t write(int fd, const void *buf, size_t n);
extern void _exit(int status) __attribute__((noreturn));

/* ---------- helpers ---------- */

static void puts_fd1(const char *s)
{
    write(1, s, strlen(s));
}

static void check(const char *name, int cond)
{
    puts_fd1("  ");
    puts_fd1(name);
    if (cond)
        puts_fd1(": PASS\n");
    else {
        puts_fd1(": FAIL\n");
        _exit(1);
    }
}

/* ---------- sub-tests ---------- */

static void test_errno(void)
{
    errno = 0;
    int ok = (errno == 0);
    errno = EINVAL;
    ok = ok && (errno == EINVAL);
    errno = 0;
    check("errno", ok);
}

static void test_ctype(void)
{
    int ok = 1;
    ok = ok && isdigit('5');
    ok = ok && !isdigit('a');
    ok = ok && isalpha('Z');
    ok = ok && !isalpha('3');
    ok = ok && (toupper('a') == 'A');
    ok = ok && (tolower('B') == 'b');
    check("ctype", ok);
}

static void test_strtol(void)
{
    long v1 = strtol("12345", (char **)0, 10);
    long v2 = strtol("-42", (char **)0, 10);
    check("strtol", v1 == 12345 && v2 == -42);
}

static void test_string(void)
{
    int ok = 1;

    char *d = strdup("hello");
    ok = ok && d && (strcmp(d, "hello") == 0);
    free(d);

    char buf[32];
    strcpy(buf, "a,b,c");
    char *tok = strtok(buf, ",");
    ok = ok && tok && (strcmp(tok, "a") == 0);
    tok = strtok((char *)0, ",");
    ok = ok && tok && (strcmp(tok, "b") == 0);

    ok = ok && (strspn("12345abc", "0123456789") == 5);

    ok = ok && (strerror(EINVAL) != (char *)0);

    check("string", ok);
}

static void test_limits(void)
{
    int ok = (INT_MAX == 2147483647);
    ok = ok && (PATH_MAX >= 256);
    check("limits", ok);
}

static jmp_buf jbuf;

static void test_setjmp(void)
{
    int val = setjmp(jbuf);
    if (val == 0) {
        longjmp(jbuf, 42);
        check("setjmp", 0);
    } else {
        check("setjmp", val == 42);
    }
}

static void test_getopt_fn(void)
{
    optind = 1;
    opterr = 0;

    char *argv[] = { "test", "-a", "-b", (char *)0 };
    int argc = 3;
    int got_a = 0, got_b = 0;
    int c;

    while ((c = getopt(argc, argv, "ab")) != -1) {
        if (c == 'a') got_a = 1;
        if (c == 'b') got_b = 1;
    }
    check("getopt", got_a && got_b);
}

static void test_rand(void)
{
    int any_nonzero = 0;
    for (int i = 0; i < 10; i++) {
        if (rand() != 0)
            any_nonzero = 1;
    }
    check("rand", any_nonzero);
}

static void test_getpwuid(void)
{
    struct passwd *pw = getpwuid(0);
    int ok = (pw != (struct passwd *)0);
    if (ok)
        ok = (strcmp(pw->pw_name, "root") == 0);
    check("getpwuid", ok);
}

static void test_regex(void)
{
    regex_t re;
    int ok = 1;

    int rc = regcomp(&re, "^hello", REG_EXTENDED | REG_NOSUB);
    ok = ok && (rc == 0);

    rc = regexec(&re, "hello world", 0, (regmatch_t *)0, 0);
    ok = ok && (rc == 0);

    rc = regexec(&re, "world hello", 0, (regmatch_t *)0, 0);
    ok = ok && (rc != 0);

    regfree(&re);
    check("regex", ok);
}

/* ---------- main ---------- */

int main(void)
{
    puts_fd1("libc_test: running\n");

    test_errno();
    test_ctype();
    test_strtol();
    test_string();
    test_limits();
    test_setjmp();
    test_getopt_fn();
    test_rand();
    test_getpwuid();
    test_regex();

    puts_fd1("libc_test: ALL PASSED\n");
    return 0;
}
