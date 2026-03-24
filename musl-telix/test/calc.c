/*
 * Phase 103: Simple integer calculator (bc-like).
 * Recursive descent parser for +, -, *, /, parentheses.
 * No floating point (freestanding, -mgeneral-regs-only).
 * Usage: calc "expression"
 */

#include <telix/types.h>

extern ssize_t write(int fd, const void *buf, size_t n);
extern void _exit(int status) __attribute__((noreturn));
extern size_t strlen(const char *s);
extern long strtol(const char *nptr, char **endptr, int base);

/* ---- output helpers ---- */

static void puts_fd1(const char *s)
{
    write(1, s, strlen(s));
}

static void print_long(long v)
{
    char buf[24];
    int neg = 0;
    unsigned long uv;

    if (v < 0) {
        neg = 1;
        uv = (unsigned long)(-(v + 1)) + 1;
    } else {
        uv = (unsigned long)v;
    }

    int i = (int)sizeof(buf) - 1;
    buf[i] = '\0';
    do {
        buf[--i] = '0' + (char)(uv % 10);
        uv /= 10;
    } while (uv);

    if (neg)
        buf[--i] = '-';

    puts_fd1(&buf[i]);
}

/* ---- parser state ---- */

static const char *input;
static int err;

static void skip_spaces(void)
{
    while (*input == ' ' || *input == '\t')
        input++;
}

/* Forward declarations */
static long parse_expr(void);

static long parse_atom(void)
{
    skip_spaces();

    if (*input == '(') {
        input++;
        long v = parse_expr();
        skip_spaces();
        if (*input == ')')
            input++;
        else
            err = 1;
        return v;
    }

    /* Unary minus */
    if (*input == '-') {
        input++;
        return -parse_atom();
    }

    /* Number */
    if ((*input >= '0' && *input <= '9')) {
        char *end;
        long v = strtol(input, &end, 10);
        if (end == input) {
            err = 1;
            return 0;
        }
        input = end;
        return v;
    }

    err = 1;
    return 0;
}

static long parse_term(void)
{
    long left = parse_atom();

    for (;;) {
        skip_spaces();
        if (*input == '*') {
            input++;
            left *= parse_atom();
        } else if (*input == '/') {
            input++;
            long right = parse_atom();
            if (right == 0) {
                puts_fd1("error: division by zero\n");
                err = 1;
                return 0;
            }
            left /= right;
        } else {
            break;
        }
        if (err) return 0;
    }
    return left;
}

static long parse_expr(void)
{
    long left = parse_term();

    for (;;) {
        skip_spaces();
        if (*input == '+') {
            input++;
            left += parse_term();
        } else if (*input == '-') {
            input++;
            left -= parse_term();
        } else {
            break;
        }
        if (err) return 0;
    }
    return left;
}

static int run_expr(const char *expr, long expected)
{
    input = expr;
    err = 0;
    long result = parse_expr();
    skip_spaces();
    if (err || *input != '\0')
        return 0;
    return (result == expected);
}

int main(int argc, char **argv)
{
    if (argc >= 2) {
        input = argv[1];
        err = 0;
        long result = parse_expr();
        skip_spaces();
        if (err || *input != '\0') {
            puts_fd1("error: invalid expression\n");
            return 1;
        }
        print_long(result);
        puts_fd1("\n");
        return 0;
    }

    /* Self-test mode (no arguments). */
    puts_fd1("calc: self-test\n");
    int ok = 1;
    ok = ok && run_expr("2+3", 5);
    ok = ok && run_expr("10-3*2", 4);
    ok = ok && run_expr("(1+2)*3", 9);
    ok = ok && run_expr("-5+10", 5);
    ok = ok && run_expr("100/10", 10);

    if (ok) {
        puts_fd1("calc: PASSED\n");
        return 0;
    } else {
        puts_fd1("calc: FAILED\n");
        return 1;
    }
}
