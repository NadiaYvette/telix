/* printf family for Telix. Core is vsnprintf. */
#include <stdio.h>
#include <string.h>

/* Forward declaration — defined in write.c */
ssize_t write(int fd, const void *buf, size_t count);

static void put_char(char *buf, size_t size, size_t *pos, char c) {
    if (*pos < size - 1)
        buf[*pos] = c;
    (*pos)++;
}

static void put_str(char *buf, size_t size, size_t *pos,
                    const char *s, int width, int left) {
    int len = 0;
    const char *p = s;
    while (*p++) len++;

    int pad = (width > len) ? width - len : 0;
    if (!left) for (int i = 0; i < pad; i++) put_char(buf, size, pos, ' ');
    for (int i = 0; i < len; i++) put_char(buf, size, pos, s[i]);
    if (left)  for (int i = 0; i < pad; i++) put_char(buf, size, pos, ' ');
}

static void put_uint(char *buf, size_t size, size_t *pos,
                     uint64_t val, int base, int width, char pad_char,
                     int is_neg, int left) {
    char tmp[24];
    int i = 0;
    const char *digits = "0123456789abcdef";

    if (val == 0) tmp[i++] = '0';
    while (val > 0) {
        tmp[i++] = digits[val % base];
        val /= base;
    }
    if (is_neg) tmp[i++] = '-';

    int total = i;
    int pad = (width > total) ? width - total : 0;

    if (!left && pad_char == '0' && is_neg) {
        put_char(buf, size, pos, '-');
        i--; /* don't print '-' again */
        for (int j = 0; j < pad; j++) put_char(buf, size, pos, '0');
        while (i > 0) put_char(buf, size, pos, tmp[--i]);
    } else {
        if (!left) for (int j = 0; j < pad; j++) put_char(buf, size, pos, pad_char);
        while (i > 0) put_char(buf, size, pos, tmp[--i]);
        if (left)  for (int j = 0; j < pad; j++) put_char(buf, size, pos, ' ');
    }
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap) {
    size_t pos = 0;
    if (size == 0) return 0;

    while (*fmt) {
        if (*fmt != '%') {
            put_char(buf, size, &pos, *fmt++);
            continue;
        }
        fmt++; /* skip '%' */

        /* Flags. */
        int left = 0;
        char pad_char = ' ';
        while (*fmt == '-' || *fmt == '0') {
            if (*fmt == '-') left = 1;
            if (*fmt == '0') pad_char = '0';
            fmt++;
        }
        if (left) pad_char = ' '; /* left-align overrides zero-pad */

        /* Width. */
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');

        /* Length modifier. */
        int is_long = 0;
        if (*fmt == 'l') { is_long = 1; fmt++; }
        if (*fmt == 'l') { is_long = 2; fmt++; } /* ll */

        switch (*fmt) {
        case 'd': case 'i': {
            int64_t v;
            if (is_long) v = va_arg(ap, int64_t);
            else v = va_arg(ap, int);
            int neg = (v < 0);
            uint64_t uv = neg ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
            put_uint(buf, size, &pos, uv, 10, width, pad_char, neg, left);
            break;
        }
        case 'u': {
            uint64_t v;
            if (is_long) v = va_arg(ap, uint64_t);
            else v = va_arg(ap, unsigned int);
            put_uint(buf, size, &pos, v, 10, width, pad_char, 0, left);
            break;
        }
        case 'x': {
            uint64_t v;
            if (is_long) v = va_arg(ap, uint64_t);
            else v = va_arg(ap, unsigned int);
            put_uint(buf, size, &pos, v, 16, width, pad_char, 0, left);
            break;
        }
        case 'p': {
            uint64_t v = (uint64_t)va_arg(ap, void *);
            put_char(buf, size, &pos, '0');
            put_char(buf, size, &pos, 'x');
            put_uint(buf, size, &pos, v, 16, 0, '0', 0, 0);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            put_str(buf, size, &pos, s, width, left);
            break;
        }
        case 'c': {
            char c = (char)va_arg(ap, int);
            put_char(buf, size, &pos, c);
            break;
        }
        case '%':
            put_char(buf, size, &pos, '%');
            break;
        default:
            put_char(buf, size, &pos, '%');
            put_char(buf, size, &pos, *fmt);
            break;
        }
        fmt++;
    }

    /* Null-terminate. */
    if (pos < size) buf[pos] = '\0';
    else buf[size - 1] = '\0';

    return (int)pos;
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

int printf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        int len = n;
        if (len > (int)sizeof(buf) - 1) len = (int)sizeof(buf) - 1;
        write(STDOUT_FD, buf, len);
    }
    return n;
}

int fprintf(int fd, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        int len = n;
        if (len > (int)sizeof(buf) - 1) len = (int)sizeof(buf) - 1;
        write(fd, buf, len);
    }
    return n;
}

int puts(const char *s) {
    int len = (int)strlen(s);
    write(STDOUT_FD, s, len);
    write(STDOUT_FD, "\n", 1);
    return len + 1;
}

int putchar(int c) {
    char ch = (char)c;
    write(STDOUT_FD, &ch, 1);
    return c;
}

int fputs(const char *s, int fd) {
    int len = (int)strlen(s);
    write(fd, s, len);
    return len;
}
