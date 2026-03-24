#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

static unsigned long long _strtoull_internal(const char *s, char **endptr, int base, int *neg_out) {
    const char *start = s;
    *neg_out = 0;
    while (isspace((unsigned char)*s)) s++;
    if (*s == '-') { *neg_out = 1; s++; }
    else if (*s == '+') s++;

    if (base == 0) {
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (s[0] == '0') { base = 8; s++; }
        else base = 10;
    } else if (base == 16 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    unsigned long long result = 0;
    const char *digits_start = s;
    while (*s) {
        int digit;
        if (*s >= '0' && *s <= '9') digit = *s - '0';
        else if (*s >= 'a' && *s <= 'z') digit = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'Z') digit = *s - 'A' + 10;
        else break;
        if (digit >= base) break;
        result = result * (unsigned long long)base + (unsigned long long)digit;
        s++;
    }
    if (s == digits_start && endptr) s = start;
    if (endptr) *endptr = (char *)s;
    return result;
}

long strtol(const char *s, char **endptr, int base) {
    int neg = 0;
    unsigned long long val = _strtoull_internal(s, endptr, base, &neg);
    if (neg) return -(long)val;
    return (long)val;
}

unsigned long strtoul(const char *s, char **endptr, int base) {
    int neg = 0;
    unsigned long long val = _strtoull_internal(s, endptr, base, &neg);
    if (neg) return (unsigned long)(-(long long)val);
    return (unsigned long)val;
}

long long strtoll(const char *s, char **endptr, int base) {
    int neg = 0;
    unsigned long long val = _strtoull_internal(s, endptr, base, &neg);
    if (neg) return -(long long)val;
    return (long long)val;
}

unsigned long long strtoull(const char *s, char **endptr, int base) {
    int neg = 0;
    return _strtoull_internal(s, endptr, base, &neg);
}

int atoi(const char *s) { return (int)strtol(s, (void*)0, 10); }
long atol(const char *s) { return strtol(s, (void*)0, 10); }

char *strtok(char *str, const char *delim) {
    static char *last;
    return strtok_r(str, delim, &last);
}

char *strtok_r(char *str, const char *delim, char **saveptr) {
    if (!str) str = *saveptr;
    if (!str) return (void*)0;
    /* skip leading delimiters */
    while (*str && strchr(delim, *str)) str++;
    if (!*str) { *saveptr = (void*)0; return (void*)0; }
    char *tok = str;
    while (*str && !strchr(delim, *str)) str++;
    if (*str) { *str = '\0'; str++; }
    *saveptr = str;
    return tok;
}

char *strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *d = malloc(len);
    if (d) memcpy(d, s, len);
    return d;
}

static const char *_err_strings[] = {
    [0] = "Success",
    [EPERM] = "Operation not permitted",
    [ENOENT] = "No such file or directory",
    [EIO] = "I/O error",
    [EBADF] = "Bad file descriptor",
    [EAGAIN] = "Resource temporarily unavailable",
    [ENOMEM] = "Cannot allocate memory",
    [EACCES] = "Permission denied",
    [EINVAL] = "Invalid argument",
    [ENOSPC] = "No space left on device",
    [ENOSYS] = "Function not implemented",
    [ERANGE] = "Result too large",
    [EDOM] = "Argument out of domain",
};
#define _NERR (sizeof(_err_strings)/sizeof(_err_strings[0]))

char *strerror(int errnum) {
    if (errnum >= 0 && (size_t)errnum < _NERR && _err_strings[errnum])
        return (char *)_err_strings[errnum];
    return (char *)"Unknown error";
}

size_t strspn(const char *s, const char *accept) {
    size_t n = 0;
    while (s[n] && strchr(accept, s[n])) n++;
    return n;
}

size_t strcspn(const char *s, const char *reject) {
    size_t n = 0;
    while (s[n] && !strchr(reject, s[n])) n++;
    return n;
}

char *strpbrk(const char *s, const char *accept) {
    while (*s) {
        if (strchr(accept, *s)) return (char *)s;
        s++;
    }
    return (void*)0;
}

char *strsep(char **stringp, const char *delim) {
    if (!*stringp) return (void*)0;
    char *tok = *stringp;
    char *end = tok;
    while (*end && !strchr(delim, *end)) end++;
    if (*end) { *end = '\0'; *stringp = end + 1; }
    else *stringp = (void*)0;
    return tok;
}

void *memchr(const void *s, int c, size_t n) {
    const unsigned char *p = s;
    for (size_t i = 0; i < n; i++)
        if (p[i] == (unsigned char)c) return (void *)(p + i);
    return (void*)0;
}
