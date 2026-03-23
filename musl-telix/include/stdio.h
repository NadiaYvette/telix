/* Minimal stdio for Telix. */
#ifndef STDIO_H
#define STDIO_H

#include <telix/types.h>
#include <stdarg.h>

#define STDOUT_FD 1
#define STDERR_FD 2

int  printf(const char *fmt, ...);
int  fprintf(int fd, const char *fmt, ...);
int  snprintf(char *buf, size_t size, const char *fmt, ...);
int  vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
int  puts(const char *s);
int  putchar(int c);
int  fputs(const char *s, int fd);

#endif /* STDIO_H */
