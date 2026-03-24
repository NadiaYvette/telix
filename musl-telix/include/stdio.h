/* Stdio for Telix — fd-based printf + FILE* streams. */
#ifndef STDIO_H
#define STDIO_H

#include <telix/types.h>
#include <stdarg.h>

#define STDOUT_FD 1
#define STDERR_FD 2

/* printf family (fd-based, from printf.c) */
int  printf(const char *fmt, ...);
int  fprintf(int fd, const char *fmt, ...);
int  snprintf(char *buf, size_t size, const char *fmt, ...);
int  vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
int  puts(const char *s);
int  putchar(int c);

/* ---- FILE stream support ---- */

#define _IO_READ  1
#define _IO_WRITE 2
#define _IO_EOF   4
#define _IO_ERR   8

#define _IONBF 0
#define _IOLBF 1
#define _IOFBF 2

#define BUFSIZ 1024
#define EOF    (-1)
#define FOPEN_MAX 16
#define FILENAME_MAX 256

typedef struct _FILE {
    int fd;
    int flags;
    int bufmode;
    unsigned char buf[BUFSIZ];
    int buf_size;
    int buf_pos;
    int buf_len;
    int ungetc_buf;   /* -1 if empty */
} FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

FILE   *fopen(const char *path, const char *mode);
int     fclose(FILE *f);
size_t  fread(void *ptr, size_t size, size_t nmemb, FILE *f);
size_t  fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f);
char   *fgets(char *s, int n, FILE *f);
int     fputs_file(const char *s, FILE *f);
int     fflush(FILE *f);
int     fseek(FILE *f, long offset, int whence);
long    ftell(FILE *f);
void    rewind(FILE *f);
int     feof(FILE *f);
int     ferror(FILE *f);
void    clearerr(FILE *f);
int     fgetc(FILE *f);
int     fputc(int c, FILE *f);
int     ungetc(int c, FILE *f);
int     setvbuf(FILE *f, char *buf, int mode, size_t size);
int     fileno(FILE *f);
int     getc(FILE *f);
int     putc(int c, FILE *f);

/* Keep the old fd-based fputs for backward compat. */
int     fputs(const char *s, int fd);

#endif /* STDIO_H */
