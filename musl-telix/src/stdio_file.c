/* FILE stream implementation for Telix.
 * No floating-point code — safe for -mgeneral-regs-only.
 */
#include <stdio.h>
#include <string.h>

/* Syscall wrappers defined in other .c files. */
extern int     open(const char *path, int flags);
extern int     close(int fd);
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
extern off_t   lseek(int fd, off_t offset, int whence);

/* Static FILE objects for the standard streams. */
static FILE _stdin_file  = { .fd = 0, .flags = _IO_READ,  .bufmode = _IONBF, .buf_size = BUFSIZ, .buf_pos = 0, .buf_len = 0, .ungetc_buf = -1 };
static FILE _stdout_file = { .fd = 1, .flags = _IO_WRITE, .bufmode = _IOLBF, .buf_size = BUFSIZ, .buf_pos = 0, .buf_len = 0, .ungetc_buf = -1 };
static FILE _stderr_file = { .fd = 2, .flags = _IO_WRITE, .bufmode = _IONBF, .buf_size = BUFSIZ, .buf_pos = 0, .buf_len = 0, .ungetc_buf = -1 };

FILE *stdin  = &_stdin_file;
FILE *stdout = &_stdout_file;
FILE *stderr = &_stderr_file;

/* Pool of FILE structs for fopen. */
static FILE _file_pool[FOPEN_MAX];
static int  _file_pool_used[FOPEN_MAX];

static FILE *_alloc_file(void) {
    for (int i = 0; i < FOPEN_MAX; i++) {
        if (!_file_pool_used[i]) {
            _file_pool_used[i] = 1;
            memset(&_file_pool[i], 0, sizeof(FILE));
            _file_pool[i].ungetc_buf = -1;
            _file_pool[i].buf_size = BUFSIZ;
            return &_file_pool[i];
        }
    }
    return (void *)0;
}

static void _free_file(FILE *f) {
    for (int i = 0; i < FOPEN_MAX; i++) {
        if (&_file_pool[i] == f) {
            _file_pool_used[i] = 0;
            return;
        }
    }
}

FILE *fopen(const char *path, const char *mode) {
    int flags = 0;
    int fflags = 0;

    if (mode[0] == 'r') {
        flags = 0x0000; /* O_RDONLY */
        fflags = _IO_READ;
        if (mode[1] == '+') { flags = 0x0002; fflags = _IO_READ | _IO_WRITE; } /* O_RDWR */
    } else if (mode[0] == 'w') {
        flags = 0x0001 | 0x0040 | 0x0200; /* O_WRONLY | O_CREAT | O_TRUNC */
        fflags = _IO_WRITE;
        if (mode[1] == '+') { flags = 0x0002 | 0x0040 | 0x0200; fflags = _IO_READ | _IO_WRITE; }
    } else if (mode[0] == 'a') {
        flags = 0x0001 | 0x0040 | 0x0400; /* O_WRONLY | O_CREAT | O_APPEND */
        fflags = _IO_WRITE;
        if (mode[1] == '+') { flags = 0x0002 | 0x0040 | 0x0400; fflags = _IO_READ | _IO_WRITE; }
    } else {
        return (void *)0;
    }

    int fd = open(path, flags);
    if (fd < 0) return (void *)0;

    FILE *f = _alloc_file();
    if (!f) { close(fd); return (void *)0; }

    f->fd = fd;
    f->flags = fflags;
    f->bufmode = _IOFBF;
    f->buf_pos = 0;
    f->buf_len = 0;
    return f;
}

int fclose(FILE *f) {
    if (!f) return EOF;
    fflush(f);
    int ret = close(f->fd);
    _free_file(f);
    return ret;
}

int fflush(FILE *f) {
    if (!f) return 0;
    if ((f->flags & _IO_WRITE) && f->buf_pos > 0) {
        ssize_t w = write(f->fd, f->buf, (size_t)f->buf_pos);
        if (w < 0) { f->flags |= _IO_ERR; return EOF; }
        f->buf_pos = 0;
    }
    return 0;
}

static int _fill_buf(FILE *f) {
    if (f->ungetc_buf >= 0) return 0; /* data available via ungetc */
    f->buf_pos = 0;
    f->buf_len = 0;
    ssize_t n = read(f->fd, f->buf, (size_t)f->buf_size);
    if (n < 0) { f->flags |= _IO_ERR; return EOF; }
    if (n == 0) { f->flags |= _IO_EOF; return EOF; }
    f->buf_len = (int)n;
    return 0;
}

int fgetc(FILE *f) {
    if (f->ungetc_buf >= 0) {
        int c = f->ungetc_buf;
        f->ungetc_buf = -1;
        return c;
    }
    if (f->bufmode == _IONBF) {
        unsigned char c;
        ssize_t n = read(f->fd, &c, 1);
        if (n <= 0) {
            if (n == 0) f->flags |= _IO_EOF;
            else f->flags |= _IO_ERR;
            return EOF;
        }
        return c;
    }
    if (f->buf_pos >= f->buf_len) {
        if (_fill_buf(f) == EOF) return EOF;
    }
    return f->buf[f->buf_pos++];
}

int fputc(int c, FILE *f) {
    unsigned char ch = (unsigned char)c;
    if (f->bufmode == _IONBF) {
        ssize_t n = write(f->fd, &ch, 1);
        if (n <= 0) { f->flags |= _IO_ERR; return EOF; }
        return ch;
    }
    if (f->buf_pos >= f->buf_size) {
        if (fflush(f) == EOF) return EOF;
    }
    f->buf[f->buf_pos++] = ch;
    if (f->bufmode == _IOLBF && ch == '\n') {
        if (fflush(f) == EOF) return EOF;
    }
    return ch;
}

int ungetc(int c, FILE *f) {
    if (c == EOF) return EOF;
    f->ungetc_buf = c;
    f->flags &= ~_IO_EOF;
    return c;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t total = size * nmemb;
    unsigned char *dst = ptr;
    size_t done = 0;
    while (done < total) {
        int c = fgetc(f);
        if (c == EOF) break;
        dst[done++] = (unsigned char)c;
    }
    return size ? done / size : 0;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t total = size * nmemb;
    const unsigned char *src = ptr;
    size_t done = 0;
    while (done < total) {
        if (fputc(src[done], f) == EOF) break;
        done++;
    }
    return size ? done / size : 0;
}

char *fgets(char *s, int n, FILE *f) {
    if (n <= 0) return (void *)0;
    int i = 0;
    while (i < n - 1) {
        int c = fgetc(f);
        if (c == EOF) {
            if (i == 0) return (void *)0;
            break;
        }
        s[i++] = (char)c;
        if (c == '\n') break;
    }
    s[i] = '\0';
    return s;
}

int fputs_file(const char *s, FILE *f) {
    while (*s) {
        if (fputc(*s, f) == EOF) return EOF;
        s++;
    }
    return 0;
}

int fseek(FILE *f, long offset, int whence) {
    fflush(f);
    f->buf_pos = 0;
    f->buf_len = 0;
    f->ungetc_buf = -1;
    f->flags &= ~_IO_EOF;
    off_t ret = lseek(f->fd, (off_t)offset, whence);
    if (ret < 0) return -1;
    return 0;
}

long ftell(FILE *f) {
    off_t pos = lseek(f->fd, 0, 1 /* SEEK_CUR */);
    if (pos < 0) return -1;
    /* Adjust for buffered read data not yet consumed. */
    if ((f->flags & _IO_READ) && f->buf_len > 0) {
        pos -= (off_t)(f->buf_len - f->buf_pos);
    }
    /* Adjust for buffered write data not yet flushed. */
    if ((f->flags & _IO_WRITE) && f->buf_pos > 0) {
        pos += (off_t)f->buf_pos;
    }
    if (f->ungetc_buf >= 0) pos--;
    return (long)pos;
}

void rewind(FILE *f) {
    fseek(f, 0, 0 /* SEEK_SET */);
    f->flags &= ~_IO_ERR;
}

int feof(FILE *f)    { return (f->flags & _IO_EOF) ? 1 : 0; }
int ferror(FILE *f)  { return (f->flags & _IO_ERR) ? 1 : 0; }
void clearerr(FILE *f) { f->flags &= ~(_IO_EOF | _IO_ERR); }

int setvbuf(FILE *f, char *buf, int mode, size_t size) {
    (void)buf;   /* We use internal buffer only. */
    (void)size;
    f->bufmode = mode;
    return 0;
}

int fileno(FILE *f) { return f->fd; }
int getc(FILE *f)   { return fgetc(f); }
int putc(int c, FILE *f) { return fputc(c, f); }
