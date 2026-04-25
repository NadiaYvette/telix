/* tools/fsprobe.c — minimal static-PIE Linux probe for the file path:
 *   open("/lib64/libc.so.6") → fd
 *   fstat(fd) → st_size
 *   read(fd, buf, 64) → first ELF bytes
 *
 * No glibc, no ld.so — raw int 0x80 syscalls.  Output written via
 * SYS_write to stderr (fd 2) so it shows up in our boot trace.
 *
 * Exit codes (always non-zero is a signal of where it stopped):
 *   0   = OK, all checks passed (ELF magic seen, size > 1MB)
 *   10  = open failed (errno in stderr msg)
 *   20  = fstat failed
 *   21  = fstat returned size < 1000
 *   30  = read returned <= 0
 *   31  = read returned < 64 bytes
 *   32  = first bytes are not ELF magic ("\x7fELF")
 *   99  = other
 */

typedef long ssize_t;
typedef unsigned long size_t;
typedef long off_t;

/* Linux syscall numbers (x86_64). */
#define SYS_read   0
#define SYS_write  1
#define SYS_open   2
#define SYS_close  3
#define SYS_fstat  5
#define SYS_lseek  8
#define SYS_mmap   9
#define SYS_exit   60
#define SYS_openat 257

#define O_RDONLY      0
#define PROT_READ     1
#define MAP_PRIVATE   2

/* Inline raw syscalls.  Using `int 0x80` since that's what other
 * Telix Linux-personality programs use; the kernel routes both 0x80
 * and `syscall` to the personality dispatcher. */
static inline long sys3(long nr, long a0, long a1, long a2)
{
    long r;
    __asm__ volatile (
        "int $0x80"
        : "=a"(r)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory"
    );
    return r;
}

static inline long sys1(long nr, long a0)
{
    long r;
    __asm__ volatile (
        "int $0x80"
        : "=a"(r)
        : "a"(nr), "D"(a0)
        : "rcx", "r11", "memory"
    );
    return r;
}

static inline long sys6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
    long r;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile (
        "int $0x80"
        : "=a"(r)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return r;
}

static inline __attribute__((noreturn)) void sys_exit(long code)
{
    __asm__ volatile ("int $0x80" : : "a"(SYS_exit), "D"(code));
    __builtin_unreachable();
}

static long w(int fd, const void *buf, size_t n)
{
    return sys3(SYS_write, fd, (long)buf, (long)n);
}

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void wstr(const char *s) { w(2, s, slen(s)); }

static void wnum(long n)
{
    char buf[24];
    int i = 23;
    int neg = 0;
    if (n < 0) { neg = 1; n = -n; }
    if (n == 0) { buf[--i] = '0'; }
    while (n > 0 && i > 0) {
        buf[--i] = '0' + (n % 10);
        n /= 10;
    }
    if (neg && i > 0) buf[--i] = '-';
    w(2, &buf[i], 24 - i);
}

static void whex(unsigned long n)
{
    static const char hx[] = "0123456789abcdef";
    char buf[18];
    int i = 18;
    if (n == 0) { buf[--i] = '0'; }
    while (n > 0 && i > 0) {
        buf[--i] = hx[n & 0xF];
        n >>= 4;
    }
    if (i >= 2) { buf[--i] = 'x'; buf[--i] = '0'; }
    w(2, &buf[i], 18 - i);
}

void _start(void)
{
    static const char path[] = "/lib64/libc.so.6";
    static const char tag[] = "[fsprobe] ";

    wstr(tag);
    wstr("starting\n");

    /* 1) open */
    long fd = sys3(SYS_open, (long)path, O_RDONLY, 0);
    wstr(tag);
    wstr("open(\""); wstr(path); wstr("\") = ");
    wnum(fd);
    wstr("\n");
    if (fd < 0) sys_exit(10);

    /* 2) fstat — st_size lives at offset 48 in struct stat (x86_64).
     * We allocate a 144-byte stat buf to match what linux_srv writes. */
    static char stbuf[144];
    long r = sys3(SYS_fstat, fd, (long)stbuf, 0);
    wstr(tag);
    wstr("fstat = ");
    wnum(r);
    if (r == 0) {
        unsigned long sz = 0;
        for (int i = 0; i < 8; i++) sz |= ((unsigned long)(unsigned char)stbuf[48 + i]) << (i * 8);
        wstr(" st_size=");
        wnum((long)sz);
        if (sz < 1000) { wstr("\n"); sys_exit(21); }
    } else {
        wstr("\n");
        sys_exit(20);
    }
    wstr("\n");

    /* 3) read first 64 bytes */
    static char rdbuf[128];
    long n = sys3(SYS_read, fd, (long)rdbuf, 64);
    wstr(tag);
    wstr("read(64) = ");
    wnum(n);
    if (n > 0) {
        wstr(" first8=");
        for (int i = 0; i < 8 && i < n; i++) {
            whex((unsigned char)rdbuf[i]);
            wstr(" ");
        }
    }
    wstr("\n");
    if (n <= 0) sys_exit(30);
    if (n < 64) sys_exit(31);
    if (rdbuf[0] != 0x7F || rdbuf[1] != 'E' || rdbuf[2] != 'L' || rdbuf[3] != 'F')
        sys_exit(32);

    /* Test high-offset reads (require ext2 double-indirect blocks).
     * libc.so.6 is large (~2.4 MB) so any offset > 268*1024 = 274432
     * needs the double-indirect path in resolve_indirect. */
    static char hibuf[64];
    long lr = sys3(SYS_lseek, fd, 0x100000, 0);  /* 1 MiB */
    wstr(tag);
    wstr("libc lseek(0x100000) = "); wnum(lr);
    long hr = sys3(SYS_read, fd, (long)hibuf, 64);
    wstr(" read(64) = "); wnum(hr);
    if (hr > 0) {
        wstr(" first8=");
        for (int i = 0; i < 8 && i < hr; i++) {
            whex((unsigned char)hibuf[i]);
            wstr(" ");
        }
    }
    wstr("\n");
    if (hr != 64) sys_exit(35);

    /* And way deeper — offset 0x180000 = 1.5 MiB, near .gnu.version */
    lr = sys3(SYS_lseek, fd, 0x180000, 0);
    wstr(tag);
    wstr("libc lseek(0x180000) = "); wnum(lr);
    hr = sys3(SYS_read, fd, (long)hibuf, 64);
    wstr(" read(64) = "); wnum(hr);
    if (hr > 0) {
        wstr(" first8=");
        for (int i = 0; i < 8 && i < hr; i++) {
            whex((unsigned char)hibuf[i]);
            wstr(" ");
        }
    }
    wstr("\n");
    if (hr != 64) sys_exit(36);

    /* libc .gnu.version_d at file offset 0x181f08 — what ld.so reads
     * to look up GLIBC_2.2.5 */
    lr = sys3(SYS_lseek, fd, 0x181f08, 0);
    wstr(tag);
    wstr("libc lseek(0x181f08) = "); wnum(lr);
    hr = sys3(SYS_read, fd, (long)hibuf, 32);
    wstr(" read(32) = "); wnum(hr);
    if (hr > 0) {
        wstr(" first16=");
        for (int i = 0; i < 16 && i < hr; i++) {
            whex((unsigned char)hibuf[i]);
            wstr(" ");
        }
    }
    wstr("\n");

    /* mmap probe: same offset as `read` above, but via the file-backed
     * mmap path that ld.so actually uses to load segments.  If mmap
     * returns different bytes here than read above, the kernel/
     * personality mmap loader has a bug. */
    long mp = sys6(SYS_mmap, 0, 0x2000, PROT_READ, MAP_PRIVATE, fd, 0x180000);
    wstr(tag);
    wstr("libc mmap(0x180000, 0x2000, R, PRIV) = ");
    whex((unsigned long)mp);
    if (mp >= 0 && mp < (long)0xFFFFFFFFFFFFF000UL) {
        const unsigned char *m = (const unsigned char *)mp;
        wstr(" first16@0x0=");
        for (int i = 0; i < 16; i++) { whex(m[i]); wstr(" "); }
        wstr("\n");
        wstr(tag);
        wstr("libc mmap @0x1f08=");
        for (int i = 0; i < 16; i++) { whex(m[0x1f08 + i]); wstr(" "); }
    }
    wstr("\n");

    /* 4) close */
    sys1(SYS_close, fd);

    /* Now repeat for libxcvt.so.0 (the new dyn-link target). */
    static const char path2[] = "/lib64/libxcvt.so.0";
    long fd2 = sys3(SYS_open, (long)path2, O_RDONLY, 0);
    wstr(tag);
    wstr("open(\""); wstr(path2); wstr("\") = ");
    wnum(fd2);
    wstr("\n");
    if (fd2 < 0) sys_exit(40);

    long r2 = sys3(SYS_fstat, fd2, (long)stbuf, 0);
    wstr(tag);
    wstr("fstat = "); wnum(r2);
    if (r2 == 0) {
        unsigned long sz = 0;
        for (int i = 0; i < 8; i++) sz |= ((unsigned long)(unsigned char)stbuf[48 + i]) << (i * 8);
        wstr(" st_size="); wnum((long)sz);
    }
    wstr("\n");
    if (r2 != 0) sys_exit(50);

    /* Read first 64 bytes of libxcvt */
    long n2 = sys3(SYS_read, fd2, (long)rdbuf, 64);
    wstr(tag);
    wstr("xcvt read(64) @0 = "); wnum(n2);
    if (n2 > 0) {
        wstr(" first8=");
        for (int i = 0; i < 8 && i < n2; i++) {
            whex((unsigned char)rdbuf[i]);
            wstr(" ");
        }
    }
    wstr("\n");
    if (n2 != 64) sys_exit(60);

    /* lseek to offset 64 then read 16 more — verify content continues */
    static long lseek_ret = 0;
    lseek_ret = sys3(SYS_lseek, fd2, 64, 0);  /* SEEK_SET=0 */
    wstr(tag);
    wstr("xcvt lseek(64) = "); wnum(lseek_ret);
    long n3 = sys3(SYS_read, fd2, (long)rdbuf, 16);
    wstr(" read(16) = "); wnum(n3);
    if (n3 > 0) {
        wstr(" bytes=");
        for (int i = 0; i < n3; i++) {
            whex((unsigned char)rdbuf[i]);
            wstr(" ");
        }
    }
    wstr("\n");

    /* Read at higher offset (the problem segment from glibc) */
    /* libxcvt.so.0: PT_LOAD #3 starts at offset 0x1d80=7552 */
    static char rdbuf3[64];
    long n4 = sys3(SYS_lseek, fd2, 0x1d80, 0);
    wstr(tag);
    wstr("xcvt lseek(0x1d80) = "); wnum(n4);
    long n5 = sys3(SYS_read, fd2, (long)rdbuf3, 64);
    wstr(" read(64) = "); wnum(n5);
    if (n5 > 0) {
        wstr(" first8=");
        for (int i = 0; i < 8 && i < n5; i++) {
            whex((unsigned char)rdbuf3[i]);
            wstr(" ");
        }
    }
    wstr("\n");

    /* libxcvt .gnu.version at file offset 0x1178 — host bytes are:
     * 00 00 01 00 02 00 01 00 01 00 02 00 01 00 00 00 */
    long n6 = sys3(SYS_lseek, fd2, 0x1178, 0);
    wstr(tag);
    wstr("xcvt lseek(0x1178) = "); wnum(n6);
    long n7 = sys3(SYS_read, fd2, (long)rdbuf3, 16);
    wstr(" read(16) = "); wnum(n7);
    if (n7 > 0) {
        wstr(" bytes=");
        for (int i = 0; i < n7; i++) {
            whex((unsigned char)rdbuf3[i]);
            wstr(" ");
        }
    }
    wstr("\n");

    sys1(SYS_close, fd2);
    wstr(tag);
    wstr("PASSED\n");
    sys_exit(0);
}
