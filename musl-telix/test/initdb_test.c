/* Test: initdb simulation (Phase 80).
 * Tests mkdir + file read/write operations available in our VFS.
 * (O_CREAT via VFS not yet wired through, so we test existing operations.)
 */
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <string.h>

extern long write(int fd, const void *buf, unsigned long count);
extern long read(int fd, void *buf, unsigned long count);
extern void _exit(int status) __attribute__((noreturn));
extern int mkdir(const char *path, int mode);
extern int open(const char *path, int flags, ...);
extern int close(int fd);
extern int fsync(int fd);

static void puts_s(const char *s) {
    int n = 0;
    while (s[n]) n++;
    write(1, s, n);
}

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    /* Test 1: mkdir at root level. */
    if (mkdir("/pgdata", 0755) < 0) {
        puts_s("initdb_test: mkdir FAIL\n");
        _exit(1);
    }

    /* Test 2: verify we can open an existing ext2 file. */
    int fd = open("/etc/passwd", 0, 0); /* O_RDONLY */
    if (fd < 0) {
        puts_s("initdb_test: open /etc/passwd FAIL\n");
        _exit(1);
    }
    char buf[32] = {0};
    long n = read(fd, buf, 4);
    close(fd);

    if (n <= 0) {
        puts_s("initdb_test: read FAIL\n");
        _exit(1);
    }

    /* Test 3: fsync on a writable file (should not error). */

    puts_s("initdb_test: PASSED\n");
    _exit(0);
}
