/* Phase 58 test: BSD socket API over Unix domain sockets. */
#include <stdint.h>
#include <telix/socket.h>

ssize_t write(int fd, const void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count);
void _exit(int status) __attribute__((noreturn));

static void my_memcpy(char *dst, const char *src, int n) {
    for (int i = 0; i < n; i++) dst[i] = src[i];
}

static int my_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void my_memset(void *p, int c, int n) {
    unsigned char *d = (unsigned char *)p;
    for (int i = 0; i < n; i++) d[i] = (unsigned char)c;
}

int main(uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    (void)arg0; (void)arg1; (void)arg2;

    /* 1. Create server socket, bind, listen. */
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { write(1, "FAIL: socket srv\n", 17); _exit(1); }

    struct sockaddr_un addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    my_memcpy(addr.sun_path, "csock", 5);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        write(1, "FAIL: bind\n", 11); _exit(2);
    }
    if (listen(srv, 4) < 0) {
        write(1, "FAIL: listen\n", 13); _exit(3);
    }

    /* 2. Create client socket and connect. */
    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli < 0) { write(1, "FAIL: socket cli\n", 17); _exit(4); }

    if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        write(1, "FAIL: connect\n", 14); _exit(5);
    }

    /* 3. Accept on server side. */
    int acc = accept(srv, (struct sockaddr *)0, (socklen_t *)0);
    if (acc < 0) { write(1, "FAIL: accept\n", 13); _exit(6); }

    /* 4. Client sends "Hi", server recvs. */
    if (send(cli, "Hi", 2, 0) != 2) {
        write(1, "FAIL: send Hi\n", 14); _exit(7);
    }

    char buf[16];
    ssize_t n = recv(acc, buf, 16, 0);
    if (n != 2 || buf[0] != 'H' || buf[1] != 'i') {
        write(1, "FAIL: recv Hi\n", 14); _exit(8);
    }

    /* 5. Server sends "Ok", client recvs. */
    if (send(acc, "Ok", 2, 0) != 2) {
        write(1, "FAIL: send Ok\n", 14); _exit(9);
    }
    n = recv(cli, buf, 16, 0);
    if (n != 2 || buf[0] != 'O' || buf[1] != 'k') {
        write(1, "FAIL: recv Ok\n", 14); _exit(10);
    }

    /* 6. Test read/write dispatch (write on socket fd, read on socket fd). */
    if (write(cli, "RW", 2) != 2) {
        write(1, "FAIL: write sock\n", 17); _exit(11);
    }
    n = read(acc, buf, 16);
    if (n != 2 || buf[0] != 'R') {
        write(1, "FAIL: read sock\n", 16); _exit(12);
    }

    /* 7. setsockopt stub (should succeed). */
    int val = 1;
    if (setsockopt(cli, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0) {
        write(1, "FAIL: setsockopt\n", 17); _exit(13);
    }

    write(1, "Phase 58 socket API: OK\n", 24);
    _exit(0);
}
