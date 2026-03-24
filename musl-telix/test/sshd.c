/* sshd — SSH-2 server for Telix.
 *
 * Binds TCP port 22, accepts connections, performs SSH-2 handshake
 * (curve25519-sha256 KEX, ssh-ed25519 host key, chacha20-poly1305@openssh.com),
 * password auth via /etc/passwd, PTY allocation, fork+exec tsh, relay loop.
 */
#include <telix/ssh.h>
#include <telix/crypto.h>
#include <telix/socket.h>
#include <telix/ipc.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <telix/syscall.h>
#include <telix/fd.h>

/* -- PTY IPC (direct to pty_srv) -- */

#define PTY_OPEN      0x9000
#define PTY_OPEN_OK   0x9001
#define PTY_WRITE_TAG 0x9010
#define PTY_WRITE_OK  0x9011
#define PTY_READ_TAG  0x9020
#define PTY_READ_OK   0x9021
#define PTY_CLOSE_TAG 0x9030
#define PTY_POLL_TAG  0x9050
#define PTY_POLL_OK   0x9051
#define PTY_EOF       0x90FF

static uint32_t pty_port_cached = 0;

static uint32_t get_pty_port(void) {
    if (!pty_port_cached)
        pty_port_cached = telix_ns_lookup("pty", 3);
    return pty_port_cached;
}

static int pty_open(uint32_t *master_h, uint32_t *slave_h) {
    uint32_t port = get_pty_port();
    if (!port) return -1;

    uint32_t rp = telix_port_create();
    telix_send(port, PTY_OPEN, 0, 0, (uint64_t)rp << 32, (uint64_t)(uint32_t)getpid());

    struct telix_msg msg;
    if (telix_recv_msg(rp, &msg) < 0 || msg.tag != PTY_OPEN_OK) {
        telix_port_destroy(rp);
        return -1;
    }
    *master_h = (uint32_t)(msg.data[0] & 0xFFFFFFFF);
    *slave_h  = (uint32_t)(msg.data[0] >> 32);
    telix_port_destroy(rp);
    return 0;
}

static int pty_write_chunk(uint32_t handle, const uint8_t *data, int len) {
    uint32_t port = get_pty_port();
    if (!port || len <= 0) return -1;
    if (len > 16) len = 16;

    uint64_t w0 = 0, w1 = 0;
    for (int i = 0; i < len; i++) {
        if (i < 8) w0 |= (uint64_t)data[i] << (i * 8);
        else       w1 |= (uint64_t)data[i] << ((i - 8) * 8);
    }

    uint32_t rp = telix_port_create();
    telix_send(port, PTY_WRITE_TAG, (uint64_t)handle, w0,
               (uint64_t)len | ((uint64_t)rp << 32), w1);

    struct telix_msg msg;
    int ok = (telix_recv_msg(rp, &msg) >= 0 && msg.tag == PTY_WRITE_OK);
    telix_port_destroy(rp);
    return ok ? len : -1;
}

static int pty_write_all(uint32_t handle, const uint8_t *data, int len) {
    int off = 0;
    while (off < len) {
        int chunk = len - off;
        if (chunk > 16) chunk = 16;
        int n = pty_write_chunk(handle, data + off, chunk);
        if (n < 0) return -1;
        off += n;
    }
    return 0;
}

/* Poll PTY master for readable data. Returns 1 if data available, 0 if not. */
static int pty_poll_readable(uint32_t handle) {
    uint32_t port = get_pty_port();
    if (!port) return 0;

    uint32_t rp = telix_port_create();
    /* POLLIN = 0x0001 */
    telix_send(port, PTY_POLL_TAG, (uint64_t)handle, 0,
               1 | ((uint64_t)rp << 32), 0);

    struct telix_msg msg;
    int readable = 0;
    if (telix_recv_msg(rp, &msg) >= 0 && msg.tag == PTY_POLL_OK) {
        readable = (msg.data[0] & 1) ? 1 : 0; /* POLLIN set? */
        /* Also check for POLLHUP (0x10). */
        if (msg.data[0] & 0x10) readable = 1; /* Will get EOF on read. */
    }
    telix_port_destroy(rp);
    return readable;
}

/* Read from PTY master. Blocks until data available. */
static int pty_read(uint32_t handle, uint8_t *buf, int maxlen) {
    uint32_t port = get_pty_port();
    if (!port) return -1;

    uint32_t rp = telix_port_create();
    telix_send(port, PTY_READ_TAG, (uint64_t)handle, 0, (uint64_t)rp << 32, 0);

    struct telix_msg msg;
    if (telix_recv_msg(rp, &msg) < 0) {
        telix_port_destroy(rp);
        return -1;
    }
    telix_port_destroy(rp);

    if (msg.tag == PTY_READ_OK) {
        int n = (int)(msg.data[2] & 0xFFFF);
        if (n > maxlen) n = maxlen;
        uint8_t b0[8], b1[8];
        for (int i = 0; i < 8; i++) b0[i] = (uint8_t)(msg.data[0] >> (i*8));
        for (int i = 0; i < 8; i++) b1[i] = (uint8_t)(msg.data[1] >> (i*8));
        for (int i = 0; i < n; i++)
            buf[i] = (i < 8) ? b0[i] : b1[i-8];
        return n;
    } else if (msg.tag == PTY_EOF) {
        return 0;
    }
    return -1;
}

static void pty_close(uint32_t handle) {
    uint32_t port = get_pty_port();
    if (!port) return;
    uint32_t rp = telix_port_create();
    telix_send(port, PTY_CLOSE_TAG, (uint64_t)handle, 0, (uint64_t)rp << 32, 0);
    struct telix_msg msg;
    telix_recv_msg(rp, &msg);
    telix_port_destroy(rp);
}

/* -- Non-blocking TCP recv (from socket.c) -- */
ssize_t recv_nb(int sockfd, void *buf, size_t len);

/* -- Relay loop: single-threaded, cooperative -- */

static void relay_loop(ssh_transport *t, ssh_channel *ch, uint32_t master_h) {
    uint8_t pty_buf[256];

    for (;;) {
        int did_work = 0;

        /* Direction 1: SSH -> PTY.
         * Check TCP socket for data using non-blocking recv. */
        {
            uint8_t peek;
            ssize_t n = recv_nb(t->fd, &peek, 0);
            if (n >= 0) {
                /* Data available on TCP socket. Read a full SSH packet. */
                uint8_t payload[SSH_MAX_PAYLOAD];
                int plen = ssh_recv_packet(t, payload);
                if (plen < 1) break;

                uint8_t pty_data[SSH_MAX_PAYLOAD];
                int pty_data_len;
                int rc = ssh_channel_process_packet(t, ch, payload, plen,
                                                     pty_data, &pty_data_len);
                if (rc == 1) break; /* Channel closed. */
                if (rc < 0) break;
                if (pty_data_len > 0) {
                    pty_write_all(master_h, pty_data, pty_data_len);
                }
                did_work = 1;
            }
        }

        /* Direction 2: PTY -> SSH.
         * Poll PTY master for readable data. */
        if (pty_poll_readable(master_h)) {
            int n = pty_read(master_h, pty_buf, sizeof(pty_buf));
            if (n > 0) {
                ssh_channel_send_data(t, ch, pty_buf, n);
                did_work = 1;
            } else if (n == 0) {
                /* Shell exited (PTY EOF). */
                break;
            }
        }

        if (!did_work)
            __telix_syscall0(SYS_YIELD);
    }

    ssh_channel_close(t, ch);
}

/* -- Handle one SSH connection -- */

static void handle_connection(int client_fd, const uint8_t *host_pk, const uint8_t *host_sk) {
    ssh_transport transport;
    ssh_transport_init(&transport, client_fd, host_pk, host_sk);

    /* Version exchange. */
    if (ssh_version_exchange(&transport) != 0) {
        printf("sshd: version exchange failed\n");
        return;
    }

    /* Key exchange. */
    if (ssh_key_exchange(&transport) != 0) {
        printf("sshd: key exchange failed\n");
        return;
    }
    printf("sshd: key exchange OK\n");

    /* Service request (ssh-userauth). */
    if (ssh_handle_service_request(&transport) != 0) {
        printf("sshd: service request failed\n");
        return;
    }

    /* User authentication. */
    if (ssh_handle_userauth(&transport) != 0) {
        printf("sshd: auth failed\n");
        return;
    }
    printf("sshd: auth OK\n");

    /* Channel open. */
    ssh_channel channels[SSH_MAX_CHANNELS];
    memset(channels, 0, sizeof(channels));
    int ch_idx = ssh_handle_channel_open(&transport, channels);
    if (ch_idx < 0) {
        printf("sshd: channel open failed\n");
        return;
    }

    /* Wait for pty-req + shell request. */
    ssh_channel *ch = &channels[ch_idx];
    for (int i = 0; i < 10 && !ch->shell_started; i++) {
        uint8_t payload[SSH_MAX_PAYLOAD];
        int len = ssh_recv_packet(&transport, payload);
        if (len < 1) break;

        if (payload[0] == SSH_MSG_CHANNEL_REQUEST) {
            int want_reply;
            int rc = ssh_handle_channel_request(&transport, ch, payload, len, &want_reply);
            if (rc == 1) break;
        } else if (payload[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
            if (len >= 9) ch->remote_window += ssh_get_uint32(payload + 5);
        }
    }

    if (!ch->shell_started) {
        printf("sshd: no shell requested\n");
        return;
    }

    /* Allocate PTY. */
    uint32_t master_h, slave_h;
    if (pty_open(&master_h, &slave_h) != 0) {
        printf("sshd: PTY alloc failed\n");
        return;
    }
    printf("sshd: PTY allocated\n");

    /* Fork + exec shell. */
    pid_t child = fork();
    if (child < 0) {
        printf("sshd: fork failed\n");
        pty_close(master_h);
        pty_close(slave_h);
        return;
    }

    if (child == 0) {
        /* Child: redirect stdin/stdout/stderr to PTY slave, exec tsh. */
        pty_close(master_h);

        /* Rewire fd 0/1/2 to PTY slave via fd table. */
        uint32_t pp = get_pty_port();
        for (int i = 0; i < 3; i++) {
            telix_fd_close(i);
            telix_fd_set_typed(i, pp, slave_h, FD_TYPE_PTY, 0);
        }

        char *argv[] = { "tsh", (char *)0 };
        char *envp[] = { "TERM=xterm", "HOME=/", "PATH=/bin", (char *)0 };
        execve("/bin/tsh", argv, envp);
        _exit(1);
    }

    /* Parent: close slave, relay. */
    pty_close(slave_h);
    printf("sshd: shell pid=%d, relaying\n", (int)child);
    relay_loop(&transport, ch, master_h);

    pty_close(master_h);
    printf("sshd: session ended\n");
}

/* -- Main -- */

int main(int arg0, int arg1, int arg2) {
    (void)arg0; (void)arg1; (void)arg2;

    printf("sshd: starting\n");
    csprng_init();

    /* Generate host key from random seed. */
    uint8_t host_pk[32], host_sk[64], seed[32];
    csprng_bytes(seed, 32);
    ed25519_create_keypair(host_pk, host_sk, seed);

    /* Create server socket. */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { printf("sshd: socket failed\n"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    addr.sin_addr = 0;

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("sshd: bind failed\n"); return 1;
    }
    if (listen(srv, 1) < 0) {
        printf("sshd: listen failed\n"); return 1;
    }
    printf("sshd: listening on port 22\n");

    for (;;) {
        struct sockaddr_in ca;
        socklen_t al = sizeof(ca);
        int client = accept(srv, (struct sockaddr *)&ca, &al);
        if (client < 0) { printf("sshd: accept failed\n"); continue; }

        printf("sshd: connection accepted\n");
        handle_connection(client, host_pk, host_sk);
        shutdown(client, SHUT_RDWR);
    }

    return 0;
}
