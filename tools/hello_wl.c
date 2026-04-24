/* Minimal Wayland client: connect, bind wl_compositor + wl_shm, push one
 * 256x256 solid-red XRGB8888 buffer via wl_shm, commit, wait for release,
 * exit.  Companion to tools/wl_compositor_min.c.
 *
 * Build (static-PIE):
 *   gcc -static-pie -fPIE -O2 -fno-stack-protector -s \
 *       -o hello_wl hello_wl.c
 *
 * Runs against tools/wl_compositor_min (the handwritten compositor) and
 * also against real libwayland servers (verified with weston/Mutter).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

/* ---------- Wire constants (client side) ---------- */

#define WL_DISPLAY_ID  1u

#define WL_DISPLAY_REQ_SYNC         0
#define WL_DISPLAY_REQ_GET_REGISTRY 1
#define WL_DISPLAY_EV_ERROR         0
#define WL_DISPLAY_EV_DELETE_ID     1

#define WL_REGISTRY_REQ_BIND        0
#define WL_REGISTRY_EV_GLOBAL       0

#define WL_CALLBACK_EV_DONE         0

#define WL_COMPOSITOR_REQ_CREATE_SURFACE 0

#define WL_SHM_REQ_CREATE_POOL      0
#define WL_SHM_EV_FORMAT            0

#define WL_SHM_POOL_REQ_CREATE_BUFFER 0
#define WL_SHM_POOL_REQ_DESTROY       1

#define WL_BUFFER_REQ_DESTROY       0
#define WL_BUFFER_EV_RELEASE        0

#define WL_SURFACE_REQ_DESTROY      0
#define WL_SURFACE_REQ_ATTACH       1
#define WL_SURFACE_REQ_DAMAGE       2
#define WL_SURFACE_REQ_COMMIT       6

#define WL_SHM_FORMAT_ARGB8888      0
#define WL_SHM_FORMAT_XRGB8888      1

/* Client-assigned object IDs we use.  A real libwayland client allocates
 * these; we pin them by hand. */
#define ID_DISPLAY      1
#define ID_REGISTRY     2
#define ID_SYNC_CB      3
#define ID_COMPOSITOR   4
#define ID_SHM          5
#define ID_POOL         6
#define ID_BUFFER       7
#define ID_SURFACE      8
#define ID_SYNC_CB2     9

/* ---------- Wire helpers ---------- */

static int verbose = 1;
#define LOG(fmt, ...) do { if (verbose) fprintf(stderr, "[cl] " fmt "\n", ##__VA_ARGS__); } while (0)
#define DIE(fmt, ...) do { fprintf(stderr, "[cl] FATAL: " fmt "\n", ##__VA_ARGS__); exit(1); } while (0)

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Send a message (no fd).  body_len must be 4-byte aligned. */
static void send_req(int fd, uint32_t obj, uint16_t op,
                     const void *body, uint16_t body_len)
{
    uint16_t total = 8 + body_len;
    uint8_t hdr[8];
    put_u32(hdr, obj);
    put_u32(hdr + 4, ((uint32_t)total << 16) | op);
    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = 8 },
        { .iov_base = (void *)body, .iov_len = body_len },
    };
    struct msghdr mh = { .msg_iov = iov, .msg_iovlen = body_len ? 2 : 1 };
    ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
    if (n < 0) DIE("sendmsg: %s", strerror(errno));
}

/* Send a message with one ancillary fd via SCM_RIGHTS. */
static void send_req_fd(int fd, uint32_t obj, uint16_t op,
                        const void *body, uint16_t body_len, int anc_fd)
{
    uint16_t total = 8 + body_len;
    uint8_t hdr[8];
    put_u32(hdr, obj);
    put_u32(hdr + 4, ((uint32_t)total << 16) | op);
    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = 8 },
        { .iov_base = (void *)body, .iov_len = body_len },
    };
    uint8_t cbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr mh = {
        .msg_iov = iov, .msg_iovlen = body_len ? 2 : 1,
        .msg_control = cbuf, .msg_controllen = sizeof cbuf,
    };
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &anc_fd, sizeof anc_fd);
    ssize_t n = sendmsg(fd, &mh, MSG_NOSIGNAL);
    if (n < 0) DIE("sendmsg+fd: %s", strerror(errno));
}

static size_t put_string(uint8_t *dst, const char *s) {
    size_t slen = strlen(s) + 1;
    size_t pad = (slen + 3) & ~(size_t)3;
    put_u32(dst, (uint32_t)slen);
    memset(dst + 4, 0, pad);
    memcpy(dst + 4, s, slen);
    return 4 + pad;
}

/* ---------- Connect ---------- */

static int connect_display(void) {
    const char *display = getenv("WAYLAND_DISPLAY");
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    char path[108];

    if (display && display[0] == '/') {
        snprintf(path, sizeof path, "%s", display);
    } else {
        static char rt[64];
        if (!runtime || !runtime[0]) {
            snprintf(rt, sizeof rt, "/run/user/%u", (unsigned)getuid());
            runtime = rt;
        }
        if (!display || !display[0]) display = "wayland-0";
        snprintf(path, sizeof path, "%s/%s", runtime, display);
    }
    LOG("connecting to %s", path);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) DIE("socket: %s", strerror(errno));

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof sun);
    sun.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sun.sun_path) DIE("socket path too long");
    strncpy(sun.sun_path, path, sizeof sun.sun_path - 1);
    socklen_t slen = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
    if (connect(fd, (struct sockaddr *)&sun, slen) < 0)
        DIE("connect(%s): %s", path, strerror(errno));
    return fd;
}

/* ---------- Receive-side state ---------- */

struct rx {
    int fd;
    uint8_t buf[8192];
    size_t len;
    /* Resolved global names from wl_registry.global events. */
    uint32_t compositor_name;
    uint32_t shm_name;
    int got_compositor;
    int got_shm;
    /* Event flags. */
    int got_sync_done;
    int got_buffer_release;
};

static void rx_read(struct rx *r) {
    ssize_t n = recv(r->fd, r->buf + r->len, sizeof r->buf - r->len, 0);
    if (n <= 0) DIE("recv: %s", n == 0 ? "EOF" : strerror(errno));
    r->len += (size_t)n;
}

static int rx_consume_one(struct rx *r) {
    if (r->len < 8) return 0;
    uint32_t obj = get_u32(r->buf);
    uint32_t szop = get_u32(r->buf + 4);
    uint16_t total = szop >> 16;
    uint16_t op = szop & 0xffff;
    if (total < 8) DIE("malformed header from compositor");
    if (r->len < total) return 0;

    const uint8_t *body = r->buf + 8;
    uint16_t blen = total - 8;

    LOG("-> obj=%u op=%u total=%u", obj, op, total);

    if (obj == ID_DISPLAY && op == WL_DISPLAY_EV_ERROR && blen >= 8) {
        uint32_t on = get_u32(body);
        uint32_t code = get_u32(body + 4);
        const char *msg = (blen >= 12) ? (const char *)(body + 12) : "(none)";
        fprintf(stderr, "[cl] wl_display.error on %u code=%u msg=%s\n",
                on, code, msg);
        exit(2);
    }
    if (obj == ID_DISPLAY && op == WL_DISPLAY_EV_DELETE_ID) {
        /* informational */
    }
    if (obj == ID_REGISTRY && op == WL_REGISTRY_EV_GLOBAL && blen >= 12) {
        uint32_t name = get_u32(body);
        uint32_t slen = get_u32(body + 4);
        const char *iface = (const char *)(body + 8);
        (void)slen;
        /* Version is after the padded string. */
        LOG("   global name=%u iface=%s", name, iface);
        if (strcmp(iface, "wl_compositor") == 0) {
            r->compositor_name = name;
            r->got_compositor = 1;
        } else if (strcmp(iface, "wl_shm") == 0) {
            r->shm_name = name;
            r->got_shm = 1;
        }
    }
    if (obj == ID_SYNC_CB && op == WL_CALLBACK_EV_DONE) {
        r->got_sync_done = 1;
    }
    if (obj == ID_SYNC_CB2 && op == WL_CALLBACK_EV_DONE) {
        r->got_sync_done = 1;
    }
    if (obj == ID_BUFFER && op == WL_BUFFER_EV_RELEASE) {
        r->got_buffer_release = 1;
    }
    return (int)total;
}

static void rx_wait_sync(struct rx *r) {
    r->got_sync_done = 0;
    while (!r->got_sync_done) {
        rx_read(r);
        for (;;) {
            int used = rx_consume_one(r);
            if (used <= 0) break;
            if ((size_t)used < r->len)
                memmove(r->buf, r->buf + used, r->len - used);
            r->len -= (size_t)used;
        }
    }
}

static void rx_wait_release(struct rx *r) {
    while (!r->got_buffer_release) {
        rx_read(r);
        for (;;) {
            int used = rx_consume_one(r);
            if (used <= 0) break;
            if ((size_t)used < r->len)
                memmove(r->buf, r->buf + used, r->len - used);
            r->len -= (size_t)used;
        }
    }
}

/* ---------- memfd shm buffer ---------- */

static int make_shm_buffer(int w, int h, uint32_t argb) {
    int fd = (int)syscall(SYS_memfd_create, "hello_wl-shm", 0);
    if (fd < 0) DIE("memfd_create: %s", strerror(errno));
    size_t stride = (size_t)w * 4;
    size_t sz = stride * (size_t)h;
    if (ftruncate(fd, (off_t)sz) < 0) DIE("ftruncate: %s", strerror(errno));
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) DIE("mmap: %s", strerror(errno));
    uint32_t *px = (uint32_t *)p;
    for (size_t i = 0; i < sz / 4; i++) px[i] = argb;
    munmap(p, sz);
    return fd;
}

/* ---------- Main ---------- */

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    int fd = connect_display();
    LOG("connected fd=%d", fd);

    struct rx r; memset(&r, 0, sizeof r);
    r.fd = fd;

    /* get_registry(new_id=2) */
    uint8_t buf[4];
    put_u32(buf, ID_REGISTRY);
    send_req(fd, ID_DISPLAY, WL_DISPLAY_REQ_GET_REGISTRY, buf, 4);

    /* sync(new_id=3) — round-trip so we get all globals */
    put_u32(buf, ID_SYNC_CB);
    send_req(fd, ID_DISPLAY, WL_DISPLAY_REQ_SYNC, buf, 4);

    rx_wait_sync(&r);

    if (!r.got_compositor) DIE("compositor did not advertise wl_compositor");
    if (!r.got_shm)        DIE("compositor did not advertise wl_shm");
    LOG("globals resolved: compositor=%u shm=%u", r.compositor_name, r.shm_name);

    /* bind wl_compositor, name=compositor_name, v=4, new_id=4 */
    uint8_t bind_buf[64];
    put_u32(bind_buf, r.compositor_name);
    size_t off = 4 + put_string(bind_buf + 4, "wl_compositor");
    put_u32(bind_buf + off, 4);
    off += 4;
    put_u32(bind_buf + off, ID_COMPOSITOR);
    off += 4;
    send_req(fd, ID_REGISTRY, WL_REGISTRY_REQ_BIND, bind_buf, off);

    /* bind wl_shm, v=1, new_id=5 */
    put_u32(bind_buf, r.shm_name);
    off = 4 + put_string(bind_buf + 4, "wl_shm");
    put_u32(bind_buf + off, 1);
    off += 4;
    put_u32(bind_buf + off, ID_SHM);
    off += 4;
    send_req(fd, ID_REGISTRY, WL_REGISTRY_REQ_BIND, bind_buf, off);

    const int W = 256, H = 256;
    const int stride = W * 4;
    /* 0xFFFF0000 in XRGB8888 little-endian bytes: B=00 G=00 R=FF X=FF → red */
    int shm_fd = make_shm_buffer(W, H, 0xFFFF0000);
    LOG("shm_fd=%d (%dx%d)", shm_fd, W, H);

    /* wl_shm.create_pool(new_id=6, fd, size) */
    uint8_t pool_buf[8];
    put_u32(pool_buf, ID_POOL);
    put_u32(pool_buf + 4, (uint32_t)(stride * H));
    send_req_fd(fd, ID_SHM, WL_SHM_REQ_CREATE_POOL, pool_buf, 8, shm_fd);
    close(shm_fd);  /* compositor dup'd it */

    /* wl_shm_pool.create_buffer(new_id=7, offset=0, W, H, stride, XRGB8888) */
    uint8_t cb_buf[24];
    put_u32(cb_buf,      ID_BUFFER);
    put_u32(cb_buf + 4,  0);
    put_u32(cb_buf + 8,  W);
    put_u32(cb_buf + 12, H);
    put_u32(cb_buf + 16, stride);
    put_u32(cb_buf + 20, WL_SHM_FORMAT_XRGB8888);
    send_req(fd, ID_POOL, WL_SHM_POOL_REQ_CREATE_BUFFER, cb_buf, 24);

    /* wl_compositor.create_surface(new_id=8) */
    put_u32(buf, ID_SURFACE);
    send_req(fd, ID_COMPOSITOR, WL_COMPOSITOR_REQ_CREATE_SURFACE, buf, 4);

    /* wl_surface.attach(buffer=7, 0, 0) */
    uint8_t at_buf[12];
    put_u32(at_buf,     ID_BUFFER);
    put_u32(at_buf + 4, 0);
    put_u32(at_buf + 8, 0);
    send_req(fd, ID_SURFACE, WL_SURFACE_REQ_ATTACH, at_buf, 12);

    /* wl_surface.damage(0, 0, W, H) */
    uint8_t dmg[16];
    put_u32(dmg,      0);
    put_u32(dmg + 4,  0);
    put_u32(dmg + 8,  W);
    put_u32(dmg + 12, H);
    send_req(fd, ID_SURFACE, WL_SURFACE_REQ_DAMAGE, dmg, 16);

    /* wl_surface.commit */
    send_req(fd, ID_SURFACE, WL_SURFACE_REQ_COMMIT, NULL, 0);

    LOG("committed; waiting for wl_buffer.release");
    rx_wait_release(&r);
    LOG("buffer released — success");

    /* Tidy up with a final sync so wl_display.error (if any) arrives. */
    put_u32(buf, ID_SYNC_CB2);
    send_req(fd, ID_DISPLAY, WL_DISPLAY_REQ_SYNC, buf, 4);
    rx_wait_sync(&r);

    close(fd);
    return 0;
}
