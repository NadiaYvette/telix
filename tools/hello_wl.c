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
#include <time.h>

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

/* xdg-shell v3 */
#define XDG_WM_BASE_REQ_GET_XDG_SURFACE  2
#define XDG_WM_BASE_REQ_PONG             3
#define XDG_WM_BASE_EV_PING              0
#define XDG_SURFACE_REQ_GET_TOPLEVEL     1
#define XDG_SURFACE_REQ_ACK_CONFIGURE    4
#define XDG_SURFACE_EV_CONFIGURE         0
#define XDG_TOPLEVEL_REQ_SET_TITLE       2

/* wl_seat (v5) */
#define WL_SEAT_REQ_GET_POINTER    0
#define WL_SEAT_REQ_GET_KEYBOARD   1
#define WL_SEAT_EV_CAPABILITIES    0
#define WL_SEAT_EV_NAME            1
#define WL_KEYBOARD_EV_KEYMAP      0
#define WL_KEYBOARD_EV_REPEAT_INFO 5
#define WL_KEYBOARD_EV_KEY         3

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
#define ID_XDG_WM_BASE 10
#define ID_XDG_SURFACE 11
#define ID_XDG_TOPLEVEL 12
#define ID_SEAT        13
#define ID_POINTER     14
#define ID_KEYBOARD    15

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
    /* Retry on ECONNREFUSED — the compositor may have just bind()d but
     * not yet accept()ed.  Up to ~3 s total. */
    for (int attempt = 0; attempt < 60; attempt++) {
        if (connect(fd, (struct sockaddr *)&sun, slen) == 0) return fd;
        if (errno != ECONNREFUSED && errno != ENOENT) break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    DIE("connect(%s): %s", path, strerror(errno));
}

/* ---------- Receive-side state ---------- */

struct rx {
    int fd;
    uint8_t buf[8192];
    size_t len;
    /* Resolved global names from wl_registry.global events. */
    uint32_t compositor_name;
    uint32_t shm_name;
    uint32_t xdg_wm_base_name;
    uint32_t seat_name;
    int got_compositor;
    int got_shm;
    int got_xdg_wm_base;
    int got_seat;
    /* Event flags. */
    int got_sync_done;
    int got_buffer_release;
    int got_seat_capabilities;
    int got_keymap;
    uint32_t xdg_configure_serial;  /* 0 = not seen yet */
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
        } else if (strcmp(iface, "xdg_wm_base") == 0) {
            r->xdg_wm_base_name = name;
            r->got_xdg_wm_base = 1;
        } else if (strcmp(iface, "wl_seat") == 0) {
            r->seat_name = name;
            r->got_seat = 1;
        }
    }
    if (obj == ID_SEAT && op == WL_SEAT_EV_CAPABILITIES && blen >= 4) {
        uint32_t caps = get_u32(body);
        LOG("   seat caps: 0x%x%s%s%s", caps,
            (caps & 1) ? " POINTER" : "",
            (caps & 2) ? " KEYBOARD" : "",
            (caps & 4) ? " TOUCH" : "");
        r->got_seat_capabilities = 1;
    }
    if (obj == ID_KEYBOARD && op == WL_KEYBOARD_EV_KEYMAP && blen >= 8) {
        uint32_t format = get_u32(body);
        uint32_t size   = get_u32(body + 4);
        LOG("   keymap: format=%u size=%u", format, size);
        r->got_keymap = 1;
    }
    if (obj == ID_KEYBOARD && op == WL_KEYBOARD_EV_REPEAT_INFO && blen >= 8) {
        LOG("   repeat_info: rate=%u delay=%u",
            get_u32(body), get_u32(body + 4));
    }
    if (obj == ID_KEYBOARD && op == WL_KEYBOARD_EV_KEY && blen >= 16) {
        LOG("   key: serial=%u time=%u code=%u state=%u",
            get_u32(body), get_u32(body + 4),
            get_u32(body + 8), get_u32(body + 12));
    }
    if (obj == ID_XDG_WM_BASE && op == XDG_WM_BASE_EV_PING && blen >= 4) {
        /* Answer pings so the compositor doesn't kill us. */
        uint32_t serial = get_u32(body);
        uint8_t buf[4]; put_u32(buf, serial);
        send_req(r->fd, ID_XDG_WM_BASE, XDG_WM_BASE_REQ_PONG, buf, 4);
    }
    if (obj == ID_XDG_SURFACE && op == XDG_SURFACE_EV_CONFIGURE && blen >= 4) {
        r->xdg_configure_serial = get_u32(body);
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

static void rx_wait_xdg_configure(struct rx *r) {
    r->xdg_configure_serial = 0;
    while (r->xdg_configure_serial == 0) {
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

    if (!r.got_compositor)  DIE("compositor did not advertise wl_compositor");
    if (!r.got_shm)         DIE("compositor did not advertise wl_shm");
    if (!r.got_xdg_wm_base) DIE("compositor did not advertise xdg_wm_base");
    if (!r.got_seat)        DIE("compositor did not advertise wl_seat");
    LOG("globals resolved: compositor=%u shm=%u xdg_wm_base=%u seat=%u",
        r.compositor_name, r.shm_name, r.xdg_wm_base_name, r.seat_name);

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

    /* bind xdg_wm_base, v=3, new_id=10 */
    put_u32(bind_buf, r.xdg_wm_base_name);
    off = 4 + put_string(bind_buf + 4, "xdg_wm_base");
    put_u32(bind_buf + off, 3);
    off += 4;
    put_u32(bind_buf + off, ID_XDG_WM_BASE);
    off += 4;
    send_req(fd, ID_REGISTRY, WL_REGISTRY_REQ_BIND, bind_buf, off);

    /* bind wl_seat, v=5, new_id=13 — then request pointer + keyboard so
     * the compositor sends caps/keymap/repeat_info events. */
    put_u32(bind_buf, r.seat_name);
    off = 4 + put_string(bind_buf + 4, "wl_seat");
    put_u32(bind_buf + off, 5);
    off += 4;
    put_u32(bind_buf + off, ID_SEAT);
    off += 4;
    send_req(fd, ID_REGISTRY, WL_REGISTRY_REQ_BIND, bind_buf, off);

    /* wl_seat.get_pointer(new_id=14) */
    put_u32(buf, ID_POINTER);
    send_req(fd, ID_SEAT, WL_SEAT_REQ_GET_POINTER, buf, 4);

    /* wl_seat.get_keyboard(new_id=15) */
    put_u32(buf, ID_KEYBOARD);
    send_req(fd, ID_SEAT, WL_SEAT_REQ_GET_KEYBOARD, buf, 4);

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

    /* xdg_wm_base.get_xdg_surface(new_id=11, surface=8) */
    uint8_t gxs_buf[8];
    put_u32(gxs_buf,     ID_XDG_SURFACE);
    put_u32(gxs_buf + 4, ID_SURFACE);
    send_req(fd, ID_XDG_WM_BASE, XDG_WM_BASE_REQ_GET_XDG_SURFACE, gxs_buf, 8);

    /* xdg_surface.get_toplevel(new_id=12) */
    put_u32(buf, ID_XDG_TOPLEVEL);
    send_req(fd, ID_XDG_SURFACE, XDG_SURFACE_REQ_GET_TOPLEVEL, buf, 4);

    /* xdg_toplevel.set_title("hello_wl") */
    uint8_t title_buf[32];
    size_t tl = put_string(title_buf, "hello_wl");
    send_req(fd, ID_XDG_TOPLEVEL, XDG_TOPLEVEL_REQ_SET_TITLE, title_buf, tl);

    /* Wait for the initial xdg_surface.configure before attaching a
     * buffer — the xdg-shell spec forbids pre-configure attach. */
    LOG("waiting for xdg_surface.configure");
    rx_wait_xdg_configure(&r);
    LOG("configure serial=%u; ack'ing", r.xdg_configure_serial);
    uint8_t ack_buf[4];
    put_u32(ack_buf, r.xdg_configure_serial);
    send_req(fd, ID_XDG_SURFACE, XDG_SURFACE_REQ_ACK_CONFIGURE, ack_buf, 4);

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
