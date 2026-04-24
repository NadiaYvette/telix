/* Minimal handwritten Wayland compositor — Step F (option A) stepping
 * stone for Telix's Xwayland roadmap.  Speaks the Wayland wire protocol
 * directly, no libwayland-server dependency.
 *
 * Build (static-PIE, same pattern as glibc_hello):
 *   gcc -static-pie -fPIE -O2 -fno-stack-protector -s \
 *       -o wl_compositor_min wl_compositor_min.c
 *
 * Runs both on Fedora (tested with wayland-info as client) and on Telix
 * under the Linux personality (once run inside QEMU).
 *
 * Current scope:
 *   - Accept a UDS connection on $WAYLAND_DISPLAY (or /run/user/UID/wayland-0).
 *   - Parse the 8-byte header + body framing.
 *   - Object table with per-object state (surface/pool/buffer/etc).
 *   - Globals: wl_compositor, wl_shm, wl_output (no geometry yet).
 *   - Requests: wl_display.{sync,get_registry}, wl_registry.bind,
 *     wl_compositor.create_surface/region, wl_shm.create_pool,
 *     wl_shm_pool.{create_buffer,resize,destroy}, wl_surface.{attach,commit,
 *     damage,frame,destroy}, wl_buffer.destroy, wl_region.{add,subtract,destroy},
 *     wl_output.release.
 *
 * Not yet: actual pixel blit to DRM, wl_seat/input, xdg_shell.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

/* ---------- Wayland wire constants ---------- */

#define WL_DISPLAY_ID  1u

/* wl_display */
#define WL_DISPLAY_REQ_SYNC         0
#define WL_DISPLAY_REQ_GET_REGISTRY 1
#define WL_DISPLAY_EV_ERROR         0
#define WL_DISPLAY_EV_DELETE_ID     1

/* wl_registry */
#define WL_REGISTRY_REQ_BIND        0
#define WL_REGISTRY_EV_GLOBAL       0
#define WL_REGISTRY_EV_GLOBAL_REMOVE 1

/* wl_callback */
#define WL_CALLBACK_EV_DONE         0

/* wl_compositor */
#define WL_COMPOSITOR_REQ_CREATE_SURFACE 0
#define WL_COMPOSITOR_REQ_CREATE_REGION  1

/* wl_shm */
#define WL_SHM_REQ_CREATE_POOL      0
#define WL_SHM_EV_FORMAT            0
#define WL_SHM_FORMAT_ARGB8888      0
#define WL_SHM_FORMAT_XRGB8888      1

/* wl_shm_pool */
#define WL_SHM_POOL_REQ_CREATE_BUFFER 0
#define WL_SHM_POOL_REQ_DESTROY       1
#define WL_SHM_POOL_REQ_RESIZE        2

/* wl_buffer */
#define WL_BUFFER_REQ_DESTROY       0
#define WL_BUFFER_EV_RELEASE        0

/* wl_surface */
#define WL_SURFACE_REQ_DESTROY          0
#define WL_SURFACE_REQ_ATTACH           1
#define WL_SURFACE_REQ_DAMAGE           2
#define WL_SURFACE_REQ_FRAME            3
#define WL_SURFACE_REQ_SET_OPAQUE_REG   4
#define WL_SURFACE_REQ_SET_INPUT_REG    5
#define WL_SURFACE_REQ_COMMIT           6
#define WL_SURFACE_REQ_SET_TRANSFORM    7
#define WL_SURFACE_REQ_SET_SCALE        8
#define WL_SURFACE_REQ_DAMAGE_BUFFER    9
#define WL_SURFACE_REQ_OFFSET          10

/* wl_region */
#define WL_REGION_REQ_DESTROY       0
#define WL_REGION_REQ_ADD           1
#define WL_REGION_REQ_SUBTRACT      2

/* wl_output */
#define WL_OUTPUT_REQ_RELEASE       0
#define WL_OUTPUT_EV_GEOMETRY       0
#define WL_OUTPUT_EV_MODE           1
#define WL_OUTPUT_EV_DONE           2
#define WL_OUTPUT_EV_SCALE          3
#define WL_OUTPUT_EV_NAME           4
#define WL_OUTPUT_EV_DESCRIPTION    5

/* wl_seat (v5) */
#define WL_SEAT_REQ_GET_POINTER    0
#define WL_SEAT_REQ_GET_KEYBOARD   1
#define WL_SEAT_REQ_GET_TOUCH      2
#define WL_SEAT_REQ_RELEASE        3
#define WL_SEAT_EV_CAPABILITIES    0
#define WL_SEAT_EV_NAME            1
#define WL_SEAT_CAP_POINTER        (1u << 0)
#define WL_SEAT_CAP_KEYBOARD       (1u << 1)
#define WL_SEAT_CAP_TOUCH          (1u << 2)

/* wl_pointer (v5) */
#define WL_POINTER_REQ_SET_CURSOR  0
#define WL_POINTER_REQ_RELEASE     1
#define WL_POINTER_EV_ENTER        0
#define WL_POINTER_EV_LEAVE        1
#define WL_POINTER_EV_MOTION       2
#define WL_POINTER_EV_BUTTON       3
#define WL_POINTER_EV_AXIS         4
#define WL_POINTER_EV_FRAME        5
#define WL_POINTER_BUTTON_RELEASED 0
#define WL_POINTER_BUTTON_PRESSED  1

/* wl_keyboard (v5) */
#define WL_KEYBOARD_REQ_RELEASE       0
#define WL_KEYBOARD_EV_KEYMAP         0
#define WL_KEYBOARD_EV_ENTER          1
#define WL_KEYBOARD_EV_LEAVE          2
#define WL_KEYBOARD_EV_KEY            3
#define WL_KEYBOARD_EV_MODIFIERS      4
#define WL_KEYBOARD_EV_REPEAT_INFO    5
#define WL_KEYBOARD_KEYMAP_NO_KEYMAP  0
#define WL_KEYBOARD_KEYMAP_XKB_V1     1
#define WL_KEYBOARD_KEY_RELEASED      0
#define WL_KEYBOARD_KEY_PRESSED       1

/* Linux evdev */
#define EV_SYN   0x00
#define EV_KEY   0x01
#define EV_REL   0x02
#define REL_X    0x00
#define REL_Y    0x01
#define BTN_LEFT   0x110
#define BTN_RIGHT  0x111
#define BTN_MIDDLE 0x112

/* xdg_wm_base (xdg-shell v3) */
#define XDG_WM_BASE_REQ_DESTROY            0
#define XDG_WM_BASE_REQ_CREATE_POSITIONER  1
#define XDG_WM_BASE_REQ_GET_XDG_SURFACE    2
#define XDG_WM_BASE_REQ_PONG               3
#define XDG_WM_BASE_EV_PING                0

/* xdg_surface */
#define XDG_SURFACE_REQ_DESTROY              0
#define XDG_SURFACE_REQ_GET_TOPLEVEL         1
#define XDG_SURFACE_REQ_GET_POPUP            2
#define XDG_SURFACE_REQ_SET_WINDOW_GEOMETRY  3
#define XDG_SURFACE_REQ_ACK_CONFIGURE        4
#define XDG_SURFACE_EV_CONFIGURE             0

/* xdg_toplevel */
#define XDG_TOPLEVEL_REQ_DESTROY           0
#define XDG_TOPLEVEL_REQ_SET_PARENT        1
#define XDG_TOPLEVEL_REQ_SET_TITLE         2
#define XDG_TOPLEVEL_REQ_SET_APP_ID        3
#define XDG_TOPLEVEL_REQ_SHOW_WINDOW_MENU  4
#define XDG_TOPLEVEL_REQ_MOVE              5
#define XDG_TOPLEVEL_REQ_RESIZE            6
#define XDG_TOPLEVEL_REQ_SET_MAX_SIZE      7
#define XDG_TOPLEVEL_REQ_SET_MIN_SIZE      8
#define XDG_TOPLEVEL_REQ_SET_MAXIMIZED     9
#define XDG_TOPLEVEL_REQ_UNSET_MAXIMIZED  10
#define XDG_TOPLEVEL_REQ_SET_FULLSCREEN   11
#define XDG_TOPLEVEL_REQ_UNSET_FULLSCREEN 12
#define XDG_TOPLEVEL_REQ_SET_MINIMIZED    13
#define XDG_TOPLEVEL_EV_CONFIGURE          0
#define XDG_TOPLEVEL_EV_CLOSE              1

/* ---------- Logging ---------- */

static int verbose = 1;
#define LOG(fmt, ...) do { if (verbose) fprintf(stderr, "[wl] " fmt "\n", ##__VA_ARGS__); } while (0)
#define DIE(fmt, ...) do { fprintf(stderr, "[wl] FATAL: " fmt "\n", ##__VA_ARGS__); exit(1); } while (0)

/* ---------- DRM scanout ---------- *
 *
 * Telix's linux_srv translates the kernel's DRM/KMS ioctls into its native
 * framebuffer server calls: CREATE_DUMB allocates a CPU-accessible buffer,
 * MAP_DUMB + mmap exposes it in our aspace, ADDFB wraps it in a fb_id, and
 * SETCRTC binds that fb_id to the only CRTC.  PAGE_FLIP then blits the
 * dumb buffer to the real framebuffer (fb_srv) and schedules scanout.
 *
 * All of this is optional: opening /dev/dri/card0 may fail (e.g. on Fedora
 * host without the video group).  When it does, drm_setup returns 0 and
 * commits fall back to log-only — same behaviour as the pre-DRM skeleton.
 */

#define DRM_IOCTL_MODE_CREATE_DUMB   0xC02064B2UL
#define DRM_IOCTL_MODE_MAP_DUMB      0xC01064B3UL
#define DRM_IOCTL_MODE_DESTROY_DUMB  0xC00464B4UL
#define DRM_IOCTL_MODE_ADDFB         0xC01C64AEUL
#define DRM_IOCTL_MODE_RMFB          0xC00464AFUL
#define DRM_IOCTL_MODE_SETCRTC       0xC06864A2UL
#define DRM_IOCTL_MODE_PAGE_FLIP     0xC01064B0UL

struct drm_mode_create_dumb {
    uint32_t height, width, bpp, flags;
    uint32_t handle, pitch;
    uint64_t size;
};

struct drm_mode_map_dumb {
    uint32_t handle, pad;
    uint64_t offset;
};

struct drm_mode_fb_cmd {
    uint32_t fb_id, width, height, pitch;
    uint32_t bpp, depth, handle;
};

/* drm_mode_crtc (104 bytes) — only fb_id + mode_valid are required by our
 * linux_srv impl, but libdrm sends the full struct so we match the layout. */
struct drm_mode_crtc {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t x, y;
    uint32_t gamma_size;
    uint32_t mode_valid;
    uint8_t  mode[68];  /* drm_mode_modeinfo — content ignored by Telix */
};

struct drm_mode_crtc_page_flip {
    uint32_t crtc_id, fb_id, flags, reserved;
    uint64_t user_data;
};

struct drm_scanout {
    int      fd;           /* -1 if DRM unavailable */
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t dumb_handle;
    uint32_t fb_id;
    size_t   size;
    void    *va;           /* mmap of the dumb buffer */
};

/* Single-scanout state — one CRTC, one dumb buffer, one fb_id. */
static struct drm_scanout g_drm = { .fd = -1 };

static int drm_setup(uint32_t width, uint32_t height) {
    int fd = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        LOG("drm: open /dev/dri/card0 failed: %s (running headless)", strerror(errno));
        return 0;
    }

    /* 1. CREATE_DUMB — allocates a CPU-coherent XRGB8888 buffer. */
    struct drm_mode_create_dumb cd;
    memset(&cd, 0, sizeof cd);
    cd.width  = width;
    cd.height = height;
    cd.bpp    = 32;
    if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) {
        LOG("drm: CREATE_DUMB: %s", strerror(errno));
        close(fd);
        return 0;
    }

    /* 2. MAP_DUMB — returns the magic offset into drm_fd. */
    struct drm_mode_map_dumb md = { .handle = cd.handle };
    if (ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) {
        LOG("drm: MAP_DUMB: %s", strerror(errno));
        close(fd);
        return 0;
    }

    /* 3. mmap at that offset to get the buffer VA. */
    void *va = mmap(NULL, cd.size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    fd, (off_t)md.offset);
    if (va == MAP_FAILED) {
        LOG("drm: mmap dumb: %s", strerror(errno));
        close(fd);
        return 0;
    }

    /* 4. ADDFB — wrap the dumb buffer in a framebuffer object. */
    struct drm_mode_fb_cmd fb;
    memset(&fb, 0, sizeof fb);
    fb.width  = width;
    fb.height = height;
    fb.pitch  = cd.pitch;
    fb.bpp    = 32;
    fb.depth  = 24;
    fb.handle = cd.handle;
    if (ioctl(fd, DRM_IOCTL_MODE_ADDFB, &fb) < 0) {
        LOG("drm: ADDFB: %s", strerror(errno));
        munmap(va, cd.size);
        close(fd);
        return 0;
    }

    /* 5. SETCRTC — bind fb to the only CRTC.  Telix's linux_srv ignores the
     * mode struct; only fb_id matters.  (A libdrm-compatible compositor
     * would query the connector's preferred mode and fill it in.) */
    struct drm_mode_crtc crtc;
    memset(&crtc, 0, sizeof crtc);
    crtc.crtc_id     = 1; /* DRM_CRTC_ID in linux_srv */
    crtc.fb_id       = fb.fb_id;
    crtc.mode_valid  = 1;
    /* Best-effort mode fill (ignored, but reasonable). */
    uint8_t *m = crtc.mode;
    uint32_t clock = 65000;  /* 1024x768@60 VESA */
    memcpy(m, &clock, 4);
    *(uint16_t *)(m + 4) = (uint16_t)width;    /* hdisplay */
    *(uint16_t *)(m + 14) = (uint16_t)height;  /* vdisplay */
    *(uint32_t *)(m + 28) = 0;                  /* flags */
    if (ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &crtc) < 0) {
        LOG("drm: SETCRTC: %s", strerror(errno));
        munmap(va, cd.size);
        close(fd);
        return 0;
    }

    g_drm.fd           = fd;
    g_drm.width        = width;
    g_drm.height       = height;
    g_drm.pitch        = cd.pitch;
    g_drm.dumb_handle  = cd.handle;
    g_drm.fb_id        = fb.fb_id;
    g_drm.size         = cd.size;
    g_drm.va           = va;

    /* Clear buffer to opaque black — visible pixel check if nothing is
     * drawn, and proof that SETCRTC's initial blit reached the display. */
    uint32_t *px = (uint32_t *)va;
    size_t count = cd.size / 4;
    for (size_t i = 0; i < count; i++) px[i] = 0xFF000000;

    LOG("drm: scanout ready %ux%u pitch=%u fb_id=%u dumb_handle=%u",
        width, height, cd.pitch, fb.fb_id, cd.handle);
    return 1;
}

static void drm_teardown(void) {
    if (g_drm.fd < 0) return;
    if (g_drm.va && g_drm.va != MAP_FAILED) munmap(g_drm.va, g_drm.size);
    close(g_drm.fd);
    g_drm.fd = -1;
    g_drm.va = NULL;
}

/* Present the current dumb buffer on the CRTC. */
static void drm_present(void) {
    if (g_drm.fd < 0) return;
    struct drm_mode_crtc_page_flip pf = { .crtc_id = 1, .fb_id = g_drm.fb_id };
    if (ioctl(g_drm.fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf) < 0) {
        LOG("drm: PAGE_FLIP: %s", strerror(errno));
    }
}

/* Forward declarations: input_pump / input_ensure_focused reach into the
 * client struct (kbd_obj_id, focused_surface_id, ...) but we want to keep
 * the evdev setup/teardown scaffolding next to DRM's, above the protocol
 * machinery.  Declare here, define below struct client. */
struct client;
static void input_pump(struct client *c, int fd, int is_keyboard);
static void input_ensure_focused(struct client *c);

/* ---------- Input (evdev → wl_seat) ---------- *
 *
 * The compositor owns a single seat — "default" — with keyboard + pointer
 * capabilities reported on wl_seat bind.  Evdev fds are opened eagerly so
 * wl_keyboard.keymap can later ship the keymap file descriptor; actually
 * reading input events happens via poll() in the serve_client loop.
 *
 * The keymap is currently sent as WL_KEYBOARD_KEYMAP_NO_KEYMAP (backed by
 * a memfd containing the byte 0) — enough for the hello_wl handshake to
 * succeed.  Xwayland integration will require a real XKB_V1 keymap; we'll
 * swap this out for either a bundled static keymap or a runtime xkbcommon
 * call when the Xwayland work starts.
 */

#include <sys/syscall.h>
#include <poll.h>

/* Pre-generated XKB_V1 keymap (US layout).  Produced at build time by
 * xkbcomp from the pc+us+inet(evdev) layout.  Embedded here so the
 * compositor stays a single self-contained static-PIE binary — no need
 * for runtime file lookups under the Linux personality. */
#include "xkb_keymap_us.h"

struct seat_state {
    int      kbd_fd;      /* /dev/input/event0 (keyboard) */
    int      ptr_fd;      /* /dev/input/event1 (mouse) */
    int      keymap_fd;   /* memfd containing keymap for wl_keyboard.keymap */
    size_t   keymap_len;
    /* Pointer position tracking (evdev sends relative deltas). */
    int32_t  ptr_x;
    int32_t  ptr_y;
};

static struct seat_state g_seat = { .kbd_fd = -1, .ptr_fd = -1, .keymap_fd = -1 };

/* Linux evdev input_event layout (x86_64): 24 bytes.
 *   struct timeval time;  // 16 bytes (sec + usec, 8 each)
 *   __u16 type;           // 2
 *   __u16 code;           // 2
 *   __s32 value;          // 4
 */
#define EVDEV_EVENT_SIZE 24

static void input_setup(void) {
    /* Keyboard + mouse via Linux evdev.  Failure is non-fatal: we still
     * advertise the capabilities and let clients bind, they just won't
     * receive any events. */
    g_seat.kbd_fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (g_seat.kbd_fd < 0)
        LOG("input: open /dev/input/event0: %s (no key events)", strerror(errno));
    g_seat.ptr_fd = open("/dev/input/event1", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (g_seat.ptr_fd < 0)
        LOG("input: open /dev/input/event1: %s (no pointer events)", strerror(errno));

    /* Populate a memfd with the bundled XKB_V1 US keymap.  Xwayland (and
     * any xkbcommon-based client) parses this buffer via
     * xkb_keymap_new_from_string; NO_KEYMAP is rejected, so an actual
     * keymap is required.  The trailing NUL from xxd's byte array is
     * benign — xkbcommon ignores whatever's past the parser EOF. */
    long memfd = syscall(SYS_memfd_create, "wl-keymap-xkb", 0);
    if (memfd < 0) {
        LOG("input: memfd_create failed: %s", strerror(errno));
        return;
    }
    if (ftruncate((int)memfd, (off_t)xkb_keymap_us_len) < 0) {
        LOG("input: ftruncate keymap memfd: %s", strerror(errno));
        close((int)memfd);
        return;
    }
    /* mmap + memcpy is the simplest cross-platform way to fill a memfd —
     * avoids caring whether Telix's VFS-less linux_srv supports write()
     * on MemFds. */
    void *p = mmap(NULL, xkb_keymap_us_len, PROT_READ | PROT_WRITE,
                   MAP_SHARED, (int)memfd, 0);
    if (p == MAP_FAILED) {
        LOG("input: mmap keymap memfd: %s", strerror(errno));
        close((int)memfd);
        return;
    }
    memcpy(p, xkb_keymap_us, xkb_keymap_us_len);
    munmap(p, xkb_keymap_us_len);
    g_seat.keymap_fd = (int)memfd;
    g_seat.keymap_len = xkb_keymap_us_len;
    LOG("input: seat ready kbd_fd=%d ptr_fd=%d keymap_fd=%d (xkb_v1, %zu bytes)",
        g_seat.kbd_fd, g_seat.ptr_fd, g_seat.keymap_fd, g_seat.keymap_len);
}

static void input_teardown(void) {
    if (g_seat.kbd_fd    >= 0) close(g_seat.kbd_fd);
    if (g_seat.ptr_fd    >= 0) close(g_seat.ptr_fd);
    if (g_seat.keymap_fd >= 0) close(g_seat.keymap_fd);
    g_seat.kbd_fd = g_seat.ptr_fd = g_seat.keymap_fd = -1;
}

/* Monotonic time in ms, for wl_*.time fields.  A real compositor would use
 * CLOCK_MONOTONIC; here a wall-ish counter is good enough. */
static uint32_t now_ms(void) {
    static uint32_t t = 0;
    return ++t;
}

/* (input_ensure_focused and input_pump are defined further down, after
 * struct client's full definition — they need the field layout.) */

/* Blit a client's shm-backed surface buffer to the scanout dumb buffer.
 * Naive top-left placement with per-row clip against the display.  Surface
 * pixels are assumed XRGB8888 / ARGB8888 (the two formats we advertise). */
static void drm_blit_surface(const void *src_base, size_t src_offset,
                             int32_t width, int32_t height,
                             int32_t stride)
{
    if (g_drm.fd < 0 || !g_drm.va) return;
    if (width <= 0 || height <= 0 || stride < width * 4) return;

    const uint8_t *src = (const uint8_t *)src_base + src_offset;
    uint8_t *dst = (uint8_t *)g_drm.va;

    size_t rows = (size_t)height;
    if (rows > g_drm.height) rows = g_drm.height;
    size_t row_bytes = (size_t)width * 4;
    if (row_bytes > g_drm.pitch) row_bytes = g_drm.pitch;

    for (size_t r = 0; r < rows; r++) {
        memcpy(dst + r * g_drm.pitch,
               src + r * (size_t)stride,
               row_bytes);
    }
    LOG("drm: blit %zux%zu bytes/row=%zu → scanout", rows, row_bytes / 4, row_bytes);
}

/* ---------- Object table ---------- */

enum obj_type {
    OBJ_NONE = 0,
    OBJ_WL_DISPLAY,
    OBJ_WL_REGISTRY,
    OBJ_WL_CALLBACK,
    OBJ_WL_COMPOSITOR,
    OBJ_WL_SHM,
    OBJ_WL_SHM_POOL,
    OBJ_WL_BUFFER,
    OBJ_WL_SURFACE,
    OBJ_WL_REGION,
    OBJ_WL_OUTPUT,
    OBJ_XDG_WM_BASE,
    OBJ_XDG_SURFACE,
    OBJ_XDG_TOPLEVEL,
    OBJ_WL_SEAT,
    OBJ_WL_POINTER,
    OBJ_WL_KEYBOARD,
};

static const char *obj_type_name(enum obj_type t) {
    switch (t) {
    case OBJ_NONE:          return "(none)";
    case OBJ_WL_DISPLAY:    return "wl_display";
    case OBJ_WL_REGISTRY:   return "wl_registry";
    case OBJ_WL_CALLBACK:   return "wl_callback";
    case OBJ_WL_COMPOSITOR: return "wl_compositor";
    case OBJ_WL_SHM:        return "wl_shm";
    case OBJ_WL_SHM_POOL:   return "wl_shm_pool";
    case OBJ_WL_BUFFER:     return "wl_buffer";
    case OBJ_WL_SURFACE:    return "wl_surface";
    case OBJ_WL_REGION:     return "wl_region";
    case OBJ_WL_OUTPUT:     return "wl_output";
    case OBJ_XDG_WM_BASE:   return "xdg_wm_base";
    case OBJ_XDG_SURFACE:   return "xdg_surface";
    case OBJ_XDG_TOPLEVEL:  return "xdg_toplevel";
    case OBJ_WL_SEAT:       return "wl_seat";
    case OBJ_WL_POINTER:    return "wl_pointer";
    case OBJ_WL_KEYBOARD:   return "wl_keyboard";
    }
    return "(unknown)";
}

struct shm_pool {
    int  fd;
    void *base;     /* mmap */
    size_t size;
    int refcount;   /* wl_buffer refs + the pool itself (while not destroyed) */
    int destroyed;  /* pool destroy requested; wait for refcount==0 */
};

struct wl_buffer_state {
    struct shm_pool *pool;
    size_t offset;
    int32_t width, height, stride;
    uint32_t format;
};

struct wl_surface_state {
    /* Pending (double-buffered until commit). */
    uint32_t pending_buffer;  /* wl_buffer object id, 0 = none */
    int has_pending_buffer;   /* set by attach even if pending_buffer==0 (detach) */
    /* Current after most recent commit. */
    uint32_t current_buffer;
    /* If the surface has been given an xdg_surface role, this is that
     * object's id (non-zero).  The first commit on a role-assigned
     * surface triggers a configure handshake before the client can
     * legally attach a buffer. */
    uint32_t xdg_surface_id;
};

struct xdg_surface_state {
    uint32_t wl_surface_id;   /* the wl_surface this wraps */
    uint32_t toplevel_id;     /* set once get_toplevel has assigned a role */
    uint32_t last_configure_serial;
    int      configured;      /* true once we've emitted the first configure */
    int      acked;           /* true once client has ack_configured */
};

struct xdg_toplevel_state {
    uint32_t xdg_surface_id;  /* back-reference to the wrapping xdg_surface */
    char     title[64];
    char     app_id[64];
};

struct obj_entry {
    enum obj_type type;
    union {
        struct shm_pool           *pool;
        struct wl_buffer_state    *buffer;
        struct wl_surface_state   *surface;
        struct xdg_surface_state  *xdg_surface;
        struct xdg_toplevel_state *xdg_toplevel;
    };
};

/* Flat table indexed by object ID.  Wayland client IDs start at 2; server
 * IDs (we don't use any yet) would start at 0xff000000.  Small table fits
 * every real client we care about. */
#define MAX_CLIENT_OBJS 1024

struct client {
    int fd;
    uint8_t rbuf[8192];
    size_t rlen;
    int rfds[16];
    int nrfds;
    struct obj_entry objs[MAX_CLIENT_OBJS];

    /* Input routing: object ids the client got back from
     * wl_seat.get_pointer / get_keyboard.  Zero until requested.  When
     * evdev events arrive we fan them out via these ids.  Real
     * compositors track focus per-surface; this is kiosk-style where
     * the sole client owns the seat. */
    uint32_t kbd_obj_id;
    uint32_t ptr_obj_id;
    /* First surface that reached commit — counts as 'focused' for the
     * purposes of enter/leave events. */
    uint32_t focused_surface_id;
    /* Whether we've already sent wl_keyboard.enter / wl_pointer.enter
     * for the focused surface. */
    int kbd_entered;
    int ptr_entered;
};

/* ---------- Globals advertised to clients ---------- */

struct global {
    uint32_t     name;      /* unique name sent in wl_registry.global */
    const char  *interface;
    uint32_t     version;
    enum obj_type type;     /* type to assign to new bound object */
};

/* Version numbers chosen to match what most clients request without forcing
 * us to implement higher-version events.  wl_compositor v4 added
 * damage_buffer/offset; we accept them as no-ops. */
static const struct global GLOBALS[] = {
    { 1, "wl_compositor", 4, OBJ_WL_COMPOSITOR },
    { 2, "wl_shm",        1, OBJ_WL_SHM        },
    { 3, "wl_output",     3, OBJ_WL_OUTPUT     },
    { 4, "xdg_wm_base",   3, OBJ_XDG_WM_BASE   },
    { 5, "wl_seat",       5, OBJ_WL_SEAT       },
};
#define N_GLOBALS ((int)(sizeof GLOBALS / sizeof GLOBALS[0]))

/* ---------- Wire helpers ---------- */

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int32_t get_i32(const uint8_t *p) { return (int32_t)get_u32(p); }

/* Parse a Wayland string starting at *p (must be <= args+arg_len).
 * Wire format: u32 length_including_nul, bytes (length), pad to 4.
 * Returns total bytes consumed including the 4-byte length prefix and pad,
 * or -1 on malformed input.  *out_str points into the input buffer (stable
 * for the lifetime of this message).  *out_len excludes the NUL. */
static ssize_t parse_string(const uint8_t *p, const uint8_t *end,
                            const char **out_str, size_t *out_len)
{
    if (end - p < 4) return -1;
    uint32_t len = get_u32(p);
    uint32_t pad = (len + 3u) & ~3u;
    if (len == 0) {
        if (end - p < 4) return -1;
        *out_str = "";
        *out_len = 0;
        return 4;
    }
    if ((size_t)(end - p) < 4u + pad) return -1;
    const char *s = (const char *)(p + 4);
    /* Require NUL terminator at end of declared length. */
    if (s[len - 1] != '\0') return -1;
    *out_str = s;
    *out_len = len - 1;
    return (ssize_t)(4 + pad);
}

static int send_msg_fd(struct client *c, uint32_t object_id, uint16_t opcode,
                       const void *body, uint16_t body_len, int fd)
{
    uint16_t total = 8 + body_len;
    uint8_t hdr[8];
    put_u32(hdr, object_id);
    put_u32(hdr + 4, ((uint32_t)total << 16) | opcode);

    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = 8 },
        { .iov_base = (void *)body, .iov_len = body_len },
    };
    uint8_t cbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr mh = {
        .msg_iov = iov,
        .msg_iovlen = body_len ? 2 : 1,
    };
    if (fd >= 0) {
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof cbuf;
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &fd, sizeof fd);
    }
    ssize_t n = sendmsg(c->fd, &mh, MSG_NOSIGNAL);
    if (n < 0) { LOG("sendmsg: %s", strerror(errno)); return -1; }
    return 0;
}

static int send_msg(struct client *c, uint32_t object_id, uint16_t opcode,
                    const void *body, uint16_t body_len)
{
    return send_msg_fd(c, object_id, opcode, body, body_len, -1);
}

/* Lay out a wire string into dst (caller-sized).  Returns bytes written
 * (4-byte header + length-with-NUL padded to 4).  Does not overrun dst_sz. */
static size_t put_string(uint8_t *dst, size_t dst_sz, const char *s) {
    size_t slen = strlen(s) + 1;
    size_t pad = (slen + 3) & ~(size_t)3;
    if (4 + pad > dst_sz) return 0;
    put_u32(dst, (uint32_t)slen);
    memset(dst + 4, 0, pad);
    memcpy(dst + 4, s, slen);
    return 4 + pad;
}

static void send_error(struct client *c, uint32_t object_id,
                       uint32_t code, const char *msg)
{
    uint8_t body[512];
    size_t slen = put_string(body + 8, sizeof body - 8, msg);
    if (!slen) return;
    put_u32(body, object_id);
    put_u32(body + 4, code);
    send_msg(c, WL_DISPLAY_ID, WL_DISPLAY_EV_ERROR, body, 8 + slen);
    LOG("-> wl_display.error(object=%u code=%u msg=\"%s\")", object_id, code, msg);
}

static void send_delete_id(struct client *c, uint32_t id) {
    uint8_t body[4];
    put_u32(body, id);
    send_msg(c, WL_DISPLAY_ID, WL_DISPLAY_EV_DELETE_ID, body, 4);
}

static void send_callback_done(struct client *c, uint32_t id, uint32_t serial) {
    uint8_t body[4];
    put_u32(body, serial);
    send_msg(c, id, WL_CALLBACK_EV_DONE, body, 4);
    if (id < MAX_CLIENT_OBJS) c->objs[id].type = OBJ_NONE;
    send_delete_id(c, id);
}

static void send_registry_global(struct client *c, uint32_t reg_id,
                                 const struct global *g)
{
    uint8_t body[128];
    put_u32(body, g->name);
    size_t sw = put_string(body + 4, sizeof body - 8, g->interface);
    if (!sw) return;
    put_u32(body + 4 + sw, g->version);
    send_msg(c, reg_id, WL_REGISTRY_EV_GLOBAL, body, 4 + sw + 4);
}

static void send_shm_format(struct client *c, uint32_t shm_id, uint32_t fmt) {
    uint8_t body[4];
    put_u32(body, fmt);
    send_msg(c, shm_id, WL_SHM_EV_FORMAT, body, 4);
}

/* ---------- Object lifecycle ---------- */

/* Allocate/replace an obj_entry.  Frees prior state if any. */
static void obj_clear(struct client *c, uint32_t id) {
    if (id >= MAX_CLIENT_OBJS) return;
    struct obj_entry *e = &c->objs[id];
    switch (e->type) {
    case OBJ_WL_SHM_POOL: {
        struct shm_pool *p = e->pool;
        if (p) {
            p->refcount--;
            if (p->refcount <= 0) {
                if (p->base && p->base != MAP_FAILED) munmap(p->base, p->size);
                if (p->fd >= 0) close(p->fd);
                free(p);
            }
        }
        break;
    }
    case OBJ_WL_BUFFER: {
        struct wl_buffer_state *b = e->buffer;
        if (b) {
            if (b->pool) {
                b->pool->refcount--;
                if (b->pool->refcount <= 0) {
                    if (b->pool->base && b->pool->base != MAP_FAILED)
                        munmap(b->pool->base, b->pool->size);
                    if (b->pool->fd >= 0) close(b->pool->fd);
                    free(b->pool);
                }
            }
            free(b);
        }
        break;
    }
    case OBJ_WL_SURFACE: free(e->surface); break;
    case OBJ_XDG_SURFACE: free(e->xdg_surface); break;
    case OBJ_XDG_TOPLEVEL: free(e->xdg_toplevel); break;
    default: break;
    }
    memset(e, 0, sizeof *e);
}

/* Bump forward and return the next configure serial.  Wayland serials are
 * monotonic across the whole connection; using a single counter is fine. */
static uint32_t g_next_serial = 1;
static uint32_t alloc_serial(void) { return g_next_serial++; }

/* Send xdg_surface.configure(serial) then wl_display.delete_id for the
 * surface's staging — actually just configure; delete is wrong here. */
static void send_xdg_surface_configure(struct client *c, uint32_t xdg_surface_id,
                                       uint32_t serial)
{
    uint8_t body[4];
    put_u32(body, serial);
    send_msg(c, xdg_surface_id, XDG_SURFACE_EV_CONFIGURE, body, 4);
}

/* Send xdg_toplevel.configure(width, height, states[]).  Kiosk-style: full
 * display, no state bits set yet — the client picks its own buffer size. */
static void send_xdg_toplevel_configure(struct client *c, uint32_t toplevel_id,
                                        int32_t width, int32_t height)
{
    uint8_t body[16];
    put_u32(body,       (uint32_t)width);
    put_u32(body + 4,   (uint32_t)height);
    put_u32(body + 8,   0);  /* array length: 0 states */
    put_u32(body + 12,  0);  /* (pad for 4-byte alignment) */
    send_msg(c, toplevel_id, XDG_TOPLEVEL_EV_CONFIGURE, body, 12);
    (void)body[12]; (void)body[15];  /* silence unused-pad warnings */
}

/* ---------- Request dispatch ---------- */

static void handle_wl_display(struct client *c, uint16_t opcode,
                              const uint8_t *args, uint16_t arg_len)
{
    switch (opcode) {
    case WL_DISPLAY_REQ_SYNC: {
        if (arg_len < 4) { LOG("sync: short args"); return; }
        uint32_t new_id = get_u32(args);
        LOG("wl_display.sync(new_id=%u)", new_id);
        if (new_id >= MAX_CLIENT_OBJS) {
            send_error(c, WL_DISPLAY_ID, 0, "new_id out of range");
            return;
        }
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_CALLBACK;
        send_callback_done(c, new_id, 0);
        break;
    }
    case WL_DISPLAY_REQ_GET_REGISTRY: {
        if (arg_len < 4) { LOG("get_registry: short args"); return; }
        uint32_t new_id = get_u32(args);
        LOG("wl_display.get_registry(new_id=%u)", new_id);
        if (new_id >= MAX_CLIENT_OBJS) {
            send_error(c, WL_DISPLAY_ID, 0, "registry new_id out of range");
            return;
        }
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_REGISTRY;
        for (int i = 0; i < N_GLOBALS; i++)
            send_registry_global(c, new_id, &GLOBALS[i]);
        break;
    }
    default:
        LOG("wl_display: unknown opcode %u", opcode);
        send_error(c, WL_DISPLAY_ID, 1, "unknown wl_display opcode");
        break;
    }
}

static void handle_wl_registry(struct client *c, uint32_t reg_id,
                               uint16_t opcode,
                               const uint8_t *args, uint16_t arg_len)
{
    switch (opcode) {
    case WL_REGISTRY_REQ_BIND: {
        const uint8_t *end = args + arg_len;
        if (args + 4 > end) { LOG("bind: short name"); return; }
        uint32_t name = get_u32(args);
        const uint8_t *p = args + 4;
        /* Typed new_id form: interface_string + version + new_id */
        const char *iface = NULL; size_t ilen = 0;
        ssize_t sw = parse_string(p, end, &iface, &ilen);
        if (sw < 0) { LOG("bind: malformed interface string"); return; }
        p += sw;
        if (p + 8 > end) { LOG("bind: short version/new_id"); return; }
        uint32_t version = get_u32(p);
        uint32_t new_id  = get_u32(p + 4);

        LOG("wl_registry(%u).bind(name=%u iface=%s v=%u new_id=%u)",
            reg_id, name, iface, version, new_id);

        if (new_id >= MAX_CLIENT_OBJS) {
            send_error(c, reg_id, 0, "bind new_id out of range");
            return;
        }
        /* Find the matching global. */
        const struct global *g = NULL;
        for (int i = 0; i < N_GLOBALS; i++) {
            if (GLOBALS[i].name == name
                && strcmp(GLOBALS[i].interface, iface) == 0) {
                g = &GLOBALS[i]; break;
            }
        }
        if (!g) {
            send_error(c, reg_id, 0, "unknown global");
            return;
        }
        obj_clear(c, new_id);
        c->objs[new_id].type = g->type;

        /* Per-type just-bound announcements. */
        if (g->type == OBJ_WL_SHM) {
            send_shm_format(c, new_id, WL_SHM_FORMAT_ARGB8888);
            send_shm_format(c, new_id, WL_SHM_FORMAT_XRGB8888);
        } else if (g->type == OBJ_WL_OUTPUT) {
            /* Use the DRM-detected mode when scanout is live; otherwise
             * fall back to the same 1024x768 linux_srv advertises. */
            uint32_t out_w = g_drm.fd >= 0 ? g_drm.width  : 1024u;
            uint32_t out_h = g_drm.fd >= 0 ? g_drm.height : 768u;
            uint8_t body[128];
            put_u32(body,       0);  /* x */
            put_u32(body + 4,   0);  /* y */
            put_u32(body + 8,   270);/* physical_width (mm) */
            put_u32(body + 12,  203);/* physical_height (mm) */
            put_u32(body + 16,  0);  /* subpixel: unknown */
            size_t mw = put_string(body + 20, sizeof body - 20, "Telix");
            size_t mxw = put_string(body + 20 + mw,
                                    sizeof body - 20 - mw, "Virtual Display");
            put_u32(body + 20 + mw + mxw, 0); /* transform: normal */
            send_msg(c, new_id, WL_OUTPUT_EV_GEOMETRY,
                     body, 20 + mw + mxw + 4);

            uint8_t m[16];
            put_u32(m,      (1u << 0) | (1u << 1)); /* flags: current | preferred */
            put_u32(m + 4,  out_w);
            put_u32(m + 8,  out_h);
            put_u32(m + 12, 60000);                   /* refresh mHz */
            send_msg(c, new_id, WL_OUTPUT_EV_MODE, m, 16);

            uint8_t s[4];
            put_u32(s, 1);
            send_msg(c, new_id, WL_OUTPUT_EV_SCALE, s, 4);

            send_msg(c, new_id, WL_OUTPUT_EV_DONE, NULL, 0);
        } else if (g->type == OBJ_WL_SEAT) {
            /* Advertise pointer + keyboard capability bits, then the
             * human-readable name.  Both are required for a well-behaved
             * wl_seat. */
            uint8_t cap_body[4];
            put_u32(cap_body, WL_SEAT_CAP_POINTER | WL_SEAT_CAP_KEYBOARD);
            send_msg(c, new_id, WL_SEAT_EV_CAPABILITIES, cap_body, 4);
            uint8_t name_body[32];
            size_t nb = put_string(name_body, sizeof name_body, "default");
            send_msg(c, new_id, WL_SEAT_EV_NAME, name_body, nb);
        }
        break;
    }
    default:
        LOG("wl_registry: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_compositor(struct client *c, uint32_t id,
                                 uint16_t opcode,
                                 const uint8_t *args, uint16_t arg_len)
{
    switch (opcode) {
    case WL_COMPOSITOR_REQ_CREATE_SURFACE: {
        if (arg_len < 4) { LOG("create_surface short"); return; }
        uint32_t new_id = get_u32(args);
        LOG("wl_compositor(%u).create_surface(new_id=%u)", id, new_id);
        if (new_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        obj_clear(c, new_id);
        struct wl_surface_state *s = calloc(1, sizeof *s);
        if (!s) { send_error(c, id, 2, "oom"); return; }
        c->objs[new_id].type = OBJ_WL_SURFACE;
        c->objs[new_id].surface = s;
        break;
    }
    case WL_COMPOSITOR_REQ_CREATE_REGION: {
        if (arg_len < 4) { LOG("create_region short"); return; }
        uint32_t new_id = get_u32(args);
        LOG("wl_compositor(%u).create_region(new_id=%u)", id, new_id);
        if (new_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_REGION;
        break;
    }
    default:
        LOG("wl_compositor: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_shm(struct client *c, uint32_t id,
                          uint16_t opcode,
                          const uint8_t *args, uint16_t arg_len)
{
    switch (opcode) {
    case WL_SHM_REQ_CREATE_POOL: {
        if (arg_len < 8) { LOG("create_pool short"); return; }
        uint32_t new_id = get_u32(args);
        int32_t  size   = get_i32(args + 4);
        LOG("wl_shm(%u).create_pool(new_id=%u size=%d)", id, new_id, size);
        if (c->nrfds <= 0) {
            send_error(c, id, 0, "create_pool missing fd");
            return;
        }
        /* Pop front fd. */
        int fd = c->rfds[0];
        memmove(c->rfds, c->rfds + 1, (c->nrfds - 1) * sizeof c->rfds[0]);
        c->nrfds--;
        if (new_id >= MAX_CLIENT_OBJS) {
            close(fd);
            send_error(c, id, 0, "create_pool new_id out of range");
            return;
        }
        if (size <= 0) {
            close(fd);
            send_error(c, id, 0, "create_pool bad size");
            return;
        }
        void *base = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, fd, 0);
        if (base == MAP_FAILED) {
            LOG("mmap shm pool: %s", strerror(errno));
            close(fd);
            send_error(c, id, 2, "mmap pool failed");
            return;
        }
        struct shm_pool *p = calloc(1, sizeof *p);
        if (!p) { munmap(base, size); close(fd); send_error(c, id, 2, "oom"); return; }
        p->fd = fd;
        p->base = base;
        p->size = (size_t)size;
        p->refcount = 1;
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_SHM_POOL;
        c->objs[new_id].pool = p;
        break;
    }
    default:
        LOG("wl_shm: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_shm_pool(struct client *c, uint32_t id,
                               uint16_t opcode,
                               const uint8_t *args, uint16_t arg_len)
{
    struct shm_pool *p = c->objs[id].pool;
    if (!p) { send_error(c, id, 0, "dead pool"); return; }
    switch (opcode) {
    case WL_SHM_POOL_REQ_CREATE_BUFFER: {
        if (arg_len < 24) { LOG("shm_pool.create_buffer short"); return; }
        uint32_t new_id = get_u32(args);
        int32_t  off    = get_i32(args + 4);
        int32_t  w      = get_i32(args + 8);
        int32_t  h      = get_i32(args + 12);
        int32_t  stride = get_i32(args + 16);
        uint32_t format = get_u32(args + 20);
        LOG("wl_shm_pool(%u).create_buffer(new_id=%u off=%d %dx%d stride=%d fmt=%u)",
            id, new_id, off, w, h, stride, format);
        if (off < 0 || w <= 0 || h <= 0 || stride < w * 4
            || (size_t)(off + stride * h) > p->size) {
            send_error(c, id, 0, "create_buffer out of range");
            return;
        }
        if (new_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        struct wl_buffer_state *b = calloc(1, sizeof *b);
        if (!b) { send_error(c, id, 2, "oom"); return; }
        b->pool = p;
        p->refcount++;
        b->offset = (size_t)off;
        b->width = w; b->height = h; b->stride = stride;
        b->format = format;
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_BUFFER;
        c->objs[new_id].buffer = b;
        break;
    }
    case WL_SHM_POOL_REQ_DESTROY: {
        LOG("wl_shm_pool(%u).destroy", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    }
    case WL_SHM_POOL_REQ_RESIZE: {
        if (arg_len < 4) return;
        int32_t new_size = get_i32(args);
        LOG("wl_shm_pool(%u).resize(%d)", id, new_size);
        if (new_size <= 0 || (size_t)new_size <= p->size) {
            send_error(c, id, 0, "resize must grow");
            return;
        }
        void *nb = mremap(p->base, p->size, (size_t)new_size, MREMAP_MAYMOVE);
        if (nb == MAP_FAILED) {
            LOG("mremap: %s", strerror(errno));
            send_error(c, id, 2, "mremap failed");
            return;
        }
        p->base = nb;
        p->size = (size_t)new_size;
        break;
    }
    default:
        LOG("wl_shm_pool: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_buffer(struct client *c, uint32_t id, uint16_t opcode,
                             const uint8_t *args, uint16_t arg_len)
{
    (void)args; (void)arg_len;
    switch (opcode) {
    case WL_BUFFER_REQ_DESTROY:
        LOG("wl_buffer(%u).destroy", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    default:
        LOG("wl_buffer: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_surface(struct client *c, uint32_t id, uint16_t opcode,
                              const uint8_t *args, uint16_t arg_len)
{
    struct wl_surface_state *s = c->objs[id].surface;
    if (!s) { send_error(c, id, 0, "dead surface"); return; }
    switch (opcode) {
    case WL_SURFACE_REQ_DESTROY:
        LOG("wl_surface(%u).destroy", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    case WL_SURFACE_REQ_ATTACH: {
        if (arg_len < 12) { LOG("attach short"); return; }
        uint32_t buf_id = get_u32(args);
        int32_t  x = get_i32(args + 4);
        int32_t  y = get_i32(args + 8);
        LOG("wl_surface(%u).attach(buffer=%u %d,%d)", id, buf_id, x, y);
        s->pending_buffer = buf_id;
        s->has_pending_buffer = 1;
        break;
    }
    case WL_SURFACE_REQ_DAMAGE: {
        if (arg_len < 16) return;
        LOG("wl_surface(%u).damage", id);
        break;
    }
    case WL_SURFACE_REQ_FRAME: {
        if (arg_len < 4) return;
        uint32_t cb_id = get_u32(args);
        LOG("wl_surface(%u).frame(new_id=%u)", id, cb_id);
        if (cb_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        obj_clear(c, cb_id);
        c->objs[cb_id].type = OBJ_WL_CALLBACK;
        /* Fire the callback immediately — good enough for a skeleton.
         * A real compositor fires at vblank. */
        send_callback_done(c, cb_id, 0);
        break;
    }
    case WL_SURFACE_REQ_SET_OPAQUE_REG:
    case WL_SURFACE_REQ_SET_INPUT_REG:
    case WL_SURFACE_REQ_SET_TRANSFORM:
    case WL_SURFACE_REQ_SET_SCALE:
    case WL_SURFACE_REQ_DAMAGE_BUFFER:
    case WL_SURFACE_REQ_OFFSET:
        /* Accept silently for now. */
        break;
    case WL_SURFACE_REQ_COMMIT: {
        LOG("wl_surface(%u).commit", id);
        /* First surface with a committed buffer wins keyboard/pointer focus. */
        if (!c->focused_surface_id) c->focused_surface_id = id;
        if (s->has_pending_buffer) {
            s->current_buffer = s->pending_buffer;
            s->has_pending_buffer = 0;
            if (s->current_buffer && s->current_buffer < MAX_CLIENT_OBJS
                && c->objs[s->current_buffer].type == OBJ_WL_BUFFER)
            {
                struct wl_buffer_state *b = c->objs[s->current_buffer].buffer;
                LOG("  committed buffer: %dx%d stride=%d fmt=%u",
                    b->width, b->height, b->stride, b->format);
                /* Blit the client's surface into the scanout dumb buffer
                 * and page-flip — the buffer can be reused as soon as we
                 * return, which is what wl_buffer.release signals. */
                if (b->pool && b->pool->base) {
                    drm_blit_surface(b->pool->base, b->offset,
                                     b->width, b->height, b->stride);
                    drm_present();
                }
                send_msg(c, s->current_buffer, WL_BUFFER_EV_RELEASE, NULL, 0);
            }
        }
        break;
    }
    default:
        LOG("wl_surface: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_region(struct client *c, uint32_t id, uint16_t opcode,
                             const uint8_t *args, uint16_t arg_len)
{
    (void)args; (void)arg_len;
    switch (opcode) {
    case WL_REGION_REQ_DESTROY:
        LOG("wl_region(%u).destroy", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    case WL_REGION_REQ_ADD:
    case WL_REGION_REQ_SUBTRACT:
        break;
    default:
        LOG("wl_region: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_output(struct client *c, uint32_t id, uint16_t opcode,
                             const uint8_t *args, uint16_t arg_len)
{
    (void)args; (void)arg_len;
    switch (opcode) {
    case WL_OUTPUT_REQ_RELEASE:
        LOG("wl_output(%u).release", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    default:
        LOG("wl_output: unknown opcode %u", opcode);
        break;
    }
}

/* Copy a wire-format string into dst[dst_sz], NUL-terminated + bounded.
 * Returns the number of bytes consumed from args (including the 4-byte
 * length header and the 4-byte padding), or -1 if malformed. */
static ssize_t copy_wire_string(const uint8_t *args, uint16_t arg_len,
                                char *dst, size_t dst_sz)
{
    if (arg_len < 4) return -1;
    uint32_t len = get_u32(args);
    uint32_t pad = (len + 3u) & ~3u;
    if (len == 0 || 4u + pad > arg_len) return -1;
    if (args[4 + len - 1] != '\0') return -1;
    size_t copy_len = (size_t)len - 1;
    if (copy_len >= dst_sz) copy_len = dst_sz - 1;
    memcpy(dst, args + 4, copy_len);
    dst[copy_len] = '\0';
    return (ssize_t)(4 + pad);
}

static void handle_wl_seat(struct client *c, uint32_t id, uint16_t opcode,
                           const uint8_t *args, uint16_t arg_len)
{
    switch (opcode) {
    case WL_SEAT_REQ_GET_POINTER: {
        if (arg_len < 4) return;
        uint32_t new_id = get_u32(args);
        LOG("wl_seat(%u).get_pointer(new_id=%u)", id, new_id);
        if (new_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_POINTER;
        c->ptr_obj_id = new_id;
        /* If we already have a focused surface, fire the enter event now. */
        input_ensure_focused(c);
        break;
    }
    case WL_SEAT_REQ_GET_KEYBOARD: {
        if (arg_len < 4) return;
        uint32_t new_id = get_u32(args);
        LOG("wl_seat(%u).get_keyboard(new_id=%u)", id, new_id);
        if (new_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_WL_KEYBOARD;
        c->kbd_obj_id = new_id;
        /* wl_keyboard.keymap(format, fd, size) with SCM_RIGHTS fd.  The
         * fd stays owned by the compositor — libwayland dup()s it before
         * close, but the client on our test path will just close the
         * received fd so reuse is fine either way. */
        if (g_seat.keymap_fd >= 0) {
            uint8_t body[8];
            put_u32(body,     WL_KEYBOARD_KEYMAP_XKB_V1);
            put_u32(body + 4, (uint32_t)g_seat.keymap_len);
            send_msg_fd(c, new_id, WL_KEYBOARD_EV_KEYMAP, body, 8,
                        g_seat.keymap_fd);
        }
        /* wl_keyboard.repeat_info(rate, delay) — rate in keys/sec, delay in ms. */
        uint8_t rbody[8];
        put_u32(rbody,     25);   /* 25 keys/s */
        put_u32(rbody + 4, 600);  /* 600 ms */
        send_msg(c, new_id, WL_KEYBOARD_EV_REPEAT_INFO, rbody, 8);
        /* wl_keyboard.modifiers with all zero mods — clients expect a
         * modifiers state to initialise to. */
        uint8_t mbody[20];
        put_u32(mbody,      alloc_serial());
        put_u32(mbody + 4,  0);
        put_u32(mbody + 8,  0);
        put_u32(mbody + 12, 0);
        put_u32(mbody + 16, 0);
        send_msg(c, new_id, WL_KEYBOARD_EV_MODIFIERS, mbody, 20);
        input_ensure_focused(c);
        break;
    }
    case WL_SEAT_REQ_GET_TOUCH:
        /* Accept silently — no touch capability advertised, so clients
         * shouldn't call this in the first place.  Allocate a passthrough
         * object so subsequent requests won't hit "dead object" errors. */
        if (arg_len >= 4) {
            uint32_t new_id = get_u32(args);
            if (new_id < MAX_CLIENT_OBJS) {
                obj_clear(c, new_id);
                c->objs[new_id].type = OBJ_WL_REGION;
            }
        }
        break;
    case WL_SEAT_REQ_RELEASE:
        LOG("wl_seat(%u).release", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    default:
        LOG("wl_seat: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_pointer(struct client *c, uint32_t id, uint16_t opcode,
                              const uint8_t *args, uint16_t arg_len)
{
    (void)args; (void)arg_len;
    switch (opcode) {
    case WL_POINTER_REQ_SET_CURSOR:
        /* Client sets a cursor surface — accepted silently. */
        break;
    case WL_POINTER_REQ_RELEASE:
        LOG("wl_pointer(%u).release", id);
        if (c->ptr_obj_id == id) { c->ptr_obj_id = 0; c->ptr_entered = 0; }
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    default:
        LOG("wl_pointer: unknown opcode %u", opcode);
        break;
    }
}

static void handle_wl_keyboard(struct client *c, uint32_t id, uint16_t opcode,
                               const uint8_t *args, uint16_t arg_len)
{
    (void)args; (void)arg_len;
    switch (opcode) {
    case WL_KEYBOARD_REQ_RELEASE:
        LOG("wl_keyboard(%u).release", id);
        if (c->kbd_obj_id == id) { c->kbd_obj_id = 0; c->kbd_entered = 0; }
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    default:
        LOG("wl_keyboard: unknown opcode %u", opcode);
        break;
    }
}

static void handle_xdg_wm_base(struct client *c, uint32_t id,
                               uint16_t opcode,
                               const uint8_t *args, uint16_t arg_len)
{
    switch (opcode) {
    case XDG_WM_BASE_REQ_DESTROY:
        LOG("xdg_wm_base(%u).destroy", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    case XDG_WM_BASE_REQ_GET_XDG_SURFACE: {
        if (arg_len < 8) { LOG("get_xdg_surface: short args"); return; }
        uint32_t new_id     = get_u32(args);
        uint32_t surface_id = get_u32(args + 4);
        LOG("xdg_wm_base(%u).get_xdg_surface(new_id=%u surface=%u)",
            id, new_id, surface_id);
        if (new_id >= MAX_CLIENT_OBJS || surface_id >= MAX_CLIENT_OBJS
            || c->objs[surface_id].type != OBJ_WL_SURFACE)
        {
            send_error(c, id, 0, "get_xdg_surface: bad surface");
            return;
        }
        struct xdg_surface_state *xs = calloc(1, sizeof *xs);
        if (!xs) { send_error(c, id, 2, "oom"); return; }
        xs->wl_surface_id = surface_id;
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_XDG_SURFACE;
        c->objs[new_id].xdg_surface = xs;
        /* Back-link from wl_surface so commit can enforce the
         * configure-before-attach rule. */
        c->objs[surface_id].surface->xdg_surface_id = new_id;
        break;
    }
    case XDG_WM_BASE_REQ_CREATE_POSITIONER: {
        /* Positioners are only needed for popups, which we don't handle —
         * but we still need to allocate the object id so subsequent requests
         * don't hit "dead object" errors. */
        if (arg_len < 4) return;
        uint32_t new_id = get_u32(args);
        LOG("xdg_wm_base(%u).create_positioner(new_id=%u) — stub", id, new_id);
        if (new_id >= MAX_CLIENT_OBJS) return;
        obj_clear(c, new_id);
        /* Reuse OBJ_WL_REGION as a "opaque no-op object" type. */
        c->objs[new_id].type = OBJ_WL_REGION;
        break;
    }
    case XDG_WM_BASE_REQ_PONG:
        /* Client acknowledging our (non-existent) ping. */
        break;
    default:
        LOG("xdg_wm_base: unknown opcode %u", opcode);
        break;
    }
}

static void handle_xdg_surface(struct client *c, uint32_t id,
                               uint16_t opcode,
                               const uint8_t *args, uint16_t arg_len)
{
    struct xdg_surface_state *xs = c->objs[id].xdg_surface;
    if (!xs) { send_error(c, id, 0, "dead xdg_surface"); return; }
    switch (opcode) {
    case XDG_SURFACE_REQ_DESTROY:
        LOG("xdg_surface(%u).destroy", id);
        /* Detach back-reference on the underlying wl_surface, if any. */
        if (xs->wl_surface_id < MAX_CLIENT_OBJS
            && c->objs[xs->wl_surface_id].type == OBJ_WL_SURFACE)
        {
            c->objs[xs->wl_surface_id].surface->xdg_surface_id = 0;
        }
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    case XDG_SURFACE_REQ_GET_TOPLEVEL: {
        if (arg_len < 4) return;
        uint32_t new_id = get_u32(args);
        LOG("xdg_surface(%u).get_toplevel(new_id=%u)", id, new_id);
        if (new_id >= MAX_CLIENT_OBJS) { send_error(c, id, 0, "out of range"); return; }
        struct xdg_toplevel_state *tl = calloc(1, sizeof *tl);
        if (!tl) { send_error(c, id, 2, "oom"); return; }
        tl->xdg_surface_id = id;
        obj_clear(c, new_id);
        c->objs[new_id].type = OBJ_XDG_TOPLEVEL;
        c->objs[new_id].xdg_toplevel = tl;
        xs->toplevel_id = new_id;
        /* Send the initial configure handshake.  For kiosk-style
         * presentation we suggest the full display size; the client is
         * free to pick its own buffer dimensions in response. */
        int32_t w = g_drm.fd >= 0 ? (int32_t)g_drm.width  : 1024;
        int32_t h = g_drm.fd >= 0 ? (int32_t)g_drm.height : 768;
        send_xdg_toplevel_configure(c, new_id, w, h);
        uint32_t serial = alloc_serial();
        xs->last_configure_serial = serial;
        xs->configured = 1;
        send_xdg_surface_configure(c, id, serial);
        break;
    }
    case XDG_SURFACE_REQ_GET_POPUP:
        /* Popups are layered on top of a parent surface; not modelled here,
         * but still need to eat the new_id so the client doesn't stall on
         * a dead object. */
        if (arg_len >= 4) {
            uint32_t new_id = get_u32(args);
            LOG("xdg_surface(%u).get_popup(new_id=%u) — stub", id, new_id);
            if (new_id < MAX_CLIENT_OBJS) {
                obj_clear(c, new_id);
                c->objs[new_id].type = OBJ_WL_REGION;
            }
        }
        break;
    case XDG_SURFACE_REQ_SET_WINDOW_GEOMETRY:
        /* Hint for where the window's 'visible' geometry is within the
         * buffer (excluding drop shadows etc).  Ignored. */
        break;
    case XDG_SURFACE_REQ_ACK_CONFIGURE: {
        if (arg_len < 4) return;
        uint32_t serial = get_u32(args);
        LOG("xdg_surface(%u).ack_configure(serial=%u)", id, serial);
        if (serial == xs->last_configure_serial) xs->acked = 1;
        break;
    }
    default:
        LOG("xdg_surface: unknown opcode %u", opcode);
        break;
    }
}

static void handle_xdg_toplevel(struct client *c, uint32_t id,
                                uint16_t opcode,
                                const uint8_t *args, uint16_t arg_len)
{
    struct xdg_toplevel_state *tl = c->objs[id].xdg_toplevel;
    if (!tl) { send_error(c, id, 0, "dead xdg_toplevel"); return; }
    switch (opcode) {
    case XDG_TOPLEVEL_REQ_DESTROY:
        LOG("xdg_toplevel(%u).destroy", id);
        obj_clear(c, id);
        send_delete_id(c, id);
        break;
    case XDG_TOPLEVEL_REQ_SET_TITLE:
        if (copy_wire_string(args, arg_len, tl->title, sizeof tl->title) >= 0) {
            LOG("xdg_toplevel(%u).set_title(\"%s\")", id, tl->title);
        }
        break;
    case XDG_TOPLEVEL_REQ_SET_APP_ID:
        if (copy_wire_string(args, arg_len, tl->app_id, sizeof tl->app_id) >= 0) {
            LOG("xdg_toplevel(%u).set_app_id(\"%s\")", id, tl->app_id);
        }
        break;
    case XDG_TOPLEVEL_REQ_SET_PARENT:
    case XDG_TOPLEVEL_REQ_SHOW_WINDOW_MENU:
    case XDG_TOPLEVEL_REQ_MOVE:
    case XDG_TOPLEVEL_REQ_RESIZE:
    case XDG_TOPLEVEL_REQ_SET_MAX_SIZE:
    case XDG_TOPLEVEL_REQ_SET_MIN_SIZE:
    case XDG_TOPLEVEL_REQ_SET_MAXIMIZED:
    case XDG_TOPLEVEL_REQ_UNSET_MAXIMIZED:
    case XDG_TOPLEVEL_REQ_SET_FULLSCREEN:
    case XDG_TOPLEVEL_REQ_UNSET_FULLSCREEN:
    case XDG_TOPLEVEL_REQ_SET_MINIMIZED:
        /* All accepted silently — kiosk behaviour treats every client as
         * full-screen and non-interactive. */
        break;
    default:
        LOG("xdg_toplevel: unknown opcode %u", opcode);
        break;
    }
}

/* Dispatch one complete message from client buffer.  Returns bytes consumed,
 * or 0 if more data needed, or -1 on protocol error. */
static ssize_t dispatch_one(struct client *c) {
    if (c->rlen < 8) return 0;
    uint32_t object_id = get_u32(c->rbuf);
    uint32_t szop = get_u32(c->rbuf + 4);
    uint16_t total = szop >> 16;
    uint16_t opcode = szop & 0xffff;
    if (total < 8) {
        LOG("malformed header: total=%u opcode=%u", total, opcode);
        return -1;
    }
    if (c->rlen < total) return 0;

    const uint8_t *args = c->rbuf + 8;
    uint16_t arg_len = total - 8;

    if (object_id >= MAX_CLIENT_OBJS) {
        LOG("object_id %u out of range", object_id);
        return total;
    }
    enum obj_type ot = c->objs[object_id].type;
    LOG("<- obj=%u (%s) op=%u total=%u", object_id, obj_type_name(ot), opcode, total);

    switch (ot) {
    case OBJ_WL_DISPLAY:    handle_wl_display(c, opcode, args, arg_len); break;
    case OBJ_WL_REGISTRY:   handle_wl_registry(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_COMPOSITOR: handle_wl_compositor(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_SHM:        handle_wl_shm(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_SHM_POOL:   handle_wl_shm_pool(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_BUFFER:     handle_wl_buffer(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_SURFACE:    handle_wl_surface(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_REGION:     handle_wl_region(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_OUTPUT:     handle_wl_output(c, object_id, opcode, args, arg_len); break;
    case OBJ_XDG_WM_BASE:   handle_xdg_wm_base(c, object_id, opcode, args, arg_len); break;
    case OBJ_XDG_SURFACE:   handle_xdg_surface(c, object_id, opcode, args, arg_len); break;
    case OBJ_XDG_TOPLEVEL:  handle_xdg_toplevel(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_SEAT:       handle_wl_seat(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_POINTER:    handle_wl_pointer(c, object_id, opcode, args, arg_len); break;
    case OBJ_WL_KEYBOARD:   handle_wl_keyboard(c, object_id, opcode, args, arg_len); break;
    case OBJ_NONE:
        LOG("request on dead/unknown object %u", object_id);
        send_error(c, object_id, 0, "invalid object");
        break;
    default:
        LOG("no handler for object %u (type %s) op %u",
            object_id, obj_type_name(ot), opcode);
        break;
    }
    return total;
}

/* ---------- Recv with ancillary fds ---------- */

static int client_recv(struct client *c) {
    uint8_t cbuf[CMSG_SPACE(sizeof(int) * 16)];
    struct iovec iov = {
        .iov_base = c->rbuf + c->rlen,
        .iov_len  = sizeof c->rbuf - c->rlen,
    };
    struct msghdr mh = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof cbuf,
    };
    ssize_t n = recvmsg(c->fd, &mh, MSG_CMSG_CLOEXEC);
    if (n == 0) return 0;
    if (n < 0) {
        if (errno == EINTR) return 1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
        LOG("recvmsg: %s", strerror(errno));
        return -1;
    }
    c->rlen += (size_t)n;

    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            int nfd = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            int *fdp = (int *)CMSG_DATA(cm);
            for (int i = 0; i < nfd; i++) {
                if (c->nrfds < (int)(sizeof c->rfds / sizeof c->rfds[0])) {
                    c->rfds[c->nrfds++] = fdp[i];
                    LOG("   recv fd=%d (queue depth %d)", fdp[i], c->nrfds);
                } else {
                    LOG("   fd queue full, closing %d", fdp[i]);
                    close(fdp[i]);
                }
            }
        }
    }
    return 1;
}

/* ---------- Socket setup ---------- */

static int make_listen_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) DIE("socket: %s", strerror(errno));

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof sun);
    sun.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sun.sun_path)
        DIE("socket path too long: %s", path);
    strncpy(sun.sun_path, path, sizeof sun.sun_path - 1);

    unlink(path);

    if (bind(fd, (struct sockaddr *)&sun,
             offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1) < 0)
        DIE("bind(%s): %s", path, strerror(errno));

    if (listen(fd, 4) < 0)
        DIE("listen: %s", strerror(errno));

    LOG("listening on %s (fd=%d)", path, fd);
    return fd;
}

static void build_socket_path(char *out, size_t out_sz) {
    const char *display = getenv("WAYLAND_DISPLAY");
    const char *runtime = getenv("XDG_RUNTIME_DIR");

    if (display && display[0] == '/') {
        snprintf(out, out_sz, "%s", display);
        return;
    }
    if (!runtime || !runtime[0]) {
        uid_t uid = getuid();
        static char rt[64];
        snprintf(rt, sizeof rt, "/run/user/%u", (unsigned)uid);
        runtime = rt;
    }
    if (!display || !display[0]) display = "wayland-0";
    snprintf(out, out_sz, "%s/%s", runtime, display);
}

/* ---------- Main loop ---------- */

/* Ensure enter events have been sent to the focused surface.  Called just
 * before dispatching any input-derived Wayland event. */
static void input_ensure_focused(struct client *c) {
    if (!c->focused_surface_id) return;
    if (c->kbd_obj_id && !c->kbd_entered) {
        uint8_t body[16];
        put_u32(body, alloc_serial());
        put_u32(body + 4, c->focused_surface_id);
        put_u32(body + 8, 0);  /* keys array: empty */
        put_u32(body + 12, 0); /* (pad for alignment) */
        send_msg(c, c->kbd_obj_id, WL_KEYBOARD_EV_ENTER, body, 12);
        c->kbd_entered = 1;
    }
    if (c->ptr_obj_id && !c->ptr_entered) {
        uint8_t body[16];
        put_u32(body,      alloc_serial());
        put_u32(body + 4,  c->focused_surface_id);
        put_u32(body + 8,  0); /* surface_x fixed: 0.0 */
        put_u32(body + 12, 0); /* surface_y fixed: 0.0 */
        send_msg(c, c->ptr_obj_id, WL_POINTER_EV_ENTER, body, 16);
        c->ptr_entered = 1;
    }
}

/* Drain an evdev fd and fan translated events out to `c`.
 * `is_keyboard`: true for key events, false for pointer. */
static void input_pump(struct client *c, int fd, int is_keyboard) {
    uint8_t buf[EVDEV_EVENT_SIZE * 32];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n <= 0) return;
    input_ensure_focused(c);

    for (ssize_t off = 0; off + EVDEV_EVENT_SIZE <= n; off += EVDEV_EVENT_SIZE) {
        uint16_t type  = (uint16_t)(buf[off + 16] | (buf[off + 17] << 8));
        uint16_t code  = (uint16_t)(buf[off + 18] | (buf[off + 19] << 8));
        int32_t  value = (int32_t)(buf[off + 20] | (buf[off + 21] << 8)
                                 | (buf[off + 22] << 16) | (buf[off + 23] << 24));

        if (type == EV_SYN) continue;

        if (is_keyboard && type == EV_KEY && c->kbd_obj_id) {
            uint8_t body[16];
            put_u32(body,      alloc_serial());
            put_u32(body + 4,  now_ms());
            put_u32(body + 8,  code);
            put_u32(body + 12, value ? WL_KEYBOARD_KEY_PRESSED
                                     : WL_KEYBOARD_KEY_RELEASED);
            send_msg(c, c->kbd_obj_id, WL_KEYBOARD_EV_KEY, body, 16);
        } else if (!is_keyboard && c->ptr_obj_id) {
            if (type == EV_REL && code == REL_X) {
                g_seat.ptr_x += value;
                uint8_t body[16];
                /* fixed-point 24.8: pixel << 8 */
                put_u32(body,      now_ms());
                put_u32(body + 4,  (uint32_t)(g_seat.ptr_x << 8));
                put_u32(body + 8,  (uint32_t)(g_seat.ptr_y << 8));
                put_u32(body + 12, 0);
                send_msg(c, c->ptr_obj_id, WL_POINTER_EV_MOTION, body, 12);
            } else if (type == EV_REL && code == REL_Y) {
                g_seat.ptr_y += value;
                uint8_t body[16];
                put_u32(body,      now_ms());
                put_u32(body + 4,  (uint32_t)(g_seat.ptr_x << 8));
                put_u32(body + 8,  (uint32_t)(g_seat.ptr_y << 8));
                put_u32(body + 12, 0);
                send_msg(c, c->ptr_obj_id, WL_POINTER_EV_MOTION, body, 12);
            } else if (type == EV_KEY) {
                /* BTN_LEFT/RIGHT/MIDDLE arrive as EV_KEY events with
                 * codes in the BTN_* range — forward as pointer buttons. */
                uint8_t body[16];
                put_u32(body,      alloc_serial());
                put_u32(body + 4,  now_ms());
                put_u32(body + 8,  code);
                put_u32(body + 12, value ? WL_POINTER_BUTTON_PRESSED
                                         : WL_POINTER_BUTTON_RELEASED);
                send_msg(c, c->ptr_obj_id, WL_POINTER_EV_BUTTON, body, 16);
            }
            /* Wayland v5: frame after every logical input group.  Cheap. */
            send_msg(c, c->ptr_obj_id, WL_POINTER_EV_FRAME, NULL, 0);
        }
    }
}

static void serve_client(int cfd) {
    struct client c;
    memset(&c, 0, sizeof c);
    c.fd = cfd;
    c.objs[WL_DISPLAY_ID].type = OBJ_WL_DISPLAY;

    /* Input dispatch runs opportunistically rather than via a poll() on
     * both the client socket and the evdev fds.  Telix's linux_srv has a
     * poll() that returns early on unknown fd kinds, and the result was
     * flaky when mixing UDS + evdev in a single pollfd set.  The evdev
     * fds are O_NONBLOCK, so drain-then-recv gives us the input-event
     * fanout with far less surface area — at the cost of higher latency
     * on rapid key events (which we don't care about for smoke tests). */
    for (;;) {
        if (g_seat.kbd_fd >= 0) input_pump(&c, g_seat.kbd_fd, 1);
        if (g_seat.ptr_fd >= 0) input_pump(&c, g_seat.ptr_fd, 0);
        int r = client_recv(&c);
        if (r == 0) { LOG("client disconnected"); break; }
        if (r < 0)  { LOG("client recv error, dropping"); break; }
        for (;;) {
            ssize_t used = dispatch_one(&c);
            if (used <= 0) {
                if (used < 0) { LOG("protocol error, dropping client"); goto cleanup; }
                break;
            }
            if ((size_t)used < c.rlen)
                memmove(c.rbuf, c.rbuf + used, c.rlen - used);
            c.rlen -= (size_t)used;
        }
    }
cleanup:
    for (int i = 0; i < c.nrfds; i++) close(c.rfds[i]);
    for (uint32_t i = 0; i < MAX_CLIENT_OBJS; i++) obj_clear(&c, i);
    close(cfd);
}

int main(int argc, char **argv) {
    int one_shot = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--one-shot") == 0) one_shot = 1;
    }
    if (!one_shot && getenv("WL_COMPOSITOR_ONE_SHOT")) one_shot = 1;

    char sock_path[108];
    build_socket_path(sock_path, sizeof sock_path);
    LOG("socket path: %s%s", sock_path, one_shot ? " (one-shot)" : "");

    /* Set up scanout before accepting clients so the wl_output geometry
     * we advertise matches the display that'll actually receive pixels.
     * 1024x768 matches what Telix's linux_srv / fb_srv expose; libdrm
     * would query the connector for its preferred mode. */
    drm_setup(1024, 768);
    input_setup();

    int lfd = make_listen_socket(sock_path);

    for (;;) {
        int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            LOG("accept: %s", strerror(errno));
            break;
        }
        LOG("client connected (fd=%d)", cfd);
        serve_client(cfd);
        LOG("client closed, awaiting next");
        if (one_shot) break;
    }

    drm_teardown();
    input_teardown();
    close(lfd);
    unlink(sock_path);
    return 0;
}
