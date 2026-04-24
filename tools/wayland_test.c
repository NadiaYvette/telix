/* Step F smoke test: verify DRM + evdev + memfd/SHM + UDS infrastructure
 * needed by a Wayland compositor works under the Telix Linux personality.
 *
 * Build:
 *   gcc -static-pie -fPIE -O2 -fno-stack-protector -s -o wayland_test wayland_test.c
 *
 * Exercises:
 *   1. DRM: open /dev/dri/card0, DRM_IOCTL_VERSION, DRM_IOCTL_MODE_GETRESOURCES
 *   2. Evdev: open /dev/input/event0, EVIOCGVERSION, EVIOCGID, EVIOCGNAME
 *   3. Memfd: memfd_create, ftruncate, mmap MAP_SHARED, write pattern, verify
 *   4. UDS: socket AF_UNIX, bind /run/user/0/test-wl, listen
 *
 * Returns 0 on success, section number (1-4) on first failure.
 */
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdint.h>

/* --- helpers --- */

static void puts_s(const char *s) {
    write(1, s, strlen(s));
}

static void puts_ok(const char *label) {
    puts_s("  ");
    puts_s(label);
    puts_s(": OK\n");
}

static void puts_fail(const char *label) {
    puts_s("  ");
    puts_s(label);
    puts_s(": FAIL\n");
}

/* --- DRM ioctls (Linux x86_64 _IOWR encoding) --- */

#define DRM_IOCTL_VERSION          0xC0406400UL
#define DRM_IOCTL_MODE_GETRESOURCES 0xC04064A0UL

struct drm_version {
    int version_major;
    int version_minor;
    int version_patchlevel;
    uint64_t name_len;
    char *name;
    uint64_t date_len;
    char *date;
    uint64_t desc_len;
    char *desc;
};

struct drm_mode_card_res {
    uint64_t fb_id_ptr;
    uint64_t crtc_id_ptr;
    uint64_t connector_id_ptr;
    uint64_t encoder_id_ptr;
    uint32_t count_fbs;
    uint32_t count_crtcs;
    uint32_t count_connectors;
    uint32_t count_encoders;
    uint32_t min_width, max_width;
    uint32_t min_height, max_height;
};

/* --- Evdev ioctls --- */

#define EVIOCGVERSION  0x80044501UL
#define EVIOCGID       0x80084502UL
#define EVIOCGNAME_256 0x80FF4506UL  /* EVIOCGNAME(256) */

struct input_id {
    uint16_t bustype;
    uint16_t vendor;
    uint16_t product;
    uint16_t version;
};

/* --- test functions --- */

static int test_drm(void) {
    puts_s("[1/4] DRM/KMS\n");

    int fd = open("/dev/dri/card0", O_RDWR);
    if (fd < 0) { puts_fail("open /dev/dri/card0"); return 1; }
    puts_ok("open /dev/dri/card0");

    /* DRM_IOCTL_VERSION */
    char name[32] = {0};
    struct drm_version ver;
    memset(&ver, 0, sizeof(ver));
    ver.name = name;
    ver.name_len = sizeof(name) - 1;
    if (ioctl(fd, DRM_IOCTL_VERSION, &ver) < 0) {
        puts_fail("DRM_IOCTL_VERSION");
        close(fd);
        return 1;
    }
    puts_s("  version: ");
    /* Print major.minor.patch */
    char vbuf[4];
    vbuf[0] = '0' + ver.version_major; vbuf[1] = '.';
    vbuf[2] = '0' + ver.version_minor; vbuf[3] = '\n';
    write(1, vbuf, 4);
    puts_s("  driver: ");
    puts_s(name);
    puts_s("\n");
    puts_ok("DRM_IOCTL_VERSION");

    /* DRM_IOCTL_MODE_GETRESOURCES — first call with zero counts to get sizes */
    struct drm_mode_card_res res;
    memset(&res, 0, sizeof(res));
    if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        puts_fail("DRM_IOCTL_MODE_GETRESOURCES");
        close(fd);
        return 1;
    }
    puts_ok("DRM_IOCTL_MODE_GETRESOURCES");

    close(fd);
    return 0;
}

static int test_evdev(void) {
    puts_s("[2/4] Evdev input\n");

    int fd = open("/dev/input/event0", O_RDONLY);
    if (fd < 0) { puts_fail("open /dev/input/event0"); return 2; }
    puts_ok("open /dev/input/event0");

    /* EVIOCGVERSION */
    int version = 0;
    if (ioctl(fd, EVIOCGVERSION, &version) < 0) {
        puts_fail("EVIOCGVERSION");
        close(fd);
        return 2;
    }
    puts_s("  evdev version: 0x");
    /* Print hex */
    static const char hex[] = "0123456789abcdef";
    char hbuf[9];
    for (int i = 7; i >= 0; i--) {
        hbuf[7 - i] = hex[(version >> (i * 4)) & 0xf];
    }
    hbuf[8] = '\n';
    write(1, hbuf, 9);
    puts_ok("EVIOCGVERSION");

    /* EVIOCGID */
    struct input_id id;
    memset(&id, 0, sizeof(id));
    if (ioctl(fd, EVIOCGID, &id) < 0) {
        puts_fail("EVIOCGID");
        close(fd);
        return 2;
    }
    puts_ok("EVIOCGID");

    /* EVIOCGNAME */
    char name[256] = {0};
    int ret = ioctl(fd, EVIOCGNAME_256, name);
    if (ret < 0) {
        puts_fail("EVIOCGNAME");
        close(fd);
        return 2;
    }
    puts_s("  device: ");
    puts_s(name);
    puts_s("\n");
    puts_ok("EVIOCGNAME");

    close(fd);
    return 0;
}

static int test_memfd_shm(void) {
    puts_s("[3/4] Memfd / SHM\n");

    /* memfd_create("wl-shm", MFD_ALLOW_SEALING) */
    int fd = (int)syscall(SYS_memfd_create, "wl-shm", 2 /* MFD_ALLOW_SEALING */);
    if (fd < 0) { puts_fail("memfd_create"); return 3; }
    puts_ok("memfd_create");

    /* ftruncate to 4096 bytes (one page) */
    if (ftruncate(fd, 4096) < 0) {
        puts_fail("ftruncate");
        close(fd);
        return 3;
    }
    puts_ok("ftruncate(4096)");

    /* mmap MAP_SHARED */
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        puts_fail("mmap MAP_SHARED");
        close(fd);
        return 3;
    }
    puts_ok("mmap MAP_SHARED");

    /* Write a pattern and verify */
    uint32_t *pixels = (uint32_t *)ptr;
    for (int i = 0; i < 1024; i++) {
        pixels[i] = 0xFF336699; /* XRGB8888 blue-ish */
    }
    if (pixels[0] == 0xFF336699 && pixels[1023] == 0xFF336699) {
        puts_ok("write+verify pattern");
    } else {
        puts_fail("write+verify pattern");
        munmap(ptr, 4096);
        close(fd);
        return 3;
    }

    /* F_GET_SEALS / F_ADD_SEALS via fcntl */
    int seals = fcntl(fd, 1034 /* F_GET_SEALS */);
    if (seals < 0) {
        puts_fail("F_GET_SEALS");
    } else {
        puts_ok("F_GET_SEALS");
        /* Add F_SEAL_SHRINK */
        int r = fcntl(fd, 1033 /* F_ADD_SEALS */, 0x02 /* F_SEAL_SHRINK */);
        if (r < 0) {
            puts_fail("F_ADD_SEALS(SHRINK)");
        } else {
            puts_ok("F_ADD_SEALS(SHRINK)");
        }
    }

    munmap(ptr, 4096);
    close(fd);
    return 0;
}

static int test_uds(void) {
    puts_s("[4/4] Unix domain sockets\n");

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { puts_fail("socket AF_UNIX"); return 4; }
    puts_ok("socket AF_UNIX");

    /* Bind to a Wayland-style path */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/run/user/0/test-wl", sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr,
             sizeof(addr.sun_family) + strlen(addr.sun_path) + 1) < 0) {
        puts_fail("bind /run/user/0/test-wl");
        close(fd);
        return 4;
    }
    puts_ok("bind /run/user/0/test-wl");

    if (listen(fd, 1) < 0) {
        puts_fail("listen");
        close(fd);
        return 4;
    }
    puts_ok("listen");

    /* Clean up: unlink + close */
    unlink("/run/user/0/test-wl");
    close(fd);
    return 0;
}

int main(void) {
    puts_s("=== Wayland infrastructure smoke test ===\n");

    int rc;
    if ((rc = test_drm()) != 0) return rc;
    if ((rc = test_evdev()) != 0) return rc;
    if ((rc = test_memfd_shm()) != 0) return rc;
    if ((rc = test_uds()) != 0) return rc;

    puts_s("=== All 4 tests passed ===\n");
    return 0;
}
