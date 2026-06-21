/* telix-cpuset.c — setuid-root helper to (re)create the Telix QEMU cpuset
 * partition AUTONOMOUSLY (e.g. after a host reboot) without an interactive
 * sudo prompt.
 *
 * This is the setuid sibling of tools/host-setup/setup-qemu-rt-cgroup.sh:
 * it manages the SAME cgroup (/sys/fs/cgroup/qemu-rt) the same way (a "root"
 * partition — NOT "isolated", which killed parallelism at boot 99amfsq2),
 * and chowns cgroup.procs to the invoking user so run-qemu-x86.sh's
 * TELIX_RT_CGROUP attach works without sudo.  Use whichever you prefer:
 *   - `sudo tools/host-setup/setup-qemu-rt-cgroup.sh 0-9`  (manual, by you)
 *   - `telix-cpuset setup`                                  (autonomous, by me, once setuid)
 *
 * Build + install (once, as root):
 *     cc -O2 -Wall -Wextra -o tools/telix-cpuset tools/telix-cpuset.c
 *     sudo chown root:root tools/telix-cpuset
 *     sudo chmod u+s       tools/telix-cpuset
 *
 * Usage (no sudo after setuid):
 *     telix-cpuset setup         # create/refresh qemu-rt root partition on TELIX_CPUS
 *     telix-cpuset status        # show partition state + members
 *     telix-cpuset teardown      # dissolve (members -> parent, cpus return to pool)
 * Then boot: TELIX_RT_CGROUP=/sys/fs/cgroup/qemu-rt tools/boot-h14.sh
 *
 * Safety: only ever operates on the FIXED cgroup path below; never execs;
 * chowns cgroup.procs only to the REAL (invoking) uid.  Edit TELIX_CPUS +
 * rebuild to change the core set (keep it consistent with pgcl owning 12-19).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CG_ROOT    "/sys/fs/cgroup"
#define QEMU_RT_CG CG_ROOT "/qemu-rt"          /* matches run-qemu-x86.sh TELIX_RT_CGROUP */
#define TELIX_CPUS "0-9"                        /* P-cores 0-4; pgcl=12-19, desktop=10-11 */

static int write_str(const char *path, const char *val, int quiet) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) { if (!quiet) fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }
    ssize_t n = write(fd, val, strlen(val));
    int e = errno;
    close(fd);
    if (n < 0) { if (!quiet) fprintf(stderr, "write %s <- %s: %s\n", path, val, strerror(e)); errno = e; return -1; }
    return 0;
}

static int read_line(const char *path, char *buf, size_t len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { snprintf(buf, len, "(absent)"); return -1; }
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0) { snprintf(buf, len, "(err)"); return -1; }
    buf[n] = 0;
    char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
    return 0;
}

static int cmd_setup(void) {
    write_str(CG_ROOT "/cgroup.subtree_control", "+cpuset", 1);   /* ok if already on */

    if (mkdir(QEMU_RT_CG, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", QEMU_RT_CG, strerror(errno));
        return 1;
    }
    if (write_str(QEMU_RT_CG "/cpuset.cpus", TELIX_CPUS, 0) < 0) return 1;
    write_str(QEMU_RT_CG "/cpuset.cpus.exclusive", TELIX_CPUS, 1); /* kernel >= 5.19; ok if absent */
    if (write_str(QEMU_RT_CG "/cpuset.cpus.partition", "root", 0) < 0) return 1;

    char part[64], eff[64];
    read_line(QEMU_RT_CG "/cpuset.cpus.partition", part, sizeof part);
    read_line(QEMU_RT_CG "/cpuset.cpus.effective", eff, sizeof eff);
    if (strstr(part, "invalid")) {
        fprintf(stderr, "FAILED: partition=%s (cpus %s not exclusively grantable — a sibling "
                        "cgroup may already claim them).\n", part, TELIX_CPUS);
        return 2;
    }

    /* Let the invoking user write tasks into the cgroup without sudo, so
     * run-qemu-x86.sh (TELIX_RT_CGROUP) can self-attach.  Mirrors
     * setup-qemu-rt-cgroup.sh. */
    uid_t ruid = getuid();
    if (chown(QEMU_RT_CG "/cgroup.procs", ruid, (gid_t)-1) < 0)
        fprintf(stderr, "warn: chown cgroup.procs: %s\n", strerror(errno));

    printf("OK: %s -> root partition on cpus %s (effective=%s)\n", QEMU_RT_CG, TELIX_CPUS, eff);
    printf("boot with: TELIX_RT_CGROUP=%s tools/boot-h14.sh\n", QEMU_RT_CG);
    return 0;
}

static int cmd_status(void) {
    struct stat st;
    if (stat(QEMU_RT_CG, &st) < 0) { printf("qemu-rt partition: NOT set up (run `telix-cpuset setup`)\n"); return 0; }
    char part[64], cpus[64], eff[64], root_eff[64];
    read_line(QEMU_RT_CG "/cpuset.cpus.partition", part, sizeof part);
    read_line(QEMU_RT_CG "/cpuset.cpus", cpus, sizeof cpus);
    read_line(QEMU_RT_CG "/cpuset.cpus.effective", eff, sizeof eff);
    read_line(CG_ROOT "/cpuset.cpus.effective", root_eff, sizeof root_eff);
    printf("qemu-rt partition: state=%s cpus=%s effective=%s\n", part, cpus, eff);
    printf("root effective (everyone else): %s\n", root_eff);
    char buf[8192]; int fd = open(QEMU_RT_CG "/cgroup.procs", O_RDONLY);
    if (fd >= 0) { ssize_t n = read(fd, buf, sizeof buf - 1); close(fd);
        int c = 0; if (n > 0) { buf[n] = 0; for (char *p = buf; *p; p++) if (*p == '\n') c++; }
        printf("members: %d pid(s)\n", c); }
    return 0;
}

static int cmd_teardown(void) {
    char buf[8192]; int fd = open(QEMU_RT_CG "/cgroup.procs", O_RDONLY);
    if (fd >= 0) { ssize_t n = read(fd, buf, sizeof buf - 1); close(fd);
        if (n > 0) { buf[n] = 0; char *save = NULL;
            for (char *t = strtok_r(buf, "\n", &save); t; t = strtok_r(NULL, "\n", &save))
                write_str(CG_ROOT "/cgroup.procs", t, 1); } }
    write_str(QEMU_RT_CG "/cpuset.cpus.partition", "member", 1);
    if (rmdir(QEMU_RT_CG) < 0 && errno != ENOENT)
        fprintf(stderr, "rmdir %s: %s\n", QEMU_RT_CG, strerror(errno));
    else
        printf("qemu-rt partition dissolved; cpus %s returned to pool.\n", TELIX_CPUS);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s {setup|status|teardown}\n", argv[0]); return 2; }
    if (!strcmp(argv[1], "setup"))    return cmd_setup();
    if (!strcmp(argv[1], "status"))   return cmd_status();
    if (!strcmp(argv[1], "teardown")) return cmd_teardown();
    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 2;
}
