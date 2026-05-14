#!/bin/bash
# Sudo helper: write a single PID into /sys/fs/cgroup/qemu-rt/cgroup.procs.
# Used by run-qemu-x86.sh when TELIX_RT_CGROUP is set and the shim's
# CAP_SYS_ADMIN attempt fails (which we've seen on Fedora 43 + kernel
# 6.18 despite getcap/runtime-CapEff confirming the cap is effective —
# the kernel's cgroup migration check rejects the common-ancestor
# bypass for reasons that aren't documented).
#
# Install once with NOPASSWD sudoers so the wrapper doesn't prompt:
#   echo 'nyc ALL=(root) NOPASSWD: /home/nyc/src/telix/tools/host-setup/qemu-rt-attach.sh *' | \
#       sudo tee /etc/sudoers.d/telix-qemu-rt-attach
#   sudo chmod 440 /etc/sudoers.d/telix-qemu-rt-attach
#
# After install, run-qemu-x86.sh will use:
#   sudo -n /path/to/qemu-rt-attach.sh "$$"  # before exec
#
# Security model: this script only ever writes to ONE specific file
# (/sys/fs/cgroup/qemu-rt/cgroup.procs) and rejects anything else.
# It validates the PID arg is a number and belongs to the invoking
# user.  No file path traversal, no arbitrary cgroup writes.

set -e

if [ "$(id -u)" != "0" ]; then
    echo "$0: must be run as root (sudo)" >&2
    exit 1
fi

CG=/sys/fs/cgroup/qemu-rt
[ -d "$CG" ] || { echo "$0: $CG does not exist; run setup-qemu-rt-cgroup.sh first" >&2; exit 1; }

PID="$1"
case "$PID" in
    ''|*[!0-9]*)
        echo "$0: PID must be numeric, got '$PID'" >&2
        exit 1
        ;;
esac

# Validate the PID belongs to the invoking user (SUDO_UID, since we ran via sudo).
PID_UID=$(stat -c %u "/proc/$PID" 2>/dev/null) || { echo "$0: no such pid $PID" >&2; exit 1; }
if [ -n "${SUDO_UID:-}" ] && [ "$PID_UID" != "$SUDO_UID" ]; then
    echo "$0: pid $PID is owned by uid $PID_UID, but caller is uid $SUDO_UID — refusing" >&2
    exit 1
fi

# Do the migration.  All threads of the process move with the procs write.
echo "$PID" > "$CG/cgroup.procs"
echo "$0: pid $PID attached to $CG"
