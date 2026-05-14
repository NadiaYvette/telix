#!/bin/bash
# Create a cgroup v2 cpuset partition with cpus.partition=isolated.
# The kernel scheduler's load balancer ignores CPUs in an isolated
# partition — they only run tasks explicitly placed there (or pinned
# via taskset).  This prevents non-qemu tasks from getting starved
# behind our SCHED_FIFO qemu vCPUs on the pinned cores.
#
# Run as root once per boot:
#   sudo tools/host-setup/setup-qemu-rt-cgroup.sh [CPU_LIST]
#
# CPU_LIST defaults to 0-3.  Override on the command line, e.g.:
#   sudo tools/host-setup/setup-qemu-rt-cgroup.sh 4-7
#
# After setup, in your shell:
#   export TELIX_RT_CGROUP=/sys/fs/cgroup/qemu-rt
#   TELIX_RTPRIO=50 tools/boot-h14.sh
# run-qemu-x86.sh's wrapper will write its own pid into the cgroup
# before exec'ing qemu, so qemu inherits cgroup membership.

set -e

if [ "$(id -u)" != "0" ]; then
    echo "$0: must be run as root (sudo $0 ...)" >&2
    exit 1
fi

CG=/sys/fs/cgroup/qemu-rt
CPUS="${1:-0-3}"

# Enable cpuset in root's subtree_control so child cgroups can use it.
if ! grep -qw cpuset /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then
    echo "+cpuset" > /sys/fs/cgroup/cgroup.subtree_control
fi

mkdir -p "$CG"

# Set the cpus.  Cleared first to avoid "value too short" on resize.
echo "$CPUS" > "$CG/cpuset.cpus"

# Mark as an isolated partition.  Kernel docs (cgroup-v2.rst):
#   isolated:  Like a "root" partition with the additional restriction
#              that all the CPUs in cpus.cpus are excluded from load
#              balancing.
echo "isolated" > "$CG/cpuset.cpus.partition"

# Verify it took.  Some kernels reject the transition with an error
# stored in cpuset.cpus.partition itself (e.g. "isolated invalid (no
# usable CPUs)").
state="$(cat "$CG/cpuset.cpus.partition")"
case "$state" in
    isolated)
        echo "OK: $CG → isolated partition on CPUs $CPUS"
        ;;
    *)
        echo "FAILED: $CG/cpuset.cpus.partition = '$state'" >&2
        echo "  Common causes:" >&2
        echo "    • Parent cgroup doesn't have $CPUS in its effective cpuset" >&2
        echo "    • A sibling cgroup already claims overlapping CPUs" >&2
        exit 1
        ;;
esac

# Allow the invoking user to write tasks into this cgroup without sudo.
# Owner = user; group stays root; only cgroup.procs is user-writable.
TARGET_USER="${SUDO_USER:-$USER}"
chown "$TARGET_USER" "$CG/cgroup.procs"
chmod u+w "$CG/cgroup.procs"

echo "Granted '$TARGET_USER' write access to $CG/cgroup.procs"
echo
echo "Use it:"
echo "  export TELIX_RT_CGROUP=$CG"
echo "  TELIX_RTPRIO=50 tools/boot-h14.sh"
