#!/bin/bash
# Build qemu-rt-shim and apply CAP_SYS_NICE to the result.
# Usage: ./build-and-install.sh
#
# After running, set TELIX_RT_SHIM to the printed binary path before
# launching boots:
#   export TELIX_RT_SHIM=/path/printed/below
#   TELIX_RTPRIO=50 tools/boot-h14.sh

set -e

cd "$(dirname "$0")"

# Use stable toolchain — the parent .cargo/config is no_std + nightly
# kernel build, which would conflict.  Our local .cargo/config overrides
# target and unsets build-std.
rustup run stable cargo build --release

BIN="$(pwd)/target/x86_64-unknown-linux-gnu/release/qemu-rt-shim"
[ -x "$BIN" ] || { echo "build did not produce $BIN" >&2; exit 1; }

# Apply both caps so the shim can both elevate to SCHED_FIFO (cap_sys_nice)
# AND join an isolated cpuset cgroup across sibling subtrees (cap_sys_admin,
# bypassing the cgroup v2 common-ancestor migration check).  If you only
# want FIFO, swap for: sudo setcap 'cap_sys_nice=ep' "$BIN"
echo "applying setcap cap_sys_nice,cap_sys_admin=ep on $BIN (requires sudo)..."
sudo setcap 'cap_sys_nice,cap_sys_admin=ep' "$BIN"

echo
echo "qemu-rt-shim ready.  To use:"
echo "  export TELIX_RT_SHIM=$BIN"
echo "  TELIX_RTPRIO=50 tools/boot-h14.sh"
echo
echo "verify cap with:  getcap $BIN"
