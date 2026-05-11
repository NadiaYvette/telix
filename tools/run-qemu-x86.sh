#!/bin/bash
# Run the Telix kernel on QEMU x86-64 (q35 machine, Multiboot1).
# Usage: run-qemu-x86.sh <kernel-elf> [--debug]
#
# QEMU's -kernel Multiboot loader requires a 32-bit ELF.
# We convert the 64-bit ELF to 32-bit with objcopy.
#
# Port overrides (to avoid conflicts with other QEMU sessions):
#   TELIX_SSH_PORT  — host SSH forwarding port (default 3222)
#   TELIX_GDB_PORT  — GDB listen port (default 3234)

set -e

KERNEL="${1:?Usage: run-qemu-x86.sh <kernel-elf> [--debug]}"
shift

SSH_PORT="${TELIX_SSH_PORT:-3222}"
GDB_PORT="${TELIX_GDB_PORT:-3234}"

# Convert 64-bit ELF to 32-bit ELF for QEMU's Multiboot loader.
KERNEL32="${KERNEL}.mb32"
objcopy -O elf32-i386 "$KERNEL" "$KERNEL32"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

ACCEL="${TELIX_ACCEL:-tcg}"
case "$ACCEL" in
    kvm)  CPU_MODEL=host ;;
    *)    CPU_MODEL=qemu64; ACCEL=tcg ;;
esac

SMP="${TELIX_SMP:-4}"

QEMU_ARGS=(
    -machine q35,accel=$ACCEL
    -cpu $CPU_MODEL
    -m 512M
    -kernel "$KERNEL32"
    -smp "$SMP"
)

# Display mode: TELIX_DISPLAY=gpu|vbe (default: none/nographic).
case "${TELIX_DISPLAY:-}" in
    gpu)
        QEMU_ARGS+=(-device virtio-gpu-pci -display gtk -serial mon:stdio)
        ;;
    vbe)
        QEMU_ARGS+=(-vga std -display gtk -serial mon:stdio)
        ;;
    *)
        QEMU_ARGS+=(-nographic -serial mon:stdio)
        ;;
esac

# Pass kernel command line if TELIX_CMDLINE is set.
if [ -n "${TELIX_CMDLINE:-}" ]; then
    QEMU_ARGS+=(-append "$TELIX_CMDLINE")
fi

# Add virtio-blk disk if test.img exists.
if [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",format=raw,if=none,id=disk0,snapshot=on
        -device virtio-blk-pci,drive=disk0
    )
fi

# Add NVMe device if TELIX_NVME=1 and test.img exists.
# Creates a second reference to the same disk image (snapshot mode, read-only from NVMe side).
if [ "${TELIX_NVME:-}" = "1" ] && [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",format=raw,if=none,id=nvme0,snapshot=on
        -device nvme,drive=nvme0,serial=TELIX-NVME-01
    )
fi

# Add USB xHCI controller + devices if TELIX_USB=1.
if [ "${TELIX_USB:-}" = "1" ]; then
    QEMU_ARGS+=(
        -device qemu-xhci,id=xhci0
        -device usb-kbd,bus=xhci0.0
        -device usb-mouse,bus=xhci0.0
    )
fi

# Add Intel HDA audio device if TELIX_AUDIO=1.
if [ "${TELIX_AUDIO:-}" = "1" ]; then
    QEMU_ARGS+=(
        -device intel-hda,id=hda0
        -device hda-duplex,bus=hda0.0
    )
fi

# Add virtio-net.
# TELIX_NET=tap        TAP device (requires sudo setup, supports raw IP).
# TELIX_NET=sock_listen   Socket netdev listening on TELIX_NET_PORT
#                         (Tier-5 piece F: virtual L2 between two QEMUs).
# TELIX_NET=sock_connect  Socket netdev connecting to TELIX_NET_PORT.
# Default: SLIRP user-mode networking (no raw IP, but zero-config).
case "${TELIX_NET:-}" in
    tap)
        TAP_IF="${TELIX_TAP:-tap0}"
        QEMU_ARGS+=(
            -netdev tap,id=net0,ifname="$TAP_IF",script=no,downscript=no
            -device virtio-net-pci,netdev=net0
        )
        ;;
    sock_listen|sock_connect)
        # Tier-5 piece F: UDP-multicast socket netdev — both instances
        # join the same multicast group so all L2 frames each sends are
        # seen by the other.  Simpler than TCP listen/connect and works
        # without timing-coordinated startup.  MAC differs per instance
        # so the kernel virtio-net RX filter accepts both broadcast and
        # the unique unicast.
        MCAST_GROUP="${TELIX_NET_MCAST:-230.0.0.1:7710}"
        case "${TELIX_NET}" in
            sock_listen)  MAC="52:54:00:11:11:01" ;;
            sock_connect) MAC="52:54:00:11:11:02" ;;
        esac
        QEMU_ARGS+=(
            -netdev socket,id=net0,mcast=${MCAST_GROUP},localaddr=127.0.0.1
            -device virtio-net-pci,netdev=net0,mac=${MAC}
        )
        ;;
    *)
        QEMU_ARGS+=(
            -netdev user,id=net0,guestfwd=tcp:10.0.2.100:1234-cmd:cat,hostfwd=tcp::${SSH_PORT}-:22
            -device virtio-net-pci,netdev=net0
        )
        ;;
esac

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -gdb tcp::${GDB_PORT})
    echo "Waiting for GDB on localhost:${GDB_PORT} ..." >&2
fi

# Non-freezing gdb stub (for catching live faults without halting at
# entry).  Pair with -no-reboot so a triple fault halts the CPU
# instead of resetting the VM, leaving state intact for gdb to inspect.
#
#   TELIX_GDB_ATTACH=1 tools/boot-h14.sh ...
#   # In another terminal:
#   gdb /path/to/telix-kernel
#   (gdb) target remote localhost:3234
#   (gdb) ...
#
if [ "${TELIX_GDB_ATTACH:-}" = "1" ]; then
    QEMU_ARGS+=(-gdb tcp::${GDB_PORT} -no-reboot)
    echo "GDB attach available on localhost:${GDB_PORT} (no -S, no auto-reboot)" >&2
fi

# Disable auto-reboot on triple fault even without gdb — useful for
# capturing post-fault serial output.  Without this QEMU resets the
# VM on triple fault and SeaBIOS re-runs, garbling the boot log.
if [ "${TELIX_NO_REBOOT:-}" = "1" ]; then
    QEMU_ARGS+=(-no-reboot)
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
