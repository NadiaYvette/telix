# Telix Real Hardware Boot Roadmap

**Goal:** Boot Telix on a real laptop from a USB stick, progressively gaining the ability to use the host Fedora installation's userspace and disk partitions, culminating in the existing Xwayland + GNOME + Firefox demo target.

**Development model:** Framebuffer console output from the first step onward. Kernel panics and other failures are debugged by photographing the screen and feeding images to the development environment after rebooting into Linux.

---

## Phase R0: EFI Stub and Framebuffer Console

**Prerequisite:** Working x86-64 QEMU kernel (105/105 tests passing)

1. **EFI stub loader.** Make the Telix kernel image a valid PE/COFF executable that UEFI firmware can load directly. Receives EFI system table, memory map, and GOP (Graphics Output Protocol) framebuffer info from UEFI boot services. Calls `ExitBootServices()`, then jumps to the Rust kernel entry point. Model: Linux `CONFIG_EFI_STUB`.

2. **GOP framebuffer console.** Before `ExitBootServices()`, query the GOP for framebuffer base address, resolution, stride, and pixel format. After exiting boot services, write a simple bitmap font renderer that draws text to the linear framebuffer. This is the primary debugging output for all subsequent steps — every kernel panic, assertion failure, and diagnostic message must be visible on screen.

3. **USB stick preparation.** Create a GPT-partitioned USB stick with an EFI System Partition (FAT32) containing the Telix EFI binary at `\EFI\BOOT\BOOTX64.EFI`. The laptop's UEFI boot menu (typically F12 or similar) selects the USB stick. A second partition (FAT32 or ext2, depending on what Telix can read) holds test binaries and an initramfs.

4. **Validation:** Laptop displays Telix boot messages on screen. Kernel initializes, prints memory map, halts. Take a photo.

**Estimated scope:** EFI stub (~300–500 lines), framebuffer console (~200–400 lines), USB stick tooling (shell script).

---

## Phase R1: ACPI and Interrupts

1. **ACPI table discovery.** Locate the RSDP (Root System Description Pointer) via EFI system table's ACPI 2.0 GUID. Parse RSDT/XSDT to find other tables. No AML interpreter needed at this stage — only fixed-format tables.

2. **MADT (Multiple APIC Description Table) parsing.** Enumerate Local APICs (one per CPU), I/O APICs, and interrupt source overrides. This replaces QEMU's devicetree-based CPU and interrupt controller discovery.

3. **LAPIC and I/O APIC initialization.** Configure the Local APIC for timer interrupts and IPIs. Configure the I/O APIC for routing external interrupts (keyboard, NVMe, etc.). The LAPIC timer provides the per-CPU timer; if TCG-style timer problems don't exist on real hardware (they won't — this is native execution), per-CPU timers should work correctly from the start.

4. **SMP bring-up.** Send INIT-SIPI-SIPI sequence to secondary CPUs discovered via MADT. Secondary CPUs enter the scheduler.

5. **FADT parsing.** Minimal: identify PM timer or HPET for calibrating the LAPIC timer frequency. Identify ACPI power management registers for eventual shutdown/reboot.

6. **Validation:** Telix boots, reports N CPUs found and running, timer interrupts firing on all CPUs. Kernel reaches idle on all CPUs.

**Estimated scope:** ACPI table parsing (~500–800 lines), LAPIC/IOAPIC setup (partially exists from QEMU x86-64 support), SMP startup (~200 lines).

---

## Phase R2: Storage Access

1. **PCI/PCIe enumeration.** Walk the PCI configuration space (using MCFG from ACPI for PCIe ECAM, or legacy I/O port config for fallback). Enumerate devices, read BARs, identify NVMe controllers and other devices by class code and vendor/device ID.

2. **NVMe driver.** NVMe is a clean, register-level interface: allocate admin queue pair, identify controller, identify namespace, allocate I/O queue pair(s), submit read/write commands. The spec is public and well-documented. Target: synchronous block read/write to the laptop's primary NVMe SSD. Async conversion comes later.

3. **GPT partition table parsing.** Read LBA 1, parse the GPT header, read the partition entry array. Identify partitions by type GUID (EFI System, Linux filesystem, Linux swap, etc.) and partition GUID/label.

4. **FAT32 driver (minimal, for the EFI System Partition and USB data partition).** FAT32 is simple enough to implement quickly and provides immediate read access to a partition you can populate from Linux. Load test binaries and initramfs from the FAT32 partition.

5. **Validation:** Telix reads and lists GPT partitions on the laptop's NVMe SSD and the USB stick. Loads and executes a static test binary from the FAT32 partition.

**Estimated scope:** PCI enumeration (~400–600 lines), NVMe driver (~1500–3000 lines), GPT parsing (~100–200 lines), FAT32 read-only (~500–800 lines).

---

## Phase R3: Static Userspace on Real Hardware

1. **Static busybox on FAT32.** Cross-compile a statically linked busybox (musl, x86-64). Place it on the USB stick's FAT32 data partition. This avoids needing a dynamic linker, glibc compatibility, or a full Linux personality — static musl binaries make only direct syscalls.

2. **Linux personality (minimal static subset).** Implement enough Linux syscall translation to run static busybox: execve, read, write, open, close, stat/fstat/lstat, mmap, mprotect, brk, ioctl (terminal: TIOCGWINSZ, TCGETS, TCSETS), clone/fork, wait4, exit/exit_group, pipe, dup/dup2, fcntl, getcwd, chdir, access, getpid/getppid, rt_sigaction, rt_sigprocmask, rt_sigreturn, uname, getdents64, clock_gettime. Roughly 40–50 syscalls.

3. **Framebuffer terminal.** Keyboard input (USB HID or PS/2, depending on laptop) + framebuffer output = interactive terminal. PS/2 keyboard is simpler for initial bring-up (I/O ports 0x60/0x64, IRQ 1). USB HID requires a USB host controller driver (xHCI), which is substantially more work.

4. **Validation:** Telix boots on the laptop, presents a `sh` prompt on the framebuffer console, user can type commands, run `ls`, `cat`, `echo`, etc. **This is the "screenshot milestone" for real hardware.**

**Estimated scope:** Busybox cross-compilation (build system work), Linux personality core (~2000–4000 lines for 40–50 syscalls), PS/2 keyboard driver (~200 lines).

---

## Phase R4: Accessing Fedora's Filesystem

**This phase is where Telix begins piggybacking on the existing Fedora installation.**

1. **Determine Fedora's storage layout.** Typical Fedora installs use: btrfs on a LUKS-encrypted LVM logical volume (recent default), or ext4 on LVM, or ext4/btrfs without LVM. The encrypted case requires LUKS unlock (crypto stack — substantial work). The unencrypted case requires only the filesystem driver and optionally LVM metadata parsing.

2. **Choose the path of least resistance:**
   - **If Fedora root is unencrypted ext4 without LVM:** Implement ext4 read-only. ext4 is well-documented and widely implemented. Read-only avoids journaling complexity.
   - **If Fedora root is btrfs:** Implement btrfs read-only. More complex than ext4 (COW, checksums, subvolumes) but Fedora default since F33.
   - **If encrypted or LVM:** Create a dedicated unencrypted ext4 or btrfs partition from Linux (`fdisk` + `mkfs.ext4`) for Telix to use. Avoid LUKS/LVM initially.
   - **Simplest fallback:** Mount Fedora partitions from Linux, copy needed binaries to the USB stick's FAT32 partition. No Fedora filesystem driver needed, but limits what's available.

3. **Ext4 read-only driver.** Superblock parsing, block group descriptors, inode reading, extent tree traversal (modern ext4), directory entry parsing (htree). All block reads go through NVMe driver. Target: read files and traverse directories on Fedora's root partition.

4. **Dynamic linker and glibc compatibility.** To run Fedora's dynamically-linked binaries: implement `execve` with ELF interpreter support (`PT_INTERP` → load `ld-linux-x86-64.so.2`), provide the auxiliary vector (`AT_PHDR`, `AT_ENTRY`, `AT_SYSINFO_EHDR` for vDSO, etc.), implement `mmap` with `MAP_FIXED` and `MAP_PRIVATE` for the dynamic linker's use, provide `/proc/self/maps` and `/proc/self/exe` (glibc checks these). This is significantly harder than running static binaries — glibc's startup sequence probes many Linux-specific interfaces.

5. **Procfs/sysfs emulation (minimal).** Synthesize enough of `/proc` and `/sys` that glibc initialization succeeds and common tools work: `/proc/self/maps`, `/proc/self/exe`, `/proc/self/fd/`, `/proc/stat`, `/proc/meminfo`, `/proc/cpuinfo`, `/sys/devices/system/cpu/`.

6. **Validation:** Telix mounts Fedora's root partition read-only, runs `/usr/bin/bash` from it, dynamically linked against Fedora's glibc.

**Estimated scope:** ext4 read-only (~2000–4000 lines), dynamic linker support (~500–1000 lines of personality server work), procfs emulation (~500–1000 lines). The glibc compatibility debugging is likely the most time-consuming part — it's the "time-consuming" work you encountered before.

---

## Phase R5: Graphics on Real Hardware

1. **Identify the laptop's GPU.** Intel integrated (Iris Xe or similar), AMD (Radeon), or NVIDIA. Intel is the most tractable target — the i915/xe driver interface is complex but Intel publishes hardware documentation (PRMs) for their GPUs.

2. **Two paths for initial graphics:**
   - **Simple path: Keep using the UEFI GOP framebuffer.** The framebuffer established before `ExitBootServices()` persists. It's slow (no acceleration, no modesetting, no VSync) but it works for basic GUI rendering. A Wayland compositor can render to it in software (LLVMpipe/Lavapipe for OpenGL/Vulkan, or CPU-only compositing).
   - **Full path: DRM/KMS driver.** Implement (or port) a DRM/KMS-compatible driver for the laptop's GPU. This is a major undertaking — Intel Iris Xe alone is tens of thousands of lines. The DRM compat layer from the graphics architecture roadmap (Section 17) applies here.

3. **Input: USB HID (xHCI).** The laptop's keyboard and touchpad are almost certainly USB (even if they appear as PS/2 to legacy software, modern laptops use an internal USB connection or I2C-HID). For a touchpad, you need at minimum the xHCI host controller driver and USB HID class driver. This is substantial work (~3000–5000 lines for xHCI alone). Alternatively, many laptops still expose the keyboard as PS/2 via the i8042 controller, which suffices for keyboard input without USB.

4. **Validation:** Telix renders a graphical display on the laptop screen — even if it's just a framebuffer console with a bitmap font, or a simple compositor showing colored rectangles.

**Estimated scope:** Highly variable. GOP framebuffer reuse is nearly free (already done in R0). Full GPU driver is months of work.

---

## Phase R6: Xwayland + GNOME + Firefox on Real Hardware

This is the existing roadmap from Section 10 of the development roadmap, but on real hardware rather than QEMU:

1. **Wayland compositor** rendering to GOP framebuffer (software) or GPU driver (accelerated).
2. **Xwayland** running under the compositor via the Linux personality.
3. **GTK/glib** from Fedora's installation, running via the Linux personality.
4. **dbus session bus.**
5. **GNOME Shell** (Mutter in Xwayland mode).
6. **Firefox.**
7. **Capture photo of Firefox rendering a web page on the laptop screen.** This is the "ultimate screenshot milestone."

**Prerequisites from earlier phases:** All of R0–R5, plus network driver (for Firefox to fetch pages — virtio-net doesn't exist on real hardware; you need the laptop's actual NIC driver, likely Intel or Realtek), DNS resolution, and a TCP/IP stack.

---

## Summary: Phase Dependencies

```
R0 (EFI stub + framebuffer)
 └─ R1 (ACPI + interrupts + SMP)
     └─ R2 (PCI + NVMe + GPT + FAT32)
         ├─ R3 (static busybox + minimal Linux personality + keyboard)
         │   └─ "Real hardware shell prompt" milestone
         └─ R4 (ext4/btrfs + dynamic linker + glibc + procfs)
             ├─ "Running Fedora binaries on Telix" milestone
             └─ R5 (GPU or GOP framebuffer + input)
                 └─ R6 (Wayland + Xwayland + GNOME + Firefox)
                     └─ "Ultimate screenshot" milestone
```

---

## Debugging Strategy

All phases after R0 are debugged by:

1. Boot Telix from USB.
2. Observe panic/hang on framebuffer.
3. Photograph the screen (phone camera).
4. Reboot into Fedora.
5. Upload photo to Claude session for analysis.
6. Fix, rebuild, reflash USB stick, retry.

For non-panic issues (wrong behavior, garbled output), serial output via USB-to-serial adapter may be valuable if the laptop has a USB port that Telix can drive (requires xHCI — chicken-and-egg problem). Alternative: write diagnostic state to a known offset on the USB stick's FAT32 partition, read it back from Linux after reboot.

---

## Relationship to QEMU Development

Real hardware phases are **not sequential blockers** for QEMU-based development. Most subsystem work (scheduler, VM, I/O servers, swap, personality server) proceeds under QEMU. Real hardware phases R0–R3 are a parallel track that can be pursued opportunistically. The main synergy is that the Linux personality server, syscall translation, and filesystem drivers developed for the QEMU path are directly reused on real hardware — the NVMe and ACPI work is the primary real-hardware-specific investment.
