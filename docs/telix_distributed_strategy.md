# Telix: Strategy for Distributed Device Ecosystem Readiness

**Goal:** Bring Telix from its current state — a microkernel that runs
dynamically-linked Linux applications under QEMU and supports a working
Xwayland → xeyes pipeline across three architectures — to a position where
it could credibly be seen as ready for investment in hardware-backed
development toward a HarmonyOS-competitive ecosystem of devices.

**Premise:** The endpoint is not building the ecosystem — it is
demonstrating sufficient technical maturity that someone with resources
(hardware vendor, research lab, investor) could look at Telix and see a
plausible foundation for one.

**Structure:** The strategy is organised into tiers. Each tier builds on
the previous one, produces visible milestones, and addresses specific
blind spots. Tiers are not strictly sequential — some work within a tier
can proceed in parallel — but the overall flow moves from foundational
stability through application-hosting competence to distributed operation.

This document was last refreshed 2026-05-05 to reflect the actual state
of the codebase. Earlier revisions had grown stale relative to what's
actually shipped.

---

## Tier 0: Kernel Stability and Completeness — *largely done; longevity work ongoing*

**Current state:**
- Core IPC, capability system, memory allocator, scheduler, and task /
  thread management work on x86-64, aarch64, and riscv64. mips64 and
  loongarch64 have partial coverage.
- Boot-time `PAGE_MMUSHIFT` and bootmem-style memory registration are
  done.
- 105+ kernel tests pass on the well-supported architectures.
- Scheduler hardening: lazy preemption, `default_quantum=1`,
  remote-wake `yield_asap`, EEVDF dispatch, sleep-wake-latency
  histogram + per-CPU tick-gap diagnostic, steal-to-waker re-targeting
  for stale CPUs (Plan A: see commit `ff0d4ae`).
- Hypervisor framework: cross-arch `arch::hypervisor` module with
  `HypervisorOps` trait; KVM detected on x86_64 via CPUID; KVM on aarch64
  detected via DT-gated SMCCC vendor-hyp UID HVC; KVM_HC_SEND_IPI
  hypercall plumbed (with `icr=vector` ABI fix in `23a0440`); per-CPU
  KVM_FEATURE_STEAL_TIME pages bound at BSP and AP bring-up.

**Open items in this tier:**

- **Swap subsystem.** Still absent. Without swap, any memory pressure
  scenario is fatal. Minimum viable: swap PTE encoding per architecture,
  bitmap slot allocator on a raw partition, WSCLOCK integration,
  fault-handler integration. Implement kernel-internal first; factor
  out to a user-space `swap_srv` later.
- **mips64 crash diagnosis.** ~10 / 105 tests pass before crashes.
  Either fix or knowingly defer.
- **loongarch64 cross-binary fixes.** Three failures from missing test
  binaries. Building them moves the pass count appreciably.
- **Sustained longevity testing.** Run the existing test suite in a
  loop for hours; identify and fix any leaks, deadlocks, or
  use-after-free that only manifest under sustained operation. The
  existing aspace-race panic (still rare; `track_caller` diagnostic
  shipped in `f2b8ce2`) belongs here.

**Blind spots this tier reveals:**

- Memory fragmentation under sustained alloc / dealloc cycles without
  swap.
- Timer and scheduling correctness on non-x86-64 under SMP — partly
  attacked by the new wake-latency diagnostics; tail-latency
  outliers under KVM virtual-timer coalescing remain a host-side
  issue we route around with steal-to-waker.
- Capability revocation correctness under concurrent access.

---

## Tier 1: I/O Infrastructure — *largely done*

**Current state:**
- Block-device server (`blk_srv`) for virtio-blk, with a separate
  cache layer (`cache_srv`).
- VFS message protocol (`vfs_srv`) is shipped and exercised by the
  servers below.
- **Multiple filesystems in tree**: `fat_srv` / `fat16_srv`,
  `ext_srv` / `ext2_srv`, `xfs_srv`, `btrfs_srv`, `ntfs_srv`,
  `apfs_srv`, `iso9660_srv`, `udf_srv`, `ramdisk_srv`, `rootfs_srv`,
  `tmpfs_srv`, `procfs_srv`, `devfs_srv`. Coverage spans the major
  filesystems Linux understands plus the read-only formats useful for
  installer / live-media flows.
- `part_srv` for partition-table parsing; `nvme_srv` for NVMe block
  devices.
- Scratch / grant / async I/O paths shipped; the recent
  `IRFS_IO_READ_ASYNC` plumbing in `linux_srv` (steps 1-5 in commits
  `e951768` → `b4be100`) avoids parking the dispatch thread on
  initramfs reads.

**Open items in this tier:**

- **ZFS.** Pool / dataset model is significantly different from the
  existing FS implementations (vdev, zio pipeline, copy-on-write block
  layout, integrated RAID-Z). A `zfs_srv` skeleton is being scaffolded
  alongside this strategy refresh; the actual block-allocator,
  uberblock, and DSL plumbing are large work items.
- **iSCSI target completeness.** `iscsi_srv` exists in the tree but is
  early-stage — sessions / login / SCSI command dispatch are partial.

**Blind spots this tier reveals:**

- IPC performance under I/O load. Heavy lib-load workloads (Xwayland
  bring-up) initially saturated the dispatch thread; the multi-thread
  initramfs_srv worker pool (commit `9868712`) and reply-thread split
  in `linux_srv` (`8d35917`) directly attacked this. WATCHDOG IPC-stall
  counts dropped from 75 / boot to 0-5 / boot in the verified runs.
- Grant-mechanism correctness — historic flakes around
  grant-pages-phys mismatch (`project_grant_pages_phys_mismatch.md`)
  motivated the cache-blk content-magic verification path.

---

## Tier 2: Userspace Application Hosting — *Linux personality runs dynamically-linked binaries*

**Current state:**
- `linux_srv` is the Linux personality server. It implements the bulk
  of the Linux syscall surface needed to run **dynamically-linked**
  binaries from Fedora's root filesystem: `execve`, `read`/`write`/
  `open`/`close`/`openat`, `mmap`/`mprotect`/`brk`, `stat`/`fstat`/
  `fstatat`, the `clone`/`fork`/`wait4`/`exit` family, futexes
  (`FUTEX_WAIT`, `FUTEX_WAKE` with proper memory-ordering),
  `sigaction`/`rt_sigaction`/`sigreturn`, full TLS setup
  (FS base on x86-64, TPIDR_EL0 on aarch64), epoll, AF_UNIX
  sockets with SCM_RIGHTS fd-passing, memfd, pipe, dup2/3, fcntl,
  getdents64, getrandom, prlimit, set_robust_list, set_tid_address,
  rseq, arch_prctl, etc.
- The personality server runs **Xwayland 24.1.10** end-to-end:
  ld.so loads ~50 shared libraries (libc, libm, libGL, libdrm,
  libXfont2, libfreetype, libharfbuzz, libcrypto, libssl, libsystemd,
  libwayland-client, libxcb, libX11, libXt, libXmu, libXdmcp, libXau,
  libXrender, libXi, libXext, libGLdispatch, libgssapi_krb5,
  libpcre2, libpng, libei, libICE, libgcc_s, libepoxy, libgraphite2,
  libbrotlicommon, ...). Xwayland binds the X0 socket and an `xeyes`
  client connects to both the Wayland socket (handle passed via
  SCM_RIGHTS) and the X0 socket (per memory
  `project_xwayland_x0_listen_race.md`, end-to-end success on
  boot `91amfsq367` and many subsequent runs).
- Procfs (`procfs_srv`) provides `/proc/self/maps`, `/proc/self/exe`,
  `/proc/self/fd/`, `/proc/stat`, `/proc/meminfo`, `/proc/cpuinfo`.
  Sysfs CPU-topology nodes are partial.

**Open items in this tier:**

- **Long tail of glibc-ish quirks.** Each new binary exposes
  different syscalls / fixup behaviour. Examples in flight: libc's
  exit-cleanup (`__intl_freemem`) page-faults under specific
  configurations; LD_DEBUG=symbols / bindings causes a libc
  `__intl_freemem` PF on exit even with `_exit(0)`. These are
  per-binary surface-area issues and will keep shaking out as
  application coverage broadens.
- **Signal handling under multi-thread Linux processes.** Today's
  signal delivery is correct for the common cases but signal masks
  and per-thread routing under many concurrent threads need more
  testing.

**Blind spots this tier reveals:**

- Compatibility long tail — see open item above. Largely tractable
  but irreducibly time-consuming.
- Non-Linux personalities: Telix's `personality` abstraction is
  general; nothing prevents adding a BSD, Plan 9, or POSIX-clean
  personality alongside Linux. Out of scope for current effort.

---

## Tier 3: Network Stack — *partial; ipv4/ipv6 dual-stack landing*

**Current state:**
- `eth_srv` driver server (virtio-net under QEMU).
- `net_srv` umbrella for IP-layer concerns.
- `tcp4_srv`, `ip6_srv` (IPv6 + ICMPv6), `sctp_srv` (SCTP — uncommon
  but in tree).
- `iscsi_srv` for network-attached storage.
- `batman_srv` — B.A.T.M.A.N. mesh-routing scaffold (a non-trivial
  asset for the future distributed-bonding work).
- `iwl_srv` — early Intel WiFi driver work.
- AF_UNIX socket family fully wired through `linux_srv` and
  `uds_srv`; AF_INET / AF_INET6 sockets bridge to `tcp4_srv` /
  `ip6_srv`.

**Open items in this tier:**

- **NAT.** No `nat_srv` in tree. The IPv4 / IPv6 dual-stack
  compatibility story (NAT44 for legacy IPv4, NAT66 for IPv6
  prefix translation, **NAT64 / NAT46** per RFC 6146 / RFC 6877
  for IPv6-only deployments reaching IPv4 hosts) is the gap. A
  scaffold is being added alongside this strategy refresh; real
  state-table / port-mapping / ICMP rewrite logic is open work.
- **DNS resolution.** Stub resolver is partial. A real one needs
  recursive resolution support and DNSSEC at some point.
- **TLS.** Provided by application-space libraries (libcrypto,
  libssl from a Fedora root). Kernel needs to expose `getrandom`
  (it does) and the socket abstraction (it does). Nothing
  kernel-side blocks Firefox's TLS from working in principle.

**Blind spots this tier reveals:**

- Network performance — every packet through multiple IPC
  boundaries. Zero-copy buffer sharing (the existing grant
  mechanism) needs to extend cleanly into the network path.
- epoll scalability for server / event-loop workloads — the
  existing implementation handles small-fd-set cases
  (Wayland event loop, xeyes); thousands-of-fd workloads
  haven't been load-tested.

---

## Tier 4: Graphics and Input — *Wayland + Xwayland live*

**Current state:**
- `fb_srv` framebuffer server.
- `compositor_srv` and `wl_compositor_min` — minimal Wayland
  compositor, sufficient to host Xwayland as a Wayland client.
- `input_srv` (keyboard / pointer event delivery) + `term_srv`
  (terminal abstraction over `pty_srv`).
- `i915_srv` — Intel DRM driver beginnings.
- `hda_srv` — Intel HDA audio scaffolding.
- The headline demo: **Xwayland (Wayland client) hosting xeyes
  (X11 client) on top of `wl_compositor_min`**. xeyes connects to
  both the Wayland socket and the X0 socket through `linux_srv`'s
  AF_UNIX path. End-to-end verified across multiple boot runs.

**Open items in this tier:**

- **Real Wayland surface compositing.** `wl_compositor_min` is
  minimal — it accepts surface attaches and damage but doesn't yet
  render to an actual framebuffer. Connecting `compositor_srv` (or
  a successor) to `fb_srv` with damage-tracked composition is the
  next step.
- **GPU acceleration.** `i915_srv` work + DRM-via-personality
  emulation in `linux_srv` are both present but neither is yet at
  the "Mesa / GBM works" point. Xwayland's own fallback to swrast
  is what currently produces output; libGL / GBM acceleration is
  open.
- **Vsync / frame pacing.**

**Blind spots this tier reveals:**

- Shared-memory between clients and compositor — Wayland's `wl_shm`
  is the common path; this is wired through `linux_srv`'s memfd +
  SCM_RIGHTS support, but performance under heavy traffic isn't
  benchmarked.
- GPU memory management.

---

## Tier 5: Distributed Device Bonding — *frontier; some scaffolding in tree*

**This is the actual frontier, where HarmonyOS-competitive
functionality begins.**

**Current state:**
- `proxy_srv` exists in tree as a starting point for the
  cross-device IPC proxy (its current implementation needs an audit
  to see how much of the eventual responsibility it covers).
- The name-server (`svc_register` / `svc_lookup`) doesn't yet
  understand "remote" services.
- No discovery protocol yet.
- No authenticated channel yet.

**Work items:**

- **Device identity and capability advertisement.** Each Telix
  instance has a unique device identity and a capability manifest
  describing what services it offers (display, storage, compute,
  input, sensors, audio). The manifest is a structured message
  format — essentially a service directory.
- **Discovery protocol.** Initial form: UDP multicast on the
  virtual network. A `discovery_srv` scaffold should land alongside
  this strategy refresh; periodic broadcasts of identity + manifest;
  peer table of known devices. For real hardware, layered with BLE
  advertisement / scanning for proximity discovery (see Tier 6).
- **Authenticated secure channel.** Pre-shared keys for the QEMU
  prototype; full PKI for product. Confidentiality + integrity for
  all subsequent inter-device communication.
- **Name-server extension for remote services.** A service can be
  registered as "remote" — the name-server returns a proxy endpoint
  that forwards IPC over the secure channel.
- **Proxy endpoint.** Receives IPC from local clients, serialises,
  forwards over the network, deserialises responses. The
  architectural challenge: **grant translation** — local IPC uses
  zero-copy grants, but the network path requires copying. The
  proxy must transparently bridge the two models.
- **Service migration.** Optional. Serialise a running service's
  state, transfer, restart elsewhere, update name-server pointers.
  HarmonyOS's "task continuity" feature.

**Demonstration scenarios:**

1. *Sensor sharing.* Two QEMU instances on a virtual network;
   instance A produces periodic sensor readings; instance B reads
   them as if local through a transparent name-server proxy.
2. *Display sharing.* Instance A has a virtio-gpu; instance B has
   no display; an application on instance B renders GUI output that
   appears on instance A's display.

**Blind spots this tier reveals:**

- Proxied-IPC latency.
- Disconnection handling.
- Bonding-process security.
- Distributed-state consistency (CRDTs vs eventual consistency vs
  causal — pick one explicitly).

---

## Tier 6: Real Hardware — *partial; the Bluetooth gap matters here*

**Current state:**
- Real-hardware boot work is documented in
  `docs/real_hardware_boot_roadmap.md` (separate from this strategy).
- ACPI-based device enumeration on aarch64 is a known gap (see
  `project_aarch64_device_enum.md`).
- `usb_srv` scaffolding for USB host stacks.
- No Bluetooth in tree at any level — neither HCI driver, nor
  L2CAP, nor BLE GAP / GATT. A `bt_srv` scaffold is being added
  alongside this strategy refresh.

**Work items:**

- **Real hardware boot.** EFI stub, ACPI, framebuffer, NVMe / AHCI,
  real keyboard input. Target: shell prompt on a real laptop.
- **Real network driver.** Whatever NIC the target laptop has
  (Intel, Realtek, Qualcomm). Significant driver effort but
  well-documented for common parts.
- **Bluetooth LE for proximity discovery.** Replaces UDP-multicast
  discovery with BLE advertising / scanning. Requires:
  - HCI transport driver (USB transport per the Bluetooth Core
    Specification, or UART for embedded targets).
  - HCI command / event framework.
  - L2CAP (for LE-credit-based flow-controlled channels carrying
    higher-layer protocols).
  - GAP / GATT for discovery advertisements.
  - A minimal SMP / pairing implementation.
  - **Bluetooth networking** (the user-flagged item) means PAN /
    BNEP / IPSP — IP packets carried over BLE, important for
    seamless device-to-device data flow without a Wi-Fi network in
    the middle.
- **Second device.** Raspberry Pi or comparable ARM64 SBC running
  Telix. Cross-architecture distributed bonding (laptop x86_64
  + SBC aarch64) is the minimum viable "ecosystem" demo.

**Blind spots this tier reveals:**

- Driver quality on real hardware.
- Power management on real hardware.
- Bluetooth stack complexity — full Bluetooth is large; the
  initial demo can be BLE-only, but eventually classic BR / EDR
  for audio / HID needs to follow.
- Cross-architecture distributed operation requires
  endian-neutral, alignment-clean wire formats.

---

## Cross-cutting tracks worth seeding now

Some work doesn't sit cleanly in one tier — it threads across
several. These are the items the user has flagged as "incidental
things" worth having code in tree for, even if the substantive
work happens later:

- **Bluetooth (`bt_srv`).** Scaffold. Reserves the architectural
  spot; later fills out HCI driver + LE stack + PAN / IPSP.
- **NAT (`nat_srv`).** Scaffold. The IPv4 / IPv6 dual-stack
  interop story (NAT44 / NAT66 / NAT64 / NAT46) lives here.
- **ZFS (`zfs_srv`).** Scaffold. Pool / dataset model is far
  enough from the existing FS implementations to deserve its own
  starting point rather than retrofitting into one of them.
- **Discovery (`discovery_srv`).** Multicast advertisement /
  peer-table scaffold. The first concrete piece of Tier 5.

Each scaffold ships as a userlib bin that registers a service name
and runs a stub message-dispatch loop. The architectural placement
becomes immediately obvious and real implementations can attach
without first having to negotiate where they live.

---

## What an Investor or Backer Would Want to See

At minimum, before anyone would consider investing in Telix as a
platform for a device ecosystem:

**Tiers 0-2 stable:** The kernel is stable, has swap, runs Linux
binaries (tier 2 already exceeds this — Xwayland is well past
"it's not a toy"), and passes sustained stress testing. Outstanding
gap: swap.

**Tier 3 partially complete:** Network connectivity works.
Applications can fetch data over the network. NAT64 / NAT46 lets
IPv6-only deployments reach IPv4 services.

**Tier 4 visible:** Wayland + Xwayland already provide a credible
GUI demo on QEMU; full surface compositing to `fb_srv` and
acceleration are the visible-progress items.

**Tier 5 demonstrated:** Two QEMU instances bonding and sharing
services transparently. The demo may be simple (sensor sharing,
clipboard sharing) but the underlying protocol and proxy
infrastructure must be robust enough that the demo doesn't look
fragile.

**A clear articulation of what Telix provides that HarmonyOS,
Fuchsia, and RIOT / Zephyr don't.** Possible angles:

- The page-clustering / superpage-guarantee VM innovation.
- Rust-native microkernel with capability-based security.
- Open-source with no vendor lock-in.
- Architecturally clean distributed bonding that follows
  naturally from the microkernel's message-passing design.
- Multi-architecture from day one, as a property rather than a
  port.

**A second contributor.** Even one additional contributor changes
the perception from "one person's hobby" to "a small team's
project."

---

## Risk Register

**Risks that could derail the strategy at any tier:**

| Risk | Tier | Severity | Mitigation |
|------|------|----------|------------|
| IPC performance ceiling for I/O-intensive workloads | 1-2 | Mitigating: multi-thread initramfs + reply-thread split landed; further fine-grained locks tracked in plan A.2c. | Continue measurement; the wake-latency histogram + tick-gap diagnostics give us live data. |
| glibc compatibility long tail | 2 | Active: each new binary surfaces something. | Per-binary firefighting; document the surface; the scope is irreducible. |
| QEMU virtual-timer coalescing → multi-second wake tails | 0 | Mitigated: Plan A steal-to-waker re-targets stale CPUs (commit `ff0d4ae`); KVM PV_SEND_IPI hypercall enabled. | Histograms quantify residual; consider per-vcpu pinning for production deployments. |
| Network proxy latency too high for interactive use | 5 | Future. | Batch small messages; co-located proxies; accept some use cases need local services. |
| Sole-developer unavailability | All | Critical | Document everything (this doc); keep code quality high; attract a collaborator. |
| No hardware available for Tier 6 | 6 | Medium | Raspberry Pi boards are inexpensive; defer BLE until hardware in hand. |
| Scope creep from distributed work pulling focus from kernel stability | 1-5 | High | Strict tier ordering; don't commit to Tier 5 implementation until Tier 2 quirks are settled. |
| Bluetooth stack effort underestimated | 6 | Medium | Land scaffolding now; stage real implementation by transport (USB-HCI first, UART later) and by profile (LE-only first, BR / EDR later). |

---

## Suggested Sequencing

The original document had time estimates. Given how much has shipped
between then and now, the better current framing is by *next*
milestone rather than month-numbered quarters.

**Next milestone (kernel-layer):** Swap subsystem. This is the last
load-bearing absent feature in Tier 0.

**Next milestone (application-layer):** Stabilise the long
boot-variance tail. The Plan A steal-to-waker, multi-thread server
work, and KVM PV plumbing have moved this from "unusably variable"
to "mostly works"; pushing it to "always works in 1500 s" is the
follow-on. With swap landed, real application workloads beyond
xeyes (e.g., a browser, a build) become feasible.

**Next milestone (distributed-layer):** The discovery / proxy
scaffold lands now; the first cross-VM service-sharing demo (tier
5 first scenario above) is the visible win.

**Next milestone (hardware-layer):** Real hardware boot reaches
shell prompt on a target laptop. Bluetooth scaffolding is in tree
ready for the HCI driver effort that follows.

The critical path runs through Tier 5's proxy infrastructure: that
work brings the most weight to bear on the strategic positioning
("HarmonyOS-competitive distributed device ecosystem") but depends
on the network stack stabilising and on the proxy / grant-translation
architecture surviving design review.
