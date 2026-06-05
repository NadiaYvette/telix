#![no_std]
#![no_main]
#![cfg_attr(target_arch = "mips64", feature(asm_experimental_arch))]

mod arch;
mod boot;
mod cap;
mod drivers;
mod firmware;
mod io;
mod ipc;
mod loader;
mod mm;
mod sched;
mod sync;
mod syscall;
mod trace;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // #208: panic via `DirectUart` rather than `println!`.  The regular
    // path uses `StackBuf` which is the same field family the #208
    // corruption hits — when `len` is overwritten with a kstack-shaped
    // value, the bounds-check inside `_print` re-panics, recursing the
    // panic handler and producing a silent triple-fault.  Going direct
    // bypasses StackBuf entirely so we see the panic text.
    #[cfg(target_arch = "x86_64")]
    {
        use core::fmt::Write;
        let mut d = crate::arch::x86_64::serial::DirectUart;
        let _ = writeln!(d, "KERNEL PANIC: {}", info);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        println!("KERNEL PANIC: {}", info);
    }
    loop {
        core::hint::spin_loop();
    }
}

pub fn kmain() -> ! {
    println!("Telix kernel initializing...");

    // Platform init: exceptions, interrupt controller, timer.
    arch::platform::init();

    // Hypervisor detection — runs early enough that the rest of boot
    // (and ops()) can query the kind, but after platform::init so any
    // arch-specific hypercall mechanism is ready.
    arch::hypervisor::detect_and_install();

    // Parse firmware tables (DTB / Multiboot+ACPI) to discover RAM, CPUs,
    // devices. Must happen before phys::init() — firmware data lives in
    // physical memory that the allocator could overwrite.
    arch::platform::parse_firmware();

    // Parse kernel command line (extracted from firmware by parse_firmware).
    // Must happen before phys::init() since page_mmushift affects allocation.
    boot::cmdline::parse();
    let mmushift = boot::cmdline::page_mmushift();
    mm::page::init_runtime_page_size(mmushift);
    mm::slab::reinit_for_page_size();
    println!("  Page size: {} bytes (mmushift={})", mm::page::page_size(), mmushift);

    // Resolve runtime CPU count (firmware detection + nr_cpus=N cmdline cap).
    // Must happen after parse_firmware + cmdline::parse and before any
    // per-CPU storage is sized or allocated.
    let nr = sched::smp::detect_cpu_count();
    println!("  CPUs: {} (ceiling {})", nr, sched::smp::MAX_CPUS);

    // Physical memory allocator.
    // Start managed RAM at kernel_end so the allocator never touches
    // firmware (OpenSBI) or kernel image pages — its bitmap metadata
    // is written into pages within the managed range, which must be free.
    let (_ram_start, ram_end) = arch::platform::ram_range();
    let kernel_end = arch::platform::kernel_end_addr();
    mm::phys::init(kernel_end, ram_end, kernel_end, kernel_end);

    // Allocate dynamic per-CPU storage now that phys is live. Currently a
    // no-op; subsequent commits in the runtime-nr_cpus series migrate
    // per-CPU arrays here.
    sched::smp::init_dynamic_percpu();

    // Bring up the swap backend if requested on the cmdline. Must run
    // after phys::init (backends allocate storage) and before any
    // workload that can trigger WSCLOCK.
    mm::swap::init();

    // Enable MMU: set up kernel identity-mapped page tables.
    // Must happen before secondary CPU startup (they need the page table root).
    arch::platform::enable_mmu();

    // Initialize framebuffer console (if GOP/VBE framebuffer is available).
    // After MMU enable so the framebuffer address is identity-mapped.
    drivers::fb_console::init();

    // Quick phys allocator test.
    if let Some(page) = mm::phys::alloc_page() {
        println!("  Phys alloc test: page at {:?}", page);
        mm::phys::free_page(page);
        println!("  Phys alloc test: freed");
    }

    // Slab allocator test.
    mm::slab::print_stats();
    if let Some(obj) = mm::slab::alloc(64) {
        println!("  Slab alloc test: 64-byte object at {:?}", obj);
        mm::slab::free(obj, 64);
        println!("  Slab alloc test: freed");
    }
    if let Some(obj) = mm::slab::alloc(256) {
        println!("  Slab alloc test: 256-byte object at {:?}", obj);
        mm::slab::free(obj, 256);
        println!("  Slab alloc test: freed");
    }

    // Extent tree tests.
    println!("Testing extent tree...");
    mm::extent::run_tests();

    // VMA tree tests.
    println!("Testing VMA tree...");
    mm::vmatree::run_tests();

    // Initialize capability system.
    cap::init();
    println!("  Cap system initialized");

    // Capability system test (validates CDT/CNode logic).
    test_capabilities();

    // ART port-table stress (Track 2 of the create_anon BUG investigation).
    // Now passes after the rcu BATCH_CAP fix (commit fixing slab-256
    // corruption from RcuBatch overflow). Kept off-by-default to keep
    // boot fast; flip to true for regression checks.
    const ART_STRESS_ENABLED: bool = true;
    if ART_STRESS_ENABLED {
        test_art_port_stress();
    }

    // Scheduler.
    sched::init();
    sched::topology::init();

    // Start secondary CPUs.
    println!("Starting secondary CPUs...");
    arch::platform::start_secondary_cpus();
    sched::topology::print();

    // #235 Piece C2: drop the low-RAM identity map.  Helper is in
    // arch::x86_64::mm::unmap_pml4_0; call gated off pending C2e.
    // C2d swept loader/elf, syscall handlers, scheduler spawn helpers
    // and virtio-blk vring buffers.  Boot 11amfsq2942 (unmap on) now
    // reaches Phase 2 demand-paging PASS + Phase 3 acpi_srv spawn,
    // but wedges on `THREAD-PTR-OOR: tid=14 p=0x0` (THREAD_TABLE lookup
    // returns NULL for an unspawned tid).  Next session investigates
    // who's calling `thread_ref(14)` before the spawn lands.
    // arch::x86_64::mm::unmap_pml4_0();

    // Background page pre-zeroing daemon.
    sched::spawn(mm::zeropool::zero_daemon, 1, 5).expect("spawn zero_daemon");

    // Background page reclaim daemon (kswapd).
    sched::spawn(mm::kswapd::kswapd, 200, 10).expect("spawn kswapd");

    // Phase 2: Demand-paging test.
    println!("Testing demand-paged memory...");
    test_demand_paging();

    // Phase 3+4 run in a dedicated kernel thread so the BSP can enter the idle
    // loop immediately. On single-CPU, the idle loop is needed so the scheduler
    // can preempt it to run the startup thread and other kernel threads.
    // Priority 60 is lower than spawned servers (50) so they can run during waits.
    sched::spawn(startup_thread, 60, 20).expect("spawn startup");

    // Arm the first one-shot timer so the scheduler can preempt the idle loop.
    let first_tick = arch::timer::monotonic_ns() + 10_000_000; // 10ms
    arch::timer::program_oneshot_ns(first_tick);

    println!("Enabling interrupts");
    arch::platform::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    arch::platform::idle_loop()
}

/// Kernel startup thread: spawns I/O servers and userspace processes.
/// Runs as a normal kernel thread (not the idle thread) so the scheduler
/// can preempt between it and the threads it spawns — critical for single-CPU.
fn startup_thread() -> ! {
    // #178 probe: detect re-entry of the kernel boot init flow.  Boot 530
    // showed `Phase 4: Spawning init process...` printed twice with two
    // distinct initramfs_srv aspaces, suggesting startup_thread itself
    // runs twice.  Count + identify the invoking thread / CPU on entry.
    static STARTUP_INVOCATION: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    let inv_n = STARTUP_INVOCATION.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    let entry_tid = sched::current_thread_id();
    let entry_cpu = sched::smp::cpu_id();
    println!(
        "  [STARTUP-PROBE] invocation #{} tid={} cpu={}",
        inv_n, entry_tid, entry_cpu
    );
    if inv_n > 1 {
        // Don't double-spawn — bail.  We want the log evidence above; the
        // second-pass spawn block is what creates the duplicate
        // initramfs_srv on port 6083 and wedges the boot per #178.
        println!(
            "  [STARTUP-PROBE] startup_thread re-entered — parking; \
             the first invocation already owns Phase 3/4 spawns."
        );
        loop {
            core::hint::spin_loop();
        }
    }

    // Phase 3: I/O server stack.
    println!("Phase 3: Starting I/O servers...");

    // Service registry is now kernel-internal (no namesrv thread needed).
    // Servers call SYS_SVC_REGISTER/SYS_SVC_LOOKUP directly.

    sched::spawn(io::initramfs::initramfs_server, 50, 20).expect("spawn initramfs");

    // Driver model Step A: smoke-test IRQ→port message delivery.
    io::irq_dispatch::self_test();

    // Driver model Step B: register firmware-discovered MMIO regions as
    // Memory-cap-backed regions, then smoke-test the registry and cap
    // derivation path.
    cap::mmio::populate_from_firmware();
    println!(
        "  [mmio-cap] firmware: mem_regions={}, cpus={}, virtio_devs={}, regions={}",
        firmware::mem_regions().len(),
        firmware::cpus().len(),
        firmware::virtio_devices().len(),
        cap::mmio::count()
    );
    cap::mmio::self_test();

    // Spawn ACPI table server (x86_64 only — ACPI tables from BIOS area).
    #[cfg(target_arch = "x86_64")]
    {
        let (acpi_base, acpi_size) = firmware::acpi::table_region_bounds();
        if acpi_base != 0 && acpi_size != 0 {
            if let Some(rid) =
                cap::mmio::register_region(acpi_base, acpi_size, cap::mmio::CacheAttr::Device)
            {
                match sched::spawn_user_with_mmio_cap(b"acpi_srv", 50, 20, 0, rid) {
                    Some(tid) => println!("  acpi_srv spawned (thread {})", tid),
                    None => println!("  WARNING: acpi_srv not found (ok if not yet built)"),
                }
            }
        }
    }

    // Spawn PCI bus enumeration server (all arches with ECAM).
    if let Some(ecam) = firmware::pci_ecam() {
        if let Some(rid) = cap::mmio::register_region(
            ecam.base as usize,
            ecam.size as usize,
            cap::mmio::CacheAttr::Device,
        ) {
            match sched::spawn_user_with_mmio_cap(b"pci_srv", 50, 20, 0, rid) {
                Some(tid) => println!("  pci_srv spawned (thread {})", tid),
                None => println!("  WARNING: pci_srv not found (ok if not yet built)"),
            }
        }
    }
    // x86_64 fallback: spawn pci_srv in legacy I/O mode if no ECAM.
    #[cfg(target_arch = "x86_64")]
    if firmware::pci_ecam().is_none() {
        match sched::spawn_user(b"pci_srv", 50, 20, 0) {
            Some(tid) => println!("  pci_srv spawned (thread {}, legacy I/O)", tid),
            None => println!("  WARNING: pci_srv not found (ok if not yet built)"),
        }
    }

    // Discover and spawn virtio-mmio device servers.
    // Uses firmware-discovered devices (from DTB) with hardcoded fallback.
    // On x86_64 find_device returns None (no MMIO transport), so these are no-ops.
    if let Some(base) = drivers::virtio_mmio::find_device(drivers::virtio_mmio::DEVICE_BLK) {
        let irq = drivers::virtio_mmio::device_irq(base) as u64;
        // Look up (or lazily register) the MMIO region for this device in
        // the cap registry. `populate_from_firmware` usually covers this
        // already; register_region is idempotent on (base, size).
        let region_id = cap::mmio::register_region(base, 0x1000, cap::mmio::CacheAttr::Device);
        // The driver calls sys_irq_attach to bind its IRQ port and provide
        // the MMIO base for kernel-side ACK (Step C4).
        let arg0_upper = irq << 48;
        println!(
            "  virtio-blk at {:#x}, irq {}, region_id={:?}, spawning blk_srv",
            base, irq, region_id
        );
        let spawned = match region_id {
            Some(rid) => sched::spawn_user_with_mmio_cap(b"blk_srv", 50, 20, arg0_upper, rid),
            // Fall back to the legacy path if registration failed (shouldn't
            // happen — 32 slots is plenty).
            None => sched::spawn_user(b"blk_srv", 50, 20, (base as u64) | arg0_upper),
        };
        match spawned {
            Some(tid) => println!("  blk_srv spawned (thread {})", tid),
            None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
        }
    }

    if let Some(base) = drivers::virtio_mmio::find_device(drivers::virtio_mmio::DEVICE_NET) {
        let irq = drivers::virtio_mmio::device_irq(base) as u64;
        let region_id = cap::mmio::register_region(base, 0x1000, cap::mmio::CacheAttr::Device);
        // Note: eth_srv is poll-based, so no irq_dispatch::register here.
        let arg0_upper = irq << 48;
        println!(
            "  virtio-net at {:#x}, irq {}, region_id={:?}, spawning eth_srv",
            base, irq, region_id
        );
        let spawned = match region_id {
            Some(rid) => sched::spawn_user_with_mmio_cap(b"eth_srv", 50, 20, arg0_upper, rid),
            None => sched::spawn_user(b"eth_srv", 50, 20, (base as u64) | arg0_upper),
        };
        match spawned {
            Some(tid) => println!("  eth_srv spawned (thread {})", tid),
            None => println!("  WARNING: eth_srv not found (ok if not yet built)"),
        }
        // ip6_srv is a pure IPC server — no device access needed, just spawn it.
        match sched::spawn_user(b"ip6_srv", 50, 20, 0) {
            Some(tid) => println!("  ip6_srv spawned (thread {})", tid),
            None => println!("  WARNING: ip6_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"batman_srv", 50, 20, 0) {
            Some(tid) => println!("  batman_srv spawned (thread {})", tid),
            None => println!("  WARNING: batman_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"tcp4_srv", 50, 20, 0) {
            Some(tid) => println!("  tcp4_srv spawned (thread {})", tid),
            None => println!("  WARNING: tcp4_srv not found (ok if not yet built)"),
        }
    }

    // x86_64: Discover virtio devices via PCI bus scan.
    #[cfg(target_arch = "x86_64")]
    {
        println!("  Scanning PCI bus for virtio devices...");
        if let Some(dev) = arch::x86_64::pci::find_virtio_device(0x1001) {
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"blk_srv", 50, 20, arg0) {
                Some(tid) => println!("  blk_srv spawned (thread {})", tid),
                None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
            }
        }
        if let Some(dev) = arch::x86_64::pci::find_virtio_device(0x1000) {
            // eth_srv is poll-based, but its device may share a PCI IRQ line
            // with blk_srv. Register the MMIO base so the kernel's IRQ handler
            // can ACK the net device and deassert the level-triggered line.
            io::irq_dispatch::register(dev.irq as u32, dev.bar0 as usize);
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"eth_srv", 50, 20, arg0) {
                Some(tid) => println!("  eth_srv spawned (thread {})", tid),
                None => println!("  WARNING: eth_srv not found (ok if not yet built)"),
            }
        }
        match sched::spawn_user(b"ip6_srv", 50, 20, 0) {
            Some(tid) => println!("  ip6_srv spawned (thread {})", tid),
            None => println!("  WARNING: ip6_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"batman_srv", 50, 20, 0) {
            Some(tid) => println!("  batman_srv spawned (thread {})", tid),
            None => println!("  WARNING: batman_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"tcp4_srv", 50, 20, 0) {
            Some(tid) => println!("  tcp4_srv spawned (thread {})", tid),
            None => println!("  WARNING: tcp4_srv not found (ok if not yet built)"),
        }
        // NVMe controller discovery and nvme_srv spawn.
        if let Some(nvme) = arch::x86_64::pci::find_nvme_device() {
            let region_id = cap::mmio::register_region(
                nvme.bar0 as usize,
                nvme.bar0_size as usize,
                cap::mmio::CacheAttr::Device,
            );
            let arg0_upper = (nvme.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => {
                    sched::spawn_user_with_mmio_cap(b"nvme_srv", 50, 20, arg0_upper, rid)
                }
                None => sched::spawn_user(b"nvme_srv", 50, 20, arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  nvme_srv spawned (thread {})", tid),
                None => println!("  WARNING: nvme_srv not found (ok if not yet built)"),
            }
        }

        // Intel Wi-Fi controller discovery and iwl_srv spawn.
        if let Some(iwl) = arch::x86_64::pci::find_iwl_device() {
            let region_id = cap::mmio::register_region(
                iwl.bar0 as usize,
                iwl.bar0_size as usize,
                cap::mmio::CacheAttr::Device,
            );
            let arg0_upper = (iwl.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => {
                    sched::spawn_user_with_mmio_cap(b"iwl_srv", 50, 20, arg0_upper, rid)
                }
                None => sched::spawn_user(b"iwl_srv", 50, 20, arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  iwl_srv spawned (thread {})", tid),
                None => println!("  WARNING: iwl_srv not found (ok if not yet built)"),
            }
        }

        // MediaTek 5G modem discovery and mtk_srv spawn.
        if let Some(mtk) = arch::x86_64::pci::find_mtk_device() {
            let region_id = cap::mmio::register_region(
                mtk.bar0 as usize,
                mtk.bar0_size as usize,
                cap::mmio::CacheAttr::Device,
            );
            let arg0_upper = (mtk.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => {
                    sched::spawn_user_with_mmio_cap(b"mtk_srv", 50, 20, arg0_upper, rid)
                }
                None => sched::spawn_user(b"mtk_srv", 50, 20, arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  mtk_srv spawned (thread {})", tid),
                None => println!("  WARNING: mtk_srv not found (ok if not yet built)"),
            }
        }

        // Intel GPU (i915) discovery and i915_srv spawn.
        if let Some(i915) = arch::x86_64::pci::find_i915_device() {
            let region_id = cap::mmio::register_region(
                i915.bar0 as usize,
                i915.bar0_size as usize,
                cap::mmio::CacheAttr::Device,
            );
            let arg0_upper = (i915.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => {
                    sched::spawn_user_with_mmio_cap(b"i915_srv", 50, 20, arg0_upper, rid)
                }
                None => sched::spawn_user(b"i915_srv", 50, 20, arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  i915_srv spawned (thread {})", tid),
                None => println!("  WARNING: i915_srv not found (ok if not yet built)"),
            }
        }

        // xHCI USB host controller discovery and usb_srv spawn.
        if let Some(xhci) = arch::x86_64::pci::find_xhci_device() {
            let region_id = cap::mmio::register_region(
                xhci.bar0 as usize,
                xhci.bar0_size as usize,
                cap::mmio::CacheAttr::Device,
            );
            let arg0_upper = (xhci.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => {
                    sched::spawn_user_with_mmio_cap(b"usb_srv", 50, 20, arg0_upper, rid)
                }
                None => sched::spawn_user(b"usb_srv", 50, 20, arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  usb_srv spawned (thread {})", tid),
                None => println!("  WARNING: usb_srv not found (ok if not yet built)"),
            }
        }

        // Intel HD Audio (HDA) discovery and hda_srv spawn.
        if let Some(hda) = arch::x86_64::pci::find_hda_device() {
            let region_id = cap::mmio::register_region(
                hda.bar0 as usize,
                hda.bar0_size as usize,
                cap::mmio::CacheAttr::Device,
            );
            let arg0_upper = (hda.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => {
                    sched::spawn_user_with_mmio_cap(b"hda_srv", 50, 20, arg0_upper, rid)
                }
                None => sched::spawn_user(b"hda_srv", 50, 20, arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  hda_srv spawned (thread {})", tid),
                None => println!("  WARNING: hda_srv not found (ok if not yet built)"),
            }
        }

        // Discover virtio-GPU and encode bar0+irq for fb_srv arg0.
        let mut fb_arg0_upper: u64 = 0;
        if let Some(vgpu) = arch::x86_64::pci::find_virtio_gpu() {
            fb_arg0_upper = ((vgpu.irq as u64) << 48) | ((vgpu.bar0 as u64) << 16);
        }

        // Probe BochsVBE (QEMU -vga std) and set up framebuffer info.
        arch::x86_64::pci::probe_bochs_vbe();
        // Re-try framebuffer console init now that VBE info is available.
        // (The early init at boot only succeeds on EFI where GOP is set up.)
        drivers::fb_console::init();
        // Register the VBE framebuffer as an MMIO region so fb_srv and
        // compositor_srv can map it via sys_mmio_map_cap. This is x86_64's
        // only MMIO device outside PCI I/O ports.
        let vbe_region = firmware::framebuffer_info().and_then(|fb| {
            let size = (fb.pitch as usize) * (fb.height as usize);
            if fb.addr != 0 && size > 0 {
                cap::mmio::register_region(fb.addr as usize, size, cap::mmio::CacheAttr::WriteCombine)
            } else {
                None
            }
        });
        // fb_srv arg0 encoding:
        //   bits  0-15: VBE framebuffer MMIO cap slot (from spawn_user_with_mmio_cap)
        //   bits 16-31: virtio-GPU BAR0 I/O port (0 if no GPU)
        //   bits 48-63: virtio-GPU IRQ
        let fb_spawn = match vbe_region {
            Some(rid) => sched::spawn_user_with_mmio_cap(b"fb_srv", 50, 20, fb_arg0_upper, rid),
            None => sched::spawn_user(b"fb_srv", 50, 20, fb_arg0_upper),
        };
        match fb_spawn {
            Some(tid) => println!("  fb_srv spawned (thread {})", tid),
            None => println!("  WARNING: fb_srv not found (ok if not yet built)"),
        }
        // Spawn input_srv: PS/2 keyboard + mouse (always present on x86_64).
        match sched::spawn_user(b"input_srv", 50, 20, 0) {
            Some(tid) => println!("  input_srv spawned (thread {})", tid),
            None => println!("  WARNING: input_srv not found (ok if not yet built)"),
        }
        // Spawn compositor_srv: connects to fb_srv + input_srv. It maps the
        // VBE framebuffer directly via a cap granted here (same region as
        // fb_srv — shared-memory display).
        let comp_spawn = match vbe_region {
            Some(rid) => sched::spawn_user_with_mmio_cap(b"compositor_srv", 50, 20, 0, rid),
            None => sched::spawn_user(b"compositor_srv", 50, 20, 0),
        };
        match comp_spawn {
            Some(tid) => println!("  compositor_srv spawned (thread {})", tid),
            None => println!("  WARNING: compositor_srv not found (ok if not yet built)"),
        }
    }

    // MIPS64 Malta: Discover virtio devices via GT-64120 PCI bus scan.
    #[cfg(target_arch = "mips64")]
    {
        println!("  Scanning PCI bus for virtio devices (Malta GT-64120)...");
        if let Some(dev) = arch::mips64::pci::find_virtio_device(0x1001) {
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"blk_srv", 50, 20, arg0) {
                Some(tid) => println!("  blk_srv spawned (thread {})", tid),
                None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
            }
        }
        if let Some(dev) = arch::mips64::pci::find_virtio_device(0x1000) {
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"eth_srv", 50, 20, arg0) {
                Some(tid) => println!("  eth_srv spawned (thread {})", tid),
                None => println!("  WARNING: eth_srv not found (ok if not yet built)"),
            }
        }
        match sched::spawn_user(b"ip6_srv", 50, 20, 0) {
            Some(tid) => println!("  ip6_srv spawned (thread {})", tid),
            None => println!("  WARNING: ip6_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"batman_srv", 50, 20, 0) {
            Some(tid) => println!("  batman_srv spawned (thread {})", tid),
            None => println!("  WARNING: batman_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"tcp4_srv", 50, 20, 0) {
            Some(tid) => println!("  tcp4_srv spawned (thread {})", tid),
            None => println!("  WARNING: tcp4_srv not found (ok if not yet built)"),
        }
    }

    // LoongArch64: Discover virtio devices via PCI ECAM scan.
    // PCI BARs aren't in the firmware mem-region table; register them
    // dynamically here so drivers can map them via sys_mmio_map_cap.
    #[cfg(target_arch = "loongarch64")]
    {
        println!("  Scanning PCI bus for virtio devices (ECAM)...");
        if let Some(dev) = arch::loongarch64::pci::find_virtio_device(0x1001) {
            let region_id =
                cap::mmio::register_region(dev.bar0, 0x1000, cap::mmio::CacheAttr::Device);
            let arg0_upper = (dev.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => sched::spawn_user_with_mmio_cap(b"blk_srv", 50, 20, arg0_upper, rid),
                None => sched::spawn_user(b"blk_srv", 50, 20, (dev.bar0 as u64) | arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  blk_srv spawned (thread {})", tid),
                None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
            }
        }
        if let Some(dev) = arch::loongarch64::pci::find_virtio_device(0x1000) {
            let region_id =
                cap::mmio::register_region(dev.bar0, 0x1000, cap::mmio::CacheAttr::Device);
            let arg0_upper = (dev.irq as u64) << 48;
            let spawned = match region_id {
                Some(rid) => sched::spawn_user_with_mmio_cap(b"eth_srv", 50, 20, arg0_upper, rid),
                None => sched::spawn_user(b"eth_srv", 50, 20, (dev.bar0 as u64) | arg0_upper),
            };
            match spawned {
                Some(tid) => println!("  eth_srv spawned (thread {})", tid),
                None => println!("  WARNING: eth_srv not found (ok if not yet built)"),
            }
        }
        match sched::spawn_user(b"ip6_srv", 50, 20, 0) {
            Some(tid) => println!("  ip6_srv spawned (thread {})", tid),
            None => println!("  WARNING: ip6_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"batman_srv", 50, 20, 0) {
            Some(tid) => println!("  batman_srv spawned (thread {})", tid),
            None => println!("  WARNING: batman_srv not found (ok if not yet built)"),
        }
        match sched::spawn_user(b"tcp4_srv", 50, 20, 0) {
            Some(tid) => println!("  tcp4_srv spawned (thread {})", tid),
            None => println!("  WARNING: tcp4_srv not found (ok if not yet built)"),
        }
    }

    // Complete deferred swap backend initialization (blk backend needs
    // the "blk" service to be registered with the name server).
    mm::swap::init_blk_deferred();

    // Swap end-to-end verification: fault pages with known data patterns,
    // evict via WSCLOCK (triggering swap-out), re-fault (swap-in), verify data.
    if mm::swap::is_ram_backend() {
        test_swap_e2e();
        test_swap_cow_fork();
    }

    // Phase 4: Spawning init process...
    println!("Phase 4: Spawning init process...");

    // Spawn userspace initramfs server with CPIO data mapped at 0x3_0000_0000.
    {
        use core::sync::atomic::Ordering;
        let cpio_data: &[u8] = include_bytes!("io/initramfs.cpio");
        let srv_port = ipc::port::create().expect("initramfs_srv port");
        io::initramfs::USER_INITRAMFS_PORT.store(srv_port, Ordering::Release);

        // Register initramfs in the kernel service registry.
        io::namesrv::svc_register(b"initramfs", srv_port);

        match sched::spawn_user_with_data(
            b"initramfs_srv",
            50,
            20,
            cpio_data,
            0x3_0000_0000,
            srv_port as u64,
        ) {
            Some(tid) => {
                // Grant SEND|RECV|MANAGE cap for the initramfs port to the new task.
                let task_id = sched::thread_task_id(tid);
                cap::grant_full_port_cap(task_id, srv_port);
                println!(
                    "  initramfs_srv spawned (thread {}, port {})",
                    tid, srv_port
                );
            }
            None => println!("  ERROR: failed to spawn initramfs_srv"),
        }
    }

    // Spawn rootfs server (CPIO-backed writable FS, mountable at "/").
    {
        use core::sync::atomic::Ordering;
        let cpio_data: &[u8] = include_bytes!("io/initramfs.cpio");
        let srv_port = ipc::port::create().expect("rootfs_srv port");

        // Register rootfs in the kernel service registry.
        io::namesrv::svc_register(b"rootfs", srv_port);

        match sched::spawn_user_with_data(
            b"rootfs_srv",
            50,
            20,
            cpio_data,
            0x4_0000_0000, // different VA from initramfs_srv (0x3_0000_0000)
            srv_port as u64,
        ) {
            Some(tid) => {
                let task_id = sched::thread_task_id(tid);
                cap::grant_full_port_cap(task_id, srv_port);
                println!(
                    "  rootfs_srv spawned (thread {}, port {})",
                    tid, srv_port
                );
            }
            None => println!("  WARNING: rootfs_srv not found (ok if not yet built)"),
        }
    }

    // Spawn console server (userspace, all architectures).
    match sched::spawn_user(b"console_srv", 50, 20, 0) {
        Some(tid) => println!("  console_srv spawned (thread {})", tid),
        None => println!("  WARNING: console_srv not found (ok if not yet built)"),
    }

    // Spawn cache server (userspace, block device caching proxy).
    match sched::spawn_user(b"cache_srv", 50, 20, 0) {
        Some(tid) => println!("  cache_srv spawned (thread {})", tid),
        None => println!("  WARNING: cache_srv not found (ok if not yet built)"),
    }

    // Spawn partition table server (reads GPT from block device).
    match sched::spawn_user(b"part_srv", 50, 20, 0) {
        Some(tid) => println!("  part_srv spawned (thread {})", tid),
        None => println!("  WARNING: part_srv not found (ok if not yet built)"),
    }

    // Spawn unified FAT filesystem server (FAT12/16/32, userspace).
    // GPT partition 1: FAT16 at 1 MiB offset.
    match sched::spawn_user(b"fat_srv", 50, 20, 1 * 1024 * 1024) {
        Some(tid) => println!("  fat_srv spawned (thread {})", tid),
        None => println!("  WARNING: fat_srv not found (ok if not yet built)"),
    }

    // Spawn unified ext2/3/4 filesystem server.
    // GPT partition 2: ext2 at 17 MiB offset.
    match sched::spawn_user(b"ext_srv", 50, 20, 17 * 1024 * 1024) {
        Some(tid) => println!("  ext_srv spawned (thread {})", tid),
        None => println!("  WARNING: ext_srv not found (ok if not yet built)"),
    }

    // Spawn XFS filesystem server.
    // GPT partition 4: XFS at 37 MiB offset.
    match sched::spawn_user(b"xfs_srv", 50, 20, 37 * 1024 * 1024) {
        Some(tid) => println!("  xfs_srv spawned (thread {})", tid),
        None => println!("  WARNING: xfs_srv not found (ok if not yet built)"),
    }

    // Spawn APFS filesystem server.
    // GPT partition 5: APFS at 337 MiB offset.
    {
        let part_off: u64 = 337 * 1024 * 1024;
        match sched::spawn_user(b"apfs_srv", 50, 20, part_off) {
            Some(tid) => {
                println!("  apfs_srv spawned (thread {})", tid);
            }
            None => println!("  WARNING: apfs_srv not found (ok if not yet built)"),
        }
    }

    // Spawn NTFS filesystem server.
    // GPT partition 6: NTFS at 369 MiB offset.
    {
        let part_off: u64 = 369 * 1024 * 1024;
        match sched::spawn_user(b"ntfs_srv", 50, 20, part_off) {
            Some(tid) => println!("  ntfs_srv spawned (thread {})", tid),
            None => println!("  WARNING: ntfs_srv not found (ok if not yet built)"),
        }
    }

    // Spawn btrfs filesystem server.
    // GPT partition 7: btrfs at 401 MiB offset.
    {
        let part_off: u64 = 401 * 1024 * 1024;
        match sched::spawn_user(b"btrfs_srv", 50, 20, part_off) {
            Some(tid) => println!("  btrfs_srv spawned (thread {})", tid),
            None => println!("  WARNING: btrfs_srv not found (ok if not yet built)"),
        }
    }

    // Spawn ISO 9660 filesystem server.
    // ISO image appended at 32 MiB offset (see tools/make-iso9660.sh).
    // Pre-spawning here (rather than inline at Phase 177) gives the server
    // time to IO_CONNECT to cache_blk and parse the PVD before any client
    // calls in.  Without this, Phase 177 races the server's init and the
    // first FS_OPEN times out for 10s.
    match sched::spawn_user(b"iso9660_srv", 50, 20, 32 * 1024 * 1024) {
        Some(tid) => println!("  iso9660_srv spawned (thread {})", tid),
        None => println!("  WARNING: iso9660_srv not found (ok if not yet built)"),
    }

    // Spawn UDF filesystem server.
    // UDF image appended at 35 MiB offset (see tools/make-udf.sh).
    match sched::spawn_user(b"udf_srv", 50, 20, 35 * 1024 * 1024) {
        Some(tid) => println!("  udf_srv spawned (thread {})", tid),
        None => println!("  WARNING: udf_srv not found (ok if not yet built)"),
    }

    // Spawn ramdisk server (userspace, no data copy needed).
    match sched::spawn_user(b"ramdisk_srv", 50, 20, 0) {
        Some(tid) => println!("  ramdisk_srv spawned (thread {})", tid),
        None => println!("  WARNING: ramdisk_srv not found (ok if not yet built)"),
    }

    match sched::spawn_user(b"init", 50, 20, 0) {
        Some(tid) => println!("  init process spawned (thread {})", tid),
        None => println!("  ERROR: failed to spawn init"),
    }

    println!("Startup complete");
    // This thread has no more work — exit by spinning (will be preempted).
    sched::scheduler::exit_current_thread(0);
}

fn test_capabilities() {
    use cap::{CapSpace, CapType, Capability, Cdt, Rights};
    use sync::SpinLock;

    static CDT_STORAGE: SpinLock<Cdt> = SpinLock::new(Cdt::new());
    {
        let mut cdt = CDT_STORAGE.lock();
        cdt.init();

        let mut server_space = CapSpace::new(0);
        let port_cap = Capability::new(
            CapType::Port,
            Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
            0xDEAD_0001,
        );
        let server_slot = server_space.insert(port_cap, &mut cdt).unwrap();
        println!(
            "  Cap test: server has {:?} at slot {}",
            server_space.lookup(server_slot).unwrap(),
            server_slot
        );

        let mut client_space = CapSpace::new(1);
        let client_slot = server_space
            .derive_to(server_slot, Rights::SEND, &mut client_space, &mut cdt)
            .unwrap();
        println!(
            "  Cap test: client has {:?} at slot {}",
            client_space.lookup(client_slot).unwrap(),
            client_slot
        );

        let mut client2_space = CapSpace::new(2);
        let client2_slot = server_space
            .derive_to(
                server_slot,
                Rights::SEND.union(Rights::GRANT),
                &mut client2_space,
                &mut cdt,
            )
            .unwrap();
        println!(
            "  Cap test: client2 has {:?} at slot {}",
            client2_space.lookup(client2_slot).unwrap(),
            client2_slot
        );

        let revoked = server_space.revoke(server_slot, &mut cdt);
        println!("  Cap test: revoked {} derived capabilities", revoked);
        println!(
            "  Cap test: server still has {:?}",
            server_space.lookup(server_slot).unwrap()
        );
    }
    println!("  Cap test: PASSED");
}

// --- ART port-table stress harness ---
// Hammers `port::create_kernel_port` + immediate `port_kernel_data` lookup
// in a tight single-thread loop. The recurring boot bug is a same-thread
// `insert returns true → lookup returns None`; this harness forces that
// path to execute thousands of times, growing the ART through Node4 →
// Node16 → Node256 along the way. Failures emit the same structured
// `LookupOutcome` diagnostic that the create_anon BUG site uses.
fn test_art_port_stress() {
    fn null_handler(
        _port_id: ipc::port::PortId,
        _user_data: usize,
        _msg: &ipc::Message,
    ) -> ipc::Message {
        ipc::Message::empty()
    }

    // Enable ART post-insert self-check for the duration of this test.
    ipc::art::SELF_CHECK_INSERT.store(true, core::sync::atomic::Ordering::Relaxed);

    const N: usize = 4000;
    let mut ports: [u64; N] = [0; N];
    let mut failures: usize = 0;

    for i in 0..N {
        let user_data = 0xCAFE_0000 + i;
        let pid = match ipc::port::create_kernel_port(null_handler, user_data) {
            Some(p) => p,
            None => {
                println!("  ART stress: create_kernel_port OOM at i={}", i);
                break;
            }
        };
        ports[i] = pid;

        // The bug: same-thread immediate lookup returning None.
        match ipc::port::port_kernel_data(pid) {
            Some(ud) => {
                if ud != user_data {
                    println!(
                        "  ART stress: user_data mismatch i={} pid={} got={:#x} want={:#x}",
                        i, pid, ud, user_data
                    );
                    failures += 1;
                }
            }
            None => {
                failures += 1;
                let root = ipc::port::port_art_root_snapshot();
                println!(
                    "  ART stress: HIT BUG at i={} pid={} root={:#x}",
                    i, pid, root
                );
                match ipc::port::port_ref_diag(pid) {
                    ipc::port::PortRefDiag::Found =>
                        println!("    diag: Found (kernel_handler==0?)"),
                    ipc::port::PortRefDiag::NotInArt(outcome) =>
                        ipc::art::print_lookup_outcome(
                            "    diag.NotInArt",
                            ipc::port::port_local(pid),
                            outcome,
                        ),
                    ipc::port::PortRefDiag::NotAlive { flags, kernel_handler_nz } =>
                        println!(
                            "    diag: NotAlive flags={:#x} kernel_handler_nz={}",
                            flags, kernel_handler_nz
                        ),
                }
            }
        }
    }

    mm::slab::debug_check_all_caches("stress.after-bulk-insert");

    // Re-verify all ports are still resolvable after the full insert run
    // (catches structural issues that surface only after later inserts
    // promote inner nodes, e.g. a stale `find_child_slot` write into a
    // freed node when the parent gets COW'd by a later insert).
    let mut post_failures: usize = 0;
    for i in 0..N {
        if ports[i] == 0 {
            continue;
        }
        if ipc::port::port_kernel_data(ports[i]).is_none() {
            post_failures += 1;
            if post_failures <= 5 {
                let root = ipc::port::port_art_root_snapshot();
                println!(
                    "  ART stress: POST-PASS lookup fail at i={} pid={} root={:#x}",
                    i, ports[i], root
                );
                match ipc::port::port_ref_diag(ports[i]) {
                    ipc::port::PortRefDiag::NotInArt(outcome) =>
                        ipc::art::print_lookup_outcome(
                            "    diag.NotInArt",
                            ipc::port::port_local(ports[i]),
                            outcome,
                        ),
                    ipc::port::PortRefDiag::Found =>
                        println!("    diag: Found"),
                    ipc::port::PortRefDiag::NotAlive { flags, kernel_handler_nz } =>
                        println!(
                            "    diag: NotAlive flags={:#x} kernel_handler_nz={}",
                            flags, kernel_handler_nz
                        ),
                }
            }
        }
    }

    // Tear down — ports leak otherwise.
    for i in 0..N {
        if ports[i] != 0 {
            ipc::port::destroy(ports[i]);
        }
    }

    if failures == 0 && post_failures == 0 {
        println!("  ART stress: {} ports created/resolved/destroyed cleanly", N);
    } else {
        println!(
            "  ART stress: FAILED — immediate={} post={}",
            failures, post_failures
        );
    }

    // Variant 2: interleaved create/destroy. Forces ART node merge/split
    // paths and slab memory reuse, which exposed the BATCH_CAP overflow.
    let mut churn_failures = 0usize;
    let mut alive: [u64; 256] = [0; 256];
    for round in 0..2000usize {
        let slot = round % alive.len();
        if alive[slot] != 0 {
            ipc::port::destroy(alive[slot]);
            alive[slot] = 0;
        }
        let pid = match ipc::port::create_kernel_port(null_handler, 0xBEEF_0000 + round) {
            Some(p) => p,
            None => break,
        };
        alive[slot] = pid;
        match ipc::port::port_kernel_data(pid) {
            Some(_) => {}
            None => {
                churn_failures += 1;
                if churn_failures <= 3 {
                    let root = ipc::port::port_art_root_snapshot();
                    println!(
                        "  ART stress (churn): HIT BUG round={} slot={} pid={} root={:#x}",
                        round, slot, pid, root
                    );
                    match ipc::port::port_ref_diag(pid) {
                        ipc::port::PortRefDiag::NotInArt(outcome) =>
                            ipc::art::print_lookup_outcome(
                                "    diag.NotInArt", ipc::port::port_local(pid), outcome,
                            ),
                        ipc::port::PortRefDiag::Found =>
                            println!("    diag: Found"),
                        ipc::port::PortRefDiag::NotAlive { flags, kernel_handler_nz } =>
                            println!(
                                "    diag: NotAlive flags={:#x} kernel_handler_nz={}",
                                flags, kernel_handler_nz
                            ),
                    }
                }
            }
        }
    }
    for &p in alive.iter() {
        if p != 0 {
            ipc::port::destroy(p);
        }
    }
    if churn_failures == 0 {
        println!("  ART stress (churn): 2000 interleaved rounds clean");
    } else {
        println!("  ART stress (churn): FAILED — failures={}", churn_failures);
    }

    // Disable the post-insert self-check now that the test is done.
    ipc::art::SELF_CHECK_INSERT.store(false, core::sync::atomic::Ordering::Relaxed);
}

// --- Phase 2: Demand paging test ---

fn test_demand_paging() {
    use mm::page::{self, MMUPAGE_SIZE};
    use mm::vma::VmaProt;
    let ps = page::page_size();

    // Always use a fresh page table root for demand paging tests.
    // Using the boot root is wrong: destroy() frees its page table pages,
    // corrupting the live kernel identity mapping.
    let pt_root = {
        let pa = mm::phys::alloc_page().expect("alloc pt root");
        unsafe {
            core::ptr::write_bytes(
                mm::page::phys_to_kva(pa.as_usize()) as *mut u8,
                0,
                mm::page::MMUPAGE_SIZE,
            );
        }
        pa.as_usize()
    };

    let aspace_id = mm::aspace::create(pt_root).expect("create aspace");
    println!("  Created address space {}", aspace_id);

    // Map 4 allocation pages of anonymous memory (lazy — no PTEs installed).
    // Use a high VA to avoid conflicting with kernel identity mapping.
    // L0 index 1 = VA 0x80_0000_0000 onwards (not used by kernel).
    let test_va = 0x80_0000_0000usize;
    let num_alloc_pages = 4;
    let num_mmu_pages = num_alloc_pages * page::page_mmucount();
    mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace
            .map_anon(test_va, num_mmu_pages, VmaProt::ReadWrite)
            .expect("map_anon");
        println!("  Mapped {} pages at VA {:#x}", num_alloc_pages, test_va);

        assert_eq!(mm::fault::count_installed_ptes(pt_root, vma), 0);
        assert_eq!(vma.page_count(), num_alloc_pages);
        assert_eq!(vma.mmu_page_count(), num_alloc_pages * page::page_mmucount());
    });

    // Simulate demand faults by calling handle_page_fault directly.
    let test_addrs = [
        test_va,
        test_va + MMUPAGE_SIZE,
        test_va + ps,
        test_va + 2 * ps + 3 * MMUPAGE_SIZE,
    ];

    for &addr in &test_addrs {
        println!("  Faulting at {:#x}...", addr);
        let result = mm::fault::handle_page_fault(aspace_id, addr, mm::fault::FaultType::Write);
        println!("  Result: {:?}", result);
        // With background pre-zeroing, a sub-page in the same allocation page
        // as a prior major fault may be minor (already zeroed + resident).
        assert!(
            result == mm::fault::FaultResult::HandledMajor
                || result == mm::fault::FaultResult::HandledMinor,
            "Expected major or minor fault at {:#x}, got {:?}",
            addr,
            result
        );
    }

    mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace.find_vma(test_va).unwrap();
        let count = mm::fault::count_installed_ptes(pt_root, vma);
        assert_eq!(count, test_addrs.len());
        println!(
            "  {} PTEs installed after {} major faults",
            count,
            test_addrs.len()
        );
    });

    // Test minor fault: evict PTE (preserves SW_ZEROED), re-fault.
    mm::fault::evict_mmupage_dispatch(pt_root, test_va);

    let result = mm::fault::handle_page_fault(aspace_id, test_va, mm::fault::FaultType::Read);
    assert!(
        result == mm::fault::FaultResult::HandledMinor,
        "Expected minor fault, got {:?}",
        result
    );
    println!("  Minor fault test: PASSED");

    // AArch64 contiguous PTE promotion test: fault all 16 MMU pages in the
    // first 64K-aligned contiguous group. The contiguous hint requires all 16
    // consecutive 4K L3 PTEs to be installed.
    #[cfg(target_arch = "aarch64")]
    {
        const CONTIG_GROUP: usize = 16; // 16 × 4K = 64K, AArch64 architecture constant
        let promotions_before =
            mm::stats::CONTIGUOUS_PROMOTIONS.load(core::sync::atomic::Ordering::Relaxed);
        // We already faulted mmu_idx 0 and 1 (test_va and test_va+4K). Fault the rest of the group.
        for i in 2..CONTIG_GROUP {
            let addr = test_va + i * MMUPAGE_SIZE;
            let result = mm::fault::handle_page_fault(aspace_id, addr, mm::fault::FaultType::Write);
            assert!(
                result == mm::fault::FaultResult::HandledMajor
                    || result == mm::fault::FaultResult::HandledMinor,
                "Expected major/minor fault at {:#x}, got {:?}",
                addr,
                result
            );
        }
        let promotions_after =
            mm::stats::CONTIGUOUS_PROMOTIONS.load(core::sync::atomic::Ordering::Relaxed);
        let promoted = promotions_after - promotions_before;
        println!("  Contiguous PTE promotions: {} (expected 1)", promoted);
        assert!(
            promoted >= 1,
            "Expected at least 1 contiguous promotion, got {}",
            promoted
        );
        println!("  AArch64 contiguous PTE test: PASSED");
    }

    // WSCLOCK reclaim test.
    // After the faults above, we have PTEs installed but the hardware reference
    // bits are NOT set (we called handle_page_fault directly, not real accesses).
    // Running WSCLOCK should clear all unreferenced PTEs and free allocation pages.
    {
        let installed_before = mm::aspace::with_aspace(aspace_id, |aspace| {
            let vma = aspace.find_vma(test_va).unwrap();
            mm::fault::count_installed_ptes(pt_root, vma)
        });
        println!("  WSCLOCK: {} PTEs installed before scan", installed_before);

        // Pass 1: clears reference bits on all referenced pages.
        let scan1 = mm::wsclock::scan(aspace_id, 100);
        println!(
            "  WSCLOCK pass 1: scanned={}, cleared={}, freed={}",
            scan1.pages_scanned, scan1.ptes_cleared, scan1.pages_freed
        );

        // Pass 2: pages not re-accessed since pass 1 have ref bit clear → evict.
        let scan2 = mm::wsclock::scan(aspace_id, 100);
        println!(
            "  WSCLOCK pass 2: scanned={}, cleared={}, freed={}",
            scan2.pages_scanned, scan2.ptes_cleared, scan2.pages_freed
        );

        let installed_after = mm::aspace::with_aspace(aspace_id, |aspace| {
            let vma = aspace.find_vma(test_va).unwrap();
            mm::fault::count_installed_ptes(pt_root, vma)
        });
        println!("  WSCLOCK: {} PTEs installed after scan", installed_after);
        assert_eq!(installed_after, 0, "All PTEs should be cleared");
        let total_freed = scan1.pages_freed + scan2.pages_freed;
        assert!(
            total_freed > 0,
            "Should have freed at least 1 allocation page"
        );

        // Re-fault the first address — should be a major fault since the page was freed.
        let result = mm::fault::handle_page_fault(aspace_id, test_va, mm::fault::FaultType::Write);
        assert!(
            result == mm::fault::FaultResult::HandledMajor,
            "Expected major fault after reclaim, got {:?}",
            result
        );
        println!(
            "  Swap stats: out={}, in={}, err={}",
            mm::swap::SWAP_OUT_COUNT.load(core::sync::atomic::Ordering::Relaxed),
            mm::swap::SWAP_IN_COUNT.load(core::sync::atomic::Ordering::Relaxed),
            mm::swap::SWAP_IO_ERRORS.load(core::sync::atomic::Ordering::Relaxed),
        );
        println!("  WSCLOCK re-fault after reclaim: PASSED");
    }

    mm::stats::print();

    mm::aspace::destroy(aspace_id);
    println!("  Demand paging test: PASSED");
}

// --- Swap end-to-end verification ---
//
// Runs after I/O servers are up (startup_thread), so the blk backend
// is initialized. Verifies that data survives the full round-trip:
// fault-in → write pattern → WSCLOCK eviction (swap-out) → re-fault (swap-in) → verify.

fn test_swap_e2e() {
    use mm::page::{self, MMUPAGE_SIZE};
    use mm::vma::VmaProt;
    let ps = page::page_size();

    println!("  Swap E2E: testing data integrity through swap round-trip...");
    let slots_before = mm::swap::slots_in_use();

    let out_before = mm::swap::SWAP_OUT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let in_before = mm::swap::SWAP_IN_COUNT.load(core::sync::atomic::Ordering::Relaxed);

    // Create a fresh page table + address space.
    let pt_root = {
        let pa = mm::phys::alloc_page().expect("swap e2e pt root");
        unsafe {
            core::ptr::write_bytes(
                mm::page::phys_to_kva(pa.as_usize()) as *mut u8,
                0,
                MMUPAGE_SIZE,
            );
        }
        pa.as_usize()
    };
    let aspace_id = mm::aspace::create(pt_root).expect("swap e2e aspace");

    // Map 4 allocation pages of anonymous memory at a high VA.
    let test_va = 0xA0_0000_0000usize;
    let num_alloc_pages = 4;
    let num_mmu_pages = num_alloc_pages * page::page_mmucount();
    mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace
            .map_anon(test_va, num_mmu_pages, VmaProt::ReadWrite)
            .expect("swap e2e map_anon");
    });

    // Fault in each allocation page and write a recognizable pattern.
    // Pattern: each allocation page gets its page index as a repeating u64.
    for page_idx in 0..num_alloc_pages {
        let va = test_va + page_idx * ps;
        let result =
            mm::fault::handle_page_fault(aspace_id, va, mm::fault::FaultType::Write);
        assert!(
            result == mm::fault::FaultResult::HandledMajor
                || result == mm::fault::FaultResult::HandledMinor,
            "swap e2e: unexpected fault result {:?} for page {}",
            result,
            page_idx,
        );

        // Write pattern: translate VA → PA, write through identity map.
        let pa = mm::hat::translate_va(pt_root, va).expect("swap e2e translate");
        let pattern = 0xDEAD_0000u64 | (page_idx as u64);
        let ptr = pa as *mut u64;
        unsafe {
            // Write pattern at the start and end of the page.
            core::ptr::write_volatile(ptr, pattern);
            let end_ptr = (pa + ps - 8) as *mut u64;
            core::ptr::write_volatile(end_ptr, pattern ^ 0xFFFF_FFFF);
        }
    }

    // Run WSCLOCK twice to evict all pages (pass 1 clears ref bits,
    // pass 2 evicts unreferenced pages). With swap enabled, evicted
    // pages should be written to the swap backend before being freed.
    let scan1 = mm::wsclock::scan(aspace_id, 100);
    let scan2 = mm::wsclock::scan(aspace_id, 100);
    let total_freed = scan1.pages_freed + scan2.pages_freed;
    println!(
        "  Swap E2E: WSCLOCK freed {} pages (pass1={}, pass2={})",
        total_freed, scan1.pages_freed, scan2.pages_freed,
    );
    assert!(total_freed >= num_alloc_pages, "swap e2e: expected to free all pages");

    let out_after = mm::swap::SWAP_OUT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let swapped_out = out_after - out_before;
    println!("  Swap E2E: {} pages swapped out", swapped_out);
    assert!(
        swapped_out >= num_alloc_pages as u32,
        "swap e2e: expected {} swap-outs, got {}",
        num_alloc_pages,
        swapped_out,
    );

    // Re-fault each page (triggers swap-in) and verify data patterns.
    for page_idx in 0..num_alloc_pages {
        let va = test_va + page_idx * ps;
        let result =
            mm::fault::handle_page_fault(aspace_id, va, mm::fault::FaultType::Read);
        assert!(
            result == mm::fault::FaultResult::HandledMajor,
            "swap e2e: expected major fault (swap-in) for page {}, got {:?}",
            page_idx,
            result,
        );

        // Verify pattern through identity-mapped PA.
        let pa = mm::hat::translate_va(pt_root, va).expect("swap e2e translate after");
        let pattern = 0xDEAD_0000u64 | (page_idx as u64);
        let ptr = pa as *const u64;
        unsafe {
            let start_val = core::ptr::read_volatile(ptr);
            let end_val = core::ptr::read_volatile((pa + ps - 8) as *const u64);
            assert_eq!(
                start_val, pattern,
                "swap e2e: page {} start mismatch: got {:#x}, expected {:#x}",
                page_idx, start_val, pattern,
            );
            assert_eq!(
                end_val,
                pattern ^ 0xFFFF_FFFF,
                "swap e2e: page {} end mismatch: got {:#x}, expected {:#x}",
                page_idx,
                end_val,
                pattern ^ 0xFFFF_FFFF,
            );
        }
    }

    let in_after = mm::swap::SWAP_IN_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let swapped_in = in_after - in_before;
    let errors = mm::swap::SWAP_IO_ERRORS.load(core::sync::atomic::Ordering::Relaxed);
    println!(
        "  Swap E2E: out={}, in={}, err={}",
        swapped_out, swapped_in, errors,
    );
    assert_eq!(errors, 0, "swap e2e: unexpected I/O errors");
    assert!(
        swapped_in >= num_alloc_pages as u32,
        "swap e2e: expected {} swap-ins, got {}",
        num_alloc_pages,
        swapped_in,
    );

    mm::aspace::destroy(aspace_id);
    let slots_after = mm::swap::slots_in_use();
    assert_eq!(
        slots_after, slots_before,
        "swap e2e: slot leak — {} before, {} after",
        slots_before, slots_after,
    );
    println!("  Swap E2E data integrity test: PASSED (no slot leaks)");
}

/// Test that fork correctly inherits swap slots. Creates a parent aspace,
/// faults in pages, writes patterns, evicts them to swap, then forks.
/// The child faults on the swapped pages and verifies data integrity.
fn test_swap_cow_fork() {
    use mm::page::{self, MMUPAGE_SIZE};
    use mm::vma::VmaProt;
    let ps = page::page_size();

    println!("  Swap COW fork: testing swap slot inheritance across fork...");
    let slots_before = mm::swap::slots_in_use();

    // --- Parent: create aspace, fault pages, write patterns ---
    // Use a proper user page table (includes kernel mappings) because
    // clone_for_cow reloads CR3 to flush TLB.
    let pt_root = mm::hat::create_user_page_table().expect("swap cow pt root");
    let parent_aspace = mm::aspace::create(pt_root).expect("swap cow parent aspace");

    let test_va = 0xB0_0000_0000usize;
    let num_alloc_pages = 4;
    let num_mmu_pages = num_alloc_pages * page::page_mmucount();
    mm::aspace::with_aspace(parent_aspace, |aspace| {
        aspace
            .map_anon(test_va, num_mmu_pages, VmaProt::ReadWrite)
            .expect("swap cow map_anon");
    });

    // Fault and write patterns.
    for page_idx in 0..num_alloc_pages {
        let va = test_va + page_idx * ps;
        mm::fault::handle_page_fault(parent_aspace, va, mm::fault::FaultType::Write);
        let pa = mm::hat::translate_va(pt_root, va).expect("swap cow translate");
        let pattern = 0xCAFE_0000u64 | (page_idx as u64);
        unsafe {
            core::ptr::write_volatile(pa as *mut u64, pattern);
            core::ptr::write_volatile((pa + ps - 8) as *mut u64, pattern ^ 0xFFFF_FFFF);
        }
    }

    // --- Evict all pages to swap ---
    let scan1 = mm::wsclock::scan(parent_aspace, 100);
    let scan2 = mm::wsclock::scan(parent_aspace, 100);
    let total_freed = scan1.pages_freed + scan2.pages_freed;
    assert!(
        total_freed >= num_alloc_pages,
        "swap cow: expected {} pages freed, got {}",
        num_alloc_pages,
        total_freed,
    );

    // --- Fork: child should inherit swap slots ---
    let (child_aspace, child_pt_root) =
        mm::aspace::clone_for_cow(parent_aspace).expect("swap cow fork");

    // --- Child faults on swapped pages and verifies data ---
    for page_idx in 0..num_alloc_pages {
        let va = test_va + page_idx * ps;
        let result =
            mm::fault::handle_page_fault(child_aspace, va, mm::fault::FaultType::Read);
        assert!(
            result == mm::fault::FaultResult::HandledMajor,
            "swap cow: child expected major fault for page {}, got {:?}",
            page_idx,
            result,
        );

        let pa = mm::hat::translate_va(child_pt_root, va).expect("swap cow child translate");
        let pattern = 0xCAFE_0000u64 | (page_idx as u64);
        unsafe {
            let start_val = core::ptr::read_volatile(pa as *const u64);
            let end_val = core::ptr::read_volatile((pa + ps - 8) as *const u64);
            assert_eq!(
                start_val, pattern,
                "swap cow: child page {} start mismatch: got {:#x}, expected {:#x}",
                page_idx, start_val, pattern,
            );
            assert_eq!(
                end_val,
                pattern ^ 0xFFFF_FFFF,
                "swap cow: child page {} end mismatch: got {:#x}, expected {:#x}",
                page_idx, end_val, pattern ^ 0xFFFF_FFFF,
            );
        }
    }

    // --- Parent also faults and verifies (swap slot has refcount > 0) ---
    for page_idx in 0..num_alloc_pages {
        let va = test_va + page_idx * ps;
        let result =
            mm::fault::handle_page_fault(parent_aspace, va, mm::fault::FaultType::Read);
        assert!(
            result == mm::fault::FaultResult::HandledMajor,
            "swap cow: parent expected major fault for page {}, got {:?}",
            page_idx,
            result,
        );

        let pa = mm::hat::translate_va(pt_root, va).expect("swap cow parent translate");
        let pattern = 0xCAFE_0000u64 | (page_idx as u64);
        unsafe {
            let start_val = core::ptr::read_volatile(pa as *const u64);
            let end_val = core::ptr::read_volatile((pa + ps - 8) as *const u64);
            assert_eq!(
                start_val, pattern,
                "swap cow: parent page {} start mismatch: got {:#x}, expected {:#x}",
                page_idx, start_val, pattern,
            );
            assert_eq!(
                end_val,
                pattern ^ 0xFFFF_FFFF,
                "swap cow: parent page {} end mismatch: got {:#x}, expected {:#x}",
                page_idx, end_val, pattern ^ 0xFFFF_FFFF,
            );
        }
    }

    mm::aspace::destroy(child_aspace);
    mm::aspace::destroy(parent_aspace);

    // Verify no swap slot leak: all slots allocated during the test
    // should be freed after both aspaces are destroyed.
    let slots_after = mm::swap::slots_in_use();
    assert_eq!(
        slots_after, slots_before,
        "swap cow: slot leak detected — {} slots before, {} after",
        slots_before, slots_after,
    );
    println!("  Swap COW fork data integrity test: PASSED (no slot leaks)");
}
