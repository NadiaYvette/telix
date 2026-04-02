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
    println!("KERNEL PANIC: {}", info);
    loop {
        core::hint::spin_loop();
    }
}

pub fn kmain() -> ! {
    println!("Telix kernel initializing...");

    // Platform init: exceptions, interrupt controller, timer.
    arch::platform::init();

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

    // Physical memory allocator.
    // Start managed RAM at kernel_end so the allocator never touches
    // firmware (OpenSBI) or kernel image pages — its bitmap metadata
    // is written into pages within the managed range, which must be free.
    let (_ram_start, ram_end) = arch::platform::ram_range();
    let kernel_end = arch::platform::kernel_end_addr();
    mm::phys::init(kernel_end, ram_end, kernel_end, kernel_end);

    // Enable MMU: set up kernel identity-mapped page tables.
    // Must happen before secondary CPU startup (they need the page table root).
    arch::platform::enable_mmu();

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

    // Scheduler.
    sched::init();
    sched::topology::init();

    // Start secondary CPUs.
    println!("Starting secondary CPUs...");
    arch::platform::start_secondary_cpus();
    sched::topology::print();

    // Background page pre-zeroing daemon.
    sched::spawn(mm::zeropool::zero_daemon, 1, 5).expect("spawn zero_daemon");

    // Phase 2: Demand-paging test.
    println!("Testing demand-paged memory...");
    test_demand_paging();

    // Phase 3+4 run in a dedicated kernel thread so the BSP can enter the idle
    // loop immediately. On single-CPU, the idle loop is needed so the scheduler
    // can preempt it to run the startup thread and other kernel threads.
    // Priority 60 is lower than spawned servers (50) so they can run during waits.
    sched::spawn(startup_thread, 60, 20).expect("spawn startup");

    println!("Enabling interrupts");
    arch::platform::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    arch::platform::idle_loop()
}

/// Kernel startup thread: spawns I/O servers and userspace processes.
/// Runs as a normal kernel thread (not the idle thread) so the scheduler
/// can preempt between it and the threads it spawns — critical for single-CPU.
fn startup_thread() -> ! {
    // Phase 3: I/O server stack.
    println!("Phase 3: Starting I/O servers...");

    // Name server (kernel thread) — must start first for service registration.
    sched::spawn(io::namesrv::namesrv_server, 50, 20).expect("spawn namesrv");
    // Wait for name server to be ready. block_current demotes our priority
    // to 254, so namesrv (prio 50) gets scheduled to complete initialization.
    while io::namesrv::NAMESRV_PORT.load(core::sync::atomic::Ordering::Acquire) == u64::MAX {
        // Fake a block so we yield to namesrv. wake_thread won't be called
        // for us, but we'll break out when NAMESRV_PORT changes.
        // Use set_yield_asap + WFI instead of block_current to avoid needing
        // a wakeup signal.
        let my_tid = sched::current_thread_id();
        sched::scheduler::set_yield_asap(my_tid);
        sched::scheduler::arch_wait_for_irq();
    }

    sched::spawn(io::initramfs::initramfs_server, 50, 20).expect("spawn initramfs");

    // Discover and spawn virtio-mmio device servers.
    // Uses firmware-discovered devices (from DTB) with hardcoded fallback.
    // On x86_64 find_device returns None (no MMIO transport), so these are no-ops.
    if let Some(base) = drivers::virtio_mmio::find_device(drivers::virtio_mmio::DEVICE_BLK) {
        let irq = drivers::virtio_mmio::device_irq(base) as u64;
        let arg0 = (base as u64) | (irq << 48);
        println!(
            "  virtio-blk at {:#x}, irq {}, spawning blk_srv with arg0={:#x}",
            base, irq, arg0
        );
        match sched::spawn_user(b"blk_srv", 50, 20, arg0) {
            Some(tid) => println!("  blk_srv spawned (thread {})", tid),
            None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
        }
    }

    if let Some(base) = drivers::virtio_mmio::find_device(drivers::virtio_mmio::DEVICE_NET) {
        let irq = drivers::virtio_mmio::device_irq(base) as u64;
        let arg0 = (base as u64) | (irq << 48);
        println!(
            "  virtio-net at {:#x}, irq {}, spawning net_srv with arg0={:#x}",
            base, irq, arg0
        );
        match sched::spawn_user(b"net_srv", 50, 20, arg0) {
            Some(tid) => println!("  net_srv spawned (thread {})", tid),
            None => println!("  WARNING: net_srv not found (ok if not yet built)"),
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
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"net_srv", 50, 20, arg0) {
                Some(tid) => println!("  net_srv spawned (thread {})", tid),
                None => println!("  WARNING: net_srv not found (ok if not yet built)"),
            }
        }
        // Probe BochsVBE (QEMU -vga std) and set up framebuffer info.
        arch::x86_64::pci::probe_bochs_vbe();
        // Spawn fb_srv: arg0=0 means no virtio-gpu, use VBE fallback.
        match sched::spawn_user(b"fb_srv", 50, 20, 0) {
            Some(tid) => println!("  fb_srv spawned (thread {})", tid),
            None => println!("  WARNING: fb_srv not found (ok if not yet built)"),
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
            match sched::spawn_user(b"net_srv", 50, 20, arg0) {
                Some(tid) => println!("  net_srv spawned (thread {})", tid),
                None => println!("  WARNING: net_srv not found (ok if not yet built)"),
            }
        }
    }

    // LoongArch64: Discover virtio devices via PCI ECAM scan.
    #[cfg(target_arch = "loongarch64")]
    {
        println!("  Scanning PCI bus for virtio devices (ECAM)...");
        if let Some(dev) = arch::loongarch64::pci::find_virtio_device(0x1001) {
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"blk_srv", 50, 20, arg0) {
                Some(tid) => println!("  blk_srv spawned (thread {})", tid),
                None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
            }
        }
        if let Some(dev) = arch::loongarch64::pci::find_virtio_device(0x1000) {
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"net_srv", 50, 20, arg0) {
                Some(tid) => println!("  net_srv spawned (thread {})", tid),
                None => println!("  WARNING: net_srv not found (ok if not yet built)"),
            }
        }
    }

    // Phase 4: Spawning init process...
    println!("Phase 4: Spawning init process...");

    // Spawn userspace initramfs server with CPIO data mapped at 0x3_0000_0000.
    {
        use core::sync::atomic::Ordering;
        let cpio_data: &[u8] = include_bytes!("io/initramfs.cpio");
        let srv_port = ipc::port::create().expect("initramfs_srv port");
        io::initramfs::USER_INITRAMFS_PORT.store(srv_port, Ordering::Release);

        // Register initramfs with name server.
        {
            let nsrv = io::namesrv::NAMESRV_PORT.load(Ordering::Acquire);
            let (n0, n1, _n2) = io::protocol::pack_name(b"initramfs");
            let name_len = 9u64;
            let reply_port = ipc::port::create().expect("reg reply port");
            let d3 = name_len | ((reply_port as u64) << 32);
            let msg = ipc::Message::new(
                io::protocol::NS_REGISTER,
                [n0, n1, srv_port as u64, d3, 0, 0],
            );
            let _ = ipc::port::send(nsrv, msg);
            let _ = ipc::port::recv(reply_port); // wait for NS_REGISTER_OK
            ipc::port::destroy(reply_port);
        }

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

        // Register rootfs with name server.
        {
            let nsrv = io::namesrv::NAMESRV_PORT.load(Ordering::Acquire);
            let (n0, n1, _n2) = io::protocol::pack_name(b"rootfs");
            let name_len = 6u64;
            let reply_port = ipc::port::create().expect("reg reply port");
            let d3 = name_len | ((reply_port as u64) << 32);
            let msg = ipc::Message::new(
                io::protocol::NS_REGISTER,
                [n0, n1, srv_port as u64, d3, 0, 0],
            );
            let _ = ipc::port::send(nsrv, msg);
            let _ = ipc::port::recv(reply_port); // wait for NS_REGISTER_OK
            ipc::port::destroy(reply_port);
        }

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

    // Spawn FAT16 filesystem server (userspace, connects to cache_srv via IPC).
    match sched::spawn_user(b"fat16_srv", 50, 20, 0) {
        Some(tid) => println!("  fat16_srv spawned (thread {})", tid),
        None => println!("  WARNING: fat16_srv not found (ok if not yet built)"),
    }

    // Spawn ext2 filesystem server (partition starts at byte 16 MiB in test.img).
    match sched::spawn_user(b"ext2_srv", 50, 20, 16 * 1024 * 1024) {
        Some(tid) => println!("  ext2_srv spawned (thread {})", tid),
        None => println!("  WARNING: ext2_srv not found (ok if not yet built)"),
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
            core::ptr::write_bytes(pa.as_usize() as *mut u8, 0, mm::page::MMUPAGE_SIZE);
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
        println!("  WSCLOCK re-fault after reclaim: PASSED");
    }

    mm::stats::print();

    mm::aspace::destroy(aspace_id);
    println!("  Demand paging test: PASSED");
}
