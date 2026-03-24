#![no_std]
#![no_main]

mod arch;
mod cap;
mod drivers;
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
    {
        let mut caps = cap::CAP_SYSTEM.lock();
        caps.init();
    }
    println!("  Cap system initialized");

    // Capability system test (validates CDT/CNode logic).
    test_capabilities();

    // Scheduler.
    sched::init();
    sched::topology::init();

    // IPC test threads (Phase 1 — disabled for Phase 3 server testing).
    // let port = ipc::port::create().expect("create IPC port");
    // IPC_TEST_PORT.store(port, core::sync::atomic::Ordering::Relaxed);
    // sched::spawn(ipc_sender, 100, 10).expect("spawn sender");
    // sched::spawn(ipc_receiver, 100, 10).expect("spawn receiver");

    // Start secondary CPUs.
    println!("Starting secondary CPUs...");
    arch::platform::start_secondary_cpus();
    sched::topology::print();

    // Background page pre-zeroing daemon.
    sched::spawn(mm::zeropool::zero_daemon, 1, 5).expect("spawn zero_daemon");

    // Phase 2: Demand-paging test.
    println!("Testing demand-paged memory...");
    test_demand_paging();

    // Phase 3: I/O server stack.
    println!("Phase 3: Starting I/O servers...");

    // Name server (kernel thread) — must start first for service registration.
    sched::spawn(io::namesrv::namesrv_server, 50, 20).expect("spawn namesrv");
    // Wait for name server to be ready.
    while io::namesrv::NAMESRV_PORT.load(core::sync::atomic::Ordering::Acquire) == u32::MAX {
        core::hint::spin_loop();
    }

    sched::spawn(io::initramfs::initramfs_server, 50, 20).expect("spawn initramfs");
    // Virtio-blk driver — spawn as userspace process on AArch64 and RISC-V.
    // Pack mmio_base | (irq << 48) into arg0 for the driver.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        if let Some(base) = drivers::virtio_mmio::find_device(drivers::virtio_mmio::DEVICE_BLK) {
            #[cfg(target_arch = "aarch64")]
            let irq = {
                let dev_index = (base - 0x0a00_0000) / 0x200;
                48 + dev_index as u64 // GIC SPI INTID
            };
            #[cfg(target_arch = "riscv64")]
            let irq = match base {
                0x1000_8000 => 8u64,
                0x1000_7000 => 7,
                0x1000_6000 => 6,
                0x1000_5000 => 5,
                0x1000_4000 => 4,
                0x1000_3000 => 3,
                0x1000_2000 => 2,
                0x1000_1000 => 1,
                _ => 1,
            };
            let arg0 = (base as u64) | (irq << 48);
            println!("  virtio-blk at {:#x}, irq {}, spawning blk_srv with arg0={:#x}", base, irq, arg0);
            match sched::spawn_user(b"blk_srv", 50, 20, arg0) {
                Some(tid) => println!("  blk_srv spawned (thread {})", tid),
                None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
            }
        } else {
            println!("  no virtio-blk device found, skipping blk_srv");
        }
    }

    // Virtio-net driver — spawn as userspace process on AArch64 and RISC-V.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        if let Some(base) = drivers::virtio_mmio::find_device(drivers::virtio_mmio::DEVICE_NET) {
            #[cfg(target_arch = "aarch64")]
            let irq = {
                let dev_index = (base - 0x0a00_0000) / 0x200;
                48 + dev_index as u64
            };
            #[cfg(target_arch = "riscv64")]
            let irq = match base {
                0x1000_8000 => 8u64,
                0x1000_7000 => 7,
                0x1000_6000 => 6,
                0x1000_5000 => 5,
                0x1000_4000 => 4,
                0x1000_3000 => 3,
                0x1000_2000 => 2,
                0x1000_1000 => 1,
                _ => 1,
            };
            let arg0 = (base as u64) | (irq << 48);
            println!("  virtio-net at {:#x}, irq {}, spawning net_srv with arg0={:#x}", base, irq, arg0);
            match sched::spawn_user(b"net_srv", 50, 20, arg0) {
                Some(tid) => println!("  net_srv spawned (thread {})", tid),
                None => println!("  WARNING: net_srv not found (ok if not yet built)"),
            }
        } else {
            println!("  no virtio-net device found, skipping net_srv");
        }
    }

    // x86_64: Discover virtio devices via PCI bus scan.
    #[cfg(target_arch = "x86_64")]
    {
        println!("  Scanning PCI bus for virtio devices...");
        // virtio-blk-pci: device ID 0x1001
        if let Some(dev) = arch::x86_64::pci::find_virtio_device(0x1001) {
            let arg0 = (dev.bar0 as u64) | ((dev.irq as u64) << 48);
            match sched::spawn_user(b"blk_srv", 50, 20, arg0) {
                Some(tid) => println!("  blk_srv spawned (thread {})", tid),
                None => println!("  WARNING: blk_srv not found (ok if not yet built)"),
            }
        }
        // virtio-net-pci: device ID 0x1000
        if let Some(dev) = arch::x86_64::pci::find_virtio_device(0x1000) {
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
            let msg = ipc::Message::new(io::protocol::NS_REGISTER, [n0, n1, srv_port as u64, d3, 0, 0]);
            let _ = ipc::port::send(nsrv, msg);
            let _ = ipc::port::recv(reply_port); // wait for NS_REGISTER_OK
            ipc::port::destroy(reply_port);
        }

        match sched::spawn_user_with_data(
            b"initramfs_srv", 50, 20, cpio_data, 0x3_0000_0000, srv_port as u64,
        ) {
            Some(tid) => {
                // Grant SEND|RECV|MANAGE cap for the initramfs port to the new task.
                let task_id = sched::thread_task_id(tid);
                let mut caps = cap::CAP_SYSTEM.lock();
                caps.grant_full_port_cap(task_id, srv_port);
                drop(caps);
                println!("  initramfs_srv spawned (thread {}, port {})", tid, srv_port);
            }
            None => println!("  ERROR: failed to spawn initramfs_srv"),
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

    println!("Enabling interrupts");
    arch::platform::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    arch::platform::idle_loop()
}

use core::sync::atomic::{AtomicU32, Ordering};
#[allow(dead_code)]
static IPC_TEST_PORT: AtomicU32 = AtomicU32::new(0);

#[allow(dead_code)]
fn ipc_sender() -> ! {
    let port_id = IPC_TEST_PORT.load(Ordering::Relaxed);
    let mut seq = 0u64;
    loop {
        let msg = ipc::Message::new(1, [seq, 0, 0, 0, 0, 0]);
        // Blocking send — blocks if the queue is full.
        match ipc::port::send(port_id, msg) {
            Ok(()) => {
                if seq % 10 == 0 {
                    println!("[sender] sent seq={}", seq);
                }
                seq += 1;
            }
            Err(()) => break,
        }
    }
    loop { core::hint::spin_loop(); }
}

#[allow(dead_code)]
fn ipc_receiver() -> ! {
    let port_id = IPC_TEST_PORT.load(Ordering::Relaxed);
    let mut received = 0u64;
    loop {
        // Blocking recv — blocks until a message arrives.
        match ipc::port::recv(port_id) {
            Ok(msg) => {
                if received % 10 == 0 {
                    println!("[receiver] got tag={} seq={}", msg.tag, msg.data[0]);
                }
                received += 1;
            }
            Err(()) => break,
        }
    }
    loop { core::hint::spin_loop(); }
}

fn test_capabilities() {
    use cap::{Capability, CapType, Rights, CapSpace, Cdt};
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
        println!("  Cap test: server has {:?} at slot {}", server_space.lookup(server_slot).unwrap(), server_slot);

        let mut client_space = CapSpace::new(1);
        let client_slot = server_space.derive_to(
            server_slot, Rights::SEND, &mut client_space, &mut cdt,
        ).unwrap();
        println!("  Cap test: client has {:?} at slot {}", client_space.lookup(client_slot).unwrap(), client_slot);

        let mut client2_space = CapSpace::new(2);
        let client2_slot = server_space.derive_to(
            server_slot, Rights::SEND.union(Rights::GRANT), &mut client2_space, &mut cdt,
        ).unwrap();
        println!("  Cap test: client2 has {:?} at slot {}", client2_space.lookup(client2_slot).unwrap(), client2_slot);

        let revoked = server_space.revoke(server_slot, &mut cdt);
        println!("  Cap test: revoked {} derived capabilities", revoked);
        println!("  Cap test: server still has {:?}", server_space.lookup(server_slot).unwrap());
    }
    println!("  Cap test: PASSED");
}

// --- AArch64-specific tests ---

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
fn test_userspace_aarch64() {
    use arch::aarch64::mm;
    use arch::aarch64::usertest;

    println!("  Setting up page tables...");

    let l0 = mm::setup_tables().expect("page tables");
    println!("  L0 table at {:#x}", l0);

    let user_code_page = crate::mm::phys::alloc_page().expect("user code page");
    let user_code_phys = user_code_page.as_usize();
    unsafe {
        core::ptr::copy_nonoverlapping(
            usertest::USER_CODE.as_ptr(),
            user_code_phys as *mut u8,
            usertest::USER_CODE.len(),
        );
    }

    let user_stack_page = crate::mm::phys::alloc_page().expect("user stack page");
    let user_stack_phys = user_stack_page.as_usize();

    let user_code_virt: usize = 0x8000_0000;
    let user_stack_virt: usize = 0x8001_0000;

    mm::map_user_pages(l0, user_code_virt, user_code_phys,
        usertest::USER_CODE.len(), mm::USER_RWX_FLAGS).expect("map user code");
    mm::map_user_pages(l0, user_stack_virt, user_stack_phys,
        4096, mm::USER_RW_FLAGS).expect("map user stack");
    println!("  User mappings: code at {:#x}, stack at {:#x}", user_code_virt, user_stack_virt);

    println!("  Enabling MMU...");
    mm::enable_mmu(l0);
    println!("  MMU enabled — identity mapping active");

    println!("  Jumping to EL0...");
    let user_sp = user_stack_virt + 4096;
    unsafe {
        core::arch::asm!(
            "msr sp_el0, {sp}",
            "msr elr_el1, {pc}",
            "mov x0, #0",
            "msr spsr_el1, x0",
            "eret",
            sp = in(reg) user_sp as u64,
            pc = in(reg) user_code_virt as u64,
            options(noreturn),
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
fn test_syscalls_aarch64() {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "mov x8, #0", "mov x0, #0x53", "svc #0",
            out("x0") ret, out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        );
    }
    println!("");
    println!("  Syscall test: debug_putchar returned {}", ret);

    let tid: u64;
    unsafe {
        core::arch::asm!(
            "mov x8, #8", "svc #0",
            out("x0") tid, out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        );
    }
    println!("  Syscall test: thread_id={}", tid);
    println!("  Syscall test: PASSED");
}

// --- RISC-V specific tests ---

#[cfg(target_arch = "riscv64")]
#[allow(dead_code)]
fn test_userspace_riscv64() {
    use arch::riscv64::mm;
    use arch::riscv64::usertest;

    println!("  Setting up Sv39 page tables...");

    let root = mm::setup_tables().expect("page tables");
    println!("  Root table at {:#x}", root);

    let user_code = usertest::user_code();
    let user_code_page = crate::mm::phys::alloc_page().expect("user code page");
    let user_code_phys = user_code_page.as_usize();
    unsafe {
        core::ptr::copy_nonoverlapping(
            user_code.as_ptr(),
            user_code_phys as *mut u8,
            user_code.len(),
        );
    }

    let user_stack_page = crate::mm::phys::alloc_page().expect("user stack page");
    let user_stack_phys = user_stack_page.as_usize();

    // User virtual addresses (in VPN[2]=1 range, avoiding kernel gigapage regions).
    let user_code_virt: usize = 0x4000_0000;
    let user_stack_virt: usize = 0x4001_0000;

    mm::map_user_pages(root, user_code_virt, user_code_phys,
        user_code.len(), mm::USER_RWX_FLAGS).expect("map user code");
    mm::map_user_pages(root, user_stack_virt, user_stack_phys,
        4096, mm::USER_RW_FLAGS).expect("map user stack");
    println!("  User mappings: code at {:#x}, stack at {:#x}", user_code_virt, user_stack_virt);

    println!("  Enabling Sv39 MMU...");
    mm::enable_mmu(root);
    println!("  MMU enabled — identity mapping active");

    // Re-arm timer so it doesn't fire immediately when SPIE enables interrupts.
    arch::riscv64::trap::rearm_timer();

    println!("  Jumping to U-mode...");
    let user_sp = user_stack_virt + 4096;
    unsafe {
        core::arch::asm!(
            // Set sstatus.SPP = 0 (return to U-mode), SPIE = 1.
            "li t0, (1 << 8)",       // SPP bit
            "csrc sstatus, t0",
            "li t0, (1 << 5)",       // SPIE bit
            "csrs sstatus, t0",
            // Set sepc = user code entry point.
            "csrw sepc, {pc}",
            // Save kernel sp in sscratch for trap entry from U-mode.
            "csrw sscratch, sp",
            // Set user stack pointer.
            "mv sp, {sp}",
            "sret",
            pc = in(reg) user_code_virt,
            sp = in(reg) user_sp,
            options(noreturn),
        );
    }
}

// --- x86-64 specific tests ---

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
fn test_syscalls_x86_64() {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, 0", "mov rdi, 0x53", "int 0x80",
            out("rax") ret,
            out("rdi") _, out("rsi") _, out("rdx") _,
            out("rcx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
        );
    }
    println!("");
    println!("  Syscall test: debug_putchar returned {}", ret);

    let tid: u64;
    unsafe {
        core::arch::asm!(
            "mov rax, 8", "int 0x80",
            out("rax") tid,
            out("rdi") _, out("rsi") _, out("rdx") _,
            out("rcx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
        );
    }
    println!("  Syscall test: thread_id={}", tid);
    println!("  Syscall test: PASSED");
}

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
fn test_userspace_x86_64() {
    use arch::x86_64::{mm, usertest, gdt};

    println!("  Setting up user page tables...");

    let pml4 = mm::setup_tables().expect("page tables");
    println!("  PML4 at {:#x}", pml4);

    let user_code = usertest::user_code();
    let user_code_page = crate::mm::phys::alloc_page().expect("user code page");
    let user_code_phys = user_code_page.as_usize();
    unsafe {
        core::ptr::copy_nonoverlapping(
            user_code.as_ptr(),
            user_code_phys as *mut u8,
            user_code.len(),
        );
    }

    let user_stack_page = crate::mm::phys::alloc_page().expect("user stack page");
    let user_stack_phys = user_stack_page.as_usize();

    // User virtual addresses at PML4 index 1 (VA >= 0x80_0000_0000).
    let user_code_virt: usize = 0x80_0000_0000;
    let user_stack_virt: usize = 0x80_0001_0000;

    mm::map_user_pages(pml4, user_code_virt, user_code_phys,
        user_code.len(), mm::USER_RWX_FLAGS).expect("map user code");
    mm::map_user_pages(pml4, user_stack_virt, user_stack_phys,
        4096, mm::USER_RW_FLAGS).expect("map user stack");
    println!("  User mappings: code at {:#x}, stack at {:#x}", user_code_virt, user_stack_virt);

    // Flush TLB with the new mappings.
    mm::enable_mmu(pml4);
    println!("  Page tables updated");

    // Set the kernel RSP0 in TSS for ring 3 → ring 0 transitions.
    let kernel_rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) kernel_rsp); }
    gdt::set_rsp0(kernel_rsp);

    println!("  Jumping to ring 3...");
    let user_sp = user_stack_virt + 4096;
    let user_cs = (gdt::USER_CS as u64) | 3; // RPL = 3
    let user_ss = (gdt::USER_DS as u64) | 3; // RPL = 3
    unsafe {
        core::arch::asm!(
            "push {ss}",      // SS
            "push {sp}",      // RSP
            "pushfq",         // RFLAGS (with IF set)
            "push {cs}",      // CS
            "push {ip}",      // RIP
            "iretq",
            ss = in(reg) user_ss,
            sp = in(reg) user_sp as u64,
            cs = in(reg) user_cs,
            ip = in(reg) user_code_virt as u64,
            options(noreturn),
        );
    }
}

// --- Phase 2: Demand paging test ---

fn test_demand_paging() {
    use mm::page::{PAGE_SIZE, MMUPAGE_SIZE, PAGE_MMUCOUNT};
    use mm::vma::VmaProt;

    // Get the current page table root.
    #[cfg(target_arch = "aarch64")]
    let pt_root = {
        let cr: u64;
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) cr); }
        let root = cr as usize;
        if root == 0 {
            // MMU not yet enabled — allocate a fresh page table root for the test.
            let pa = mm::phys::alloc_page().expect("alloc pt root");
            unsafe { core::ptr::write_bytes(pa.as_usize() as *mut u8, 0, mm::page::MMUPAGE_SIZE); }
            pa.as_usize()
        } else {
            root
        }
    };
    #[cfg(target_arch = "riscv64")]
    let pt_root = {
        // Always use a fresh page table root for user demand paging tests.
        // The kernel root has gigapage leaves (device at root[0], RAM at root[2])
        // which block get_or_create_table from subdividing into 4K page tables.
        let pa = mm::phys::alloc_page().expect("alloc pt root");
        unsafe { core::ptr::write_bytes(pa.as_usize() as *mut u8, 0, mm::page::MMUPAGE_SIZE); }
        pa.as_usize()
    };
    #[cfg(target_arch = "x86_64")]
    let pt_root = {
        let cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3); }
        (cr3 & !0xFFF) as usize
    };

    let aspace_id = mm::aspace::create(pt_root).expect("create aspace");
    println!("  Created address space {}", aspace_id);

    // Map 4 allocation pages of anonymous memory (lazy — no PTEs installed).
    // Use a high VA to avoid conflicting with kernel identity mapping.
    // L0 index 1 = VA 0x80_0000_0000 onwards (not used by kernel).
    let test_va = 0x80_0000_0000usize;
    let num_pages = 4;
    mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace.map_anon(test_va, num_pages, VmaProt::ReadWrite)
            .expect("map_anon");
        println!("  Mapped {} pages at VA {:#x}", num_pages, test_va);

        assert_eq!(mm::fault::count_installed_ptes(pt_root, vma), 0);
        assert_eq!(vma.page_count(), num_pages);
        assert_eq!(vma.mmu_page_count(), num_pages * PAGE_MMUCOUNT);
    });

    // Simulate demand faults by calling handle_page_fault directly.
    let test_addrs = [
        test_va,
        test_va + MMUPAGE_SIZE,
        test_va + PAGE_SIZE,
        test_va + 2 * PAGE_SIZE + 3 * MMUPAGE_SIZE,
    ];

    for &addr in &test_addrs {
        println!("  Faulting at {:#x}...", addr);
        let result = mm::fault::handle_page_fault(
            aspace_id, addr, mm::fault::FaultType::Write,
        );
        println!("  Result: {:?}", result);
        // With background pre-zeroing, a sub-page in the same allocation page
        // as a prior major fault may be minor (already zeroed + resident).
        assert!(
            result == mm::fault::FaultResult::HandledMajor
                || result == mm::fault::FaultResult::HandledMinor,
            "Expected major or minor fault at {:#x}, got {:?}", addr, result
        );
    }

    mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace.find_vma(test_va).unwrap();
        let count = mm::fault::count_installed_ptes(pt_root, vma);
        assert_eq!(count, test_addrs.len());
        println!("  {} PTEs installed after {} major faults", count, test_addrs.len());
    });

    // Test minor fault: evict PTE (preserves SW_ZEROED), re-fault.
    mm::fault::evict_mmupage_dispatch(pt_root, test_va);

    let result = mm::fault::handle_page_fault(
        aspace_id, test_va, mm::fault::FaultType::Read,
    );
    assert!(
        result == mm::fault::FaultResult::HandledMinor,
        "Expected minor fault, got {:?}", result
    );
    println!("  Minor fault test: PASSED");

    // AArch64 contiguous PTE promotion test: fault all 16 MMU pages in the
    // first 64K-aligned contiguous group. The contiguous hint requires all 16
    // consecutive 4K L3 PTEs to be installed.
    #[cfg(target_arch = "aarch64")]
    {
        const CONTIG_GROUP: usize = 16; // 16 × 4K = 64K, AArch64 architecture constant
        let promotions_before = mm::stats::CONTIGUOUS_PROMOTIONS.load(core::sync::atomic::Ordering::Relaxed);
        // We already faulted mmu_idx 0 and 1 (test_va and test_va+4K). Fault the rest of the group.
        for i in 2..CONTIG_GROUP {
            let addr = test_va + i * MMUPAGE_SIZE;
            let result = mm::fault::handle_page_fault(
                aspace_id, addr, mm::fault::FaultType::Write,
            );
            assert!(
                result == mm::fault::FaultResult::HandledMajor
                    || result == mm::fault::FaultResult::HandledMinor,
                "Expected major/minor fault at {:#x}, got {:?}", addr, result
            );
        }
        let promotions_after = mm::stats::CONTIGUOUS_PROMOTIONS.load(core::sync::atomic::Ordering::Relaxed);
        let promoted = promotions_after - promotions_before;
        println!("  Contiguous PTE promotions: {} (expected 1)", promoted);
        assert!(promoted >= 1, "Expected at least 1 contiguous promotion, got {}", promoted);
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
        println!("  WSCLOCK pass 1: scanned={}, cleared={}, freed={}",
            scan1.pages_scanned, scan1.ptes_cleared, scan1.pages_freed);

        // Pass 2: pages not re-accessed since pass 1 have ref bit clear → evict.
        let scan2 = mm::wsclock::scan(aspace_id, 100);
        println!("  WSCLOCK pass 2: scanned={}, cleared={}, freed={}",
            scan2.pages_scanned, scan2.ptes_cleared, scan2.pages_freed);

        let installed_after = mm::aspace::with_aspace(aspace_id, |aspace| {
            let vma = aspace.find_vma(test_va).unwrap();
            mm::fault::count_installed_ptes(pt_root, vma)
        });
        println!("  WSCLOCK: {} PTEs installed after scan", installed_after);
        assert_eq!(installed_after, 0, "All PTEs should be cleared");
        let total_freed = scan1.pages_freed + scan2.pages_freed;
        assert!(total_freed > 0, "Should have freed at least 1 allocation page");

        // Re-fault the first address — should be a major fault since the page was freed.
        let result = mm::fault::handle_page_fault(
            aspace_id, test_va, mm::fault::FaultType::Write,
        );
        assert!(
            result == mm::fault::FaultResult::HandledMajor,
            "Expected major fault after reclaim, got {:?}", result
        );
        println!("  WSCLOCK re-fault after reclaim: PASSED");
    }

    mm::stats::print();

    mm::aspace::destroy(aspace_id);
    println!("  Demand paging test: PASSED");
}

// --- Phase 3: I/O test client ---

#[allow(dead_code)]
fn test_io_client() -> ! {
    use io::protocol::*;

    // Wait for initramfs server to be ready.
    let initramfs_port = loop {
        let p = io::initramfs::INITRAMFS_PORT.load(Ordering::Acquire);
        if p != u32::MAX {
            break p;
        }
        core::hint::spin_loop();
    };
    println!("  [io-test] initramfs server on port {}", initramfs_port);

    // Create a reply port for receiving responses.
    let reply_port = ipc::port::create().expect("reply port");

    // Step 1: Connect to open "hello.txt".
    let filename = b"hello.txt";
    let (n0, n1, n2) = pack_name(filename);
    let connect_msg = ipc::Message::new(IO_CONNECT, [
        n0, n1, n2,
        filename.len() as u64,
        reply_port as u64,
        0,
    ]);
    ipc::port::send(initramfs_port, connect_msg).expect("send connect");

    let reply = ipc::port::recv(reply_port).expect("recv connect reply");
    assert!(reply.tag == IO_CONNECT_OK, "connect failed: tag={:#x}", reply.tag);
    let file_handle = reply.data[0];
    let file_size = reply.data[1];
    println!("  [io-test] opened hello.txt: handle={}, size={} bytes", file_handle, file_size);

    // Step 2: Read the file contents (inline, for small files).
    let read_msg = ipc::Message::new(IO_READ, [
        file_handle,
        0,              // offset
        file_size,      // length
        reply_port as u64,
        0, 0,
    ]);
    ipc::port::send(initramfs_port, read_msg).expect("send read");

    let reply = ipc::port::recv(reply_port).expect("recv read reply");
    assert!(reply.tag == IO_READ_OK, "read failed: tag={:#x}", reply.tag);
    let bytes_read = reply.data[0] as usize;

    // Unpack inline data from reply words.
    let mut buf = [0u8; MAX_INLINE_READ];
    let words = [reply.data[1], reply.data[2], reply.data[3], reply.data[4], reply.data[5]];
    for i in 0..bytes_read.min(MAX_INLINE_READ) {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    let text = core::str::from_utf8(&buf[..bytes_read]).unwrap_or("<invalid utf8>");
    println!("  [io-test] read {} bytes: {}", bytes_read, text);

    // Step 3: Close.
    let close_msg = ipc::Message::new(IO_CLOSE, [file_handle, 0, 0, 0, 0, 0]);
    let _ = ipc::port::send_nb(initramfs_port, close_msg);

    // Step 4: Test virtio-blk (AArch64/RISC-V only).
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        // Wait briefly for blk server. If no virtio device, skip.
        let mut tries = 0u32;
        let blk_port = loop {
            let p = io::blk_server::BLK_PORT.load(Ordering::Acquire);
            if p != u32::MAX {
                break Some(p);
            }
            tries += 1;
            if tries > 100_000 {
                break None;
            }
            core::hint::spin_loop();
        };
        let blk_port = match blk_port {
            Some(p) => p,
            None => {
                println!("  [io-test] no blk server, skipping block test");
                println!("  Phase 3 I/O test: PASSED");
                loop { core::hint::spin_loop(); }
            }
        };
        println!("  [io-test] blk server on port {}", blk_port);

        // Read sector 0.
        let read_msg = ipc::Message::new(IO_READ, [
            0,              // handle (unused for blk)
            0,              // offset = sector 0
            512,            // length
            reply_port as u64,
            0, 0,
        ]);
        ipc::port::send(blk_port, read_msg).expect("send blk read");

        let reply = ipc::port::recv(reply_port).expect("recv blk reply");
        if reply.tag == IO_READ_OK {
            println!("  [io-test] blk read sector 0: {} bytes, first word = {:#x}",
                reply.data[0], reply.data[1]);
        } else {
            println!("  [io-test] blk read error: tag={:#x} code={}", reply.tag, reply.data[0]);
        }
    }

    println!("  Phase 3 I/O test: PASSED");
    loop { core::hint::spin_loop(); }
}
