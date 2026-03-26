//! IRQ-to-userspace dispatch table.
//!
//! Allows userspace device drivers to wait for device IRQs via `sys_irq_wait`.
//! The kernel IRQ handler ACKs the virtio interrupt and wakes the waiting thread.
//!
//! The waiter table is page-allocated on first register() — no fixed IRQ limit.
//! Capacity = PAGE_SIZE / size_of::<IrqWaiter>() (e.g. 2730 at 64 KiB pages).

use core::sync::atomic::{AtomicU32, AtomicUsize, AtomicBool, AtomicPtr, Ordering};
use crate::mm::page::PAGE_SIZE;

struct IrqWaiter {
    /// Thread ID waiting for this IRQ, or 0 if none (thread 0 = idle, never waits).
    thread_id: AtomicU32,
    /// MMIO base for virtio interrupt ACK (kernel identity-mapped).
    mmio_base: AtomicUsize,
    /// IRQ fired but no waiter was blocked yet.
    pending: AtomicBool,
}

/// Page-allocated waiter table. Null until first register().
/// Initialized via CAS (lock-free one-shot init).
static IRQ_PAGE: AtomicPtr<IrqWaiter> = AtomicPtr::new(core::ptr::null_mut());

/// Number of IrqWaiter slots that fit in one page.
const fn irq_capacity() -> usize {
    PAGE_SIZE / core::mem::size_of::<IrqWaiter>()
}

/// Allocate and zero-initialize the IRQ waiter page if not yet done.
/// Returns the page pointer, or null on OOM.
fn ensure_init() -> *mut IrqWaiter {
    let ptr = IRQ_PAGE.load(Ordering::Acquire);
    if !ptr.is_null() {
        return ptr;
    }

    // Allocate and zero-init a page. Zero-init gives:
    //   thread_id = 0 (no waiter), mmio_base = 0 (not registered), pending = false.
    let page = match crate::mm::phys::alloc_page() {
        Some(pa) => pa.as_usize() as *mut IrqWaiter,
        None => return core::ptr::null_mut(),
    };
    unsafe {
        core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
    }

    // CAS: first writer wins, loser frees their page.
    match IRQ_PAGE.compare_exchange(
        core::ptr::null_mut(),
        page,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => page,
        Err(winner) => {
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(page as usize));
            winner
        }
    }
}

/// Get a reference to the waiter slot at `idx`, or None if table not initialized
/// or index out of range.
#[inline]
fn slot(idx: usize) -> Option<&'static IrqWaiter> {
    let ptr = IRQ_PAGE.load(Ordering::Acquire);
    if ptr.is_null() || idx >= irq_capacity() {
        return None;
    }
    Some(unsafe { &*ptr.add(idx) })
}

/// Normalize a platform IRQ number to a table index.
/// AArch64: INTID 48..79 → index 0..31. RISC-V: IRQ 1..8 → index 0..7.
fn normalize(irq: u32) -> usize {
    #[cfg(target_arch = "aarch64")]
    { (irq - 48) as usize }
    #[cfg(target_arch = "riscv64")]
    { (irq - 1) as usize }
    #[cfg(target_arch = "x86_64")]
    { irq as usize }
}

/// Register an IRQ for userspace dispatch (called from sys_irq_wait on first call).
/// Stores mmio_base for kernel-side virtio ACK and enables the IRQ.
/// Returns false on OOM (table page allocation failed).
pub fn register(irq: u32, mmio_base: usize) -> bool {
    let page = ensure_init();
    if page.is_null() {
        return false;
    }
    let idx = normalize(irq);
    if idx >= irq_capacity() {
        return false;
    }
    let slot = unsafe { &*page.add(idx) };
    slot.mmio_base.store(mmio_base, Ordering::Release);

    // Enable the IRQ in the platform interrupt controller.
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::irq::enable_interrupt(irq);
    }
    #[cfg(target_arch = "riscv64")]
    {
        let hart: u32;
        unsafe { core::arch::asm!("mv {0}, tp", out(reg) hart); }
        crate::arch::riscv64::plic::enable_irq(hart, irq);
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::pic::unmask(irq as u8);
    }
    true
}

/// Called from sys_irq_wait: block until the IRQ fires.
/// Returns 0 on success.
pub fn wait(irq: u32) -> u64 {
    let idx = normalize(irq);
    let slot = match slot(idx) {
        Some(s) => s,
        None => return u64::MAX,
    };

    // Check if IRQ already pending (lost-wakeup prevention).
    if slot.pending.swap(false, Ordering::Acquire) {
        return 0;
    }

    // Clear wakeup flag before storing tid (Phase 7 pattern).
    let tid = crate::sched::current_thread_id();
    crate::sched::clear_wakeup_flag(tid);
    slot.thread_id.store(tid, Ordering::Release);

    // Double-check pending after storing tid (lost-wakeup window).
    if slot.pending.swap(false, Ordering::Acquire) {
        slot.thread_id.store(0, Ordering::Release);
        return 0;
    }

    crate::sched::block_current(crate::sched::thread::BlockReason::None);

    // Woken up — clear our tid.
    slot.thread_id.store(0, Ordering::Release);
    0
}

/// Called from the kernel IRQ handler (in interrupt context).
/// ACKs the virtio interrupt and wakes any waiting thread.
/// Returns true if this IRQ was handled by userspace dispatch.
#[allow(dead_code)]
pub fn handle_irq(irq: u32) -> bool {
    let idx = normalize(irq);
    let slot = match slot(idx) {
        Some(s) => s,
        None => return false,
    };
    let mmio_base = slot.mmio_base.load(Ordering::Acquire);
    if mmio_base == 0 {
        return false; // Not registered for userspace dispatch.
    }

    // ACK the virtio interrupt (must happen in kernel/S-mode with identity map).
    #[cfg(not(target_arch = "x86_64"))]
    {
        let status = crate::drivers::virtio_mmio::read32(mmio_base, crate::drivers::virtio_mmio::INTERRUPT_STATUS);
        crate::drivers::virtio_mmio::write32(mmio_base, crate::drivers::virtio_mmio::INTERRUPT_ACK, status);
    }

    // Set pending and wake waiter.
    slot.pending.store(true, Ordering::Release);
    let tid = slot.thread_id.load(Ordering::Acquire);
    if tid != 0 {
        crate::sched::wake_thread(tid);
    }

    true
}
