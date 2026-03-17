//! IRQ-to-userspace dispatch table.
//!
//! Allows userspace device drivers to wait for device IRQs via `sys_irq_wait`.
//! The kernel IRQ handler ACKs the virtio interrupt and wakes the waiting thread.

use core::sync::atomic::{AtomicU32, AtomicUsize, AtomicBool, Ordering};

const MAX_IRQS: usize = 32;

struct IrqWaiter {
    /// Thread ID waiting for this IRQ, or u32::MAX if none.
    thread_id: AtomicU32,
    /// MMIO base for virtio interrupt ACK (kernel identity-mapped).
    mmio_base: AtomicUsize,
    /// IRQ fired but no waiter was blocked yet.
    pending: AtomicBool,
}

impl IrqWaiter {
    const fn new() -> Self {
        Self {
            thread_id: AtomicU32::new(u32::MAX),
            mmio_base: AtomicUsize::new(0),
            pending: AtomicBool::new(false),
        }
    }
}

/// One waiter slot per IRQ number (indices 0..31).
static IRQ_WAITERS: [IrqWaiter; MAX_IRQS] = {
    // const array init
    const NEW: IrqWaiter = IrqWaiter::new();
    [NEW; MAX_IRQS]
};

/// Normalize a platform IRQ number to a table index (0..MAX_IRQS-1).
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
pub fn register(irq: u32, mmio_base: usize) {
    let idx = normalize(irq);
    let slot = &IRQ_WAITERS[idx];
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
}

/// Called from sys_irq_wait: block until the IRQ fires.
/// Returns 0 on success.
pub fn wait(irq: u32) -> u64 {
    let idx = normalize(irq);
    let slot = &IRQ_WAITERS[idx];

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
        slot.thread_id.store(u32::MAX, Ordering::Release);
        return 0;
    }

    crate::sched::block_current(crate::sched::thread::BlockReason::None);

    // Woken up — clear our tid.
    slot.thread_id.store(u32::MAX, Ordering::Release);
    0
}

/// Called from the kernel IRQ handler (in interrupt context).
/// ACKs the virtio interrupt and wakes any waiting thread.
/// Returns true if this IRQ was handled by userspace dispatch.
#[allow(dead_code)]
pub fn handle_irq(irq: u32) -> bool {
    let idx = normalize(irq);
    if idx >= MAX_IRQS {
        return false;
    }
    let slot = &IRQ_WAITERS[idx];
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
    if tid != u32::MAX {
        crate::sched::wake_thread(tid);
    }

    true
}
