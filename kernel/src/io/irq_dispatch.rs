//! IRQ-to-userspace dispatch table.
//!
//! Two delivery modes are supported per IRQ:
//!
//! 1. **Thread-based** (legacy `sys_irq_wait`): a single driver thread blocks
//!    on the IRQ; the kernel handler ACKs the device and wakes the thread.
//!
//! 2. **Port-based** (`SYS_IRQ_ATTACH`): the driver registers a destination
//!    port; the kernel handler ACKs the device and queues an `IRQ_MSG` to
//!    that port via [`crate::ipc::port::send_from_kernel`]. The driver
//!    receives the message through its normal port-set wait loop, alongside
//!    client requests and device-manager commands. This is the model the
//!    driver_model.md design hangs on; legacy `sys_irq_wait` is kept working
//!    until the last consumer migrates.
//!
//! The waiter table is page-allocated on first register() — no fixed IRQ limit.
//! Capacity = page_size() / size_of::<IrqWaiter>() (e.g. ~1820 at 64 KiB pages).

use crate::ipc::Message;
use crate::ipc::port::PortId;
use crate::mm::page;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Message tag for IRQ-as-message delivery.
/// `data[0]` = IRQ number, `data[1]` = cycle timestamp at delivery.
pub const IRQ_MSG_TAG: u64 = 0x4000;

struct IrqWaiter {
    /// Thread ID waiting for this IRQ, or 0 if none (thread 0 = idle, never waits).
    thread_id: AtomicU32,
    /// MMIO base for virtio interrupt ACK (kernel identity-mapped).
    mmio_base: AtomicUsize,
    /// IRQ fired but no waiter was blocked yet.
    pending: AtomicBool,
    /// Destination port for port-based IRQ delivery, or 0 if not bound.
    /// When non-zero, `handle_irq` queues an `IRQ_MSG` message instead of
    /// (or in addition to) waking `thread_id`.
    port_id: AtomicU64,
}

/// Page-allocated waiter table. Null until first register().
/// Initialized via CAS (lock-free one-shot init).
static IRQ_PAGE: AtomicPtr<IrqWaiter> = AtomicPtr::new(core::ptr::null_mut());

/// Number of IrqWaiter slots that fit in one page.
fn irq_capacity() -> usize {
    page::page_size() / core::mem::size_of::<IrqWaiter>()
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
        core::ptr::write_bytes(page as *mut u8, 0, page::page_size());
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
            crate::mm::phys::free_page(page::PhysAddr::new(page as usize));
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
fn normalize(irq: u32) -> usize {
    crate::arch::irq::normalize_irq(irq)
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
    crate::arch::irq::enable_device_irq(irq);
    true
}

/// Bind an IRQ to a destination port for message-based delivery.
///
/// On every fire, `handle_irq` will ACK the device (if `mmio_base != 0`)
/// and queue an `IRQ_MSG` to `port_id`. Replaces any previous port binding
/// on the same IRQ. Pass `mmio_base = 0` to skip the kernel-side virtio ACK
/// (e.g. for non-virtio devices that the driver ACKs itself).
///
/// Returns false on OOM or out-of-range IRQ.
pub fn attach_port(irq: u32, port_id: PortId, mmio_base: usize) -> bool {
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
    slot.port_id.store(port_id, Ordering::Release);
    crate::arch::irq::enable_device_irq(irq);
    true
}

/// Detach a previously-bound port from an IRQ. Subsequent IRQs revert to
/// the legacy thread-based path (or are dropped if no thread waits).
pub fn detach_port(irq: u32) -> bool {
    let idx = normalize(irq);
    let slot = match slot(idx) {
        Some(s) => s,
        None => return false,
    };
    slot.port_id.store(0, Ordering::Release);
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
/// ACKs the device (virtio MMIO) and dispatches the IRQ to either a
/// port-based listener (`attach_port`) or a legacy blocked thread
/// (`sys_irq_wait`). Returns true if this IRQ had a registered listener.
#[allow(dead_code)]
pub fn handle_irq(irq: u32) -> bool {
    let idx = normalize(irq);
    let slot = match slot(idx) {
        Some(s) => s,
        None => return false,
    };
    let mmio_base = slot.mmio_base.load(Ordering::Acquire);
    let port_id = slot.port_id.load(Ordering::Acquire);
    if mmio_base == 0 && port_id == 0 {
        return false; // Not registered for userspace dispatch.
    }

    // ACK the virtio interrupt (must happen in kernel/S-mode with identity map).
    if mmio_base != 0 {
        #[cfg(not(target_arch = "x86_64"))]
        {
            let status = crate::drivers::virtio_mmio::read32(
                mmio_base,
                crate::drivers::virtio_mmio::INTERRUPT_STATUS,
            );
            crate::drivers::virtio_mmio::write32(
                mmio_base,
                crate::drivers::virtio_mmio::INTERRUPT_ACK,
                status,
            );
        }
    }

    // Port-based dispatch: queue an IRQ message. Safe to call from IRQ context
    // (no current_thread_id read; turnstile waiters are taken under
    // IRQ-disabling spinlocks so the bucket lock can't already be held).
    if port_id != 0 {
        let ts = crate::arch::timer::read_cycles();
        let msg = Message::new(IRQ_MSG_TAG, [irq as u64, ts, 0, 0, 0, 0]);
        let _ = crate::ipc::port::send_from_kernel(port_id, msg);
    }

    // Thread-based dispatch (legacy sys_irq_wait): set pending and wake waiter.
    slot.pending.store(true, Ordering::Release);
    let tid = slot.thread_id.load(Ordering::Acquire);
    if tid != 0 {
        crate::sched::wake_thread(tid);
    }

    true
}

/// Self-test for IRQ-to-port plumbing.
///
/// Creates a port, attaches the lowest valid device IRQ to it (with
/// `mmio_base = 0` to skip the kernel-side virtio ACK path), synthetically
/// invokes `handle_irq` to simulate a hardware IRQ, then drains the port
/// and checks the message tag and IRQ-number payload. Restores state on
/// the way out so the IRQ slot is left clean.
///
/// Called once from `startup_thread` after the kernel servers are up but
/// before any user driver could legitimately register on this IRQ.
pub fn self_test() {
    use crate::ipc::port;

    let (irq_lo, _) = crate::arch::irq::valid_irq_range();
    let test_irq = irq_lo;

    let port_id = match port::create() {
        Some(p) => p,
        None => {
            crate::println!("  [irq-port] FAIL: port::create");
            return;
        }
    };

    if !attach_port(test_irq, port_id, 0) {
        crate::println!("  [irq-port] FAIL: attach_port");
        port::destroy(port_id);
        return;
    }

    // Synthesize an IRQ. handle_irq runs in regular thread context here,
    // which is a strict superset of what's allowed in IRQ context.
    if !handle_irq(test_irq) {
        crate::println!("  [irq-port] FAIL: handle_irq returned false");
        detach_port(test_irq);
        port::destroy(port_id);
        return;
    }

    let msg = match port::recv_nb(port_id) {
        Ok(m) => m,
        Err(()) => {
            crate::println!("  [irq-port] FAIL: no message queued");
            detach_port(test_irq);
            port::destroy(port_id);
            return;
        }
    };

    let ok = msg.tag == IRQ_MSG_TAG && msg.data[0] == test_irq as u64;
    if ok {
        crate::println!(
            "  [irq-port] PASS: IRQ {} → port {} (tag {:#x})",
            test_irq, port_id, msg.tag
        );
    } else {
        crate::println!(
            "  [irq-port] FAIL: tag={:#x} data[0]={} (expected tag={:#x} data[0]={})",
            msg.tag, msg.data[0], IRQ_MSG_TAG, test_irq
        );
    }

    detach_port(test_irq);
    port::destroy(port_id);
}
