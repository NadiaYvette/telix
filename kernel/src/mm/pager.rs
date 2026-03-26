//! Pager fault table — tracks pending page faults for pager-backed VMAs.
//!
//! When a page fault occurs on a pager-backed VMA, the kernel allocates the
//! physical page, records the fault here, parks the faulting thread, and wakes
//! the pager thread (if blocked in wait_fault). The pager thread fills the page
//! and calls fault_complete to install the PTE and wake the faulting thread.
//!
//! The fault table is page-allocated on first use — no fixed slot limit.
//! Capacity = PAGE_SIZE / size_of::<PagerFaultEntry>() (e.g. 819 at 64 KiB pages).

use super::aspace;
use super::fault;
use super::page::{PAGE_SIZE, MMUPAGE_SIZE};
use super::stats;
use crate::sched::scheduler;
use crate::sched::thread::BlockReason;
use crate::sync::SpinLock;
use core::sync::atomic::Ordering;

/// Information about a pending pager fault.
pub struct PagerFaultInfo {
    pub aspace_id: u32,
    pub thread_id: u32,
    pub fault_va: usize,
    pub phys_addr: usize,
    pub obj_page_idx: usize,
    pub obj_id: u32,
    pub mmu_idx: usize,
    pub vma_va: usize,
    pub file_handle: u32,
    pub file_offset: u64,
}

struct PagerFaultEntry {
    active: bool,
    aspace_id: u32,
    thread_id: u32,
    fault_va: usize,
    phys_addr: usize,
    obj_page_idx: usize,
    obj_id: u32,
    mmu_idx: usize,
    vma_va: usize,
    file_handle: u32,
    file_offset: u64,
}

/// Page-backed fault table with lazy allocation.
struct PagerFaultTable {
    entries: *mut PagerFaultEntry,
    capacity: usize,
}

// Safety: entries pointer is a physical address, accessed only under SpinLock.
unsafe impl Send for PagerFaultTable {}

impl PagerFaultTable {
    const fn new() -> Self {
        Self {
            entries: core::ptr::null_mut(),
            capacity: 0,
        }
    }

    /// Ensure the backing page is allocated. Returns false on OOM.
    fn ensure_capacity(&mut self) -> bool {
        if self.entries.is_null() {
            let page = match super::phys::alloc_page() {
                Some(pa) => pa.as_usize() as *mut PagerFaultEntry,
                None => return false,
            };
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
            }
            self.entries = page;
            self.capacity = PAGE_SIZE / core::mem::size_of::<PagerFaultEntry>();
        }
        true
    }

    #[inline]
    fn get(&self, idx: usize) -> &PagerFaultEntry {
        unsafe { &*self.entries.add(idx) }
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut PagerFaultEntry {
        unsafe { &mut *self.entries.add(idx) }
    }
}

static PAGER_FAULTS: SpinLock<PagerFaultTable> = SpinLock::new(PagerFaultTable::new());

/// Record a pending pager fault. Returns a token (slot index) on success.
/// Called from the fault handler inside with_aspace() — must not park.
pub fn record_fault(info: PagerFaultInfo) -> Option<u32> {
    let mut faults = PAGER_FAULTS.lock();
    if !faults.ensure_capacity() {
        return None;
    }
    for i in 0..faults.capacity {
        let entry = faults.get_mut(i);
        if !entry.active {
            entry.active = true;
            entry.aspace_id = info.aspace_id;
            entry.thread_id = info.thread_id;
            entry.fault_va = info.fault_va;
            entry.phys_addr = info.phys_addr;
            entry.obj_page_idx = info.obj_page_idx;
            entry.obj_id = info.obj_id;
            entry.mmu_idx = info.mmu_idx;
            entry.vma_va = info.vma_va;
            entry.file_handle = info.file_handle;
            entry.file_offset = info.file_offset;
            stats::PAGER_FAULTS.fetch_add(1, Ordering::Relaxed);
            return Some(i as u32);
        }
    }
    None
}

/// IPC tag for pager fault notifications sent to object ports.
pub const PAGER_FAULT_REQ: u64 = 0x8000;

/// Park the faulting thread and notify the pager.
/// Called from the arch exception handler AFTER handle_page_fault returns
/// (no aspace lock held). Must be called after store_frame_sp().
///
/// Dual dispatch: sends an IPC message to the object's port (for external
/// pagers using recv) AND wakes a per-aspace waiter (for same-process
/// pagers using wait_fault). Both paths coexist harmlessly.
pub fn initiate_fault(token: u32) {
    let (aspace_id, obj_id, fault_va, file_handle, file_offset) = {
        let faults = PAGER_FAULTS.lock();
        if (token as usize) >= faults.capacity {
            return;
        }
        let e = faults.get(token as usize);
        (e.aspace_id, e.obj_id, e.fault_va, e.file_handle, e.file_offset)
    };

    // Path 1: Send fault notification IPC to the object's port.
    // External pagers hold RECV on this port and get the notification.
    let obj_port = super::object::object_port(obj_id);
    if obj_port != 0 {
        let msg = crate::ipc::Message::new(PAGER_FAULT_REQ, [
            token as u64,
            fault_va as u64,
            file_handle as u64,
            file_offset,
            PAGE_SIZE as u64,
            0,
        ]);
        // Kernel-initiated send — bypasses cap checks.
        let _ = crate::ipc::port::send_nb(obj_port, msg);
    }

    // Path 2: Wake per-aspace pager waiter (backward compat with wait_fault).
    let pager_tid = aspace::take_pager_waiter(aspace_id);
    if pager_tid != 0 {
        inject_fault_into_frame(pager_tid, token, fault_va, file_handle, file_offset);
        scheduler::wake_parked_thread(pager_tid);
    }

    // Park the faulting thread.
    scheduler::park_current_for_ipc(BlockReason::PagerFault);
}

/// Inject fault info into a parked pager thread's saved exception frame.
/// Sets: return reg (r0/a0) = token, r1/a1 = fault_va, r2/a2 = file_handle,
///       r3/a3 = file_offset, r4/a4 = PAGE_SIZE.
fn inject_fault_into_frame(pager_tid: u32, token: u32, fault_va: usize, file_handle: u32, file_offset: u64) {
    use crate::syscall::handlers::{set_return, set_reg, ExceptionFrame};
    let sp = scheduler::thread_saved_sp(pager_tid);
    let frame = unsafe { &mut *(sp as *mut ExceptionFrame) };
    set_return(frame, token as u64);
    set_reg(frame, 1, fault_va as u64);
    set_reg(frame, 2, file_handle as u64);
    set_reg(frame, 3, file_offset);
    set_reg(frame, 4, PAGE_SIZE as u64);
}

/// Wait for a pager fault in the current address space.
/// If a fault is pending, returns Some((token, fault_va, file_handle, file_offset, page_size)).
/// If none, parks the pager thread. When woken by initiate_fault, the fault info
/// will be injected into the saved frame (like IPC recv).
pub fn wait_fault(aspace_id: u32) -> Option<(u32, usize, u32, u64, usize)> {
    // Check for pending faults first (lock order: FAULTS before pager waiter).
    {
        let faults = PAGER_FAULTS.lock();
        for i in 0..faults.capacity {
            let entry = faults.get(i);
            if entry.active && entry.aspace_id == aspace_id {
                return Some((
                    i as u32,
                    entry.fault_va,
                    entry.file_handle,
                    entry.file_offset,
                    PAGE_SIZE,
                ));
            }
        }
    }

    // Register as waiter. initiate_fault checks this AFTER recording the fault.
    {
        let tid = scheduler::current_thread_id();
        aspace::set_pager_waiter(aspace_id, tid);
    }

    // Re-check for faults that may have arrived between our first check and
    // registering as waiter. If a fault arrived, initiate_fault either:
    // (a) saw our waiter registration and will inject+wake us, or
    // (b) didn't see it yet (we weren't registered). Check again.
    {
        let faults = PAGER_FAULTS.lock();
        for i in 0..faults.capacity {
            let entry = faults.get(i);
            if entry.active && entry.aspace_id == aspace_id {
                // Clear waiter registration.
                aspace::clear_pager_waiter(aspace_id);
                return Some((
                    i as u32,
                    entry.fault_va,
                    entry.file_handle,
                    entry.file_offset,
                    PAGE_SIZE,
                ));
            }
        }
    }

    // No faults pending. Park. initiate_fault will see our waiter registration,
    // inject fault data into our frame, and wake us.
    scheduler::park_current_for_ipc(BlockReason::PagerWait);
    None
}

/// Complete a pager fault: copy data from the caller's VA to the physical page,
/// install the PTE, and wake the faulting thread.
pub fn complete_fault(token: u32, data_va: usize, data_len: usize) -> bool {
    // Extract fault entry info.
    let entry_info = {
        let faults = PAGER_FAULTS.lock();
        if (token as usize) >= faults.capacity {
            return false;
        }
        let entry = faults.get(token as usize);
        if !entry.active {
            return false;
        }
        (
            entry.aspace_id,
            entry.thread_id,
            entry.phys_addr,
            entry.mmu_idx,
            entry.vma_va,
            entry.fault_va,
        )
    };
    let (fault_aspace_id, fault_thread_id, phys_addr,
         mmu_idx, vma_va, fault_va) = entry_info;

    // Translate the caller's data_va to physical address.
    let pt_root = scheduler::current_page_table_root();
    let src_pa = match translate_va(pt_root, data_va) {
        Some(pa) => pa,
        None => return false,
    };

    // Copy data from source PA to target physical page.
    let copy_len = data_len.min(PAGE_SIZE);
    unsafe {
        core::ptr::copy_nonoverlapping(
            src_pa as *const u8,
            phys_addr as *mut u8,
            copy_len,
        );
        if copy_len < PAGE_SIZE {
            core::ptr::write_bytes(
                (phys_addr + copy_len) as *mut u8,
                0,
                PAGE_SIZE - copy_len,
            );
        }
    }

    // Install PTE with SW_ZEROED flag (page content has been filled by the pager).
    aspace::with_aspace(fault_aspace_id, |aspace| {
        let pt_root = aspace.page_table_root;
        if let Some(vma) = aspace.find_vma_mut(vma_va) {
            let mmu_pa = phys_addr + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;
            let flags = fault::pte_flags_for_vma_pub(vma);
            install_pte(pt_root, fault_va, mmu_pa, flags);
        }
    });

    // Wake the faulting thread.
    scheduler::wake_parked_thread(fault_thread_id);

    // Clear the entry.
    {
        let mut faults = PAGER_FAULTS.lock();
        if (token as usize) < faults.capacity {
            faults.get_mut(token as usize).active = false;
        }
    }

    true
}

fn translate_va(pt_root: usize, va: usize) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::translate_va(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::translate_va(pt_root, va) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::translate_va(pt_root, va) }
}

fn install_pte(pt_root: usize, va: usize, pa: usize, flags: u64) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::map_single_mmupage(pt_root, va, pa, flags); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::map_single_mmupage(pt_root, va, pa, flags); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::map_single_mmupage(pt_root, va, pa, flags); }
}
