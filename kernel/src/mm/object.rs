//! Memory objects — the backing store for virtual memory.
//!
//! Each memory object represents a logically contiguous region of memory
//! (e.g., an anonymous demand-zero region or a cached file region).
//! Objects track their physical backing (via PageVec) and the
//! set of address spaces that map them.
//!
//! Each object is identified by a kernel-held port. The kernel handler
//! intercepts sends synchronously, and per-object spinlocks replace the
//! former global ObjectTable lock.

use super::page::PhysAddr;
use super::pagevec::PageVec;
use super::phys;
use crate::ipc::port::{self, PortId};
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Maximum number of memory objects.
pub const MAX_OBJECTS: usize = 96;

/// Maximum mappings per object (address spaces that map this object).
const MAX_MAPPINGS: usize = 8;

/// Object type tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ObjectType {
    Free = 0,
    Anonymous = 1,
    Pager = 2,
}

/// A mapping record: which address space maps this object and where.
#[derive(Clone, Copy)]
pub struct Mapping {
    pub aspace_id: u32,
    pub va_start: usize,
    pub active: bool,
}

impl Mapping {
    const fn empty() -> Self {
        Self {
            aspace_id: 0,
            va_start: 0,
            active: false,
        }
    }
}

/// Memory object — demand-zero (anonymous) or pager-backed pages.
pub struct MemObject {
    pub obj_type: ObjectType,
    /// Total size in allocation pages.
    pub page_count: u16,
    /// COW sharing group ID. Objects forked from a common ancestor share
    /// the same group ID. 0 means this object has never been COW-cloned.
    pub cow_group: u16,
    /// Physical pages backing this object (indexed by page offset within object).
    /// 0 = not yet allocated. Uses tiered storage: inline for <=4 pages,
    /// slab-allocated for larger objects.
    pub pages: PageVec,
    /// Mappings from address spaces.
    pub mappings: [Mapping; MAX_MAPPINGS],
    /// For Pager objects: file handle passed to the pager thread.
    pub file_handle: u32,
    /// For Pager objects: byte offset of this object's start within the file.
    pub file_base_offset: u64,
}

impl MemObject {
    const fn empty() -> Self {
        Self {
            obj_type: ObjectType::Free,
            page_count: 0,
            cow_group: 0,
            pages: PageVec::empty(),
            mappings: [Mapping::empty(); MAX_MAPPINGS],
            file_handle: 0,
            file_base_offset: 0,
        }
    }

    /// Allocate the physical page at offset `page_idx` if not already allocated.
    /// Returns `(PhysAddr, pre_zeroed)` where `pre_zeroed` is true if the page
    /// came from the zero pool (entire PAGE_SIZE already zeroed).
    pub fn ensure_page(&mut self, page_idx: usize) -> Option<(PhysAddr, bool)> {
        if page_idx >= self.page_count as usize {
            return None;
        }
        let existing = self.pages.get(page_idx);
        if existing != 0 {
            return Some((PhysAddr::new(existing), false));
        }
        // Try pre-zeroed pool first, then dirty allocator.
        let (pa, pre_zeroed) = if let Some(pa) = super::zeropool::alloc_zeroed_page() {
            (pa, true)
        } else {
            (phys::alloc_page()?, false)
        };
        self.pages.set(page_idx, pa.as_usize());
        Some((pa, pre_zeroed))
    }

    /// Get the physical address of page at offset `page_idx`, or None if not allocated.
    pub fn get_page(&self, page_idx: usize) -> Option<PhysAddr> {
        if page_idx >= self.page_count as usize {
            return None;
        }
        let pa = self.pages.get(page_idx);
        if pa == 0 {
            return None;
        }
        Some(PhysAddr::new(pa))
    }

    /// Clear all page pointers without freeing.
    pub fn clear_pages(&mut self) {
        self.pages.clear(self.page_count as usize);
    }

    /// Add a mapping record.
    pub fn add_mapping(&mut self, aspace_id: u32, va_start: usize) -> bool {
        for m in &mut self.mappings {
            if !m.active {
                m.aspace_id = aspace_id;
                m.va_start = va_start;
                m.active = true;
                return true;
            }
        }
        false
    }

    /// Count active mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.iter().filter(|m| m.active).count()
    }

    /// Remove a mapping record.
    pub fn remove_mapping(&mut self, aspace_id: u32, va_start: usize) {
        for m in &mut self.mappings {
            if m.active && m.aspace_id == aspace_id && m.va_start == va_start {
                m.active = false;
                return;
            }
        }
    }
}

/// Object ID type (slot index into OBJECTS table).
pub type ObjectId = u32;

// --- Per-object locking: each slot has its own SpinLock ---

/// A slot in the object table.
struct ObjectSlot {
    /// 0 = free, 1 = active. Read lock-free for scans.
    active: AtomicU8,
    /// Associated kernel port ID (0 = none).
    port_id: AtomicU64,
    /// Per-object lock protecting the MemObject.
    inner: SpinLock<MemObject>,
}

impl ObjectSlot {
    const fn new() -> Self {
        Self {
            active: AtomicU8::new(0),
            port_id: AtomicU64::new(0),
            inner: SpinLock::new(MemObject::empty()),
        }
    }
}

/// Global object table — per-slot locks, no global lock.
static OBJECTS: [ObjectSlot; MAX_OBJECTS] = {
    const SLOT: ObjectSlot = ObjectSlot::new();
    [SLOT; MAX_OBJECTS]
};

/// Atomically claim a free slot. Uses compare_exchange so two concurrent
/// creates never pick the same slot.
fn claim_free_slot() -> Option<usize> {
    for i in 0..MAX_OBJECTS {
        if OBJECTS[i].active.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return Some(i);
        }
    }
    None
}

/// Release a claimed slot (on error paths before initialization completes).
fn release_slot(slot: usize) {
    OBJECTS[slot].active.store(0, Ordering::Release);
}

/// Kernel port handler for memory objects. `user_data` is the OBJECTS slot index.
fn object_port_handler(_port_id: PortId, user_data: usize, msg: &crate::ipc::Message) -> crate::ipc::Message {
    // Minimal handler. Phase 4 will add the full message-based API for
    // external pagers. Currently, the primary access path is with_object().
    let slot = user_data;
    if slot >= MAX_OBJECTS {
        return crate::ipc::Message::empty();
    }
    let _obj = OBJECTS[slot].inner.lock();
    let _ = msg;
    crate::ipc::Message::empty()
}

/// Create a new pager-backed memory object.
/// Returns the object ID. The object gets a normal (non-kernel-held) port
/// so that an external pager can hold the receive right and get fault
/// notifications via IPC.
pub fn create_pager(page_count: u16, file_handle: u32, file_base_offset: u64) -> Option<ObjectId> {
    let slot = claim_free_slot()?;
    let pages = match PageVec::with_capacity(page_count as usize) {
        Some(p) => p,
        None => { release_slot(slot); return None; }
    };
    // Normal port (not kernel-held) — pager task holds RECV right.
    let port = match port::create() {
        Some(p) => p,
        None => { release_slot(slot); return None; }
    };

    {
        let mut obj = OBJECTS[slot].inner.lock();
        obj.obj_type = ObjectType::Pager;
        obj.page_count = page_count;
        obj.pages = pages;
        obj.file_handle = file_handle;
        obj.file_base_offset = file_base_offset;
    }
    OBJECTS[slot].port_id.store(port, Ordering::Release);
    Some(slot as ObjectId)
}

/// Create a new anonymous memory object of `page_count` allocation pages.
/// Returns the object ID.
pub fn create_anon(page_count: u16) -> Option<ObjectId> {
    let slot = claim_free_slot()?;
    let pages = match PageVec::with_capacity(page_count as usize) {
        Some(p) => p,
        None => { release_slot(slot); return None; }
    };
    let port = match port::create_kernel_port(object_port_handler, slot) {
        Some(p) => p,
        None => { release_slot(slot); return None; }
    };

    {
        let mut obj = OBJECTS[slot].inner.lock();
        obj.obj_type = ObjectType::Anonymous;
        obj.page_count = page_count;
        obj.pages = pages;
    }
    OBJECTS[slot].port_id.store(port, Ordering::Release);
    Some(slot as ObjectId)
}

/// Next COW group ID counter.
static NEXT_COW_GROUP: SpinLock<u16> = SpinLock::new(1);

/// Clone a memory object for COW. Creates a new object that shares all
/// physical pages with the original. Both objects are placed in the same
/// COW sharing group so that page ownership can be determined by scanning
/// siblings rather than maintaining per-PFN refcounts.
pub fn clone_for_cow(src_id: ObjectId) -> Option<ObjectId> {
    // Step 1: Lock source, read state, assign COW group, copy pages.
    let (page_count, group, new_pages) = {
        let mut src = OBJECTS[src_id as usize].inner.lock();
        if src.cow_group == 0 {
            let mut g = NEXT_COW_GROUP.lock();
            src.cow_group = *g;
            *g = g.wrapping_add(1);
            if *g == 0 { *g = 1; }
        }
        let group = src.cow_group;
        let page_count = src.page_count;
        let mut new_pages = PageVec::with_capacity(page_count as usize)?;
        new_pages.copy_from(&src.pages, page_count as usize);
        (page_count, group, new_pages)
    }; // Source lock released.

    // Step 2: Claim free slot + create kernel port.
    let dst_idx = claim_free_slot()?;
    let port = match port::create_kernel_port(object_port_handler, dst_idx) {
        Some(p) => p,
        None => { release_slot(dst_idx); return None; }
    };

    // Step 3: Initialize destination.
    {
        let mut dst = OBJECTS[dst_idx].inner.lock();
        dst.obj_type = ObjectType::Anonymous;
        dst.page_count = page_count;
        dst.cow_group = group;
        dst.pages = new_pages;
        for m in &mut dst.mappings {
            *m = Mapping::empty();
        }
    }
    OBJECTS[dst_idx].port_id.store(port, Ordering::Release);
    Some(dst_idx as ObjectId)
}

/// Destroy a memory object, freeing physical pages not shared with siblings.
pub fn destroy(id: ObjectId) {
    let idx = id as usize;
    let (group, page_count) = {
        let obj = OBJECTS[idx].inner.lock();
        (obj.cow_group, obj.page_count as usize)
    };

    // Free each page, checking siblings in the same COW group.
    // Lock ordering: always ascending slot index, never two simultaneously.
    for p in 0..page_count {
        let pa = OBJECTS[idx].inner.lock().pages.get(p);
        if pa == 0 { continue; }

        let shared = group != 0 && (0..MAX_OBJECTS).any(|i| {
            if i == idx { return false; }
            if OBJECTS[i].active.load(Ordering::Acquire) == 0 { return false; }
            let sib = OBJECTS[i].inner.lock();
            sib.obj_type != ObjectType::Free
                && sib.cow_group == group
                && sib.pages.contains(sib.page_count as usize, pa)
        });
        if !shared {
            phys::free_page(PhysAddr::new(pa));
        }
        OBJECTS[idx].inner.lock().pages.set(p, 0);
    }

    // Free PageVec heap and mark slot inactive.
    let port_id = OBJECTS[idx].port_id.load(Ordering::Acquire);
    {
        let mut obj = OBJECTS[idx].inner.lock();
        obj.pages.free_heap();
        obj.obj_type = ObjectType::Free;
        obj.page_count = 0;
        obj.cow_group = 0;
    }
    OBJECTS[idx].active.store(0, Ordering::Release);
    OBJECTS[idx].port_id.store(0, Ordering::Release);
    if port_id != 0 {
        port::destroy(port_id);
    }
}

/// Access an object by ID within a closure (per-object lock only).
pub fn with_object<F, R>(id: ObjectId, f: F) -> R
where
    F: FnOnce(&mut MemObject) -> R,
{
    let mut obj = OBJECTS[id as usize].inner.lock();
    f(&mut obj)
}

/// Get the port ID for an object.
pub fn object_port(id: ObjectId) -> PortId {
    OBJECTS[id as usize].port_id.load(Ordering::Acquire)
}

/// Check whether a physical page at `page_idx` in object `obj_id` is shared
/// with any sibling in the same COW group.
pub fn is_page_shared(obj_id: ObjectId, page_idx: usize) -> bool {
    let idx = obj_id as usize;
    let (group, pa) = {
        let obj = OBJECTS[idx].inner.lock();
        (obj.cow_group, obj.pages.get(page_idx))
    };
    if group == 0 || pa == 0 {
        return false;
    }
    (0..MAX_OBJECTS).any(|i| {
        if i == idx { return false; }
        if OBJECTS[i].active.load(Ordering::Acquire) == 0 { return false; }
        let sib = OBJECTS[i].inner.lock();
        sib.obj_type != ObjectType::Free
            && sib.cow_group == group
            && sib.pages.contains(sib.page_count as usize, pa)
    })
}

/// Release a physical page from object `obj_id` at `page_idx`.
/// If no sibling in the COW group references the same PA, frees the page.
/// Returns true if the physical page was freed, false if still shared.
/// Clears the page entry in either case.
pub fn release_page(obj_id: ObjectId, page_idx: usize) -> bool {
    let idx = obj_id as usize;
    let (group, pa) = {
        let mut obj = OBJECTS[idx].inner.lock();
        let pa = obj.pages.get(page_idx);
        if pa == 0 { return false; }
        obj.pages.set(page_idx, 0);
        (obj.cow_group, pa)
    };

    let shared = group != 0 && (0..MAX_OBJECTS).any(|i| {
        if i == idx { return false; }
        if OBJECTS[i].active.load(Ordering::Acquire) == 0 { return false; }
        let sib = OBJECTS[i].inner.lock();
        sib.obj_type != ObjectType::Free
            && sib.cow_group == group
            && sib.pages.contains(sib.page_count as usize, pa)
    });
    if !shared {
        super::phys::free_page(PhysAddr::new(pa));
        true
    } else {
        false
    }
}
