//! Memory objects — the backing store for virtual memory.
//!
//! Each memory object represents a logically contiguous region of memory
//! (e.g., an anonymous demand-zero region or a cached file region).
//! Objects track their physical backing (via PageVec) and the
//! set of address spaces that map them.
//!
//! Objects are identified by kernel-held ports. Resolution is lock-free
//! via `port_kernel_data(port_id) → *const ObjEntry`. Each entry has its
//! own SpinLock<MemObject> for per-object serialization.
//!
//! COW page lifetime is managed via group extents (shared_mask + copied bits)
//! for first-fork groups (2 members), eliminating per-page refcount work at
//! fork time. Cascading forks (3+ members) fall back to per-page frame
//! refcounts. Non-COW objects (cow_group_port == 0) skip all sharing ops.

use super::page::PhysAddr;
use super::pagevec::PageVec;
use super::phys;
use crate::ipc::port::{self, PortId};
use crate::mm::slab;
use crate::sync::SpinLock;

/// Slab size for ObjEntry allocations (must be a power of two ≥ actual size).
const OBJ_SLAB_SIZE: usize = 256;

/// Mappings per page in a MemObject's mapping list.
const MAPPINGS_PER_PAGE: usize = super::page::PAGE_SIZE / core::mem::size_of::<Mapping>();

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
    pub aspace_id: u64,
    pub va_start: usize,
    pub active: bool,
}

impl Mapping {
    #[allow(dead_code)]
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
    /// COW sharing group port ID. Objects forked from a common ancestor
    /// share the same group. 0 means this object has never been COW-cloned.
    pub cow_group_port: u64,
    /// Physical pages backing this object (indexed by page offset within object).
    /// 0 = not yet allocated. Uses tiered storage: inline for <=4 pages,
    /// slab-allocated for larger objects.
    pub pages: PageVec,
    /// Mappings from address spaces (page-allocated on first add_mapping).
    mappings: *mut Mapping,
    mappings_cap: u16,
    mappings_count: u16,
    /// For Pager objects: file handle passed to the pager thread.
    pub file_handle: u32,
    /// For Pager objects: byte offset of this object's start within the file.
    pub file_base_offset: u64,
    /// For Pager objects: user-facing IPC port for fault notifications.
    /// 0 for anonymous objects.
    pub pager_port: u64,
}

impl MemObject {
    const fn empty() -> Self {
        Self {
            obj_type: ObjectType::Free,
            page_count: 0,
            cow_group_port: 0,
            pages: PageVec::empty(),
            mappings: core::ptr::null_mut(),
            mappings_cap: 0,
            mappings_count: 0,
            file_handle: 0,
            file_base_offset: 0,
            pager_port: 0,
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
    #[allow(dead_code)]
    pub fn clear_pages(&mut self) {
        self.pages.clear(self.page_count as usize);
    }

    /// Ensure the mapping list backing page is allocated.
    fn ensure_mappings(&mut self) -> bool {
        if !self.mappings.is_null() {
            return true;
        }
        let page = match phys::alloc_page() {
            Some(pa) => pa.as_usize() as *mut Mapping,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(page as *mut u8, 0, super::page::PAGE_SIZE);
        }
        self.mappings = page;
        self.mappings_cap = MAPPINGS_PER_PAGE as u16;
        true
    }

    /// Add a mapping record.
    pub fn add_mapping(&mut self, aspace_id: u64, va_start: usize) -> bool {
        if !self.ensure_mappings() {
            return false;
        }
        // Reuse an inactive slot if available.
        for i in 0..self.mappings_count as usize {
            let m = unsafe { &mut *self.mappings.add(i) };
            if !m.active {
                m.aspace_id = aspace_id;
                m.va_start = va_start;
                m.active = true;
                return true;
            }
        }
        // Append.
        if self.mappings_count < self.mappings_cap {
            let m = unsafe { &mut *self.mappings.add(self.mappings_count as usize) };
            m.aspace_id = aspace_id;
            m.va_start = va_start;
            m.active = true;
            self.mappings_count += 1;
            true
        } else {
            false // page full
        }
    }

    /// Count active mappings.
    pub fn mapping_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.mappings_count as usize {
            if unsafe { (*self.mappings.add(i)).active } {
                n += 1;
            }
        }
        n
    }

    /// Remove a mapping record.
    pub fn remove_mapping(&mut self, aspace_id: u64, va_start: usize) {
        for i in 0..self.mappings_count as usize {
            let m = unsafe { &mut *self.mappings.add(i) };
            if m.active && m.aspace_id == aspace_id && m.va_start == va_start {
                m.active = false;
                return;
            }
        }
    }

    /// Iterate over all active mappings, calling `f(aspace_id, va_start)` for each.
    #[allow(dead_code)]
    pub fn for_each_mapping<F: FnMut(u64, usize)>(&self, mut f: F) {
        for i in 0..self.mappings_count as usize {
            let m = unsafe { &*self.mappings.add(i) };
            if m.active {
                f(m.aspace_id, m.va_start);
            }
        }
    }
}

/// Object ID type — a port_id (u64) that identifies the object's kernel port.
pub type ObjectId = u64;

// ---------------------------------------------------------------------------
// Port-referenced object entries
// ---------------------------------------------------------------------------

/// A slab-allocated entry, resolved lock-free via port_kernel_data.
struct ObjEntry {
    /// Kernel-held port for this object (used for resolution via PORT_ART).
    port_id: u64,
    /// Per-object lock protecting the MemObject.
    inner: SpinLock<MemObject>,
}

/// Allocate a new ObjEntry from slab.
fn alloc_entry() -> Option<*mut ObjEntry> {
    let pa = slab::alloc(OBJ_SLAB_SIZE)?;
    let p = pa.as_usize() as *mut ObjEntry;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, OBJ_SLAB_SIZE);
    }
    Some(p)
}

/// Free an ObjEntry back to slab.
fn free_entry(ptr: *mut ObjEntry) {
    slab::free(PhysAddr::new(ptr as usize), OBJ_SLAB_SIZE);
}

/// Resolve an ObjectId (port_id) to the ObjEntry pointer. Lock-free via RCU.
#[inline]
fn resolve_entry(id: ObjectId) -> Option<*const ObjEntry> {
    let user_data = port::port_kernel_data(id)?;
    Some(user_data as *const ObjEntry)
}

/// Kernel port handler for memory objects (stub).
fn object_port_handler(
    _port_id: PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

/// RCU callback to free a slab-allocated ObjEntry.
fn rcu_free_obj_callback(ptr: usize) {
    free_entry(ptr as *mut ObjEntry);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new pager-backed memory object.
/// Returns the object ID (kernel port_id). The pager thread communicates
/// via a separate user-facing port stored in MemObject.pager_port.
pub fn create_pager(page_count: u16, file_handle: u32, file_base_offset: u64) -> Option<ObjectId> {
    let pages = PageVec::with_capacity(page_count as usize)?;
    // User-facing port for external pager IPC.
    let pager_port = port::create()?;

    let ptr = alloc_entry()?;

    // Kernel-held port for resolution: user_data = entry pointer.
    let kernel_port = match port::create_kernel_port(object_port_handler, ptr as usize) {
        Some(p) => p,
        None => {
            free_entry(ptr);
            port::destroy(pager_port);
            return None;
        }
    };

    unsafe {
        (*ptr).port_id = kernel_port;
        let mut obj = MemObject::empty();
        obj.obj_type = ObjectType::Pager;
        obj.page_count = page_count;
        obj.pages = pages;
        obj.file_handle = file_handle;
        obj.file_base_offset = file_base_offset;
        obj.pager_port = pager_port;
        core::ptr::write(&mut (*ptr).inner, SpinLock::new(obj));
    }

    Some(kernel_port)
}

/// Create a new anonymous memory object of `page_count` allocation pages.
/// Returns the object ID (kernel port_id).
pub fn create_anon(page_count: u16) -> Option<ObjectId> {
    let pages = PageVec::with_capacity(page_count as usize)?;

    let ptr = alloc_entry()?;

    let kernel_port = match port::create_kernel_port(object_port_handler, ptr as usize) {
        Some(p) => p,
        None => {
            free_entry(ptr);
            return None;
        }
    };

    unsafe {
        (*ptr).port_id = kernel_port;
        let mut obj = MemObject::empty();
        obj.obj_type = ObjectType::Anonymous;
        obj.page_count = page_count;
        obj.pages = pages;
        core::ptr::write(&mut (*ptr).inner, SpinLock::new(obj));
    }

    Some(kernel_port)
}

/// Clone a memory object for COW. Creates a new object that shares all
/// physical pages with the original and registers both in a COW sharing group.
///
/// Page lifetime is tracked via epoch-based extents — no per-page refcount
/// bumps needed for any fork (first or cascading).
pub fn clone_for_cow(src_id: ObjectId) -> Option<ObjectId> {
    let src_entry = resolve_entry(src_id)? as *mut ObjEntry;

    // Step 1: lock source, read state, copy pages.
    let (page_count, group_port, new_pages) = {
        let mut src = unsafe { (*src_entry).inner.lock() };

        let first_fork = src.cow_group_port == 0;

        // Create or join a COW sharing group.
        let group_port = if first_fork {
            let gp = super::cowgroup::create()?;
            super::cowgroup::add_member(gp, src_id);
            src.cow_group_port = gp;
            gp
        } else {
            src.cow_group_port
        };

        let page_count = src.page_count;
        let mut new_pages = PageVec::with_capacity(page_count as usize)?;
        new_pages.copy_from(&src.pages, page_count as usize);

        // Fork epochs track pairwise sharing — no per-page refcount bumps needed
        // for any fork (first or cascading).

        (page_count, group_port, new_pages)
    };

    // Step 2: allocate entry + kernel port.
    let ptr = alloc_entry()?;
    let kernel_port = match port::create_kernel_port(object_port_handler, ptr as usize) {
        Some(p) => p,
        None => {
            free_entry(ptr);
            return None;
        }
    };

    // Step 3: initialize destination and register in group.
    unsafe {
        (*ptr).port_id = kernel_port;
        let mut obj = MemObject::empty();
        obj.obj_type = ObjectType::Anonymous;
        obj.page_count = page_count;
        obj.cow_group_port = group_port;
        obj.pages = new_pages;
        core::ptr::write(&mut (*ptr).inner, SpinLock::new(obj));
    }

    super::cowgroup::add_member(group_port, kernel_port);

    // Step 4: add fork epoch for this parent→child fork event.
    // Snapshot page presence from the source object.
    {
        let src = unsafe { (*src_entry).inner.lock() };
        super::cowgroup::add_fork_epoch_to_extents(
            group_port,
            src_id,
            kernel_port,
            page_count,
            |idx| src.pages.get(idx) != 0,
        );
    }

    Some(kernel_port)
}

/// Destroy a memory object, freeing physical pages.
///
/// For non-COW objects: free all pages directly.
/// For COW objects: use epoch-based extent classification to determine which
///   pages are privately owned (free) vs still shared (keep).
pub fn destroy(id: ObjectId) {
    let entry_ptr = match resolve_entry(id) {
        Some(p) => p as *mut ObjEntry,
        None => return,
    };

    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    if guard.obj_type == ObjectType::Free {
        return;
    }

    let page_count = guard.page_count as usize;
    let pager_port = guard.pager_port;
    let cow_group_port = guard.cow_group_port;

    // Free each page.
    if cow_group_port == 0 {
        // Fast path: no COW group — all pages are exclusively owned.
        for p in 0..page_count {
            let pa = guard.pages.get(p);
            if pa == 0 {
                continue;
            }
            guard.pages.set(p, 0);
            phys::free_page(PhysAddr::new(pa));
        }
    } else {
        // COW group: use epoch-based extent classification.
        // Process one superpage range at a time.
        use super::page::SUPERPAGE_ALLOC_PAGES;
        let mut base = 0;
        while base < page_count {
            let range_end = (base + SUPERPAGE_ALLOC_PAGES).min(page_count);
            let range_count = range_end - base;

            // Ask the group which pages in this range should be freed.
            let free_mask = super::cowgroup::pages_to_free_on_destroy(
                cow_group_port,
                id,
                base as u32,
                range_count as u8,
            );

            for slot in 0..range_count {
                let p = base + slot;
                let pa = guard.pages.get(p);
                if pa == 0 {
                    continue;
                }
                guard.pages.set(p, 0);

                if free_mask & (1u64 << slot) != 0 {
                    phys::free_page(PhysAddr::new(pa));
                }
                // else: page is still referenced by other members — don't free.
            }

            base = range_end;
        }
    }

    // Free PageVec heap and mappings page.
    guard.pages.free_heap();
    if !guard.mappings.is_null() {
        phys::free_page(PhysAddr::new(guard.mappings as usize));
        guard.mappings = core::ptr::null_mut();
    }
    guard.obj_type = ObjectType::Free;
    guard.page_count = 0;
    guard.cow_group_port = 0;
    drop(guard);

    // Leave COW sharing group.
    if cow_group_port != 0 {
        if let Some(survivor_id) = super::cowgroup::remove_member(cow_group_port, id) {
            // Sole survivor — detach from group. Survivor's pages are all
            // exclusively owned (either originals it never broke, or private copies).
            detach_sole_survivor(survivor_id);
        }
    }

    // Destroy ports and defer-free the entry.
    port::destroy(id);
    if pager_port != 0 {
        port::destroy(pager_port);
    }
    crate::sync::rcu::rcu_defer_free(entry_ptr as usize, rcu_free_obj_callback);
}

/// Access an object by ID within a closure, under per-object lock.
#[track_caller]
pub fn with_object<F, R>(id: ObjectId, f: F) -> R
where
    F: FnOnce(&mut MemObject) -> R,
{
    let entry_ptr = match resolve_entry(id) {
        Some(p) => p,
        None => {
            let caller = core::panic::Location::caller();
            panic!(
                "with_object: invalid ObjectId {} at {}:{}",
                id,
                caller.file(),
                caller.line()
            );
        }
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    f(&mut *guard)
}

/// Like `with_object`, but returns `None` if the object has been destroyed.
/// Use for paths where a stale object ID is possible (e.g., grant revocation
/// racing with source object destruction).
pub fn try_with_object<F, R>(id: ObjectId, f: F) -> Option<R>
where
    F: FnOnce(&mut MemObject) -> R,
{
    let entry_ptr = resolve_entry(id)?;
    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    Some(f(&mut *guard))
}

/// Get the user-facing port ID for an object (pager port for Pager objects,
/// kernel port for anonymous objects).
pub fn object_port(id: ObjectId) -> PortId {
    match resolve_entry(id) {
        Some(entry_ptr) => {
            let guard = unsafe { (*entry_ptr).inner.lock() };
            if guard.pager_port != 0 {
                guard.pager_port
            } else {
                unsafe { (*entry_ptr).port_id }
            }
        }
        None => 0,
    }
}

/// Detach the sole surviving member of a dissolved COW group.
/// Clears its `cow_group_port` so future operations (destroy, fault) take
/// the fast non-COW path. Stale frame refcounts are cleaned up by
/// `phys::free_page` when pages are eventually freed.
fn detach_sole_survivor(survivor_id: ObjectId) {
    let entry_ptr = match resolve_entry(survivor_id) {
        Some(p) => p,
        None => return,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    guard.cow_group_port = 0;
}

/// Release a physical page from object `obj_id` at `page_idx`.
/// Frees the page if no other object references the same PA.
/// Returns true if the physical page was freed, false if still shared.
/// Clears the page entry in either case.
pub fn release_page(obj_id: ObjectId, page_idx: usize) -> bool {
    let entry_ptr = match resolve_entry(obj_id) {
        Some(p) => p as *mut ObjEntry,
        None => return false,
    };

    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    let pa = guard.pages.get(page_idx);
    if pa == 0 {
        return false;
    }
    let cow_group_port = guard.cow_group_port;
    guard.pages.set(page_idx, 0);
    drop(guard);

    if cow_group_port == 0 {
        // Fast path: not COW-shared, just free.
        phys::free_page(PhysAddr::new(pa));
        return true;
    }

    // COW group: classify via epoch-based extents and free if appropriate.
    use super::page::SUPERPAGE_ALLOC_PAGES;
    let super_base = (page_idx & !(SUPERPAGE_ALLOC_PAGES - 1)) as u32;
    let slot = page_idx - super_base as usize;
    super::cowgroup::release_shared_page(
        cow_group_port,
        obj_id,
        super_base,
        slot,
        PhysAddr::new(pa),
    )
}
