//! Memory objects — the backing store for virtual memory.
//!
//! Each memory object represents a logically contiguous region of memory
//! (e.g., an anonymous demand-zero region or a cached file region).
//! Objects track their physical backing (via PageVec) and the
//! set of address spaces that map them.
//!
//! Each object is identified by a kernel-held port. The object table is
//! an ART (Adaptive Radix Tree) mapping monotonic ObjectIds to slab-
//! allocated entries, with no fixed upper limit.

use super::page::PhysAddr;
use super::pagevec::PageVec;
use super::phys;
use crate::ipc::art::Art;
use crate::ipc::port::{self, PortId};
use crate::mm::slab;
use crate::sync::SpinLock;

/// Slab size for ObjEntry allocations (must be a power of two ≥ actual size).
const OBJ_SLAB_SIZE: usize = 256;

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

/// Object ID type (opaque handle, monotonically increasing).
pub type ObjectId = u32;

// ---------------------------------------------------------------------------
// ART-backed object table
// ---------------------------------------------------------------------------

/// A slab-allocated entry in the object table.
#[repr(C)]
struct ObjEntry {
    port_id: u64,
    obj: MemObject,
}

struct ObjTable {
    art: Art,
    next_id: u32,
}

impl ObjTable {
    const fn new() -> Self {
        Self {
            art: Art::new(),
            next_id: 0,
        }
    }

    fn get(&self, id: ObjectId) -> Option<&ObjEntry> {
        let val = self.art.lookup(id as u64)?;
        Some(unsafe { &*(val as *const ObjEntry) })
    }

    fn get_mut(&mut self, id: ObjectId) -> Option<&mut ObjEntry> {
        let val = self.art.lookup(id as u64)?;
        Some(unsafe { &mut *(val as *mut ObjEntry) })
    }
}

static OBJ_TABLE: SpinLock<ObjTable> = SpinLock::new(ObjTable::new());

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

/// Next COW group ID counter.
static NEXT_COW_GROUP: SpinLock<u16> = SpinLock::new(1);

/// Kernel port handler for memory objects. `user_data` is the ObjectId.
fn object_port_handler(_port_id: PortId, user_data: usize, msg: &crate::ipc::Message) -> crate::ipc::Message {
    // Minimal handler. Phase 4 will add the full message-based API for
    // external pagers. Currently, the primary access path is with_object().
    let _id = user_data as ObjectId;
    let _ = msg;
    crate::ipc::Message::empty()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new pager-backed memory object.
/// Returns the object ID. The object gets a normal (non-kernel-held) port
/// so that an external pager can hold the receive right and get fault
/// notifications via IPC.
pub fn create_pager(page_count: u16, file_handle: u32, file_base_offset: u64) -> Option<ObjectId> {
    let pages = PageVec::with_capacity(page_count as usize)?;
    // Normal port (not kernel-held) — pager task holds RECV right.
    let port = port::create()?;

    let ptr = alloc_entry()?;

    let mut table = OBJ_TABLE.lock();
    let id = table.next_id;
    table.next_id += 1;

    unsafe {
        (*ptr).port_id = port;
        (*ptr).obj.obj_type = ObjectType::Pager;
        (*ptr).obj.page_count = page_count;
        (*ptr).obj.pages = pages;
        (*ptr).obj.file_handle = file_handle;
        (*ptr).obj.file_base_offset = file_base_offset;
    }

    if !table.art.insert(id as u64, ptr as usize) {
        drop(table);
        free_entry(ptr);
        port::destroy(port);
        return None;
    }

    Some(id)
}

/// Create a new anonymous memory object of `page_count` allocation pages.
/// Returns the object ID.
pub fn create_anon(page_count: u16) -> Option<ObjectId> {
    let pages = PageVec::with_capacity(page_count as usize)?;

    let mut table = OBJ_TABLE.lock();
    let id = table.next_id;
    table.next_id += 1;

    let port = match port::create_kernel_port(object_port_handler, id as usize) {
        Some(p) => p,
        None => return None,
    };

    let ptr = match alloc_entry() {
        Some(p) => p,
        None => {
            port::destroy(port);
            return None;
        }
    };

    unsafe {
        (*ptr).port_id = port;
        (*ptr).obj.obj_type = ObjectType::Anonymous;
        (*ptr).obj.page_count = page_count;
        (*ptr).obj.pages = pages;
    }

    if !table.art.insert(id as u64, ptr as usize) {
        free_entry(ptr);
        port::destroy(port);
        return None;
    }

    Some(id)
}

/// Clone a memory object for COW. Creates a new object that shares all
/// physical pages with the original. Both objects are placed in the same
/// COW sharing group so that page ownership can be determined by scanning
/// siblings rather than maintaining per-PFN refcounts.
pub fn clone_for_cow(src_id: ObjectId) -> Option<ObjectId> {
    let mut table = OBJ_TABLE.lock();

    // Step 1: read source state, assign COW group, copy pages.
    let (page_count, group, new_pages) = {
        let src = table.get_mut(src_id)?;
        if src.obj.cow_group == 0 {
            let mut g = NEXT_COW_GROUP.lock();
            src.obj.cow_group = *g;
            *g = g.wrapping_add(1);
            if *g == 0 { *g = 1; }
        }
        let group = src.obj.cow_group;
        let page_count = src.obj.page_count;
        let mut new_pages = PageVec::with_capacity(page_count as usize)?;
        new_pages.copy_from(&src.obj.pages, page_count as usize);
        (page_count, group, new_pages)
    };

    // Step 2: allocate entry + kernel port.
    let id = table.next_id;
    table.next_id += 1;

    let port = port::create_kernel_port(object_port_handler, id as usize)?;
    let ptr = match alloc_entry() {
        Some(p) => p,
        None => { port::destroy(port); return None; }
    };

    // Step 3: initialize destination.
    unsafe {
        (*ptr).port_id = port;
        (*ptr).obj.obj_type = ObjectType::Anonymous;
        (*ptr).obj.page_count = page_count;
        (*ptr).obj.cow_group = group;
        (*ptr).obj.pages = new_pages;
    }

    if !table.art.insert(id as u64, ptr as usize) {
        free_entry(ptr);
        port::destroy(port);
        return None;
    }

    Some(id)
}

/// Destroy a memory object, freeing physical pages not shared with siblings.
pub fn destroy(id: ObjectId) {
    let mut table = OBJ_TABLE.lock();

    let entry = match table.get(id) {
        Some(e) => e as *const ObjEntry as *mut ObjEntry,
        None => return,
    };

    let (group, page_count, port_id) = unsafe {
        ((*entry).obj.cow_group, (*entry).obj.page_count as usize, (*entry).port_id)
    };

    // Free each page, checking siblings in the same COW group.
    for p in 0..page_count {
        let pa = unsafe { (*entry).obj.pages.get(p) };
        if pa == 0 { continue; }

        let shared = group != 0 && {
            let mut found = false;
            table.art.for_each(|key, val| {
                if found { return; }
                if key == id as u64 { return; }
                let sib = unsafe { &*(val as *const ObjEntry) };
                if sib.obj.obj_type != ObjectType::Free
                    && sib.obj.cow_group == group
                    && sib.obj.pages.contains(sib.obj.page_count as usize, pa)
                {
                    found = true;
                }
            });
            found
        };
        if !shared {
            phys::free_page(PhysAddr::new(pa));
        }
        unsafe { (*entry).obj.pages.set(p, 0); }
    }

    // Free PageVec heap.
    unsafe {
        (*entry).obj.pages.free_heap();
        (*entry).obj.obj_type = ObjectType::Free;
        (*entry).obj.page_count = 0;
        (*entry).obj.cow_group = 0;
    }

    // Remove from ART and free slab.
    table.art.remove(id as u64);
    free_entry(entry);
    drop(table);

    if port_id != 0 {
        port::destroy(port_id);
    }
}

/// Access an object by ID within a closure.
/// All callers are serialized by the global object table lock.
pub fn with_object<F, R>(id: ObjectId, f: F) -> R
where
    F: FnOnce(&mut MemObject) -> R,
{
    let mut table = OBJ_TABLE.lock();
    let entry = table.get_mut(id).expect("with_object: invalid ObjectId");
    f(&mut entry.obj)
}

/// Get the port ID for an object.
pub fn object_port(id: ObjectId) -> PortId {
    let table = OBJ_TABLE.lock();
    match table.get(id) {
        Some(e) => e.port_id,
        None => 0,
    }
}

/// Check whether a physical page at `page_idx` in object `obj_id` is shared
/// with any sibling in the same COW group.
pub fn is_page_shared(obj_id: ObjectId, page_idx: usize) -> bool {
    let table = OBJ_TABLE.lock();
    let entry = match table.get(obj_id) {
        Some(e) => e,
        None => return false,
    };
    let group = entry.obj.cow_group;
    let pa = entry.obj.pages.get(page_idx);
    if group == 0 || pa == 0 {
        return false;
    }

    let mut shared = false;
    table.art.for_each(|key, val| {
        if shared { return; }
        if key == obj_id as u64 { return; }
        let sib = unsafe { &*(val as *const ObjEntry) };
        if sib.obj.obj_type != ObjectType::Free
            && sib.obj.cow_group == group
            && sib.obj.pages.contains(sib.obj.page_count as usize, pa)
        {
            shared = true;
        }
    });
    shared
}

/// Release a physical page from object `obj_id` at `page_idx`.
/// If no sibling in the COW group references the same PA, frees the page.
/// Returns true if the physical page was freed, false if still shared.
/// Clears the page entry in either case.
pub fn release_page(obj_id: ObjectId, page_idx: usize) -> bool {
    let mut table = OBJ_TABLE.lock();
    let entry = match table.get_mut(obj_id) {
        Some(e) => e as *mut ObjEntry,
        None => return false,
    };

    let (group, pa) = unsafe {
        let pa = (*entry).obj.pages.get(page_idx);
        if pa == 0 { return false; }
        (*entry).obj.pages.set(page_idx, 0);
        ((*entry).obj.cow_group, pa)
    };

    let shared = group != 0 && {
        let mut found = false;
        table.art.for_each(|key, val| {
            if found { return; }
            if key == obj_id as u64 { return; }
            let sib = unsafe { &*(val as *const ObjEntry) };
            if sib.obj.obj_type != ObjectType::Free
                && sib.obj.cow_group == group
                && sib.obj.pages.contains(sib.obj.page_count as usize, pa)
            {
                found = true;
            }
        });
        found
    };

    if !shared {
        phys::free_page(PhysAddr::new(pa));
        true
    } else {
        false
    }
}
