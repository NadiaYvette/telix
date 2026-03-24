//! Memory objects — the backing store for virtual memory.
//!
//! Each memory object represents a logically contiguous region of memory
//! (e.g., an anonymous demand-zero region or a cached file region).
//! Objects track their physical backing (via PageVec) and the
//! set of address spaces that map them.

use super::page::PhysAddr;
use super::pagevec::PageVec;
use super::phys;
use crate::sync::SpinLock;

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

/// Object ID type.
pub type ObjectId = u32;

/// Global object table.
static OBJECTS: SpinLock<ObjectTable> = SpinLock::new(ObjectTable::new());

struct ObjectTable {
    objects: [MemObject; MAX_OBJECTS],
}

impl ObjectTable {
    const fn new() -> Self {
        Self {
            objects: {
                const EMPTY: MemObject = MemObject::empty();
                [EMPTY; MAX_OBJECTS]
            },
        }
    }
}

/// Create a new pager-backed memory object.
/// Returns the object ID.
pub fn create_pager(page_count: u16, file_handle: u32, file_base_offset: u64) -> Option<ObjectId> {
    let mut table = OBJECTS.lock();
    let slot = table.objects.iter().position(|o| o.obj_type == ObjectType::Free)?;
    let pages = PageVec::with_capacity(page_count as usize)?;
    let obj = &mut table.objects[slot];
    obj.obj_type = ObjectType::Pager;
    obj.page_count = page_count;
    obj.pages = pages;
    obj.file_handle = file_handle;
    obj.file_base_offset = file_base_offset;
    Some(slot as ObjectId)
}

/// Create a new anonymous memory object of `page_count` allocation pages.
/// Returns the object ID.
pub fn create_anon(page_count: u16) -> Option<ObjectId> {
    let mut table = OBJECTS.lock();
    let slot = table.objects.iter().position(|o| o.obj_type == ObjectType::Free)?;
    let pages = PageVec::with_capacity(page_count as usize)?;
    let obj = &mut table.objects[slot];
    obj.obj_type = ObjectType::Anonymous;
    obj.page_count = page_count;
    obj.pages = pages;
    Some(slot as ObjectId)
}

/// Next COW group ID counter.
static NEXT_COW_GROUP: crate::sync::SpinLock<u16> = crate::sync::SpinLock::new(1);

/// Clone a memory object for COW. Creates a new object that shares all
/// physical pages with the original. Both objects are placed in the same
/// COW sharing group so that page ownership can be determined by scanning
/// siblings rather than maintaining per-PFN refcounts.
pub fn clone_for_cow(src_id: ObjectId) -> Option<ObjectId> {
    let mut table = OBJECTS.lock();
    let page_count = table.objects[src_id as usize].page_count;

    // Find a free slot.
    let dst_idx = table.objects.iter().position(|o| o.obj_type == ObjectType::Free)?;

    // Allocate PageVec for the clone.
    let mut new_pages = PageVec::with_capacity(page_count as usize)?;
    new_pages.copy_from(&table.objects[src_id as usize].pages, page_count as usize);

    // Assign a COW group if the source doesn't have one yet.
    if table.objects[src_id as usize].cow_group == 0 {
        let mut g = NEXT_COW_GROUP.lock();
        table.objects[src_id as usize].cow_group = *g;
        *g = g.wrapping_add(1);
        if *g == 0 { *g = 1; } // skip 0
    }
    let group = table.objects[src_id as usize].cow_group;

    let obj = &mut table.objects[dst_idx];
    obj.obj_type = ObjectType::Anonymous;
    obj.page_count = page_count;
    obj.cow_group = group;
    obj.pages = new_pages;
    // Clear mappings on the new object (caller will add its own).
    for m in &mut obj.mappings {
        *m = Mapping::empty();
    }

    Some(dst_idx as ObjectId)
}

/// Destroy a memory object, freeing physical pages not shared with siblings.
pub fn destroy(id: ObjectId) {
    let mut table = OBJECTS.lock();
    let group = table.objects[id as usize].cow_group;
    let page_count = table.objects[id as usize].page_count as usize;

    // Free each page, checking siblings in the same COW group.
    for p in 0..page_count {
        let pa = table.objects[id as usize].pages.get(p);
        if pa != 0 {
            let shared = group != 0 && table.objects.iter().enumerate().any(|(i, obj)| {
                i != id as usize
                    && obj.obj_type != ObjectType::Free
                    && obj.cow_group == group
                    && obj.pages.contains(obj.page_count as usize, pa)
            });
            if !shared {
                phys::free_page(PhysAddr::new(pa));
            }
            table.objects[id as usize].pages.set(p, 0);
        }
    }

    // Free the PageVec heap buffer.
    table.objects[id as usize].pages.free_heap();
    table.objects[id as usize].obj_type = ObjectType::Free;
    table.objects[id as usize].page_count = 0;
    table.objects[id as usize].cow_group = 0;
}

/// Access an object by ID within a closure (while holding the lock).
pub fn with_object<F, R>(id: ObjectId, f: F) -> R
where
    F: FnOnce(&mut MemObject) -> R,
{
    let mut table = OBJECTS.lock();
    f(&mut table.objects[id as usize])
}

/// Check whether a physical page at `page_idx` in object `obj_id` is shared
/// with any sibling in the same COW group.
pub fn is_page_shared(obj_id: ObjectId, page_idx: usize) -> bool {
    let table = OBJECTS.lock();
    let obj = &table.objects[obj_id as usize];
    let group = obj.cow_group;
    if group == 0 {
        return false;
    }
    let pa = obj.pages.get(page_idx);
    if pa == 0 {
        return false;
    }
    table.objects.iter().enumerate().any(|(i, sib)| {
        i != obj_id as usize
            && sib.obj_type != ObjectType::Free
            && sib.cow_group == group
            && sib.pages.contains(sib.page_count as usize, pa)
    })
}

/// Release a physical page from object `obj_id` at `page_idx`.
/// If no sibling in the COW group references the same PA, frees the page.
/// Returns true if the physical page was freed, false if still shared.
/// Clears the page entry in either case.
pub fn release_page(obj_id: ObjectId, page_idx: usize) -> bool {
    let mut table = OBJECTS.lock();
    let group = table.objects[obj_id as usize].cow_group;
    let pa = table.objects[obj_id as usize].pages.get(page_idx);
    if pa == 0 {
        return false;
    }
    table.objects[obj_id as usize].pages.set(page_idx, 0);

    let shared = group != 0 && table.objects.iter().enumerate().any(|(i, sib)| {
        i != obj_id as usize
            && sib.obj_type != ObjectType::Free
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
