//! Memory objects — the backing store for virtual memory.
//!
//! Each memory object represents a logically contiguous region of memory
//! (e.g., an anonymous demand-zero region or a cached file region).
//! Objects track their physical backing (via the extent tree) and the
//! set of address spaces that map them.

use super::page::PhysAddr;
use super::phys;
use crate::sync::SpinLock;

/// Maximum number of memory objects.
pub const MAX_OBJECTS: usize = 64;

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
    /// Physical pages backing this object (indexed by page offset within object).
    /// 0 = not yet allocated.
    pub phys_pages: [usize; 256],
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
            phys_pages: [0; 256],
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
        if self.phys_pages[page_idx] != 0 {
            return Some((PhysAddr::new(self.phys_pages[page_idx]), false));
        }
        // Try pre-zeroed pool first, then dirty allocator.
        let (pa, pre_zeroed) = if let Some(pa) = super::zeropool::alloc_zeroed_page() {
            (pa, true)
        } else {
            (phys::alloc_page()?, false)
        };
        self.phys_pages[page_idx] = pa.as_usize();
        super::frame::set_ref(pa, 1);
        Some((pa, pre_zeroed))
    }

    /// Get the physical address of page at offset `page_idx`, or None if not allocated.
    pub fn get_page(&self, page_idx: usize) -> Option<PhysAddr> {
        if page_idx >= self.page_count as usize {
            return None;
        }
        if self.phys_pages[page_idx] == 0 {
            return None;
        }
        Some(PhysAddr::new(self.phys_pages[page_idx]))
    }

    /// Free all physical pages owned by this object.
    /// Decrements reference counts; only frees the physical page when refcount hits 0.
    pub fn free_pages(&mut self) {
        for i in 0..self.page_count as usize {
            if self.phys_pages[i] != 0 {
                let pa = PhysAddr::new(self.phys_pages[i]);
                if super::frame::dec_ref(pa) == 0 {
                    phys::free_page(pa);
                }
                self.phys_pages[i] = 0;
            }
        }
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
        // Can't use array::from_fn in const. Repeat manually.
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
    for (i, obj) in table.objects.iter_mut().enumerate() {
        if obj.obj_type == ObjectType::Free {
            obj.obj_type = ObjectType::Pager;
            obj.page_count = page_count;
            obj.file_handle = file_handle;
            obj.file_base_offset = file_base_offset;
            return Some(i as ObjectId);
        }
    }
    None
}

/// Create a new anonymous memory object of `page_count` allocation pages.
/// Returns the object ID.
pub fn create_anon(page_count: u16) -> Option<ObjectId> {
    let mut table = OBJECTS.lock();
    for (i, obj) in table.objects.iter_mut().enumerate() {
        if obj.obj_type == ObjectType::Free {
            obj.obj_type = ObjectType::Anonymous;
            obj.page_count = page_count;
            return Some(i as ObjectId);
        }
    }
    None
}

/// Clone a memory object for COW. Creates a new object that shares all
/// physical pages with the original (incrementing their refcounts).
/// Returns the new object ID.
pub fn clone_for_cow(src_id: ObjectId) -> Option<ObjectId> {
    let mut table = OBJECTS.lock();
    let page_count = table.objects[src_id as usize].page_count;

    // Find a free slot.
    let mut dst_slot = None;
    for (i, obj) in table.objects.iter().enumerate() {
        if obj.obj_type == ObjectType::Free {
            dst_slot = Some(i);
            break;
        }
    }
    let dst_idx = dst_slot?;

    // Copy physical page pointers and increment refcounts.
    table.objects[dst_idx].obj_type = ObjectType::Anonymous;
    table.objects[dst_idx].page_count = page_count;
    for i in 0..page_count as usize {
        let pa = table.objects[src_id as usize].phys_pages[i];
        table.objects[dst_idx].phys_pages[i] = pa;
        if pa != 0 {
            super::frame::inc_ref(super::page::PhysAddr::new(pa));
        }
    }
    // Clear mappings on the new object (caller will add its own).
    for m in &mut table.objects[dst_idx].mappings {
        *m = Mapping::empty();
    }

    Some(dst_idx as ObjectId)
}

/// Destroy a memory object, freeing all its physical pages.
pub fn destroy(id: ObjectId) {
    let mut table = OBJECTS.lock();
    let obj = &mut table.objects[id as usize];
    obj.free_pages();
    obj.obj_type = ObjectType::Free;
    obj.page_count = 0;
}

/// Access an object by ID within a closure (while holding the lock).
pub fn with_object<F, R>(id: ObjectId, f: F) -> R
where
    F: FnOnce(&mut MemObject) -> R,
{
    let mut table = OBJECTS.lock();
    f(&mut table.objects[id as usize])
}
