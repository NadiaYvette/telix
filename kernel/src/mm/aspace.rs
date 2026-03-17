//! Address space — per-task virtual memory management.
//!
//! Each address space owns a page table root and a B+ tree of VMAs.
//! The WSCLOCK clock hand (VmaCursor) is also stored here.

use super::object::{self};
use super::vma::{Vma, VmaProt};
use super::vmatree::{VmaCursor, VmaTree};
use crate::sync::SpinLock;

/// Maximum number of address spaces.
pub const MAX_ASPACES: usize = 16;

/// Address space ID type.
pub type ASpaceId = u32;

/// Heap VA base: 8 GiB (above ELF load at 4 GiB, below stack).
pub const HEAP_VA_BASE: usize = 0x2_0000_0000;

/// An address space.
pub struct AddressSpace {
    /// Physical address of the page table root (L0/PML4/root table).
    pub page_table_root: usize,
    /// VMAs in this address space (B+ tree keyed by VA interval).
    pub vmas: VmaTree,
    /// Whether this address space slot is in use.
    pub active: bool,
    /// WSCLOCK clock hand.
    pub clock_hand: VmaCursor,
    /// Address space ID.
    pub id: ASpaceId,
    /// Bump pointer for heap VA allocation.
    pub heap_next: usize,
}

impl AddressSpace {
    const fn empty() -> Self {
        Self {
            page_table_root: 0,
            vmas: VmaTree::new(),
            active: false,
            clock_hand: VmaCursor::new(),
            id: 0,
            heap_next: HEAP_VA_BASE,
        }
    }

    /// Map an anonymous region into this address space.
    /// Returns a mutable reference to the new VMA on success.
    pub fn map_anon(
        &mut self,
        va_start: usize,
        page_count: usize,
        prot: VmaProt,
    ) -> Option<&mut Vma> {
        // Create the backing memory object.
        let obj_id = object::create_anon(page_count as u16)?;

        // Register the mapping in the object.
        object::with_object(obj_id, |obj| {
            obj.add_mapping(self.id, va_start);
        });

        // Insert into the VMA tree.
        let va_len = page_count * super::page::PAGE_SIZE;
        match self.vmas.insert(va_start, va_len, prot, obj_id, 0) {
            Some(vma) => Some(vma),
            None => {
                // OOM — clean up.
                object::destroy(obj_id);
                None
            }
        }
    }

    /// Allocate `page_count` pages of heap VA space (bump pointer).
    pub fn alloc_heap_va(&mut self, page_count: usize) -> usize {
        let va = self.heap_next;
        self.heap_next += page_count * super::page::PAGE_SIZE;
        va
    }

    /// Find the VMA containing `va` and return a mutable reference.
    pub fn find_vma_mut(&mut self, va: usize) -> Option<&mut Vma> {
        self.vmas.find_mut(va)
    }

    /// Find the VMA containing `va` (immutable).
    pub fn find_vma(&self, va: usize) -> Option<&Vma> {
        self.vmas.find(va)
    }
}

/// Global address space table.
static ASPACES: SpinLock<ASpaceTable> = SpinLock::new(ASpaceTable::new());

struct ASpaceTable {
    spaces: [AddressSpace; MAX_ASPACES],
    next_id: ASpaceId,
}

impl ASpaceTable {
    const fn new() -> Self {
        Self {
            spaces: {
                const EMPTY: AddressSpace = AddressSpace::empty();
                [EMPTY; MAX_ASPACES]
            },
            next_id: 1,
        }
    }
}

/// Create a new address space with the given page table root.
/// Returns the address space ID.
pub fn create(page_table_root: usize) -> Option<ASpaceId> {
    let mut table = ASPACES.lock();
    let id = table.next_id;
    for space in table.spaces.iter_mut() {
        if !space.active {
            space.active = true;
            space.id = id;
            space.page_table_root = page_table_root;
            space.clock_hand = VmaCursor::new();
            space.heap_next = HEAP_VA_BASE;
            table.next_id = id + 1;
            return Some(id);
        }
    }
    None
}

/// Destroy an address space.
pub fn destroy(id: ASpaceId) {
    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            // Destroy backing objects for all VMAs.
            {
                let mut it = space.vmas.iter();
                while let Some(vma) = it.next() {
                    if vma.active {
                        object::destroy(vma.object_id);
                    }
                }
            }
            space.vmas.clear();
            space.active = false;
            return;
        }
    }
}

/// Unmap an anonymous region from an address space.
/// Unmaps PTEs, removes VMA, destroys backing object.
pub fn unmap_anon(id: ASpaceId, va: usize) -> bool {
    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            let pt_root = space.page_table_root;
            // Find the VMA and collect info needed for cleanup.
            let info = if let Some(vma) = space.find_vma(va) {
                let obj_id = vma.object_id;
                let va_start = vma.va_start;
                let mmu_count = vma.mmu_page_count();
                // Unmap all installed PTEs.
                for mmu_idx in 0..mmu_count {
                    if vma.is_installed(mmu_idx) {
                        let mmu_va = va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                        unmap_single_mmupage(pt_root, mmu_va);
                    }
                }
                // Remove object mapping record.
                object::with_object(obj_id, |obj| {
                    obj.remove_mapping(id, va_start);
                });
                Some((va_start, obj_id))
            } else {
                None
            };

            if let Some((va_start, obj_id)) = info {
                space.vmas.remove(va_start);
                // Destroy object (frees phys pages) — acquires OBJECTS lock.
                object::destroy(obj_id);
                return true;
            }
            return false;
        }
    }
    false
}

fn unmap_single_mmupage(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::unmap_single_mmupage(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::unmap_single_mmupage(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::unmap_single_mmupage(pt_root, va); }
}

/// Access an address space by ID within a closure.
pub fn with_aspace<F, R>(id: ASpaceId, f: F) -> R
where
    F: FnOnce(&mut AddressSpace) -> R,
{
    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            return f(space);
        }
    }
    panic!("aspace {} not found", id);
}
