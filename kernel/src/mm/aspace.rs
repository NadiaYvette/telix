//! Address space — per-task virtual memory management.
//!
//! Each address space owns a page table root and a set of VMAs.
//! The WSCLOCK clock hand state is also stored here.

use super::object::{self, ObjectId};
use super::vma::{Vma, VmaProt, MAX_VMAS};
use crate::sync::SpinLock;

/// Maximum number of address spaces.
pub const MAX_ASPACES: usize = 16;

/// Address space ID type.
pub type ASpaceId = u32;

/// WSCLOCK clock hand position.
#[derive(Clone, Copy)]
pub struct ClockHand {
    pub vma_idx: usize,
    pub mmu_page_offset: usize,
}

impl ClockHand {
    const fn new() -> Self {
        Self {
            vma_idx: 0,
            mmu_page_offset: 0,
        }
    }
}

/// An address space.
pub struct AddressSpace {
    /// Physical address of the page table root (L0/PML4/root table).
    pub page_table_root: usize,
    /// VMAs in this address space.
    pub vmas: [Vma; MAX_VMAS],
    /// Whether this address space slot is in use.
    pub active: bool,
    /// WSCLOCK clock hand.
    pub clock_hand: ClockHand,
    /// Address space ID.
    pub id: ASpaceId,
}

impl AddressSpace {
    const fn empty() -> Self {
        Self {
            page_table_root: 0,
            vmas: {
                const EMPTY_VMA: Vma = Vma::empty();
                [EMPTY_VMA; MAX_VMAS]
            },
            active: false,
            clock_hand: ClockHand::new(),
            id: 0,
        }
    }

    /// Map an anonymous region into this address space.
    /// Returns the VMA index on success.
    pub fn map_anon(
        &mut self,
        va_start: usize,
        page_count: usize,
        prot: VmaProt,
    ) -> Option<usize> {
        // Create the backing memory object.
        let obj_id = object::create_anon(page_count as u16)?;

        // Register the mapping in the object.
        object::with_object(obj_id, |obj| {
            obj.add_mapping(self.id, va_start);
        });

        // Find a free VMA slot.
        for (i, vma) in self.vmas.iter_mut().enumerate() {
            if !vma.active {
                vma.va_start = va_start;
                vma.va_len = page_count * super::page::PAGE_SIZE;
                vma.prot = prot;
                vma.object_id = obj_id;
                vma.object_offset = 0;
                vma.installed = [0; (super::vma::MAX_VMA_MMUPAGES + 63) / 64];
                vma.zeroed = [0; (super::vma::MAX_VMA_MMUPAGES + 63) / 64];
                vma.active = true;
                return Some(i);
            }
        }
        // No free VMA slot — clean up.
        object::destroy(obj_id);
        None
    }

    /// Find the VMA containing virtual address `va`.
    pub fn find_vma(&self, va: usize) -> Option<usize> {
        for (i, vma) in self.vmas.iter().enumerate() {
            if vma.active && vma.contains(va) {
                return Some(i);
            }
        }
        None
    }

    /// Find the VMA containing `va` and return a mutable reference.
    pub fn find_vma_mut(&mut self, va: usize) -> Option<&mut Vma> {
        for vma in self.vmas.iter_mut() {
            if vma.active && vma.contains(va) {
                return Some(vma);
            }
        }
        None
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
            space.clock_hand = ClockHand::new();
            // Increment after successful allocation.
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
            for vma in space.vmas.iter_mut() {
                if vma.active {
                    object::destroy(vma.object_id);
                    *vma = Vma::empty();
                }
            }
            space.active = false;
            return;
        }
    }
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
