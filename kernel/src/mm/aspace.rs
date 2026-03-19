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
                // Demote any superpages before unmapping individual PTEs.
                {
                    let super_size = 2 * 1024 * 1024;
                    let flags = super::fault::pte_flags_for_vma_pub(vma);
                    let mut m = 0;
                    while m < mmu_count {
                        let mmu_va = va_start + m * super::page::MMUPAGE_SIZE;
                        let super_va = mmu_va & !(super_size - 1);
                        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
                            super::fault::demote_superpage(pt_root, super_va, flags);
                        }
                        let next = ((super_va + super_size) - va_start) / super::page::MMUPAGE_SIZE;
                        m = if next > m { next } else { m + (super_size / super::page::MMUPAGE_SIZE) };
                    }
                }
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

/// Clone an address space for COW fork.
/// Creates a new address space sharing all physical pages with the parent.
/// All writable PTEs are downgraded to read-only in both parent and child.
/// Returns (child_aspace_id, child_page_table_root).
pub fn clone_for_cow(parent_id: ASpaceId) -> Option<(ASpaceId, usize)> {
    // Create a new page table.
    let child_pt = create_user_page_table()?;

    let mut table = ASPACES.lock();

    // Find parent.
    let parent_idx = table.spaces.iter().position(|s| s.active && s.id == parent_id)?;

    // Find a free slot for child.
    let child_idx = table.spaces.iter().position(|s| !s.active)?;

    let child_id = table.next_id;
    table.next_id += 1;

    // Initialize child address space.
    table.spaces[child_idx].active = true;
    table.spaces[child_idx].id = child_id;
    table.spaces[child_idx].page_table_root = child_pt;
    table.spaces[child_idx].clock_hand = VmaCursor::new();
    // Copy heap_next from parent so child continues allocating after parent's heap.
    table.spaces[child_idx].heap_next = table.spaces[parent_idx].heap_next;

    // We need to iterate parent VMAs and clone them. To avoid borrow issues
    // with the table, collect VMA info first, then create child VMAs.
    // Collect parent VMA data.
    struct VmaInfo {
        va_start: usize,
        va_len: usize,
        prot: VmaProt,
        object_id: u32,
        object_offset: u32,
        installed: [u64; 64],
        zeroed: [u64; 64],
    }
    let mut vma_infos: [Option<VmaInfo>; 32] = {
        const NONE: Option<VmaInfo> = None;
        [NONE; 32]
    };
    let mut vma_count = 0;

    {
        let parent = &table.spaces[parent_idx];
        let mut it = parent.vmas.iter();
        while let Some(vma) = it.next() {
            if !vma.active || vma_count >= 32 { continue; }
            let mut info = VmaInfo {
                va_start: vma.va_start,
                va_len: vma.va_len,
                prot: vma.prot,
                object_id: vma.object_id,
                object_offset: vma.object_offset,
                installed: [0; 64],
                zeroed: [0; 64],
            };
            let bitmap_words = (vma.mmu_page_count() + 63) / 64;
            for i in 0..bitmap_words.min(64) {
                info.installed[i] = vma.installed[i];
                info.zeroed[i] = vma.zeroed[i];
            }
            vma_infos[vma_count] = Some(info);
            vma_count += 1;
        }
    }

    // Drop the table lock temporarily to clone objects (which locks OBJECTS).
    drop(table);

    // Clone each object for COW and collect new object IDs.
    let mut new_obj_ids: [u32; 32] = [0; 32];
    for i in 0..vma_count {
        if let Some(ref info) = vma_infos[i] {
            match object::clone_for_cow(info.object_id) {
                Some(new_id) => {
                    // Add mapping record for child.
                    object::with_object(new_id, |obj| {
                        obj.add_mapping(child_id, info.va_start);
                    });
                    new_obj_ids[i] = new_id;
                }
                None => {
                    // OOM — clean up already cloned objects.
                    for j in 0..i {
                        object::destroy(new_obj_ids[j]);
                    }
                    // Clean up child aspace.
                    let mut table = ASPACES.lock();
                    table.spaces[child_idx].active = false;
                    drop(table);
                    free_page_table_tree(child_pt);
                    return None;
                }
            }
        }
    }

    // Re-lock and insert VMAs into child, downgrade parent PTEs.
    let mut table = ASPACES.lock();
    let parent_pt = table.spaces[parent_idx].page_table_root;

    for i in 0..vma_count {
        if let Some(ref info) = vma_infos[i] {
            // Insert VMA into child's tree.
            let child = &mut table.spaces[child_idx];
            if let Some(child_vma) = child.vmas.insert(
                info.va_start, info.va_len, info.prot,
                new_obj_ids[i], info.object_offset,
            ) {
                // Copy bitmaps.
                let bitmap_words = (child_vma.mmu_page_count() + 63) / 64;
                for w in 0..bitmap_words.min(64) {
                    child_vma.installed[w] = info.installed[w];
                    child_vma.zeroed[w] = info.zeroed[w];
                }
            }

            // Downgrade writable PTEs in both parent and child.
            // First demote any superpages in the parent so individual PTEs can be downgraded.
            if info.prot.writable() {
                let mmu_count = info.va_len / super::page::MMUPAGE_SIZE;
                // Demote parent superpages covering this VMA.
                {
                    let super_size = 2 * 1024 * 1024;
                    let super_mmu = super_size / super::page::MMUPAGE_SIZE; // 512
                    let flags = rw_flags_for_prot(info.prot);
                    let mut m = 0;
                    while m < mmu_count {
                        let va = info.va_start + m * super::page::MMUPAGE_SIZE;
                        let super_va = va & !(super_size - 1);
                        if super::fault::is_superpage_mapped(parent_pt, super_va).is_some() {
                            super::fault::demote_superpage(parent_pt, super_va, flags);
                            super::stats::SUPERPAGE_DEMOTIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                        }
                        // Jump to next 2 MiB boundary.
                        let next_super = ((super_va + super_size) - info.va_start) / super::page::MMUPAGE_SIZE;
                        m = if next_super > m { next_super } else { m + super_mmu };
                    }
                }
                for mmu_idx in 0..mmu_count {
                    let word = mmu_idx / 64;
                    let bit = mmu_idx % 64;
                    if word < 64 && (info.installed[word] & (1u64 << bit)) != 0 {
                        let va = info.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                        downgrade_pte_readonly(parent_pt, va);
                        downgrade_pte_readonly(child_pt, va);
                    }
                }
            }

            // For child: install PTEs for all installed MMU pages (copy from parent's mappings).
            // We need to map the same physical addresses in the child's page table.
            let mmu_count = info.va_len / super::page::MMUPAGE_SIZE;
            for mmu_idx in 0..mmu_count {
                let word = mmu_idx / 64;
                let bit = mmu_idx % 64;
                if word < 64 && (info.installed[word] & (1u64 << bit)) != 0 {
                    let va = info.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                    // Look up the PA via the parent's page table.
                    if let Some(pa) = translate_va(parent_pt, va) {
                        let pa_page = pa & !(super::page::MMUPAGE_SIZE - 1);
                        // Use read-only flags for writable VMAs (COW), normal flags for others.
                        let flags = if info.prot.writable() {
                            ro_flags_for_prot(info.prot)
                        } else {
                            rw_flags_for_prot(info.prot)
                        };
                        map_single_mmupage(child_pt, va, pa_page, flags);
                    }
                }
            }
        }
    }

    Some((child_id, child_pt))
}

fn ro_flags_for_prot(_prot: VmaProt) -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::USER_RO_FLAGS }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::USER_RO_FLAGS }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::USER_RO_FLAGS }
}

fn rw_flags_for_prot(prot: VmaProt) -> u64 {
    // Inline the flag logic since pte_flags_for_vma needs a Vma reference.
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
}

fn create_user_page_table() -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::setup_tables() }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::setup_tables() }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::create_user_page_table() }
}

fn free_page_table_tree(root: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::free_page_table_tree(root); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::free_page_table_tree(root); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::free_page_table_tree(root); }
}

fn downgrade_pte_readonly(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::downgrade_pte_readonly(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::downgrade_pte_readonly(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::downgrade_pte_readonly(pt_root, va); }
}

fn translate_va(pt_root: usize, va: usize) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::translate_va(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::translate_va(pt_root, va) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::translate_va(pt_root, va) }
}

fn map_single_mmupage(pt_root: usize, va: usize, pa: usize, flags: u64) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::map_single_mmupage(pt_root, va, pa, flags); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::map_single_mmupage(pt_root, va, pa, flags); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::map_single_mmupage(pt_root, va, pa, flags); }
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
