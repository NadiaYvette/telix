//! Address space — per-task virtual memory management.
//!
//! Each address space owns a page table root and a B+ tree of VMAs.
//! The WSCLOCK clock hand (VmaCursor) is also stored here.

use super::object::{self};
use super::vma::{Vma, VmaProt};
use super::vmatree::{VmaCursor, VmaTree};
use crate::sync::SpinLock;

/// Maximum number of address spaces.
pub const MAX_ASPACES: usize = 32;

/// Address space ID type.
pub type ASpaceId = u32;

/// Heap VA base: 8 GiB (above ELF load at 4 GiB, below stack).
pub const HEAP_VA_BASE: usize = 0x2_0000_0000;

/// MAP_FIXED_NOREPLACE: fail instead of replacing existing mappings.
pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;

/// Simple xorshift64 PRNG for ASLR.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

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
    /// PRNG state for ASLR.
    pub prng_state: u64,
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
            prng_state: 0,
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

    /// Check if a VA range overlaps any existing VMA.
    pub fn overlaps_vma(&self, va_start: usize, len: usize) -> bool {
        // Check if any VMA overlaps [va_start, va_start + len).
        let mut it = self.vmas.iter();
        while let Some(vma) = it.next() {
            if vma.active {
                let vma_end = vma.va_start + vma.va_len;
                let range_end = va_start + len;
                if va_start < vma_end && range_end > vma.va_start {
                    return true;
                }
            }
        }
        false
    }

    /// Allocate `page_count` pages of heap VA space with ASLR.
    pub fn alloc_heap_va(&mut self, page_count: usize) -> usize {
        let va = self.heap_next;
        self.heap_next += page_count * super::page::PAGE_SIZE;
        va
    }

    /// Generate a random ASLR offset (in pages, 0..max_pages).
    pub fn random_pages(&mut self, max_pages: usize) -> usize {
        if self.prng_state == 0 || max_pages == 0 {
            return 0;
        }
        (xorshift64(&mut self.prng_state) as usize) % max_pages
    }

    /// Find the VMA containing `va` and return a mutable reference.
    pub fn find_vma_mut(&mut self, va: usize) -> Option<&mut Vma> {
        self.vmas.find_mut(va)
    }

    /// Find the VMA containing `va` (immutable).
    pub fn find_vma(&self, va: usize) -> Option<&Vma> {
        self.vmas.find(va)
    }

    /// MADV_DONTNEED: clear PTEs in [va_start, va_end).
    /// VMAs stay mapped — next access triggers zero-fill page fault.
    pub fn madvise_dontneed(&mut self, va_start: usize, va_end: usize) {
        let pt_root = self.page_table_root;
        let mmu_size = super::page::MMUPAGE_SIZE;
        // Walk each MMU page and clear PTE (including SW_ZEROED) so re-fault re-zeros.
        let mut va = va_start & !(mmu_size - 1);
        while va < va_end {
            if self.vmas.find(va).is_some() {
                super::fault::clear_pte_dispatch(pt_root, va);
            }
            va += mmu_size;
        }
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

/// Access an address space by ID with a mutable closure.
pub fn with_aspace_mut<R>(id: ASpaceId, f: impl FnOnce(&mut AddressSpace) -> R) -> Option<R> {
    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            return Some(f(space));
        }
    }
    None
}

/// Read a timer/cycle counter for PRNG seeding.
fn seed_from_timer() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let val: u64;
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) val); }
        val
    }
    #[cfg(target_arch = "riscv64")]
    {
        let val: u64;
        unsafe { core::arch::asm!("rdcycle {}", out(reg) val); }
        val
    }
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi); }
        ((hi as u64) << 32) | (lo as u64)
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
            // Seed PRNG and apply initial ASLR offset to heap base.
            let seed = seed_from_timer() ^ (id as u64 * 0x9e3779b97f4a7c15);
            space.prng_state = if seed == 0 { 1 } else { seed };
            // Randomize heap start by 0-255 pages (0-1MB on 4K pages).
            let offset_pages = (xorshift64(&mut space.prng_state) as usize) % 256;
            space.heap_next = HEAP_VA_BASE + offset_pages * super::page::PAGE_SIZE;
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

/// Reset an address space: destroy all VMAs and backing objects but keep the
/// slot active. Used by execve to replace the address space contents without
/// destroying the aspace itself. The page table intermediate pages are freed
/// by the caller (who also sets up a fresh page table).
pub fn reset(id: ASpaceId, new_pt_root: usize) {
    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            let old_pt_root = space.page_table_root;
            // Destroy backing objects for all VMAs.
            // First unmap all installed PTEs.
            {
                let mut it = space.vmas.iter();
                while let Some(vma) = it.next() {
                    if vma.active {
                        let mmu_count = vma.mmu_page_count();
                        // Demote superpages first.
                        {
                            let super_size = 2 * 1024 * 1024;
                            let flags = super::fault::pte_flags_for_vma_pub(vma);
                            let mut m = 0;
                            while m < mmu_count {
                                let mmu_va = vma.va_start + m * super::page::MMUPAGE_SIZE;
                                let super_va = mmu_va & !(super_size - 1);
                                if super::fault::is_superpage_mapped(old_pt_root, super_va).is_some() {
                                    super::fault::demote_superpage(old_pt_root, super_va, flags);
                                }
                                let next = ((super_va + super_size) - vma.va_start) / super::page::MMUPAGE_SIZE;
                                m = if next > m { next } else { m + (super_size / super::page::MMUPAGE_SIZE) };
                            }
                        }
                        // No need to unmap individual PTEs — the entire old page table
                        // tree will be freed below and switch_page_table flushes TLB.
                        object::with_object(vma.object_id, |obj| {
                            obj.remove_mapping(id, vma.va_start);
                        });
                        object::destroy(vma.object_id);
                    }
                }
            }
            space.vmas.clear();
            space.page_table_root = new_pt_root;
            // Re-seed PRNG and randomize heap base for the new image.
            let seed = seed_from_timer() ^ (space.id as u64 * 0x9e3779b97f4a7c15);
            space.prng_state = if seed == 0 { 1 } else { seed };
            let offset_pages = (xorshift64(&mut space.prng_state) as usize) % 256;
            space.heap_next = HEAP_VA_BASE + offset_pages * super::page::PAGE_SIZE;
            space.clock_hand = VmaCursor::new();

            // Free old page table tree.
            if old_pt_root != 0 {
                free_page_table_tree(old_pt_root);
            }
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
                // Unmap all PTEs (unconditional — page table is source of truth).
                for mmu_idx in 0..mmu_count {
                    let mmu_va = va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                    super::fault::clear_pte_dispatch(pt_root, mmu_va);
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
                // Destroy object only if no other mappings reference it.
                let remaining = object::with_object(obj_id, |obj| obj.mapping_count());
                if remaining == 0 {
                    object::destroy(obj_id);
                }
                return true;
            }
            return false;
        }
    }
    false
}

#[allow(dead_code)]
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
            vma_infos[vma_count] = Some(VmaInfo {
                va_start: vma.va_start,
                va_len: vma.va_len,
                prot: vma.prot,
                object_id: vma.object_id,
                object_offset: vma.object_offset,
            });
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
            child.vmas.insert(
                info.va_start, info.va_len, info.prot,
                new_obj_ids[i], info.object_offset,
            );

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
                    let va = info.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                    let pte = super::fault::read_pte_dispatch(parent_pt, va);
                    if super::fault::pte_is_present(pte) {
                        downgrade_pte_readonly(parent_pt, va);
                        downgrade_pte_readonly(child_pt, va);
                    }
                }
            }

            // For child: install PTEs for all present MMU pages (walk parent page table).
            let sw_z = super::fault::sw_zeroed_bit();
            let mmu_count = info.va_len / super::page::MMUPAGE_SIZE;
            for mmu_idx in 0..mmu_count {
                let va = info.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                let pte = super::fault::read_pte_dispatch(parent_pt, va);
                if super::fault::pte_is_present(pte) {
                    if let Some(pa) = translate_va(parent_pt, va) {
                        let pa_page = pa & !(super::page::MMUPAGE_SIZE - 1);
                        // Use read-only flags for writable VMAs (COW), normal flags for others.
                        let flags = if info.prot.writable() {
                            ro_flags_for_prot(info.prot)
                        } else {
                            rw_flags_for_prot(info.prot)
                        };
                        map_single_mmupage(child_pt, va, pa_page, flags | sw_z);
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
            VmaProt::None => 0,
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
            VmaProt::None => 0,
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
            VmaProt::None => 0,
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

/// Change the protection of a virtual address range within an address space.
/// `addr` and `len` must be MMUPAGE_SIZE-aligned. Handles VMA splitting if the
/// range doesn't align to VMA boundaries.
/// Returns true on success.
pub fn mprotect(id: ASpaceId, addr: usize, len: usize, new_prot: VmaProt) -> bool {
    use super::page::MMUPAGE_SIZE;

    if addr % MMUPAGE_SIZE != 0 || len % MMUPAGE_SIZE != 0 || len == 0 {
        return false;
    }

    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            let pt_root = space.page_table_root;
            let end = addr + len;

            // First pass: split VMAs at boundaries if needed.
            // Split at `addr` if it falls in the middle of a VMA.
            if let Some(vma) = space.vmas.find(addr) {
                if vma.va_start < addr {
                    let split_at = addr;
                    let orig_start = vma.va_start;
                    let orig_len = vma.va_len;
                    let orig_prot = vma.prot;
                    let orig_obj = vma.object_id;
                    let orig_off = vma.object_offset;
                    let left_mmu = (split_at - orig_start) / MMUPAGE_SIZE;

                    // Remove old VMA and insert two new ones.
                    // No bitmap copying needed — page table is source of truth.
                    space.vmas.remove(orig_start);
                    let left_len = split_at - orig_start;
                    let right_len = orig_len - left_len;
                    let right_off = orig_off + (left_mmu as u32);

                    super::object::with_object(orig_obj, |obj| {
                        obj.add_mapping(id, split_at);
                    });

                    space.vmas.insert(orig_start, left_len, orig_prot, orig_obj, orig_off);
                    space.vmas.insert(split_at, right_len, orig_prot, orig_obj, right_off);
                }
            }

            // Split at `end` if it falls in the middle of a VMA.
            if let Some(vma) = space.vmas.find(end.saturating_sub(1)) {
                let vma_end = vma.va_start + vma.va_len;
                if end < vma_end && end > vma.va_start {
                    let split_at = end;
                    let orig_start = vma.va_start;
                    let orig_len = vma.va_len;
                    let orig_prot = vma.prot;
                    let orig_obj = vma.object_id;
                    let orig_off = vma.object_offset;
                    let left_mmu = (split_at - orig_start) / MMUPAGE_SIZE;

                    space.vmas.remove(orig_start);
                    let left_len = split_at - orig_start;
                    let right_len = orig_len - left_len;
                    let right_off = orig_off + (left_mmu as u32);

                    super::object::with_object(orig_obj, |obj| {
                        obj.add_mapping(id, split_at);
                    });

                    space.vmas.insert(orig_start, left_len, orig_prot, orig_obj, orig_off);
                    space.vmas.insert(split_at, right_len, orig_prot, orig_obj, right_off);
                }
            }

            // Second pass: update protection on all VMAs fully within [addr, end).
            let mut it = space.vmas.iter();
            while let Some(vma) = it.next() {
                if !vma.active { continue; }
                if vma.va_start >= end { break; }
                let vma_end = vma.va_start + vma.va_len;
                if vma_end <= addr { continue; }

                // This VMA should be fully within [addr, end) after splitting.
                if vma.va_start >= addr && vma_end <= end {
                    let old_prot = vma.prot;
                    vma.prot = new_prot;

                    // Update PTE flags for all present MMU pages.
                    if old_prot != new_prot {
                        let new_flags = rw_flags_for_prot(new_prot);
                        let mmu_count = vma.mmu_page_count();

                        // Demote superpages first.
                        {
                            let super_size = 2 * 1024 * 1024;
                            let old_flags = rw_flags_for_prot(old_prot);
                            let mut m = 0;
                            while m < mmu_count {
                                let mmu_va = vma.va_start + m * MMUPAGE_SIZE;
                                let super_va = mmu_va & !(super_size - 1);
                                if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
                                    super::fault::demote_superpage(pt_root, super_va, old_flags);
                                }
                                let next = ((super_va + super_size) - vma.va_start) / MMUPAGE_SIZE;
                                m = if next > m { next } else { m + (super_size / MMUPAGE_SIZE) };
                            }
                        }

                        for mmu_idx in 0..mmu_count {
                            let mmu_va = vma.va_start + mmu_idx * MMUPAGE_SIZE;
                            let pte = super::fault::read_pte_dispatch(pt_root, mmu_va);
                            if super::fault::pte_is_present(pte) {
                                update_pte_flags(pt_root, mmu_va, new_flags);
                            }
                        }
                    }
                }
            }

            return true;
        }
    }
    false
}

/// Remap (resize) an anonymous mapping. Supports grow and shrink.
/// `old_addr` must be the start of an existing VMA.
/// `old_len` must match the VMA length.
/// `new_len` is the desired new length (MMUPAGE_SIZE-aligned).
/// Returns the new VA (same as old_addr on success), or 0 on error.
pub fn mremap(id: ASpaceId, old_addr: usize, old_len: usize, new_len: usize) -> usize {
    use super::page::{MMUPAGE_SIZE, PAGE_SIZE};

    if old_addr % MMUPAGE_SIZE != 0 || old_len % MMUPAGE_SIZE != 0
        || new_len % MMUPAGE_SIZE != 0 || new_len == 0
    {
        return 0;
    }

    let mut table = ASPACES.lock();
    for space in table.spaces.iter_mut() {
        if space.active && space.id == id {
            let pt_root = space.page_table_root;

            let vma = match space.find_vma_mut(old_addr) {
                Some(v) => v,
                None => return 0,
            };

            if vma.va_start != old_addr || vma.va_len != old_len {
                return 0;
            }

            if new_len == old_len {
                return old_addr;
            }

            if new_len < old_len {
                // Shrink: unmap excess MMU pages, truncate VMA.
                let old_mmu = old_len / MMUPAGE_SIZE;
                let new_mmu = new_len / MMUPAGE_SIZE;

                // Demote superpages in the excess region.
                {
                    let super_size = 2 * 1024 * 1024;
                    let flags = super::fault::pte_flags_for_vma_pub(vma);
                    let mut m = new_mmu;
                    while m < old_mmu {
                        let mmu_va = old_addr + m * MMUPAGE_SIZE;
                        let super_va = mmu_va & !(super_size - 1);
                        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
                            super::fault::demote_superpage(pt_root, super_va, flags);
                        }
                        let next = ((super_va + super_size) - old_addr) / MMUPAGE_SIZE;
                        m = if next > m { next } else { m + (super_size / MMUPAGE_SIZE) };
                    }
                }

                // Clear all PTEs in the excess region.
                for mmu_idx in new_mmu..old_mmu {
                    let mmu_va = old_addr + mmu_idx * MMUPAGE_SIZE;
                    super::fault::clear_pte_dispatch(pt_root, mmu_va);
                }

                vma.va_len = new_len;

                // Free excess backing pages that are no longer referenced.
                let new_page_count = (new_len + PAGE_SIZE - 1) / PAGE_SIZE;
                let old_page_count = (old_len + PAGE_SIZE - 1) / PAGE_SIZE;
                let obj_id = vma.object_id;

                if new_page_count < old_page_count {
                    for p in new_page_count..old_page_count {
                        super::object::release_page(obj_id, p);
                    }
                    super::object::with_object(obj_id, |obj| {
                        obj.page_count = new_page_count as u16;
                    });
                }

                return old_addr;
            }

            // Grow: extend VMA and object.
            let new_page_count = (new_len + PAGE_SIZE - 1) / PAGE_SIZE;
            let obj_id = vma.object_id;

            // Check if the object can hold the new page count.
            let can_grow = super::object::with_object(obj_id, |obj| {
                new_page_count <= obj.phys_pages.len()
            });
            if !can_grow {
                return 0;
            }

            // Check no overlapping VMA exists in the growth region.
            let growth_start = old_addr + old_len;
            let growth_end = old_addr + new_len;
            let mut overlap = false;
            {
                let mut it = space.vmas.iter();
                while let Some(v) = it.next() {
                    if !v.active { continue; }
                    if v.va_start == old_addr { continue; } // skip self
                    let v_end = v.va_start + v.va_len;
                    if v.va_start < growth_end && v_end > growth_start {
                        overlap = true;
                        break;
                    }
                }
            }
            if overlap {
                return 0;
            }

            // Extend the VMA and object.
            let vma = space.find_vma_mut(old_addr).unwrap();
            vma.va_len = new_len;
            super::object::with_object(obj_id, |obj| {
                if (new_page_count as u16) > obj.page_count {
                    obj.page_count = new_page_count as u16;
                }
            });

            return old_addr;
        }
    }
    0
}

fn update_pte_flags(pt_root: usize, va: usize, flags: u64) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::update_pte_flags(pt_root, va, flags); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::update_pte_flags(pt_root, va, flags); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::update_pte_flags(pt_root, va, flags); }
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
