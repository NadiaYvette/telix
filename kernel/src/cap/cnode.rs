//! CNode: capability storage node — a dynamically-sized array of capability slots.
//!
//! Slots are backed by a single physical page, allocated lazily on first use.
//! At 64 KiB pages and 24-byte capabilities: ~2730 slots per CNode.

use super::capability::Capability;
use crate::mm::page;
use crate::mm::phys;

/// Number of capability slots that fit in one page.
pub fn cnode_slots() -> usize {
    page::page_size() / core::mem::size_of::<Capability>()
}

/// A capability storage node: a page-backed array of capability slots.
pub struct CNode {
    slots: *mut Capability,
    num_slots: usize,
}

// Safety: the slots pointer is set once (on first use) and only accessed
// under the per-task cap_lock.
unsafe impl Send for CNode {}
unsafe impl Sync for CNode {}

impl CNode {
    pub const fn new() -> Self {
        Self {
            slots: core::ptr::null_mut(),
            num_slots: 0,
        }
    }

    /// Ensure the backing page is allocated. Returns false on OOM.
    fn ensure_slots(&mut self) -> bool {
        if !self.slots.is_null() {
            return true;
        }
        let page = match phys::alloc_page() {
            Some(pa) => pa.as_usize() as *mut Capability,
            None => return false,
        };
        // Zero-initialize — null capabilities have all zero bytes.
        unsafe {
            core::ptr::write_bytes(page as *mut u8, 0, page::page_size());
        }
        self.slots = page;
        self.num_slots = cnode_slots();
        true
    }

    /// Get a reference to a slot by index.
    pub fn get(&self, index: usize) -> Option<&Capability> {
        if index < self.num_slots {
            Some(unsafe { &*self.slots.add(index) })
        } else {
            None
        }
    }

    /// Get a mutable reference to a slot by index.
    #[allow(dead_code)]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Capability> {
        if index < self.num_slots {
            Some(unsafe { &mut *self.slots.add(index) })
        } else {
            None
        }
    }

    /// Insert a capability at the given slot index.
    /// Returns the previous capability in that slot.
    pub fn insert(&mut self, index: usize, cap: Capability) -> Option<Capability> {
        if !self.ensure_slots() {
            return None;
        }
        if index < self.num_slots {
            let slot = unsafe { &mut *self.slots.add(index) };
            let old = *slot;
            *slot = cap;
            Some(old)
        } else {
            None
        }
    }

    /// Remove (null out) the capability at the given slot index.
    /// Returns the removed capability.
    #[allow(dead_code)]
    pub fn remove(&mut self, index: usize) -> Option<Capability> {
        if index < self.num_slots {
            let slot = unsafe { &mut *self.slots.add(index) };
            let old = *slot;
            *slot = Capability::null();
            Some(old)
        } else {
            None
        }
    }

    /// Find the first empty slot. Returns the index or None.
    pub fn find_empty(&mut self) -> Option<usize> {
        if !self.ensure_slots() {
            return None;
        }
        for i in 0..self.num_slots {
            if unsafe { (*self.slots.add(i)).is_null() } {
                return Some(i);
            }
        }
        None
    }

    /// Number of slots available.
    pub fn num_slots(&self) -> usize {
        self.num_slots
    }

    /// Number of non-null capabilities.
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.num_slots {
            if !unsafe { (*self.slots.add(i)).is_null() } {
                n += 1;
            }
        }
        n
    }
}
