//! Sparse capability set — per-task permission map from 44-bit port locals to
//! 3-bit permission values.
//!
//! Uses an inline array of 32 AtomicU64 entries for lockless reads on the hot
//! path. Each entry packs `port_local[63:8] | perms[7:0]`. An entry of 0 is
//! empty. Mutations happen under the per-task cap_lock.

use core::sync::atomic::{AtomicU64, Ordering};

/// Permission bits stored in the low byte of each entry.
pub const PERM_SEND: u8 = 0b001;
pub const PERM_RECV: u8 = 0b010;
pub const PERM_MANAGE: u8 = 0b100;

/// Maximum inline entries per task. 128 entries × 8 bytes = 1024 bytes.
/// Must be large enough for processes that hold many caps (servers, init).
const INLINE_CAP: usize = 128;

/// Pack a port_local + perms into an entry.
#[inline]
const fn make_entry(port_local: u64, perms: u8) -> u64 {
    (port_local << 8) | (perms as u64)
}

/// Extract the port_local from an entry.
#[inline]
const fn entry_port(e: u64) -> u64 {
    e >> 8
}

/// Extract the perms from an entry.
#[inline]
const fn entry_perms(e: u64) -> u8 {
    (e & 0xFF) as u8
}

/// Per-task sparse capability set.
pub struct CapSet {
    entries: [AtomicU64; INLINE_CAP],
}

impl CapSet {
    pub const fn new() -> Self {
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            entries: [ZERO; INLINE_CAP],
        }
    }

    /// Lockless check: does this set contain `needed_perms` for `port_local`?
    #[inline]
    pub fn has(&self, port_local: u64, needed_perms: u8) -> bool {
        for i in 0..INLINE_CAP {
            let e = self.entries[i].load(Ordering::Relaxed);
            if e == 0 {
                continue;
            }
            if entry_port(e) == port_local {
                return (entry_perms(e) & needed_perms) == needed_perms;
            }
        }
        false
    }

    /// Grant permissions for a port. If an entry exists, OR in the new perms.
    /// Otherwise insert into the first empty slot.
    /// Call under CAP_SYSTEM lock. Returns true on success.
    pub fn grant(&self, port_local: u64, perms: u8) -> bool {
        // Check for existing entry — update perms.
        for i in 0..INLINE_CAP {
            let e = self.entries[i].load(Ordering::Relaxed);
            if e != 0 && entry_port(e) == port_local {
                let new_perms = entry_perms(e) | perms;
                self.entries[i].store(make_entry(port_local, new_perms), Ordering::Relaxed);
                return true;
            }
        }
        // Find empty slot.
        for i in 0..INLINE_CAP {
            if self.entries[i].load(Ordering::Relaxed) == 0 {
                self.entries[i].store(make_entry(port_local, perms), Ordering::Relaxed);
                return true;
            }
        }
        // All slots occupied — evict stale entries (dead ports) and retry.
        let mut evicted = false;
        for i in 0..INLINE_CAP {
            let e = self.entries[i].load(Ordering::Relaxed);
            if e == 0 {
                continue;
            }
            let pl = entry_port(e);
            if !crate::ipc::port::port_is_active_local(pl) {
                self.entries[i].store(0, Ordering::Relaxed);
                evicted = true;
            }
        }
        if evicted {
            // Retry insertion after eviction.
            for i in 0..INLINE_CAP {
                if self.entries[i].load(Ordering::Relaxed) == 0 {
                    self.entries[i].store(make_entry(port_local, perms), Ordering::Relaxed);
                    return true;
                }
            }
        }
        false
    }

    /// Remove all permissions for a port. Call under CAP_SYSTEM lock.
    pub fn remove(&self, port_local: u64) {
        for i in 0..INLINE_CAP {
            let e = self.entries[i].load(Ordering::Relaxed);
            if e != 0 && entry_port(e) == port_local {
                self.entries[i].store(0, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Clear all entries. Call under CAP_SYSTEM lock.
    #[allow(dead_code)]
    pub fn reset(&self) {
        for i in 0..INLINE_CAP {
            self.entries[i].store(0, Ordering::Relaxed);
        }
    }

    /// Check if any entry has RECV permission for `port_local`.
    #[allow(dead_code)]
    #[inline]
    pub fn has_recv(&self, port_local: u64) -> bool {
        self.has(port_local, PERM_RECV)
    }

    /// Copy all entries from another CapSet. Call under CAP_SYSTEM lock.
    pub fn copy_from(&self, other: &CapSet) {
        for i in 0..INLINE_CAP {
            self.entries[i].store(other.entries[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
}
