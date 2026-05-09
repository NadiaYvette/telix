//! Implicit d-ary min-heap (d=4) for EEVDF deadline scheduling.
//!
//! Array-backed, fixed-capacity priority queue optimised for cache locality.
//! With d=4, each sift-down level scans 4 contiguous children (≤2 cache lines),
//! and tree depth is log₄(n) — roughly half that of a binary heap.
//!
//! Empirically validated by Larkin, Sen & Tarjan (2014) as the best-performing
//! priority queue for Dijkstra-like workloads (moderate decrease-key),
//! which matches EEVDF's scheduling pattern.
//!
//! Each thread's position in the heap is tracked via `Thread::eevdf_heap_pos`
//! (updated on every swap). This gives O(1) lookup for `decrease_key` and
//! `remove` — the two operations needed for priority inheritance.

/// Branching factor.  d=4 is the sweet spot per Larkin et al.
const D: usize = 4;

/// Maximum number of entries per heap (one heap per CPU).
/// 512 runnable threads per CPU is extremely generous.
pub const HEAP_CAP: usize = 512;

/// Sentinel value for "not in heap".
pub const HEAP_POS_NONE: u16 = u16::MAX;

/// A single heap entry: virtual-deadline key + thread ID.
#[derive(Clone, Copy)]
#[repr(C)]
struct HeapEntry {
    /// Sort key (virtual deadline).  Lower = more urgent.
    key: u64,
    /// Thread ID.
    tid: u32,
    _pad: u32,
}

impl HeapEntry {
    const ZERO: Self = Self {
        key: 0,
        tid: 0,
        _pad: 0,
    };
}

/// Per-CPU d-4 implicit min-heap.
///
/// All entries live in a flat array.  Parent of node at index `i` is at
/// `(i - 1) / D`; children of node at index `i` are at `D*i + 1 .. D*i + D`.
///
/// The heap is always accessed under the per-CPU run-queue spinlock, so no
/// internal synchronisation is needed.
pub struct Heap4 {
    entries: [HeapEntry; HEAP_CAP],
    len: u32,
    /// Rotating scan-start index for `pick_eligible` tie-breaks.
    ///
    /// Strict-`<` over physical positions means all-equal-deadline ties
    /// always resolve to position 0; the heap then backfills position 0 from
    /// the tail and the just-re-enqueued thread (which lands at the new tail)
    /// wins the next pick — LIFO cycling that starves entries at positions
    /// 1..n-2 indefinitely (#120 dispatch oscillation).
    ///
    /// Rotating the scan start each call gives every position a turn at being
    /// "position 0" without forcing strict FIFO (which broke cache locality
    /// in boot 91amfsq585).  Over `len` consecutive picks each entry gets one
    /// turn at the rotation origin while still benefiting from the heap
    /// property when keys actually differ.
    scan_start: u32,
}

impl Heap4 {
    /// Create an empty heap.  Zero-init is correct: `len=0` means no entries.
    pub const fn new() -> Self {
        Self {
            entries: [HeapEntry::ZERO; HEAP_CAP],
            len: 0,
            scan_start: 0,
        }
    }

    /// Number of entries in the heap.
    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Whether the heap is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate `(tid, key)` for each entry in physical (unsorted) order.
    /// Caller-supplied closure is invoked under whatever lock the caller
    /// holds — used by CALL-TIMEOUT diagnostic dump.
    #[inline]
    pub fn for_each_entry<F: FnMut(u32, u64)>(&self, mut f: F) {
        for i in 0..(self.len as usize) {
            f(self.entries[i].tid, self.entries[i].key);
        }
    }

    /// Peek at the minimum entry without removing it.
    /// Returns `(tid, key)` or `None` if empty.
    #[inline]
    pub fn peek_min(&self) -> Option<(u32, u64)> {
        if self.len == 0 {
            None
        } else {
            Some((self.entries[0].tid, self.entries[0].key))
        }
    }

    /// Insert a thread with the given key.
    ///
    /// Returns `false` if the heap is full (caller should fall back to the
    /// legacy bitmap queue).
    ///
    /// # Safety
    /// Caller must ensure `tid` refers to a valid thread whose
    /// `eevdf_heap_pos` is currently `HEAP_POS_NONE`.
    pub fn insert(&mut self, tid: u32, key: u64) -> bool {
        if self.len as usize >= HEAP_CAP {
            return false;
        }
        let pos = self.len as usize;
        self.entries[pos] = HeapEntry {
            key,
            tid,
            _pad: 0,
        };
        self.len += 1;
        set_heap_pos(tid, pos as u16);
        self.sift_up(pos);
        true
    }

    /// Pick the eligible thread with the earliest deadline.
    ///
    /// Scans all entries and selects the one with minimum key (deadline)
    /// whose thread's `eevdf_vruntime <= max_vruntime`.  If no thread is
    /// eligible, falls back to `pop_min()` to prevent livelock.
    ///
    /// O(n) scan over contiguous 16-byte entries — cache-friendly for
    /// typical run-queue sizes (< 50 threads).
    pub fn pick_eligible(&mut self, max_vruntime: u64) -> Option<(u32, u64)> {
        if self.len == 0 {
            return None;
        }
        let n = self.len as usize;
        let mut best_pos: Option<usize> = None;
        let mut best_key: u64 = u64::MAX;
        // Rotate the scan starting position each call.  Strict-`<` is kept
        // (preserves heap-property selection when keys actually differ) but
        // the *origin* rotates, so equal-key ties don't always go to physical
        // position 0.  See `scan_start` field doc for the LIFO-starvation
        // motivation.
        let start = (self.scan_start as usize) % n;
        for k in 0..n {
            let i = (start + k) % n;
            let e = &self.entries[i];
            let vrt = super::scheduler::thread_ref(e.tid).eevdf_vruntime;
            if vrt <= max_vruntime && e.key < best_key {
                best_key = e.key;
                best_pos = Some(i);
            }
        }
        // Advance scan_start regardless of pick outcome so successive calls
        // visit different origins even when the heap is partially eligible.
        self.scan_start = self.scan_start.wrapping_add(1);
        if let Some(pos) = best_pos {
            Some(self.remove(pos))
        } else {
            // No eligible thread — fall back to earliest deadline to avoid livelock.
            self.pop_min()
        }
    }

    /// Remove and return the minimum entry.
    /// Returns `(tid, key)` or `None` if empty.
    pub fn pop_min(&mut self) -> Option<(u32, u64)> {
        if self.len == 0 {
            return None;
        }
        let root = self.entries[0];
        set_heap_pos(root.tid, HEAP_POS_NONE);
        self.len -= 1;
        if self.len > 0 {
            self.entries[0] = self.entries[self.len as usize];
            set_heap_pos(self.entries[0].tid, 0);
            self.sift_down(0);
        }
        Some((root.tid, root.key))
    }

    /// Decrease (tighten) the key of the entry at position `pos`.
    ///
    /// The caller is responsible for looking up `pos` from
    /// `thread.eevdf_heap_pos` and ensuring `new_key <= old key`.
    pub fn decrease_key(&mut self, pos: usize, new_key: u64) {
        debug_assert!(pos < self.len as usize);
        self.entries[pos].key = new_key;
        self.sift_up(pos);
    }

    /// Remove the entry at position `pos` (arbitrary removal).
    ///
    /// Used when a thread leaves the EEVDF class (e.g. boosted to RT).
    /// Returns `(tid, key)` of the removed entry.
    pub fn remove(&mut self, pos: usize) -> (u32, u64) {
        debug_assert!(pos < self.len as usize);
        let removed = self.entries[pos];
        set_heap_pos(removed.tid, HEAP_POS_NONE);
        self.len -= 1;
        if pos < self.len as usize {
            // Move the last entry into the gap.
            self.entries[pos] = self.entries[self.len as usize];
            set_heap_pos(self.entries[pos].tid, pos as u16);
            // The moved entry may need to go up or down.
            if pos > 0 && self.entries[pos].key < self.entries[parent(pos)].key {
                self.sift_up(pos);
            } else {
                self.sift_down(pos);
            }
        }
        (removed.tid, removed.key)
    }

    /// Find and remove an eligible thread in the given coscheduling group,
    /// preferring the one with the earliest deadline.
    /// Returns `(tid, key)` or `None` if no group mate is present.
    pub fn pop_for_group(&mut self, group: u32, max_vruntime: u64) -> Option<(u32, u64)> {
        let n = self.len as usize;
        let mut best_pos: Option<usize> = None;
        let mut best_key: u64 = u64::MAX;
        for i in 0..n {
            let e = &self.entries[i];
            let t = super::scheduler::thread_ref(e.tid);
            if t.cosched_group.load(core::sync::atomic::Ordering::Relaxed) == group
                && t.eevdf_vruntime <= max_vruntime
                && e.key < best_key
            {
                best_key = e.key;
                best_pos = Some(i);
            }
        }
        best_pos.map(|pos| self.remove(pos))
    }

    /// Update the key of the entry at `pos` to `new_key` (may increase or decrease).
    /// Returns the old key.
    #[allow(dead_code)]
    pub fn update_key(&mut self, pos: usize, new_key: u64) -> u64 {
        debug_assert!(pos < self.len as usize);
        let old_key = self.entries[pos].key;
        self.entries[pos].key = new_key;
        if new_key < old_key {
            self.sift_up(pos);
        } else if new_key > old_key {
            self.sift_down(pos);
        }
        old_key
    }

    // --- Internal sift operations ---

    /// Sift the entry at `pos` upward until the heap property is restored.
    fn sift_up(&mut self, mut pos: usize) {
        while pos > 0 {
            let par = parent(pos);
            if self.entries[pos].key < self.entries[par].key {
                self.swap(pos, par);
                pos = par;
            } else {
                break;
            }
        }
    }

    /// Sift the entry at `pos` downward until the heap property is restored.
    ///
    /// At each level, scans up to `D` children to find the minimum.
    /// The children are at contiguous indices `D*pos+1 .. D*pos+D`, so this
    /// is a single sequential scan over ≤2 cache lines (4 × 16 bytes = 64 bytes).
    fn sift_down(&mut self, mut pos: usize) {
        let n = self.len as usize;
        loop {
            let first_child = D * pos + 1;
            if first_child >= n {
                break; // Leaf node.
            }
            // Find the child with the smallest key.
            let last_child = (first_child + D).min(n);
            let mut min_child = first_child;
            let mut min_key = self.entries[first_child].key;
            for c in (first_child + 1)..last_child {
                if self.entries[c].key < min_key {
                    min_key = self.entries[c].key;
                    min_child = c;
                }
            }
            if min_key < self.entries[pos].key {
                self.swap(pos, min_child);
                pos = min_child;
            } else {
                break;
            }
        }
    }

    /// Swap two entries and update their threads' `heap_pos`.
    #[inline]
    fn swap(&mut self, a: usize, b: usize) {
        self.entries.swap(a, b);
        set_heap_pos(self.entries[a].tid, a as u16);
        set_heap_pos(self.entries[b].tid, b as u16);
    }
}

/// Parent index in a d-ary heap.
#[inline(always)]
const fn parent(i: usize) -> usize {
    (i - 1) / D
}

/// Write `pos` to `thread.eevdf_heap_pos`.
///
/// Called under the per-CPU run-queue spinlock, so the thread is either
/// the running thread on this CPU (exclusively owned) or enqueued (not
/// accessed concurrently).  No atomic needed.
fn set_heap_pos(tid: u32, pos: u16) {
    // Safety: we're under the per-CPU RQ lock. The thread's heap_pos is
    // only read/written by the scheduler on the CPU that owns the thread's
    // run-queue slot.
    unsafe {
        super::scheduler::thread_mut_from_ref(tid).eevdf_heap_pos = pos;
    }
}
