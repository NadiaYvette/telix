//! HAMT-based turnstile wait subsystem.
//!
//! Maps generic keys (futex addresses, port IDs) to turnstiles via a Hash
//! Array Mapped Trie (HAMT) with 16 root buckets (each independently locked).
//! Turnstiles are pre-allocated per-thread and lent to the first waiter on
//! a key (Solaris/FreeBSD turnstile lending protocol).
//!
//! Supports both non-PI (futex_wait/wake) and PI (futex_wait_pi/wake_pi)
//! variants. PI uses single-level priority inheritance matching the
//! existing IPC port PI model.
//!
//! Port waiters use the same HAMT with key_type = KEY_PORT_RECV / KEY_PORT_SEND.

use crate::mm::page::PhysAddr;
use crate::mm::slab;
use crate::sched::thread::BlockReason;
use crate::sync::SpinLock;
use core::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel: idle thread (tid=0) never blocks on futex.
const TS_NIL: u32 = 0;

/// Key type discriminators for the generic HAMT.
pub const KEY_FUTEX: u8 = 0;
pub const KEY_PORT_RECV: u8 = 1;
pub const KEY_PORT_SEND: u8 = 2;
/// Parked receiver (recv_or_park) — eligible for direct-transfer injection.
pub const KEY_PORT_RECV_PARK: u8 = 3;

/// HAMT branching factor: 4 bits per level, 16 children per node.
const HAMT_BITS: usize = 4;
const HAMT_WIDTH: usize = 1 << HAMT_BITS;
const HAMT_MASK: u64 = 0xF;

/// Maximum HAMT depth within a bucket (60 bits / 4 bits = 15 levels).
const MAX_LEVEL: usize = 14;

/// Number of root buckets (top 4 hash bits).
const NUM_BUCKETS: usize = 16;

/// Slab sizes.
const NODE_SLAB_SIZE: usize = 128; // HamtNode: 16 * 8 = 128 bytes
const TS_SLAB_SIZE: usize = 64; // Turnstile: ~48 bytes, 64B slab

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

fn futex_hash(aspace_id: u64, va: usize) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in &aspace_id.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    for &b in &(va as u64).to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Hash for port waiter keys (key_type discriminates recv vs send).
fn port_key_hash(port_id: u64, key_type: u8) -> u64 {
    let mut h = FNV_OFFSET;
    h ^= key_type as u64;
    h = h.wrapping_mul(FNV_PRIME);
    for &b in &port_id.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[inline]
fn bucket_index(hash: u64) -> usize {
    ((hash >> 60) & HAMT_MASK) as usize
}

#[inline]
fn nibble_at(hash: u64, level: usize) -> usize {
    ((hash >> (56 - level * 4)) & HAMT_MASK) as usize
}

// ---------------------------------------------------------------------------
// HAMT types
// ---------------------------------------------------------------------------

/// Inner HAMT node: 16 children, direct-indexed by hash nibble.
/// Allocated from 128-byte slab (CACHE_128).
#[repr(C)]
struct HamtNode {
    children: [usize; HAMT_WIDTH],
}

/// Tagged pointer helpers (matches ART convention):
///   0          = empty
///   ptr | 1    = leaf (Turnstile*)
///   ptr (even) = inner HamtNode*
#[inline]
fn is_leaf(tagged: usize) -> bool {
    tagged & 1 != 0
}
#[inline]
fn tag_leaf(ts: *mut Turnstile) -> usize {
    ts as usize | 1
}
#[inline]
fn untag_leaf(tagged: usize) -> *mut Turnstile {
    (tagged & !1) as *mut Turnstile
}

fn alloc_node() -> Option<*mut HamtNode> {
    let pa = slab::alloc(NODE_SLAB_SIZE)?;
    let p = pa.as_usize() as *mut HamtNode;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, NODE_SLAB_SIZE);
    }
    Some(p)
}

fn free_node(p: *mut HamtNode) {
    slab::free(PhysAddr::new(p as usize), NODE_SLAB_SIZE);
}

// ---------------------------------------------------------------------------
// HAMT root and static
// ---------------------------------------------------------------------------

struct HamtRoot {
    children: [usize; HAMT_WIDTH],
}

impl HamtRoot {
    const fn new() -> Self {
        Self {
            children: [0; HAMT_WIDTH],
        }
    }
}

static WAIT_HAMT: [SpinLock<HamtRoot>; NUM_BUCKETS] = {
    const INIT: SpinLock<HamtRoot> = SpinLock::new(HamtRoot::new());
    [INIT; NUM_BUCKETS]
};

// ---------------------------------------------------------------------------
// HAMT operations (operate on locked HamtRoot)
// ---------------------------------------------------------------------------

fn hamt_lookup(
    root: &HamtRoot,
    hash: u64,
    key_type: u8,
    aspace_id: u64,
    va: usize,
) -> Option<*mut Turnstile> {
    let mut slot = root.children[nibble_at(hash, 0)];
    let mut level = 1usize;
    loop {
        if slot == 0 {
            return None;
        }
        if is_leaf(slot) {
            let ts = untag_leaf(slot);
            let t = unsafe { &*ts };
            if t.key_type == key_type && t.aspace_id == aspace_id && t.va == va {
                return Some(ts);
            }
            return None;
        }
        if level > MAX_LEVEL {
            return None;
        }
        let node = unsafe { &*(slot as *const HamtNode) };
        slot = node.children[nibble_at(hash, level)];
        level += 1;
    }
}

fn hamt_insert(root: &mut HamtRoot, hash: u64, ts_ptr: *mut Turnstile) -> bool {
    let nibble0 = nibble_at(hash, 0);
    let mut slot: *mut usize = &mut root.children[nibble0];
    let mut level = 1usize;

    loop {
        let val = unsafe { *slot };
        if val == 0 {
            unsafe {
                *slot = tag_leaf(ts_ptr);
            }
            return true;
        }
        if is_leaf(val) {
            let existing = untag_leaf(val);
            let ex = unsafe { &*existing };
            let new_ts = unsafe { &*ts_ptr };
            if ex.key_type == new_ts.key_type
                && ex.aspace_id == new_ts.aspace_id
                && ex.va == new_ts.va
            {
                return false; // duplicate key
            }
            if level > MAX_LEVEL {
                return false;
            } // hash exhausted
            let node = match alloc_node() {
                Some(n) => n,
                None => return false,
            };
            let ex_nibble = nibble_at(ex.hash, level);
            let new_nibble = nibble_at(hash, level);
            if ex_nibble != new_nibble {
                unsafe {
                    (*node).children[ex_nibble] = val;
                    (*node).children[new_nibble] = tag_leaf(ts_ptr);
                    *slot = node as usize;
                }
                return true;
            }
            // Same nibble — push existing into node, continue deeper.
            unsafe {
                (*node).children[ex_nibble] = val;
                *slot = node as usize;
                slot = &mut (*node).children[new_nibble];
            }
            level += 1;
            continue;
        }
        // Inner node — descend.
        if level > MAX_LEVEL {
            return false;
        }
        let node = val as *mut HamtNode;
        let nibble = nibble_at(hash, level);
        slot = unsafe { &mut (*node).children[nibble] };
        level += 1;
    }
}

/// Remove a turnstile from the HAMT. Returns the pointer if found.
/// Uses recursive descent for bottom-up node collapsing.
fn hamt_remove(
    root: &mut HamtRoot,
    hash: u64,
    key_type: u8,
    aspace_id: u64,
    va: usize,
) -> Option<*mut Turnstile> {
    let nibble0 = nibble_at(hash, 0);
    hamt_remove_at(
        &mut root.children[nibble0],
        hash,
        key_type,
        aspace_id,
        va,
        1,
    )
}

fn hamt_remove_at(
    slot: &mut usize,
    hash: u64,
    key_type: u8,
    aspace_id: u64,
    va: usize,
    level: usize,
) -> Option<*mut Turnstile> {
    let val = *slot;
    if val == 0 {
        return None;
    }

    if is_leaf(val) {
        let ts = untag_leaf(val);
        let t = unsafe { &*ts };
        if t.key_type == key_type && t.aspace_id == aspace_id && t.va == va {
            *slot = 0;
            return Some(ts);
        }
        return None;
    }

    if level > MAX_LEVEL {
        return None;
    }

    let node = val as *mut HamtNode;
    let nibble = nibble_at(hash, level);
    let result = hamt_remove_at(
        unsafe { &mut (*node).children[nibble] },
        hash,
        key_type,
        aspace_id,
        va,
        level + 1,
    );

    if result.is_some() {
        // Try to collapse: count remaining children.
        let node_ref = unsafe { &*node };
        let mut count = 0u64;
        let mut last_child = 0usize;
        for i in 0..HAMT_WIDTH {
            if node_ref.children[i] != 0 {
                count += 1;
                last_child = node_ref.children[i];
                if count > 1 {
                    break;
                }
            }
        }
        if count == 0 {
            free_node(node);
            *slot = 0;
        } else if count == 1 && is_leaf(last_child) {
            free_node(node);
            *slot = last_child;
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Turnstile struct and alloc/free
// ---------------------------------------------------------------------------

#[repr(C)]
struct Turnstile {
    aspace_id: u64,
    key_type: u8,
    _pad0: [u8; 7],
    va: usize, // futex: virtual address; port: port_id as usize
    hash: u64,
    head: u32,
    tail: u32,
    waiter_count: u16,
    _pad1: u16,
    owner_tid: u32,
    max_waiter_prio: u8,
    _pad2: [u8; 3],
}

fn alloc_turnstile() -> Option<*mut Turnstile> {
    let pa = slab::alloc(TS_SLAB_SIZE)?;
    let p = pa.as_usize() as *mut Turnstile;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, TS_SLAB_SIZE);
    }
    Some(p)
}

fn free_turnstile(p: *mut Turnstile) {
    slab::free(PhysAddr::new(p as usize), TS_SLAB_SIZE);
}

fn init_turnstile(ts: *mut Turnstile, key_type: u8, aspace_id: u64, va: usize, hash: u64) {
    let t = unsafe { &mut *ts };
    t.key_type = key_type;
    t.aspace_id = aspace_id;
    t.va = va;
    t.hash = hash;
    t.head = TS_NIL;
    t.tail = TS_NIL;
    t.waiter_count = 0;
    t.owner_tid = 0;
    t.max_waiter_prio = 255;
}

/// Take the current thread's pre-allocated turnstile, or allocate a fresh one.
fn take_or_alloc_turnstile(tid: u32) -> Option<*mut Turnstile> {
    let addr = thread_ref(tid).turnstile.swap(0, Ordering::Relaxed);
    if addr != 0 {
        Some(addr as *mut Turnstile)
    } else {
        alloc_turnstile()
    }
}

// ---------------------------------------------------------------------------
// Wait queue (doubly-linked through Thread ts_next/ts_prev)
// ---------------------------------------------------------------------------

fn ts_enqueue(ts: &mut Turnstile, tid: u32) {
    let tref = thread_ref(tid);
    tref.ts_next.store(TS_NIL, Ordering::Relaxed);
    tref.ts_prev.store(ts.tail, Ordering::Relaxed);
    if ts.tail != TS_NIL {
        thread_ref(ts.tail).ts_next.store(tid, Ordering::Relaxed);
    } else {
        ts.head = tid;
    }
    ts.tail = tid;
    ts.waiter_count += 1;
}

fn ts_dequeue_head(ts: &mut Turnstile) -> Option<u32> {
    let head = ts.head;
    if head == TS_NIL {
        return None;
    }
    let head_ref = thread_ref(head);
    let next = head_ref.ts_next.load(Ordering::Relaxed);
    head_ref.ts_next.store(TS_NIL, Ordering::Relaxed);
    head_ref.ts_prev.store(TS_NIL, Ordering::Relaxed);
    ts.head = next;
    if next != TS_NIL {
        thread_ref(next).ts_prev.store(TS_NIL, Ordering::Relaxed);
    } else {
        ts.tail = TS_NIL;
    }
    ts.waiter_count -= 1;
    Some(head)
}

/// Remove a specific thread from the wait queue. Returns true if found.
fn ts_remove(ts: &mut Turnstile, tid: u32) -> bool {
    let mut cur = ts.head;
    while cur != TS_NIL {
        if cur == tid {
            let tref = thread_ref(tid);
            let prev = tref.ts_prev.load(Ordering::Relaxed);
            let next = tref.ts_next.load(Ordering::Relaxed);
            if prev != TS_NIL {
                thread_ref(prev).ts_next.store(next, Ordering::Relaxed);
            } else {
                ts.head = next;
            }
            if next != TS_NIL {
                thread_ref(next).ts_prev.store(prev, Ordering::Relaxed);
            } else {
                ts.tail = prev;
            }
            tref.ts_next.store(TS_NIL, Ordering::Relaxed);
            tref.ts_prev.store(TS_NIL, Ordering::Relaxed);
            ts.waiter_count -= 1;
            return true;
        }
        cur = thread_ref(cur).ts_next.load(Ordering::Relaxed);
    }
    false
}

/// Enqueue in priority order (ascending numeric = highest priority first).
/// Used by PI futex variants.
fn ts_enqueue_prio(ts: &mut Turnstile, tid: u32) {
    let my_prio = thread_ref(tid).prio.load(Ordering::Acquire);
    let mut cur = ts.head;
    let mut prev_tid = TS_NIL;
    while cur != TS_NIL {
        if thread_ref(cur).prio.load(Ordering::Acquire) > my_prio {
            break;
        }
        prev_tid = cur;
        cur = thread_ref(cur).ts_next.load(Ordering::Relaxed);
    }
    let tref = thread_ref(tid);
    tref.ts_prev.store(prev_tid, Ordering::Relaxed);
    tref.ts_next.store(cur, Ordering::Relaxed);
    if prev_tid != TS_NIL {
        thread_ref(prev_tid).ts_next.store(tid, Ordering::Relaxed);
    } else {
        ts.head = tid;
    }
    if cur != TS_NIL {
        thread_ref(cur).ts_prev.store(tid, Ordering::Relaxed);
    } else {
        ts.tail = tid;
    }
    ts.waiter_count += 1;
}

// ---------------------------------------------------------------------------
// Thread reference helper (uses THREAD_TABLE radix lookup)
// ---------------------------------------------------------------------------

#[inline]
fn thread_ref(tid: u32) -> &'static crate::sched::thread::Thread {
    let p = crate::sched::scheduler::THREAD_TABLE.get(tid) as *const crate::sched::thread::Thread;
    unsafe { &*p }
}

// ---------------------------------------------------------------------------
// Public futex API (non-PI)
// ---------------------------------------------------------------------------

/// Block the current thread if the u32 at user VA `addr` equals `expected`.
/// Returns 0 on wake, 1 on value mismatch, u64::MAX on error.
pub fn futex_wait(addr: usize, expected: u32) -> u64 {
    let tid = crate::sched::current_thread_id();
    let aspace_id = crate::sched::current_aspace_id();
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let hash = futex_hash(aspace_id, addr);
    let bucket = bucket_index(hash);

    {
        let mut root = WAIT_HAMT[bucket].lock();

        // Read current value from user memory while holding the lock.
        let mut buf = [0u8; 4];
        if !crate::syscall::handlers::copy_from_user(pt_root, addr, &mut buf) {
            return u64::MAX;
        }
        if u32::from_ne_bytes(buf) != expected {
            return 1;
        }

        // Clear wakeup flag WHILE HOLDING the lock (prevents lost wakeup).
        crate::sched::clear_wakeup_flag(tid);

        // Find or create turnstile for this address.
        let ts_ptr = if let Some(ts) = hamt_lookup(&root, hash, KEY_FUTEX, aspace_id, addr) {
            ts
        } else {
            let ts_ptr = match take_or_alloc_turnstile(tid) {
                Some(p) => p,
                None => return u64::MAX,
            };
            init_turnstile(ts_ptr, KEY_FUTEX, aspace_id, addr, hash);
            if !hamt_insert(&mut root, hash, ts_ptr) {
                free_turnstile(ts_ptr);
                return u64::MAX;
            }
            ts_ptr
        };

        let ts = unsafe { &mut *ts_ptr };
        ts_enqueue(ts, tid);
        thread_ref(tid)
            .ts_blocked_on
            .store(ts_ptr as usize, Ordering::Relaxed);
    }

    crate::sched::block_current(BlockReason::FutexWait);

    // Clean up if we were killed (still on queue).
    let tref = thread_ref(tid);
    let ts_addr = tref.ts_blocked_on.swap(0, Ordering::Acquire);
    if ts_addr != 0 {
        cleanup_blocked_inner(tid, ts_addr, bucket, hash, KEY_FUTEX, aspace_id, addr);
    }

    // Ensure we have a turnstile for future use.
    if tref.turnstile.load(Ordering::Relaxed) == 0 {
        if let Some(ts) = alloc_turnstile() {
            tref.turnstile.store(ts as usize, Ordering::Relaxed);
        }
    }

    0
}

/// Wake up to `count` threads waiting on the futex at `addr`.
/// Returns number of threads actually woken.
pub fn futex_wake(addr: usize, count: u32) -> u64 {
    let aspace_id = crate::sched::current_aspace_id();
    let hash = futex_hash(aspace_id, addr);
    let bucket = bucket_index(hash);
    let mut woken = 0u64;

    let mut root = WAIT_HAMT[bucket].lock();
    let ts_ptr = match hamt_lookup(&root, hash, KEY_FUTEX, aspace_id, addr) {
        Some(ts) => ts,
        None => return 0,
    };
    let ts = unsafe { &mut *ts_ptr };

    let mut last_tid = TS_NIL;
    while woken < count as u64 {
        match ts_dequeue_head(ts) {
            Some(tid) => {
                thread_ref(tid).ts_blocked_on.store(0, Ordering::Relaxed);
                crate::sched::wake_thread(tid);
                last_tid = tid;
                woken += 1;
            }
            None => break,
        }
    }

    if ts.waiter_count == 0 {
        hamt_remove(&mut root, hash, KEY_FUTEX, aspace_id, addr);
        // Return turnstile to the last woken thread if it needs one.
        if last_tid != TS_NIL {
            let tref = thread_ref(last_tid);
            if tref
                .turnstile
                .compare_exchange(0, ts_ptr as usize, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                free_turnstile(ts_ptr);
            }
        } else {
            free_turnstile(ts_ptr);
        }
    }

    drop(root);
    woken as u64
}

// ---------------------------------------------------------------------------
// PI futex API
// ---------------------------------------------------------------------------

/// PI futex word format (userspace AtomicU32):
///   Bits 0-30: owner ThreadId (0 = unlocked)
///   Bit 31:    waiters flag (kernel has blocked waiters)
const PI_WAITERS_BIT: u32 = 0x80000000;
const PI_TID_MASK: u32 = 0x7FFFFFFF;

/// Block on a PI futex. `expected_owner` is the TID of the lock holder.
/// Returns 0 on wake, 1 on value mismatch, u64::MAX on error.
pub fn futex_wait_pi(addr: usize, expected_owner: u32) -> u64 {
    let tid = crate::sched::current_thread_id();
    let aspace_id = crate::sched::current_aspace_id();
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let hash = futex_hash(aspace_id, addr);
    let bucket = bucket_index(hash);

    {
        let mut root = WAIT_HAMT[bucket].lock();

        // Read and verify owner.
        let mut buf = [0u8; 4];
        if !crate::syscall::handlers::copy_from_user(pt_root, addr, &mut buf) {
            return u64::MAX;
        }
        let word = u32::from_ne_bytes(buf);
        if (word & PI_TID_MASK) != expected_owner {
            return 1;
        }

        // Set waiters bit in userspace word.
        let new_word = word | PI_WAITERS_BIT;
        if new_word != word {
            crate::syscall::handlers::copy_to_user(pt_root, addr, &new_word.to_ne_bytes());
        }

        crate::sched::clear_wakeup_flag(tid);

        // Find or create turnstile.
        let ts_ptr = if let Some(ts) = hamt_lookup(&root, hash, KEY_FUTEX, aspace_id, addr) {
            ts
        } else {
            let ts_ptr = match take_or_alloc_turnstile(tid) {
                Some(p) => p,
                None => return u64::MAX,
            };
            init_turnstile(ts_ptr, KEY_FUTEX, aspace_id, addr, hash);
            if !hamt_insert(&mut root, hash, ts_ptr) {
                free_turnstile(ts_ptr);
                return u64::MAX;
            }
            ts_ptr
        };

        let ts = unsafe { &mut *ts_ptr };
        ts.owner_tid = expected_owner;

        // Enqueue in priority order.
        ts_enqueue_prio(ts, tid);
        let my_prio = thread_ref(tid).prio.load(Ordering::Acquire);
        if my_prio < ts.max_waiter_prio {
            ts.max_waiter_prio = my_prio;
        }

        thread_ref(tid)
            .ts_blocked_on
            .store(ts_ptr as usize, Ordering::Relaxed);

        // Boost the lock owner's priority.
        if expected_owner != 0 {
            crate::sched::scheduler::boost_priority(expected_owner, my_prio);
        }
    }

    crate::sched::block_current(BlockReason::FutexWait);

    // Clean up if killed.
    let tref = thread_ref(tid);
    let ts_addr = tref.ts_blocked_on.swap(0, Ordering::Acquire);
    if ts_addr != 0 {
        cleanup_blocked_inner(tid, ts_addr, bucket, hash, KEY_FUTEX, aspace_id, addr);
    }

    if tref.turnstile.load(Ordering::Relaxed) == 0 {
        if let Some(ts) = alloc_turnstile() {
            tref.turnstile.store(ts as usize, Ordering::Relaxed);
        }
    }

    0
}

/// Wake the highest-priority waiter on a PI futex and transfer ownership.
/// Called by the current lock owner. Returns 0 on success, 1 if no waiters.
pub fn futex_wake_pi(addr: usize) -> u64 {
    let caller_tid = crate::sched::current_thread_id();
    let aspace_id = crate::sched::current_aspace_id();
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let hash = futex_hash(aspace_id, addr);
    let bucket = bucket_index(hash);

    let mut root = WAIT_HAMT[bucket].lock();
    let ts_ptr = match hamt_lookup(&root, hash, KEY_FUTEX, aspace_id, addr) {
        Some(ts) => ts,
        None => return 1,
    };
    let ts = unsafe { &mut *ts_ptr };

    // Dequeue the highest-priority waiter (head of sorted queue).
    let new_owner = match ts_dequeue_head(ts) {
        Some(tid) => tid,
        None => return 1,
    };
    thread_ref(new_owner)
        .ts_blocked_on
        .store(0, Ordering::Relaxed);

    // Transfer ownership.
    let has_more = ts.waiter_count > 0;
    let new_word = (new_owner & PI_TID_MASK) | if has_more { PI_WAITERS_BIT } else { 0 };
    crate::syscall::handlers::copy_to_user(pt_root, addr, &new_word.to_ne_bytes());

    ts.owner_tid = new_owner;

    // Recalculate max_waiter_prio.
    if has_more {
        ts.max_waiter_prio = thread_ref(ts.head).prio.load(Ordering::Acquire);
    }

    // Reset old owner's priority, boost new owner if needed.
    crate::sched::scheduler::reset_priority(caller_tid);
    if has_more {
        crate::sched::scheduler::boost_priority(new_owner, ts.max_waiter_prio);
    }

    if ts.waiter_count == 0 {
        hamt_remove(&mut root, hash, KEY_FUTEX, aspace_id, addr);
        let tref = thread_ref(new_owner);
        if tref
            .turnstile
            .compare_exchange(0, ts_ptr as usize, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            free_turnstile(ts_ptr);
        }
    }

    drop(root);
    crate::sched::wake_thread(new_owner);
    0
}

// ---------------------------------------------------------------------------
// Cleanup and thread turnstile management
// ---------------------------------------------------------------------------

/// Clean up if a thread is still on a turnstile wait queue (killed case).
fn cleanup_blocked_inner(
    tid: u32,
    ts_addr: usize,
    bucket: usize,
    hash: u64,
    key_type: u8,
    aspace_id: u64,
    va: usize,
) {
    let mut root = WAIT_HAMT[bucket].lock();
    if let Some(found_ts) = hamt_lookup(&root, hash, key_type, aspace_id, va) {
        if found_ts as usize == ts_addr {
            let ts = unsafe { &mut *found_ts };
            if ts_remove(ts, tid) && ts.waiter_count == 0 {
                hamt_remove(&mut root, hash, key_type, aspace_id, va);
                thread_ref(tid).turnstile.store(ts_addr, Ordering::Relaxed);
            }
        }
    }
}

/// Clean up a thread's turnstile state on exit. Called before SCHEDULER lock.
pub fn cleanup_blocked(tid: u32) {
    let tref = thread_ref(tid);
    let ts_addr = tref.ts_blocked_on.swap(0, Ordering::Acquire);
    if ts_addr == 0 {
        return;
    }
    let ts = unsafe { &*(ts_addr as *const Turnstile) };
    let bucket = bucket_index(ts.hash);
    let hash = ts.hash;
    let key_type = ts.key_type;
    let aspace_id = ts.aspace_id;
    let va = ts.va;
    cleanup_blocked_inner(tid, ts_addr, bucket, hash, key_type, aspace_id, va);
}

/// Allocate a turnstile for a new thread. Returns phys addr or 0 on OOM.
pub fn alloc_thread_turnstile() -> usize {
    match alloc_turnstile() {
        Some(p) => p as usize,
        None => 0,
    }
}

/// Free a thread's turnstile on exit.
pub fn free_thread_turnstile(addr: usize) {
    if addr != 0 {
        free_turnstile(addr as *mut Turnstile);
    }
}

// ---------------------------------------------------------------------------
// Port wait/wake API
// ---------------------------------------------------------------------------

/// Enqueue the current thread on a port turnstile, but re-check `condition`
/// under the HAMT bucket lock to prevent lost wakeups.
///
/// `condition` returns `true` if the thread should still block (e.g. queue
/// still empty for recv, queue still full for send). If it returns `false`,
/// the thread is NOT enqueued and this function returns `false`.
///
/// Returns `true` if the thread was enqueued (caller should then park).
pub fn port_enqueue_with_check<F: FnOnce() -> bool>(
    port_id: u64,
    key_type: u8,
    tid: u32,
    condition: F,
) -> bool {
    let hash = port_key_hash(port_id, key_type);
    let bucket = bucket_index(hash);

    let mut root = WAIT_HAMT[bucket].lock();

    // Clear wakeup flag under lock.
    crate::sched::clear_wakeup_flag(tid);

    // Re-check condition under the lock.
    if !condition() {
        return false;
    }

    // Port keys: aspace_id=0, va=port_id as usize.
    let aspace_id = 0u64;
    let va = port_id as usize;

    let ts_ptr = if let Some(ts) = hamt_lookup(&root, hash, key_type, aspace_id, va) {
        ts
    } else {
        let ts_ptr = match take_or_alloc_turnstile(tid) {
            Some(p) => p,
            None => return false,
        };
        init_turnstile(ts_ptr, key_type, aspace_id, va, hash);
        if !hamt_insert(&mut root, hash, ts_ptr) {
            free_turnstile(ts_ptr);
            return false;
        }
        ts_ptr
    };

    let ts = unsafe { &mut *ts_ptr };
    ts_enqueue(ts, tid);
    thread_ref(tid)
        .ts_blocked_on
        .store(ts_ptr as usize, Ordering::Relaxed);

    drop(root);
    true
}

/// Wake one thread waiting on a port turnstile.
/// Returns the woken tid, or `None` if no waiters.
pub fn port_wake_one(port_id: u64, key_type: u8) -> Option<u32> {
    let hash = port_key_hash(port_id, key_type);
    let bucket = bucket_index(hash);
    let aspace_id = 0u64;
    let va = port_id as usize;

    let mut root = WAIT_HAMT[bucket].lock();
    let ts_ptr = match hamt_lookup(&root, hash, key_type, aspace_id, va) {
        Some(ts) => ts,
        None => return None,
    };
    let ts = unsafe { &mut *ts_ptr };

    let tid = match ts_dequeue_head(ts) {
        Some(t) => t,
        None => return None,
    };
    thread_ref(tid).ts_blocked_on.store(0, Ordering::Relaxed);

    if ts.waiter_count == 0 {
        hamt_remove(&mut root, hash, key_type, aspace_id, va);
        let tref = thread_ref(tid);
        if tref
            .turnstile
            .compare_exchange(0, ts_ptr as usize, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            free_turnstile(ts_ptr);
        }
    }

    drop(root);
    crate::sched::wake_thread(tid);
    Some(tid)
}

/// Dequeue one waiter from a port turnstile WITHOUT waking it.
/// Returns the dequeued tid, or `None` if no waiters.
/// The caller is responsible for waking the thread (e.g. after injecting a message).
pub fn port_dequeue_one(port_id: u64, key_type: u8) -> Option<u32> {
    let hash = port_key_hash(port_id, key_type);
    let bucket = bucket_index(hash);
    let aspace_id = 0u64;
    let va = port_id as usize;

    let mut root = WAIT_HAMT[bucket].lock();
    let ts_ptr = match hamt_lookup(&root, hash, key_type, aspace_id, va) {
        Some(ts) => ts,
        None => return None,
    };
    let ts = unsafe { &mut *ts_ptr };

    let tid = match ts_dequeue_head(ts) {
        Some(t) => t,
        None => return None,
    };
    thread_ref(tid).ts_blocked_on.store(0, Ordering::Relaxed);

    if ts.waiter_count == 0 {
        hamt_remove(&mut root, hash, key_type, aspace_id, va);
        let tref = thread_ref(tid);
        if tref
            .turnstile
            .compare_exchange(0, ts_ptr as usize, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            free_turnstile(ts_ptr);
        }
    }

    drop(root);
    Some(tid)
}

/// Wake all threads waiting on a port turnstile.
/// Returns the number of threads woken.
pub fn port_wake_all(port_id: u64, key_type: u8) -> u32 {
    let hash = port_key_hash(port_id, key_type);
    let bucket = bucket_index(hash);
    let aspace_id = 0u64;
    let va = port_id as usize;

    let mut root = WAIT_HAMT[bucket].lock();
    let ts_ptr = match hamt_lookup(&root, hash, key_type, aspace_id, va) {
        Some(ts) => ts,
        None => return 0,
    };
    let ts = unsafe { &mut *ts_ptr };

    let mut woken = 0u32;
    let mut last_tid = TS_NIL;
    while let Some(tid) = ts_dequeue_head(ts) {
        thread_ref(tid).ts_blocked_on.store(0, Ordering::Relaxed);
        crate::sched::wake_thread(tid);
        last_tid = tid;
        woken += 1;
    }

    // Turnstile is empty — remove from HAMT.
    hamt_remove(&mut root, hash, key_type, aspace_id, va);
    if last_tid != TS_NIL {
        let tref = thread_ref(last_tid);
        if tref
            .turnstile
            .compare_exchange(0, ts_ptr as usize, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            free_turnstile(ts_ptr);
        }
    } else {
        free_turnstile(ts_ptr);
    }

    drop(root);
    woken
}
