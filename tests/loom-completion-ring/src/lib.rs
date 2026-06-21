//! Loom model of the completion-ABI SPSC ring.
//!
//! Mirrors `kernel/src/ipc/completion.rs::SpscRing` exactly: a single producer
//! owns `tail`, a single consumer owns `head`. The producer writes the slot
//! then **Release**-stores `tail`; the consumer **Acquire**-loads `tail` before
//! reading the slot (and symmetrically `head` frees a slot for reuse only after
//! the read). The Release/Acquire pairs are the only thing making the
//! (non-atomic) slot read/write data-race-free.
//!
//! `CAP = 2`, `N = 3` is the minimal config that still exercises slot **reuse**:
//! push #3 reuses slot 0, which is correct only if the full-check's Acquire load
//! of `head` observes the consumer's Release of `head` from popping #1.
//!
//! Two tests:
//!   * `spsc_ring_fifo_no_loss` — the correct ring: FIFO, no loss/dup, across
//!     every interleaving loom explores.
//!   * `relaxed_publish_races` (`#[should_panic]`) — the same ring with a
//!     **Relaxed** `tail` publish: loom detects the now-unsynchronized slot
//!     access, proving the correctness test has teeth.

use loom::cell::UnsafeCell;
use loom::sync::atomic::{AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

const CAP: u32 = 2;
const MASK: u32 = CAP - 1;
const N: u32 = 3;

/// Correct SPSC ring (Release publish / Acquire consume).
struct Ring {
    head: AtomicU32,
    tail: AtomicU32,
    slots: [UnsafeCell<u32>; CAP as usize],
}

// Safe: the SPSC contract (one producer, one consumer) plus the Release/Acquire
// discipline give every slot access a happens-before ordering.
unsafe impl Sync for Ring {}

impl Ring {
    fn new() -> Self {
        Ring {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: [UnsafeCell::new(0), UnsafeCell::new(0)],
        }
    }

    fn push(&self, val: u32) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= CAP {
            return false;
        }
        let idx = (tail & MASK) as usize;
        self.slots[idx].with_mut(|p| unsafe { *p = val });
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    fn pop(&self) -> Option<u32> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let idx = (head & MASK) as usize;
        let val = self.slots[idx].with(|p| unsafe { *p });
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(val)
    }
}

/// Same ring but the producer publishes `tail` with **Relaxed** ordering — the
/// injected bug. The consumer's Acquire load of `tail` no longer synchronizes
/// with the slot write, so the slot read/write race; loom must catch it.
struct RelaxedRing {
    head: AtomicU32,
    tail: AtomicU32,
    slots: [UnsafeCell<u32>; CAP as usize],
}

unsafe impl Sync for RelaxedRing {}

impl RelaxedRing {
    fn new() -> Self {
        RelaxedRing {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: [UnsafeCell::new(0), UnsafeCell::new(0)],
        }
    }

    fn push(&self, val: u32) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= CAP {
            return false;
        }
        let idx = (tail & MASK) as usize;
        self.slots[idx].with_mut(|p| unsafe { *p = val });
        self.tail.store(tail.wrapping_add(1), Ordering::Relaxed); // BUG: was Release
        true
    }

    fn pop(&self) -> Option<u32> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let idx = (head & MASK) as usize;
        let val = self.slots[idx].with(|p| unsafe { *p });
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_ring_fifo_no_loss() {
        loom::model(|| {
            let ring = Arc::new(Ring::new());

            let producer = {
                let r = ring.clone();
                thread::spawn(move || {
                    let mut i = 0u32;
                    while i < N {
                        if r.push(i) {
                            i += 1;
                        } else {
                            thread::yield_now(); // full — let the consumer drain
                        }
                    }
                })
            };

            let consumer = {
                let r = ring.clone();
                thread::spawn(move || {
                    let mut expect = 0u32;
                    while expect < N {
                        match r.pop() {
                            Some(v) => {
                                assert_eq!(v, expect, "FIFO/loss violation");
                                expect += 1;
                            }
                            None => thread::yield_now(), // empty — wait for a push
                        }
                    }
                })
            };

            producer.join().unwrap();
            consumer.join().unwrap();
        });
    }

    /// The Relaxed publish must produce an execution loom flags as a bug
    /// (unsynchronized slot access). If loom ever stops catching it, this test
    /// fails by *not* panicking — a signal the model lost its teeth.
    #[test]
    #[should_panic]
    fn relaxed_publish_races() {
        loom::model(|| {
            let ring = Arc::new(RelaxedRing::new());

            let producer = {
                let r = ring.clone();
                thread::spawn(move || {
                    let mut i = 0u32;
                    while i < N {
                        if r.push(i) {
                            i += 1;
                        } else {
                            thread::yield_now();
                        }
                    }
                })
            };

            let consumer = {
                let r = ring.clone();
                thread::spawn(move || {
                    let mut expect = 0u32;
                    while expect < N {
                        match r.pop() {
                            Some(v) => {
                                assert_eq!(v, expect);
                                expect += 1;
                            }
                            None => thread::yield_now(),
                        }
                    }
                })
            };

            producer.join().unwrap();
            consumer.join().unwrap();
        });
    }
}
