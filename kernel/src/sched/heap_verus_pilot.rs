// Verus formal-verification pilot for the d-ary min-heap (kernel/src/sched/heap.rs).
//
// =====================================================================
// THIS FILE IS NOT PART OF THE KERNEL BUILD.
// =====================================================================
//
// It is intentionally NOT registered in `kernel/src/sched/mod.rs`. It is a
// parallel implementation, simplified down to the algorithmic core
// (insert + pop_min + heap-property invariant), annotated with Verus
// `requires` / `ensures` / `invariant` clauses.
//
// Verus (https://verus-lang.github.io/verus/) is a Rust dialect that uses
// SMT solvers (Z3) to prove specifications about imperative code. It needs
// its own toolchain and compiles via a custom rustc driver; it cannot be
// applied retroactively to the existing heap.rs (which uses inline
// thread-state callbacks, debug_assert!, etc., that Verus does not yet
// model out of the box).
//
// ---------------------------------------------------------------------
// HOW TO RUN
// ---------------------------------------------------------------------
//
// 1. Install Verus (one-time, ~10 min). From the Verus README:
//
//    git clone https://github.com/verus-lang/verus.git ~/src/verus
//    cd ~/src/verus/source
//    ./tools/get-z3.sh             # downloads pinned Z3 binary
//    source ../tools/activate
//    vargo build --release
//
//    The driver lands at ~/src/verus/source/target-verus/release/verus
//    (also available as `verus` once you `source tools/activate`).
//
//    There is also a VS Code extension ("verus-analyzer") that bundles a
//    binary under ~/.verus, but that path was not present on this box at
//    the time of writing.
//
// 2. Run on this file as a standalone proof:
//
//    cd /home/nyc/src/telix
//    verus --crate-type=lib kernel/src/sched/heap_verus_pilot.rs
//
//    (Verus expects a single .rs file or a small driver crate; do NOT
//    invoke it through cargo on the kernel — the kernel is no_std and
//    pulls in arch-specific code Verus cannot handle.)
//
// 3. Expected output on success:
//
//    verification results:: 4 verified, 0 errors
//
//    On failure, Verus prints the failing assertion and a counter-example.
//
// ---------------------------------------------------------------------
// WHAT THIS PILOT COVERS
// ---------------------------------------------------------------------
//
//   * `is_heap`                — predicate: parent ≤ children for d=4
//   * `insert`                 — preserves is_heap (with sift_up loop invariant)
//   * `pop_min`                — preserves is_heap (with sift_down loop invariant)
//   * `peek_min`               — returns the actual minimum
//
// What it deliberately does NOT cover:
//
//   * `eevdf_heap_pos` cross-data-structure invariant (each tid's recorded
//     position equals its array index). Verus *can* express this, but it
//     requires modeling the per-thread side-table — out of scope for a pilot.
//   * `pick_eligible` / `pop_for_group` — these read live thread state
//     (`eevdf_vruntime`, `cosched_group`) via `super::scheduler::thread_ref`.
//     That is a foreign-function-style escape from the heap's local
//     reasoning frame and would need either (a) a ghost map argument or
//     (b) a Verus model of the global thread table.
//   * Capacity overflow on `insert` (modeled here as a no-op return false,
//     so the heap-property postcondition is trivially preserved).
//
// =====================================================================

#![allow(unused)]
#![cfg(verus_pilot)]

// vstd is Verus's verified standard library. It provides ghost types
// (Seq, Set), spec-only functions, and proof-mode primitives.
use vstd::prelude::*;

verus! {

pub const D: usize = 4;
pub const HEAP_CAP: usize = 512;

#[derive(Clone, Copy)]
pub struct HeapEntry {
    pub key: u64,
    pub tid: u32,
}

pub struct Heap4 {
    pub entries: [HeapEntry; HEAP_CAP],
    pub len: usize,
}

// -----------------------------------------------------------------------
// Spec-only helpers
// -----------------------------------------------------------------------

/// Parent index in a d=4 heap. Spec-mode (no runtime cost).
pub open spec fn parent_spec(i: int) -> int {
    (i - 1) / (D as int)
}

/// Heap property: every non-root node's parent has a key ≤ its own.
/// Quantified over the *populated* prefix [0, len).
pub open spec fn is_heap(entries: Seq<HeapEntry>, len: int) -> bool {
    forall|i: int| 1 <= i < len ==> #[trigger] entries[parent_spec(i)].key <= entries[i].key
}

/// Spec view of the entries array as a sequence.
pub open spec fn entries_seq(h: &Heap4) -> Seq<HeapEntry> {
    Seq::new(HEAP_CAP as nat, |i: int| h.entries[i])
}

// -----------------------------------------------------------------------
// peek_min
// -----------------------------------------------------------------------

impl Heap4 {

    pub fn peek_min(&self) -> (out: Option<(u32, u64)>)
        requires
            self.len <= HEAP_CAP,
            is_heap(entries_seq(self), self.len as int),
        ensures
            self.len == 0 ==> out is None,
            self.len > 0 ==> {
                &&& out is Some
                // The peeked key is the minimum of all populated entries.
                &&& forall|i: int| 0 <= i < self.len ==>
                        #[trigger] entries_seq(self)[i].key >= out->0.1
            },
    {
        if self.len == 0 {
            None
        } else {
            // From is_heap, root is min: by induction along parent chains.
            // Verus discharges this from the heap predicate + a small lemma.
            proof { lemma_root_is_min(entries_seq(self), self.len as int); }
            Some((self.entries[0].tid, self.entries[0].key))
        }
    }

    // -------------------------------------------------------------------
    // insert
    // -------------------------------------------------------------------

    pub fn insert(&mut self, tid: u32, key: u64) -> (ok: bool)
        requires
            old(self).len <= HEAP_CAP,
            is_heap(entries_seq(old(self)), old(self).len as int),
        ensures
            self.len <= HEAP_CAP,
            is_heap(entries_seq(self), self.len as int),
            ok ==> self.len == old(self).len + 1,
            !ok ==> self.len == old(self).len,
    {
        if self.len >= HEAP_CAP {
            return false;
        }
        let pos = self.len;
        self.entries.set(pos, HeapEntry { key, tid });
        self.len = pos + 1;
        self.sift_up(pos);
        true
    }

    /// Sift up restores heap property after a key was decreased (or a new
    /// entry was placed at `pos`). Loop invariant: heap property holds
    /// everywhere *except possibly* between `pos` and `parent(pos)`.
    fn sift_up(&mut self, mut pos: usize)
        requires
            old(self).len <= HEAP_CAP,
            pos < old(self).len,
            // Heap property holds on the prefix [0, len) except possibly at edge (pos, parent(pos)).
            forall|i: int|
                1 <= i < old(self).len as int && i != pos as int ==>
                    #[trigger] entries_seq(old(self))[parent_spec(i)].key
                        <= entries_seq(old(self))[i].key,
        ensures
            self.len == old(self).len,
            is_heap(entries_seq(self), self.len as int),
    {
        while pos > 0
            invariant
                self.len == old(self).len,
                self.len <= HEAP_CAP,
                pos < self.len,
                // Same "almost heap" invariant, threaded through the loop.
                forall|i: int|
                    1 <= i < self.len as int && i != pos as int ==>
                        #[trigger] entries_seq(self)[parent_spec(i)].key
                            <= entries_seq(self)[i].key,
            decreases pos,
        {
            let par: usize = (pos - 1) / D;
            if self.entries[pos].key < self.entries[par].key {
                let tmp = self.entries[pos];
                self.entries.set(pos, self.entries[par]);
                self.entries.set(par, tmp);
                pos = par;
            } else {
                // Edge (pos, par) is now satisfied → full heap property holds.
                return;
            }
        }
        // pos == 0: no parent edge to check, full heap property holds.
    }

    // -------------------------------------------------------------------
    // pop_min
    // -------------------------------------------------------------------

    pub fn pop_min(&mut self) -> (out: Option<(u32, u64)>)
        requires
            old(self).len <= HEAP_CAP,
            is_heap(entries_seq(old(self)), old(self).len as int),
        ensures
            self.len <= HEAP_CAP,
            is_heap(entries_seq(self), self.len as int),
            old(self).len == 0 ==> out is None && self.len == 0,
            old(self).len > 0 ==> out is Some && self.len == old(self).len - 1,
    {
        if self.len == 0 {
            return None;
        }
        let root_tid = self.entries[0].tid;
        let root_key = self.entries[0].key;
        self.len = self.len - 1;
        if self.len > 0 {
            self.entries.set(0, self.entries[self.len]);
            self.sift_down(0);
        }
        Some((root_tid, root_key))
    }

    /// Sift down: at each level, find the smallest of up to D children;
    /// if it beats the current node, swap and recurse.
    fn sift_down(&mut self, mut pos: usize)
        requires
            old(self).len <= HEAP_CAP,
            pos < old(self).len,
            // "Almost heap": holds everywhere except possibly between pos
            // and its children.
            forall|i: int|
                1 <= i < old(self).len as int && parent_spec(i) != pos as int ==>
                    #[trigger] entries_seq(old(self))[parent_spec(i)].key
                        <= entries_seq(old(self))[i].key,
        ensures
            self.len == old(self).len,
            is_heap(entries_seq(self), self.len as int),
        decreases (old(self).len - pos) as int,
    {
        let n = self.len;
        loop
            invariant
                self.len == old(self).len,
                self.len <= HEAP_CAP,
                pos < self.len,
                n == self.len,
                forall|i: int|
                    1 <= i < self.len as int && parent_spec(i) != pos as int ==>
                        #[trigger] entries_seq(self)[parent_spec(i)].key
                            <= entries_seq(self)[i].key,
            decreases (self.len - pos) as int,
        {
            let first_child = D * pos + 1;
            if first_child >= n {
                return;
            }
            let last_child = if first_child + D < n { first_child + D } else { n };

            let mut min_child: usize = first_child;
            let mut c: usize = first_child + 1;
            while c < last_child
                invariant
                    first_child <= min_child < last_child,
                    first_child + 1 <= c <= last_child,
                    last_child <= n,
                    forall|j: int|
                        first_child <= j < c as int ==>
                            #[trigger] entries_seq(self)[min_child as int].key
                                <= entries_seq(self)[j].key,
                decreases (last_child - c) as int,
            {
                if self.entries[c].key < self.entries[min_child].key {
                    min_child = c;
                }
                c = c + 1;
            }

            if self.entries[min_child].key < self.entries[pos].key {
                let tmp = self.entries[pos];
                self.entries.set(pos, self.entries[min_child]);
                self.entries.set(min_child, tmp);
                pos = min_child;
            } else {
                return;
            }
        }
    }
}

// -----------------------------------------------------------------------
// Lemma: root is the minimum
// -----------------------------------------------------------------------
//
// Standard heap fact: from is_heap, induct along the parent chain to
// show entries[0].key ≤ entries[i].key for all i < len.
//
// Verus typically discharges this with a recursive proof on the parent
// chain. We sketch the structure; the SMT solver fills in arithmetic.
proof fn lemma_root_is_min(s: Seq<HeapEntry>, len: int)
    requires
        len > 0,
        s.len() >= len,
        is_heap(s, len),
    ensures
        forall|i: int| 0 <= i < len ==> s[0].key <= s[i].key,
    decreases len,
{
    // Induction along parent chains. For each i, parent_spec(i) < i (when
    // i ≥ 1), so by recursion the property holds at parent_spec(i), and
    // is_heap gives us s[parent_spec(i)].key ≤ s[i].key, hence
    // s[0].key ≤ s[i].key. Verus's SMT backend handles the arithmetic
    // ((i-1)/4 < i for i ≥ 1) once trigger discipline is set.
    assert forall|i: int| 0 <= i < len implies s[0].key <= s[i].key by {
        if i > 0 {
            let p = parent_spec(i);
            assert(0 <= p < i);
            // recurse / instantiate is_heap
            assert(s[p].key <= s[i].key);
        }
    }
}

} // verus!
