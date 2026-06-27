# Verus verification of `mm/extent.rs` (in-tree)

This branch (`verus-extent`) brings **machine-checked Verus proofs of the extent
allocator into mainline telix**, so the VM invariants verify in CI on every change and
cannot silently rot. It is the telix-side landing zone for a two-repository, two-shell
collaboration.

## The collaboration

| Repo / shell | Role |
|---|---|
| **tessera** (`NadiaYvette/tessera`, public on github/sourcehut/disroot/framagit) | **Spec authority.** A Lean 4 development that *proves what correct means* for the clustered-superpage VM — the invariants, the refinement tower, and a bug catalogue mined from telix+pgcl. It also Kani-verifies the *actual* telix functions (`rust/extent-kani/coalesce.rs`). tessera drafts the Verus specs and supplies the independent (Lean + Kani) justification for each one. |
| **telix** (this repo / branch) | **Integration authority.** Owns the `#![no_std]` build, the slab allocator internals (which Verus models with pointer permissions), CI, and mainline. It wires the specs into the real source, runs Verus, and merges to `master`. |

The two Claude shells cooperate through **this branch** (the shared git workspace) plus
the human orchestrator — tessera pushes spec drafts here; telix integrates, verifies,
and merges forward.

## Why this is sound, not just plausible

Every Verus `ensures`/`invariant` here is **already proved twice in tessera**, by
independent means, before it lands:

- in **Lean 4** (`proof/Tessera/*.lean`, ~22 axiom-clean modules) — the abstract theorem;
- in **Kani** (`rust/extent-kani/`) — bounded model-checking of the *verbatim* telix
  function.

So Verus is the *third* check and the one that lives with the code. `CORRESPONDENCE.md`
maps each Verus clause to the Lean theorem and Kani harness that justify it.

## Staged plan (tractable order — do not start at the pointer tree)

1. **Pointer-free logic** — `ExtentFlags::{contains,union}`, `ExtentEntry::{end,can_coalesce}`.
   No pointers; Verus handles it directly. **This is the seed in `extent_coalesce.rs`.**
2. **Leaf-array operations** — insert/remove within one `LeafNode::entries` (bounded
   array, no tree-walking).
3. **The pointer B+-tree** — `insert` / `split_leaf_and_insert` with `vstd` `PointsTo`
   permissions for the `*mut` nodes and the slab allocator as a resource. The hard rung.

## Integration notes for the telix side

- The seed is a **self-contained `verus!{}` module** with the leaf deps stubbed
  (`PhysAddr`, `page_size`). The telix-side task is to re-point it at the real
  `mm::page::PhysAddr` / `page::page_size()` and decide the in-tree shape: a `verus!{}`
  block guarded so the normal `cargo build` skips the spec code, verified by a separate
  `verus` CI step.
- Verus toolchain: a prebuilt release from `verus-lang/verus` (binary + `vstd` + z3);
  pin the version in CI.
- The seed's `proof fn`s are the soundness obligations (e.g. `can_coalesce ⇒ physically
  adjacent + same object`), mirroring the Kani harness `coalesce_is_sound`.

## Status

- [x] Branch + plan + correspondence
- [x] **Stage 1 `extent_coalesce.rs` VERIFIED** — `11 verified, 0 errors`.
- [x] **Stage 2 `extent_leaf.rs` VERIFIED** — `6 verified, 0 errors`: leaf
      `insert_entry_at`/`remove_entry_at` preserve the leaf's sorted-by-start invariant
      (`insert_preserves_sorted`/`remove_preserves_sorted`) — the per-leaf analogue of
      `ExtentMap.insert_ordered`. `verify.sh` runs both stages.
- [x] **Stage 3a `extent_node.rs` VERIFIED** — `6 verified, 0 errors`: a leaf operation
      performed **through a raw pointer** (`PointsTo<LeafNode>` permission — the sound,
      checked form of telix's `unsafe { &mut *leaf_ptr }`) preserves the invariant
      (`leaf_insert_through_ptr`), plus a full allocate→operate→free lifecycle
      (`demo_alloc_insert_free`). The first raw-pointer rung — Verus's home turf, where it
      does what Lean/Kani cannot (model the heap).
- [x] **Stage 3b `extent_split.rs` VERIFIED** — `5 verified, 0 errors`: the leaf split
      (`split_leaf`) keeps the lower half and moves the upper half to a freshly-allocated
      sibling, **across two `PointsTo` permissions at once**, proven to lose/duplicate no
      entries (`old' ++ new' == combined`), keep both halves sorted, and yield a valid
      separator (`split_sorted`). The multi-node rung.
- [x] **Stage 3c `extent_chain.rs` VERIFIED** — `5 verified, 0 errors`: the whole-tree
      structural invariant. A well-formed leaf chain (each leaf sorted, adjacent leaves
      separated) flattens to a **globally sorted extent map** (`chain_flatten_sorted`,
      built on `concat_sorted`) — the multi-node analogue of `ExtentMap.Ordered` /
      `BTree.bst_ordered`, closing the loop back to the Layer-A ordering invariant.
- [ ] telix integration of stages 1–3c into mainline `mm/extent.rs` (re-point stubs at
      `mm::page`; host in a `verus!{}` block; the Verus build step re-verifies all five on
      every compile)
- [ ] remaining exec mechanics (optional, beyond the structural core): the executable
      `next`/`prev` linked-list maintenance, and `insert_into_parent` recursive split
      propagation with the full multi-permission tree (a research-grade exercise).

**Five stages verified — 33 Verus obligations, 0 errors** — spanning `can_coalesce` →
leaf ops → a node through a pointer → a two-node split → the whole-chain ordered map.

## Beyond the extent B+-tree — broadened roadmap

- [x] **PTE ⟷ rmap relation invariant** (`rmap.rs`, `4 verified`): a page's cached
      `mapcount` tracks its true reverse map; correct map/unmap preserve it; under-remove
      is a provable error (pgcl #1/#143 — the page-cache-corruption / mapcount-drift
      cluster). The bug-densest invariant, and exactly what a CBMC check on Linux
      `mm/rmap.c` would target.
- [ ] **next/prev exec linking** — the executable doubly-linked-leaf-list maintenance
      (the back-pointer invariant `a.next.prev == a`), completing the chain story.
- [x] **recursive B+-tree structural invariant** (`extent_tree.rs`, `5 verified`): an
      arbitrary-depth search tree's in-order traversal is one globally sorted extent map
      (`bst_sorted`, structural induction over a recursive datatype) — the Verus twin of
      Lean `BTree.bst_ordered`, unbounded. The last structural rung.
- [ ] remaining (deepest): recursive `insert` preserving the invariant; and the
      *pointer* recursive tree (`insert_into_parent` propagation over an unbounded
      `PointsTo` set) — research-grade, beyond the structural core.
