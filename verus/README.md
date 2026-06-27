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
- [ ] telix integration of stages 1–3a into mainline `mm/extent.rs` (re-point stubs at
      `mm::page`; host in a `verus!{}` block; wire into the Verus build step — note: telix
      is integrating Verus into its build system, so these re-verify on every compile)
- [ ] stage 3b–c (the rest of the pointer tree): `find_leaf` tree-walk, the linked-leaf
      `next`/`prev` invariant, `split_leaf_and_insert`, and `insert_into_parent` — the
      multi-node permission reasoning. The hard remainder.
