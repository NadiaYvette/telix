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

- **The in-tree integration scaffolding is drafted — see `INTEGRATION.md`.** The shape is
  settled by one constraint: Verus's pinned rustc (`1.96.0`) cannot compile the edition-2024
  `no_std` kernel crate, so the proofs verify **standalone** (not part of `cargo build`); the
  kernel build is untouched and pulls in no `vstd` dependency.
  - `verify-intree.sh` — the single CI entry point (version-pin check → drift-guard → verify all).
  - `drift-guard.sh` + `mirror-baseline.sha256` — bind the standalone (verbatim) proofs to the
    real `mm/` code via `// VERUS-MIRROR-BEGIN/END` markers; CI fails if a proved function changes
    until it is re-verified. (Markers are placed around `ExtentFlags` / `ExtentEntry::can_coalesce`
    in `kernel/src/mm/extent.rs` as the template.)
  - `ci.example.yml` — two independent jobs (kernel `cargo build` on nightly; `verify-intree.sh`
    on pinned Verus). `INTEGRATION.md` has the migration ladder to annotating the real functions.
- Verus toolchain: a prebuilt release from `verus-lang/verus` (binary + `vstd` + z3);
  pin the version in CI (`TOOLCHAIN.md`).
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
- [x] telix integration **scaffolding** drafted (`INTEGRATION.md`): in-tree standalone
      verification (`verify-intree.sh`), the proof⟷code drift-guard (`drift-guard.sh` +
      markers in `mm/extent.rs`), and CI wiring (`ci.example.yml`) — rung 1 of the migration
      ladder, with the seam cut for re-pointing the stubs (rungs 2–3).
- [x] remaining exec mechanics (done, not optional after all): the executable `next`/`prev`
      linked-list maintenance (`extent_ptr_list.rs`) **and** `insert_into_parent` recursive
      split propagation through the full multi-permission tree (`extent_ptr_tree.rs`).

**Eleven modules verified — 64 Verus obligations, 0 errors** — spanning `can_coalesce` →
leaf ops → a node through a pointer → a two-node split → the whole-chain ordered map.

## Beyond the extent B+-tree — broadened roadmap

- [x] **PTE ⟷ rmap relation invariant** (`rmap.rs`, `4 verified`): a page's cached
      `mapcount` tracks its true reverse map; correct map/unmap preserve it; under-remove
      is a provable error (pgcl #1/#143 — the page-cache-corruption / mapcount-drift
      cluster). The bug-densest invariant, and exactly what a CBMC check on Linux
      `mm/rmap.c` would target.
- [x] **cross-mm aggregate-refcount gate** (`rmap_cluster.rs`, `4 verified`): pgcl #143's
      free-while-mapped at *folio* granularity across multiple mms — `refcount == Σ live
      sub-PTEs across mms`, so `refcount == 0 ⟺ !folio_mapped()` (`free_iff_unmapped`), a
      sibling mm's mapping keeps `refcount > 0` (`mapped_implies_refcount_pos`), and
      `folio_mapped ∧ refcount == 0` is a provable invariant violation
      (`freed_while_mapped_breaks_wf`). The **sequential (∀-state) complement** of the Iris
      ∀-interleaving proof `tessera/property2/coq/rmap_defer.v` — the #143 fix obligation,
      machine-checked from both sides.
- [x] **sub-page placement & the permutation π** (`extent_placement.rs`, `5 verified`): the #143
      wrong-data class, in-tree for telix. The virtual→physical sub-page map `π : vsub ↦ psub` is
      normally identity but not always (relocation keeps psub, changes vsub); a rematerialize path
      that rebuilds psub from the faulting vaddr loses π and serves wrong content (pgcl Bug 2).
      `carry_psub_faithful` (the fix — carry psub, any π), `reconstruct_from_vaddr_wrong` (the bug),
      `extent_translation_is_identity` (telix's linear `start/MMUPAGE + vsub` *is* the identity
      placement → correct iff aligned). The Verus twin of tessera `Placement`/`Permute`, on telix's
      real `PhysAddr`/`MMUPAGE_SIZE`/`ExtentEntry` — a forward-looking guard for when telix grows a
      swap/migration path.
- [x] **#208 fork-COW kernel-PML4 invariant** (`fork_cow_pml4.rs`, `4 verified`): telix's own
      corruption family. The kernel PML4 set is indices 507..=511 (`boot.S`), shared by every AS; a
      fork COW pass that marks the whole PML4 write-protects the kernel's own mappings → the "5f
      silent triple". `fork_preserves_kernel` (correct: mark user half only), `fork_buggy_corrupts_
      kernel` (the #208 bug), `user_pml4_safe`/`fork_preserves_safe`/`fork_buggy_breaks_safe` (the
      `USER-CR3-BAD` probe's invariant, proved). The PML4-entry-level instance of tessera
      `Fork.forkKernel_breaks_userSafe`.
- [x] **next/prev exec linking** — `extent_link.rs` (`3 verified`, bounded sibling splice) +
      **`extent_ptr_list.rs` (`6 verified`, the UNBOUNDED chain)**: an arbitrary-length
      doubly-linked leaf chain through raw pointers, owned *forward* by a recursive permission
      collection (`ListPerm`) with each node's `prev` validated against its structural predecessor
      — so `wf` *is* the chain-wide `a.next.prev == a` (`back_pointer_holds` extracts it). A
      recursive traversal (`last_ptr`) walks the unbounded `*mut` chain soundly, and `push_front`
      maintains the invariant across the back-pointer write that silently corrupts if dropped.
      This is the piece `extent_link.rs` explicitly deferred ("needs a heap/ghost-map model of all
      permissions at once") — now done. The chain story, completed.
- [x] **recursive B+-tree, structural + insert** (`extent_tree.rs`, `8 verified`): an
      arbitrary-depth search tree's in-order traversal is one globally sorted extent map
      (`bst_sorted`); the **recursive insert preserves the invariant** (`insert_preserves_bst`)
      and loses no entry, adding exactly the new one (`insert_contains`). The Verus twin of
      Lean `BTree.lean`, unbounded. The structural recursive tree — done.
- [x] **the POINTER recursive tree** (`extent_ptr_tree.rs`, `6 verified`): the deepest rung —
      an *arbitrary-depth tree of nodes behind raw pointers*, where the right to dereference the
      whole tree is a **recursive permission collection** (`TreePerm`: each node's `PointsTo`
      plus, recursively, its children's permission trees). Both directions verified: a recursive
      **traversal** (`contains`) walks the unbounded `*mut` tree soundly and agrees with the
      abstract key set, and a recursive **insert** (`insert`) allocates a fresh node, rewires the
      parent pointer, and reconstructs the permission collection on the way up — preserving `wf`
      and `bst` and adding exactly the key. This fuses `extent_tree.rs` (recursive datatype) with
      `extent_node.rs`/`extent_split.rs` (pointer permissions): what they did for the *shape* and
      for *one/two nodes*, now for the *unbounded heap-pointer tree*. The summit of the tower.
