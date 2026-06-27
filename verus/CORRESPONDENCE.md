# Verus ⟷ Kani ⟷ Lean correspondence

Every Verus obligation in `extent_coalesce.rs` is justified by an *independent* proof in
the tessera repo. This is what makes the in-tree Verus spec trustworthy rather than
merely plausible: it is the third of three checks, by three different tools, of the same
property.

tessera: `NadiaYvette/tessera` (public — github / sourcehut / disroot / framagit).

## Stage 1 — `ExtentEntry::can_coalesce`, `end`, `ExtentFlags`

| Verus clause (`extent_coalesce.rs`) | Kani harness (`rust/extent-kani/coalesce.rs`) | Lean theorem (`proof/Tessera/`) |
|---|---|---|
| `can_coalesce` ⟹ `self.end() == other.start` (physical adjacency) | `coalesce_is_sound`: `assert(a.end() == b.start)` | `Frames.grantsF` contiguity / `Basic.Disjoint` adjacency (the `hi == lo` boundary) |
| `can_coalesce` ⟹ `object_id == other.object_id ∧ object_id != 0` (same non-anon object) | `coalesce_is_sound`: `assert(a.object_id == b.object_id ∧ a.object_id != 0)` | `Sharing`/`Cow` backing-object identity (same `Backing` ⇒ coalescible) |
| `can_coalesce` ⟹ `object_offset + page_count == other.object_offset` (offset-contiguous) | `coalesce_is_sound`: the offset assertion | `Frames.grantsF`: the linear `frame + (v − base)` translation across a merge |
| `can_coalesce` ⟹ `flags == other.flags ∧ refcount == other.refcount` (identical state) | `coalesce_is_sound`: the flags/refcount asserts | `Kau.dirty`/inv5 + the refcount discipline (merge preserves the per-extent state) |
| `end` overflow-free (the `requires` bound) | Kani's automatic arithmetic-overflow checks (0 failures) | — (arithmetic; below the Lean granule-unit abstraction) |
| `union` ⟹ `contains(a) ∧ contains(b)` (flag join is an upper bound) | `union_contains_both_operands` | — (bit-level; `bit_vector` in Verus) |

## Stage 2 — leaf-array operations (`extent_leaf.rs`)

| Verus obligation | Kani harness | Lean theorem |
|---|---|---|
| `insert_preserves_sorted`: inserting at the sorted position keeps the leaf sorted | `rust/extent-kani/lib.rs` `insert_preserves_order` (bounded array insert) | `proof/Tessera/ExtentMap.lean` `insert_ordered` (the abstract theorem) |
| `remove_preserves_sorted`: removal keeps the leaf sorted (subsequence of a sorted seq) | — | `ExtentMap`/`Basic` `Pairwise` sublist closure |
| `insert_entry_at` / `remove_entry_at` functional spec (`Seq::insert`/`Seq::remove`) + count | the harness's array-shift semantics | `ExtentMap.insert_mem` (insert adds exactly the element) |

telix's manual shift-right/shift-left over the fixed `[ExtentEntry; LEAF_CAP]` + count
computes exactly `Seq::insert`/`Seq::remove` on the live content; the Verus spec is stated
at that logical level, and the telix side proves its array code meets it.

## Why three tools

- **Lean** proves the property *abstractly*, for all inputs, over the idealized model —
  it tells us the spec is the **right** one (it's the invariant the whole refinement
  tower preserves).
- **Kani** proves it on the **verbatim telix code**, bounded — it tells us the spec
  **holds of the actual function** (including real integer overflow).
- **Verus** proves it on the code **in mainline, unbounded, in CI** — it tells us the
  spec **keeps holding as telix evolves.**

Lean says *what* correct is; Kani confirms *this code* meets it now; Verus keeps it met.

## Provenance of each property

The properties trace to the failure catalogue (`tessera/doc/failure-modes-telix.md`):
coalescing the wrong extents (mismatched object, stale offset, non-adjacent, anonymous)
is the telix #14 / overlap-and-merge family. `can_coalesce`'s six conjuncts are exactly
the guards the catalogue says must hold — now machine-checked at the source.
