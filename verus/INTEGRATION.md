# Integrating the Verus proofs into telix mainline

How the `verus/*.rs` proofs live in the telix tree and verify in CI on every change — the
*scaffolding*. `TOOLCHAIN.md` covers the Verus⟷Rust version coupling; this covers the in-tree
shape, the build/CI wiring, and the migration ladder. `CORRESPONDENCE.md` maps each proof to its
Lean/Kani twin.

## The one constraint that decides the shape

Verus is a **rustc driver pinned to one exact toolchain** (here `1.96.0`; `TOOLCHAIN.md`). telix's
kernel is **edition 2024, `no_std`, nightly**, with `*-unknown-none` targets, inline asm, and
bleeding-edge features. **Verus's pinned rustc cannot compile that crate**, and the proof modules
pull in `vstd` (`Seq`/`Set`/`PointsTo`), which is not `no_std`-clean for the kernel target.

So the proofs are **verified standalone** — each `verus/*.rs` is checked on its own
(`verus --crate-type=lib file.rs`), exactly as `verify.sh` already does — **not** as part of
`cargo build`. Consequences, both deliberate:

- **The kernel build is untouched.** No `vstd`/`builtin` dependency enters the kernel binary;
  production `cargo build` neither sees nor needs any of this. The proofs are not `mod`-included.
- **The proofs are verbatim copies** of the real `mm/` struct defs and method bodies (only the
  leaf deps `PhysAddr`/`page_size` are stubbed). That is sound *only if the copy cannot silently
  drift from the real code* — which is what the **drift-guard** enforces (below).

This is the honest current rung. The end-state TOOLCHAIN.md describes (annotations on the *real*
functions, "same source builds two ways") is rung 4 of the ladder below; it needs either Verus to
reach edition-2024/`no_std` or the verifiable core factored into a Verus-compatible inner crate.

## The pieces (all in `verus/`)

| File | Role |
|---|---|
| `*.rs` (11 modules) | the proofs — verified standalone, in-tree, versioned with the code |
| `verify.sh` | run the pinned Verus over every module (local dev) |
| **`verify-intree.sh`** | **the CI entry point**: version-pin check → drift-guard → `verify.sh` |
| **`drift-guard.sh`** | fail if a real mm/ function proved here changed since it was verified |
| `mirror-baseline.sha256` | the recorded hashes of the mirrored regions (the "last verified" mark) |
| `TOOLCHAIN.md` / `CORRESPONDENCE.md` | version strategy / proof⟷Lean⟷Kani map |

## The drift-guard — what makes verbatim proofs trustworthy

Because the proofs copy the real code, the danger is telix editing `mm/extent.rs` while the proof
sits stale and green. The guard closes that gap with **marker comments** around each proved region
in the real source:

```rust
// VERUS-MIRROR-BEGIN extent_entry_coalesce  (proved in verus/extent_coalesce.rs — see verus/INTEGRATION.md)
pub struct ExtentEntry { … }
impl ExtentEntry { fn end(…) {…}  fn can_coalesce(…) {…} }
// VERUS-MIRROR-END extent_entry_coalesce
```

`drift-guard.sh` hashes each marked region and compares to `mirror-baseline.sha256`. If a region
changes, CI **fails** with the diff and the instruction to re-verify and re-baseline. So a change
to `can_coalesce` cannot land without someone re-confirming the proof. (Demonstrated: editing one
conjunct of `can_coalesce` trips the guard; reverting clears it.)

Workflow when the guard fires:
1. Reconcile the change into the matching `verus/*.rs` (often nothing — a semantics-preserving edit).
2. `verus/verify-intree.sh` — confirm the proof still passes.
3. `verus/drift-guard.sh --update` — record the new baseline (the deliberate "re-verified" stamp).

## CI wiring

Two **independent** jobs on the same checkout (see `ci.example.yml`):

- `cargo build` / `cargo clippy` — telix's nightly, the real kernel. *Unconstrained by Verus.*
- `verus/verify-intree.sh` — Verus's pinned `1.96.0`, the proofs + drift-guard.

Both must pass. They share no toolchain; a Verus bump never blocks a kernel-Rust bump (and vice
versa) — that decoupling is the whole point (`TOOLCHAIN.md`).

## The migration ladder (where this goes)

1. **Standalone verbatim + drift-guard** — *now*. Proofs in-tree, mirrored regions guarded.
2. **Share the leaf types** — re-point the stubbed `PhysAddr`/`page_size` at a tiny
   Verus-compatible shim that the kernel and the proofs both use, so those two names are no longer
   duplicated. (The soundness proofs are page-size-agnostic, so the feature-dependent `PAGE_SIZE`
   value does not affect them — note that in the shim.)
3. **Factor the verifiable core** — move the pure extent logic (`can_coalesce`, leaf ops, the
   tree/list invariants) into an `edition = "2021"`, Verus-subset inner module/crate that the
   kernel re-exports. Verus then checks the *actual* code, not a copy; the drift-guard retires for
   those regions.
4. **Annotate in place** — once Verus's pinned rustc reaches the kernel's edition/features, carry
   `requires`/`ensures` directly on the real functions and verify with `cargo verus` (the
   "same source two ways" of `TOOLCHAIN.md`). The end state.

Each rung is independently shippable; we are at rung 1 with the seam (markers + guard) cut so
rungs 2–3 are mechanical.

## Adding or migrating a module (checklist)

- [ ] Proof in `verus/<name>.rs`; passes `verus --crate-type=lib <name>.rs`.
- [ ] Add it to the loop in `verify.sh`.
- [ ] Wrap the real mm/ region it mirrors in `// VERUS-MIRROR-BEGIN <region>` … `END <region>`.
- [ ] `verus/drift-guard.sh --update` to baseline it.
- [ ] A `CORRESPONDENCE.md` row (Verus clause ⟷ Lean theorem ⟷ Kani harness).
- [ ] `verus/verify-intree.sh` green end-to-end.

## Division of labour (recap from TOOLCHAIN.md)

tessera owns *"does this Verus version verify the specs"* (re-runs `verify.sh` against a candidate
Verus). telix owns *"does this Verus version's rustc + vstd fit our CI"* and the in-tree wiring
here. A Verus bump is coordinated: tessera green-lights the specs, telix green-lights the build.
