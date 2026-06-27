# Verus / Rust toolchain — integrating into telix master

The concrete version situation and the strategy for keeping Verus in mainline while telix
tracks up-to-date Rust.

## The coupling (measured, this seed)

| | Version |
|---|---|
| Verus | `0.2026.06.20.911e4e7` (prebuilt release from `verus-lang/verus`) |
| **Pinned rustc (for *verification*)** | **`1.96.0-x86_64-unknown-linux-gnu`** (from `version.json`) |
| `vstd` / `builtin` | `0.0.0-2026-06-14-…`, edition 2021 |

Verus is a **rustc driver** built against one exact toolchain (it uses `rustc_private`
internals). Each Verus release pins one rustc; releases are frequent (date-stamped) and the
pin advances with them, lagging latest nightly by ~weeks (here: 1.96.0 vs a 1.97-nightly host).

## The key fact: the *same source* builds two ways

A `verus! { … }` block compiles under **both**:
- **telix's normal `cargo build`** (any reasonably recent Rust): the `verus!` proc-macro
  (from `verus_builtin_macros`) expands to plain executable Rust — the `requires`/`ensures`/
  `proof` parts become no-ops. Needs `builtin`, `builtin_macros`, `vstd` as deps.
- **Verus** (its pinned 1.96.0): the same block is *verified*.

So the verification toolchain and telix's build toolchain are **decoupled**. telix builds the
kernel with whatever Rust it wants; only the *verify step* is locked to Verus's 1.96.0.

## Recommended setup for master

1. **Pin a Verus version** (vendor the release, or a fetch script) — reproducible CI.
2. **Two CI steps on the same source**:
   - `cargo build` — telix's up-to-date Rust (the real kernel build).
   - `cargo verus verify` (the shipped `cargo-verus` subcommand) — Verus's 1.96.0 toolchain.
   Both must pass. `cargo-verus` has `verify` / `build` (verify *and* build) / `check`.
3. **Add `builtin` / `builtin_macros` / `vstd` as build-deps** (path to the vendored Verus
   release, or crates.io if published) so the `verus!{}` modules compile under the normal build.
4. **Keep the `verus!{}`-annotated modules within Verus's supported Rust subset** — i.e. don't
   use language features newer than the pinned rustc (1.96.0) inside annotated code. Un-annotated
   modules are unconstrained.

## Reconciling "telix wants up-to-date Rust"

- The kernel proper: **no constraint** — build with the latest Rust.
- The annotated modules (e.g. `mm/extent.rs` once it carries `verus!{}`): constrained to what
  the pinned rustc supports *for the verify step*. The gap is small (~one version) and **closes
  with each Verus release** — bumping Verus is how telix pulls the verification toolchain forward.
- Strategy: **bump Verus deliberately** (not every kernel-Rust bump). Each Verus bump may (a) move
  the pinned rustc forward — good — and (b) change `vstd` APIs — so the specs may need a touch-up.
  Pin, test, bump on tessera's side first (tessera re-verifies all seeds against the new Verus),
  then telix adopts.

## Division across the two repos

tessera owns "does this Verus version verify the specs" (it re-runs `verify.sh` against a candidate
Verus and reports). telix owns "does this Verus version's rustc + `vstd` fit our build and CI."
A Verus bump is a coordinated step: tessera green-lights the specs, telix green-lights the build.
