# kernel-v2 build plan — the second-round verified kernel

Status: **scaffolding done (2026-08-25)** — workspace layout, build
system, and the capability-transport first component are in place and
host-testable; the Rocq/Iris spec side is pending K1.

## Where the planning lives

The **authoritative planning for the second-round prototype lives in
Tessera**, not here:

- [`~/src/tessera/doc/kernel-development-plan.md`](~/src/tessera/doc/kernel-development-plan.md)
  — the high-level strategy: two prototypes, the K1–K10 build-up order,
  verification strategy, relationship to the hardware model, test
  strategy, open questions.
- [`~/src/tessera/doc/stage3-kernel-strategy.md`](~/src/tessera/doc/stage3-kernel-strategy.md)
  — the verification pipeline: manual Iris heap_lang, the machine-
  interface layer, the Rust→Rocq connection.
- [`~/src/tessera/doc/formalization-status.md`](~/src/tessera/doc/formalization-status.md)
  and the rest of Tessera's `doc/` tree — milestone status and the
  hardware-model side.

This document records only the **Telix-repo specifics** the Tessera
plans do not cover: the concrete crate layout and build-system
mechanics inside this repository, and the Rust→Iris→hardware-model
correspondence itemised in
[`docs/kernel-v2-verification-bridge.md`](kernel-v2-verification-bridge.md).
Changes to the strategy, build-up order, or pipeline belong in the
Tessera docs, not here.

The design intent comes from the whitepaper (`~/src/telix-whitepaper/`):
the first-round prototype stays as a frozen reference, and the second-round
kernel is built incrementally, component by component, beside it in the
same repository.  Verified components cannot be structured like the
prototype's monolithic VM — the framekernel/multikernel matryoshka,
external pagers, and continuation-passing style demand different code
structure — so the side-by-side build lets the prototype guide the
redesign without being entangled by it.

---

## 1. Two prototypes, one repository — the actual layout

The Tessera plan's ideal sketch (`telix/{prototype,kernel}/`) does not
match the repository as it exists: `kernel/` *is* the prototype, a
flat workspace crate.  The build plan therefore uses:

```
telix/
├─ kernel/                  # first-round prototype — FROZEN
│                           #   build untouched (tools/build-kernel.sh -p telix-kernel)
├─ kernel-v2/               # second-round verified kernel (NEW, OWN cargo workspace)
│  ├─ Cargo.toml            #   standalone [workspace]; host-testable std-first
│  ├─ .cargo/config.toml    #   host target for direct invocations (see §2.2)
│  └─ src/
│     ├─ lib.rs             #   no_std in kernel builds, std under cargo test
│     ├─ caps/              # Phase 1: capability transport (ports, caps, msg passing)
│     └─ ...                # later: framekernel, allocator, pagers, personalities
├─ docs/                    # this plan + kernel-v2-verification-bridge.md
├─ tools/build-kernel-v2.sh # kernel-v2 test/build entry (neutral-CWD, see §2.2)
├─ tools/verify.sh          # runs the Telix-side checks; points at the Tessera Rocq build
└─ Makefile                 # `make test-kernel-v2`, `make verify`, `make verify-rocq`
```

### Why `kernel-v2/` and not `kernel/`

The prototype owns `kernel/` and its build (`build-kernel.sh` targets
`-p telix-kernel` explicitly).  Keeping the prototype's crate name and
path stable means **zero changes to the existing build path**.  The new
crate takes a fresh name (`telix-kernel-v2`), a fresh path, and a fresh
build story.  The two crates are allowed to diverge in structure by
design; nothing in kernel-v2 imports from the prototype.

### Why kernel-v2 is its OWN workspace (not a member)

The repo-root `.cargo/config.toml` defaults every build to the
`aarch64-unknown-none` bare-metal target with `[unstable] build-std =
["core"]` — correct for the prototype kernel (which needs build-std for
its bare targets), fatal for host unit tests: the build-std core
collides with std's core (`duplicate lang item: sized`).  Cargo **merges
config arrays**, so a nested config cannot clear the root's `build-std`.
kernel-v2 therefore follows the repo's established pattern for
experimental crates (the 29 excluded loom test crates): it is a
standalone workspace, invisible to root-workspace commands, and its
build entry point handles the config split explicitly (§2.2).

---

## 2. Build-system changes

### 2.1 Root workspace

The root `Cargo.toml` is **unchanged**: `kernel-v2` is deliberately NOT a
member (see "Why kernel-v2 is its own workspace" above).  The `exclude`
list is unchanged.  `build-kernel.sh` / `build-user.sh` are untouched —
they build by package name and never see kernel-v2.

### 2.2 Toolchain split (the "necessarily decoupled" rule)

The production kernel requires nightly (`build-std`, custom bare
targets); the verifiers (Verus/Kani) pin stable.  These can never be
one toolchain, and that is the design, not a constraint to fight —
per `docs/verus-extent-integration.md`:

- **kernel-v2** compiles on the root `rust-toolchain.toml` (nightly).
  The crate is written so it is `no_std` in kernel builds
  (`#![cfg_attr(not(test), no_std)]`) but std-enabled under `cargo
  test`, so every component is host-testable on the development
  machine with ordinary `cargo test`.
- **The config split.** The repo-root `.cargo/config.toml` forces the
  bare-metal target + build-std on the whole tree.  cargo discovers
  config files relative to the *current directory*, so
  `tools/build-kernel-v2.sh` runs cargo from a neutral CWD (a
  `mktemp -d` outside the repo): the repo-root config drops out of the
  discovery chain, and `CARGO_TARGET_DIR` pins artifacts to
  `kernel-v2/target`.  A `kernel-v2/.cargo/config.toml` sets the host
  target for direct invocations but cannot clear `build-std` (array
  merging) — the script is the supported entry point.
- **verify/** crates (Verus/Kani, later) are standalone workspaces and
  carry their own `rust-toolchain.toml` pinning the stable toolchain.
  rustup selects the nearest toolchain file by directory, so the
  stable pin wins inside `verify/*` without affecting the production
  build.
- **Side rec (orthogonal):** pin the root floating `channel = "nightly"`
  to a dated nightly (e.g. `nightly-2026-04-18`) so builds are
  reproducible and proofs are checked against a known rustc.

### 2.3 The Rocq/Iris side lives in Tessera, not here

The kernel's Iris heap_lang specs are Rocq files that sit on top of the
Tessera hardware model (same proof assistant, same Iris, same gpfsl —
the `shootdown_weak_broadcast.v` family).  They belong in
`tessera/hardware/rocq/` and are wired into that repo's `build.sh`
(which enforces axiom hygiene with `axiom_free` on headline theorems).
Telix does not duplicate the Rocq stack; `tools/verify.sh` invokes the
Tessera build for the kernel-spec files.  This is a deliberate split:
**kernel code here, kernel specs there, connected by the bridge
document** (`docs/kernel-v2-verification-bridge.md`).

### 2.4 Entry points

- `make test-kernel-v2` — `tools/build-kernel-v2.sh --test` (host unit
  tests, from a neutral CWD).
- `make verify` — Telix-side checks (unit tests + format hygiene on
  kernel-v2) and, if the Tessera tree is present, the Rocq kernel-spec
  build.
- `make verify-rocq` — `bash $TESSERA/hardware/rocq/build.sh` (or the
  kernel-specs-only invocation once K1 lands).

---

## 3. Build-up order — capability transport first

The K1–K10 table in Tessera's `doc/kernel-development-plan.md` is the
canonical order; see that document (not this one) for the full table
and dependencies.  Two updates to it were decided here:

- The first kernel-v2 component is the **capability transport** (per the
2026-08-25 decision), which the K table does not name explicitly;
it sits at the heart of a microkernel (the seL4 lesson: IPC +
capability table is the core).  It is defined as **Phase K1.5**, landing
between K1 (machine interface) and K2 (framekernel core):

| Phase | Component | Where | Verification | Depends on |
|-------|-----------|-------|--------------|------------|
| **K1** | Machine-interface Iris layer (~2,000 lines Rocq) | Tessera `hardware/rocq` | Proved against the Tessera machine model | hardware proofs (done) |
| **K1.5** | **Capability transport** — cap table, ports, message passing | Telix `kernel-v2/src/caps/` (Rust) + Tessera `kernel_specs/cap_transport_iris.v` (Rocq) | Manual Iris against K1 resources | K1 |
| K2 | Framekernel core: PTE walk/modify, sfence.vma, IPI send/recv | kernel-v2 | Manual Iris against K1 | K1 |
| K3 | LLFree allocator (lock-free, coremapless) | kernel-v2 | Manual Iris (or trusted primitive) | K1 |
| K4 | TLB shootdown protocol implementation | kernel-v2 | Manual Iris composing K1 + S2 theorems | K1, K2 |
| K5 | IOMMU management (IOTLB invalidate, ATS/PRI) | kernel-v2 | Manual Iris composing K1 + S4 theorems | K1, K2 |
| K6 | Scheduler management loop (EEVDF, per-core) | kernel-v2 | Manual Iris (bounded state) | K2 |
| K7 | External pager framework (capability channels, fault dispatch) | kernel-v2 | Protocol-level (K1 contracts) | K1.5, K2, K4 |
| K8–K10 | First pager, first personality server, device drivers | kernel-v2 | Independent / untrusted | K7 |

The full table, rationale, and dependencies live in the Tessera plan.

K1.5 reuses K1's memory/allocation resources for the capability table,
gpfsl for the lock-free ring binding, the SSG-3 interrupt-controller
model for cross-partition wakeups (`bc_machine_ipi_step_via_intc`
style), and the SSG-1 topology model for domain scoping — so every
part of the transport links back to a hardware-model proof.

### Why capability transport first

1. It is the ABI-facing core of a microkernel — nothing else in kernel-v2
   can be exercised without it (scheduling, pagers, and personalities
   all talk over capability channels).
2. It is **self-contained and host-testable**: cap tables, ports, and
   message queues are pure data-structure logic with no MMIO, no
   assembly, no interrupt entry — the ideal first component for the
   spec-first Rust shape (below).
3. It exercises the *full* verification pipeline end to end (Rust →
   Iris spec → K1 machine interface → hardware model) at small scale,
   de-risking the pipeline before the framekernel core is attempted.

---

## 4. The capability transport — spec-first shape

The kernel-v2 Rust code is written in the **spec-first shape** so it can
be audited against the Iris heap_lang spec by hand, in the seL4 style:

- **Total functions over explicit state.** Every operation takes the
  relevant state (`&mut CapTable`, `&mut Port`, …) and returns a
  `Result`; failures leave the state unchanged.  No globals, no
  interior mutability, no `unsafe`.
- **Ownership is explicit.** `send(port, msg)` takes the message by
  value: the message's ownership moves from the sender into the port's
  queue — the same transfer of ownership the Iris spec states.
- **Bounded queues.** A port has a maximum queue depth; `send` returns
  `Err(QueueFull)` (state unchanged) rather than silently growing —
  the boundedness the lock-free ring refinement will preserve.
- **No rights amplification.** `grant` copies a capability with rights
  ⊆ the source's rights; the kernel's sole authority over the table is
  what makes handles unforgeable (the seL4 model).
- **Host tests encode the invariants** the Iris spec will prove:
  FIFO order, bounded queues, no partial mutation on error, slot
  lifecycle, no rights amplification.

The Iris side (`tessera/hardware/rocq/kernel_specs/cap_transport_iris.v`,
once K1 lands) states these as heap_lang programs with pre/post
conditions over K1's memory and gpfsl resources.  The correspondence is
itemised in `docs/kernel-v2-verification-bridge.md`.

The port's bounded FIFO queue is the *abstract* representation; the
whitepaper's dynamically-bound lock-free memory rings are the *concrete*
representation, connected by a refinement — the same Layer-A/Layer-S
pattern Tessera already uses for extent/superpage tiling.

---

## 5. Verification pipeline (summary)

The pipeline itself is planned in Tessera's `stage3-kernel-strategy.md`;
the Telix-side artifact is the itemised Rust→Iris correspondence in
[`docs/kernel-v2-verification-bridge.md`](kernel-v2-verification-bridge.md).
In one line: kernel-v2 Rust (spec-first, audited by hand) ↔ Iris
heap_lang spec (Rocq, `tessera/hardware/rocq/kernel_specs/`) ↔ K1
machine-interface resources ↔ the axiom-free Tessera machine model,
with `axiom_free` hygiene on every headline theorem, host unit tests
per component, and QEMU diff-tests against Tessera's oracle for the
protocol paths.

---

## 6. Open questions

1. **K1 subset for K1.5**: the capability transport needs only a small
   slice of the machine interface (memory/allocation resources, gpfsl,
   intc wakeup).  Should K1.5's spec be written against a *minimal*
   K1 subset so it is not blocked on the full ~2,000-line K1 layer?
   (Recommended: yes — define the minimal subset first.)
2. **Assembly specialisation**: privileged instructions (`sfence.vma`,
   `mret`, `csrw satp`) are specialised from the Sail model per the
   whitepaper; the capability transport itself is assembly-free, so it
   does not block on this.
3. **Ring refinement**: the lock-free-ring refinement of the port queue
   is a later milestone (like Tessera's tiling refinement).  Confirm it
   stays out of K1.5 scope initially.
4. **Prototype reuse**: the prototype's cap/ and ipc/ modules
   (`kernel/src/cap/`, `kernel/src/ipc/`) are the reference for the
   transport's semantics; how much of their structure carries over is a
   per-component decision, guided by the frozen prototype.
