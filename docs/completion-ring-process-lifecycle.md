# Completion-ring lifecycle across process creation/exec/exit

Status: **design + audit** (2026-06-23). No code changed. Prerequisite before the
completion ABI (io_uring-style SQ/CQ rings) becomes the **general async syscall
interface for arbitrary processes** rather than a handful of long-lived servers.

## What a "ring context" actually is

`SYS_IO_SETUP` → `io_setup` (`kernel/src/ipc/completion.rs:239`) gives a task a
completion context with two physical parts and one gate:

- **Two ring pages** (SQ + CQ), allocated by `map_ring` (`completion.rs:215`):
  - kernel side: `kva = phys_to_kva(pa)` — a **direct-map** VA, always valid
    kernel-side while the page is allocated, independent of any process page table.
  - user side: `uva = alloc_heap_va()` + a **raw `hat::map_range` PTE**
    (`completion.rs:227-228`). **No VMA, no memory object backs it** — it is a
    bare leaf PTE plus a bump in the heap cursor.
- **Three `Task` atomics** (`kernel/src/sched/task.rs:252-256`): `io_sq_kva`,
  `io_cq_kva` (the direct-map kernel VAs), and `io_depth` (0 = no context).
- **The gate**: the deliver hook (`kernel/src/syscall/port.rs:~944`,
  `completion.rs:~519`) routes a task's inbound port messages into its CQ
  **iff `io_depth != 0`**, writing through `io_cq_kva` (the direct map).

`io_teardown` (`completion.rs:285`) clears the three atomics but, by its own
comment, deliberately does **not** unmap/free the pages — "full reclamation
belongs to address-space teardown." That handoff is the bug: nothing on the
aspace-teardown paths reclaims them, because they have no VMA/object to reclaim.

The context has **no binding to the aspace or task lifecycle**. The only thing
that ever clears it is an explicit `SYS_IO_TEARDOWN` from userspace.

## Why Telix makes this sharp

Telix doesn't fork-copy; a parent explicitly constructs a child and does surgery
on the child's address space (COW-dup of VMAs, explicit segment maps). There is
no implicit "the child is a copy of the parent" that would carry — or correctly
not carry — a ring. Every lifecycle transition must handle the ring *explicitly*,
and today none of them do.

## Audit of the three transitions (verified against code)

### 1. exec — LIVE HAZARD (IPC black-hole + page leak/UAF)
`sys_execve` (`handlers.rs:2749`) → `aspace::reset` (`aspace.rs:583-619`):
allocates a fresh page table (`handlers.rs:2929`), `object::destroy`s every VMA
(frees VMA-backed leaves), frees the old PT tree (`aspace.rs:615`), switches.
**Nothing on the exec path touches `io_depth`/`io_sq_kva`/`io_cq_kva` or calls
`io_teardown`** (grepped `handlers.rs:2749-3274` + `aspace.rs` — zero refs).

Consequence for a task that did `io_setup` then `execve`:
- The ring pages have no VMA → `object::destroy` does not free them; the
  VMA-less leaf is orphaned (leaked), and the old user PTE dies with the freed PT
  tree.
- `io_depth` stays `!= 0` and `io_sq_kva`/`io_cq_kva` still point (via direct map)
  at the orphaned pages. The deliver hook keeps **hijacking the exec'd program's
  inbound IPC into a ring the new program never set up and cannot read** → the
  new program silently loses messages. (If the orphaned leaf is ever reclaimed,
  the direct-map write becomes a UAF instead.)

### 2. exit — LIVE HAZARD (stale context leaks into the reused Task slot)
`exit_current_thread` (`scheduler.rs:11143`) → `aspace::destroy` (`aspace.rs:510`)
frees VMA-backed pages + RCU-frees the PT tree. Again **nothing clears the ring
atomics** and the VMA-less ring pages are not reclaimed. Worse, Task slots are
**recycled**: `alloc_task_id` (`scheduler.rs:~4778`) returns a reaped slot
*without* re-zeroing (only fresh-page allocations run `Task::empty`), and
`finalize_spawn` (`scheduler.rs:5186`) resets many stale fields but **omits the
`io_*` trio**.

Consequence: a ring-using process that exits without `io_teardown` (the common
case — every ring user eventually exits) leaves `io_depth != 0` + stale ring KVAs
in the slot. The next task to reuse that slot inherits them; the deliver hook
(gated on `io_depth != 0` alone, no per-task validation) routes that new task's
inbound IPC into a stale/foreign ring → corruption or cross-process leakage.
**This is the most serious one** — it fires on ordinary exit, no exec required.

### 3. clone/fork — correct-by-accident, with a minor isolation nuance
`clone_for_cow` (`aspace.rs:794-977`) COW-dups only **active VMAs**
(`aspace.rs:828-843`) with no per-region filtering. The ring pages have no VMA →
they are invisible to clone → **not inherited** as mappings, and the child `Task`
starts with `io_* = 0` (`Task::empty`, `task.rs:345-349`). So the child correctly
has no completion context (matches io_uring: rings are not inherited across fork).
Nuance: the ring's leaf PTE lives in a **shared COW PT node**
(`clone_shared_tables` shares PDPT/PD), so the child's page table can still
*resolve* the parent's ring user-VA to the parent's ring page until a COW-break —
a small isolation aliasing (the child could read the parent's ring at that VA if
it guessed it). Benign for correctness (child's `io_depth=0` → kernel never uses
it), but untidy.

## Precedent

io_uring / IOCP semantics, which we should match:
- **per-process**, created explicitly (`io_setup`);
- **not inherited across fork/clone** (child must create its own);
- **does not survive exec** (the ring is destroyed; the new image re-creates it);
- **freed at exit**.

Telix already gets fork right (by accident); exec and exit are wrong.

## Defined semantics (the design)

**Invariant to establish:** a task's ring context is bound to its address space.
It exists from `io_setup` until the aspace is replaced (exec), destroyed (exit),
or the task explicitly tears it down — and **`io_depth` is cleared, with the
deliver hook quiesced, before the ring pages can be freed or the slot reused.**

Concrete rules:

1. **One reclamation primitive.** Add `clear_completion_ctx(task)` (in
   `completion.rs`) that: (a) `io_depth.store(0, Release)` FIRST so the deliver
   hook stops taking new entries; (b) frees the two ring pages
   (`free_ring(kva)`); (c) zeroes `io_sq_kva`/`io_cq_kva`. `io_teardown` becomes a
   thin wrapper that also frees the pages (closing today's per-setup page leak).

2. **Concurrency.** Clearing `io_depth` Release stops *new* deliveries, but a
   deliver may be mid-write on another CPU. Free the ring pages via the **existing
   RCU defer** machinery (the same path `aspace::destroy` already uses to defer PT
   teardown, `aspace.rs:557`), so in-flight deliveries drain before the page is
   reused. Do **not** free synchronously.

3. **exec:** call `clear_completion_ctx` on the `aspace::reset` path, before the
   old aspace is torn down. Rings do not survive exec; the new image re-runs
   `io_setup` if it wants one.

4. **exit:** call `clear_completion_ctx` on the `exit_current_thread` /
   `aspace::destroy` path.

5. **Task reuse (defense in depth):** also zero `io_sq_kva`/`io_cq_kva`/`io_depth`
   in the reaped-slot branch of `alloc_task_id` (or in `finalize_spawn`'s reset
   list), so even a missed clear-on-exit cannot poison the next occupant.

6. **clone isolation (lower priority):** give ring pages a proper VMA/object with
   a *skip-on-clone* marker (see #7) OR map them in a per-aspace region that
   `clone_for_cow` excludes, so the child's page table cannot resolve the parent's
   ring VA at all.

7. **Principled root-fix (recommended, larger): back ring pages with a
   VMA/object.** If the SQ/CQ pages were ordinary VMA/object-backed mappings
   (with a `skip-clone` + `kernel-also-mapped` attribute), then: aspace teardown
   reclaims them automatically (no special hook, no leak), clone filters them by
   the flag (isolation for free), and the lifecycle becomes uniform with all other
   process memory. The targeted hooks (#1–#5) are the minimal correctness fix; #7
   is the clean design and also lets us **lift the one-shot-per-task restriction**
   (boot lc9) since re-setup would just be another mapping.

## Recommended plan (phased; code later, on a calm host for validation)

- **Phase A — correctness (closes both live hazards).** `clear_completion_ctx`
  + RCU-deferred page free; call from exec (`aspace::reset`) and exit
  (`exit_current_thread`/`aspace::destroy`); zero `io_*` on Task-slot reuse.
- **Phase B — principled.** VMA/object-back the ring pages (skip-clone flag);
  remove the targeted exec/exit hooks in favor of automatic aspace reclamation;
  lift the one-shot restriction.
- **Validation** (needs a calm host — deep boots are #120-flaky under load):
  1. `io_setup` → `execve` a different image → confirm the new image's inbound IPC
     works (no black-hole) and no leaked/again-routed CQEs.
  2. `io_setup` → exit → force Task-slot reuse → confirm the next task's IPC is
     clean (no stale-ring routing).
  3. clone after `io_setup` → confirm child cannot read the parent's ring VA.
  A loom model of deliver-hook ‖ clear_completion_ctx (the concurrency in #2) is
  cheap and worth adding.

## Scope note

All of the above is **latent today**: the only ring users are linux_srv (one
`io_setup` at boot, never exec's/exits) and init's transient smokes (explicit
`io_teardown`). None hits the exec or exit-reuse transitions. But this lifecycle
is a hard prerequisite before any *general* process — which exec's, forks, and
exits routinely — can use the completion ABI. It must land before the ABI goes
beyond servers.
