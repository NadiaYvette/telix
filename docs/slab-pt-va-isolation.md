# Slab + PT virtual-address isolation regions

## Motivation

Boot 19amfsq1049 captured decisive evidence (per
`project_208_untracked_writer_caught.md`): zero_daemon's iretq frame
shadow was valid at park time, but the live memory at sp was garbage at
validate time.  Additionally, `tref.saved_sp` no longer matched the last
*tracked* writer's value — yet every direct `t.saved_sp = X` in the kernel
is paired with `record_saved_sp_write`.

So an *untracked* writer is mutating `Thread.saved_sp`'s memory.  Since no
Rust code path bypasses the tracking helper, the bug is cross-data-
structure corruption: some other code thinks it is writing to its own
data structure, but its calculated address happens to land on a Thread
struct slab object.

## Goal

Catch the cross-write at the moment it happens, by putting each kernel
data-structure domain in its own virtual address region with **unmapped
guard regions** between them.  Cross-region writes generate a page fault
and we can capture the writer's RIP.

We have abundant unused virtual address space (47 canonical bits ≈ 140
TiB), so wide guards (TiB-sized) are cheap.

## Proposed VA layout

```
0xFFFFFFFF_80000000  KERNEL TEXT/DATA/BSS         (existing, ~1 GiB)
                     ...
0xFFFFFE00_00000000  PT_REGION                    (1 TiB)
0xFFFFFDC0_00000000   ... guard (256 GiB)
0xFFFFFD80_00000000  SLAB_THREAD_REGION           (256 GiB; Thread struct)
0xFFFFFD40_00000000   ... guard (256 GiB)
0xFFFFFD00_00000000  SLAB_SCHED_REGION            (256 GiB; sched heap, ART, extent tree)
0xFFFFFCC0_00000000   ... guard (256 GiB)
0xFFFFFC80_00000000  SLAB_IPC_REGION              (256 GiB; turnstiles, ports, caps)
0xFFFFFC40_00000000   ... guard (256 GiB)
0xFFFFFC00_00000000  SLAB_DEFAULT_REGION          (256 GiB; everything else)
                     ...
0xFFFFFA00_00000000  KSTACK_REGION                (256 GiB; kernel thread stacks)
                     ...
0xFFFFF600_00000000  PHYS_DIRECT_MAP              (offset-mapped phys for kernel)
```

Each region uses a fresh PML4 slot.  Guards are simply un-mapped PML4
entries (one whole PML4 slot = 512 GiB, far more than needed but
free).

## Phasing

This is a multi-session project.  Each phase is independently testable
and committable.

### Phase 1: VA region infrastructure (small, low-risk)

- Add VA constants in `arch/x86_64/mm.rs`.
- Set up PML4 entries pointing at empty PDPTs at boot.
- No allocator changes.  No code uses these VAs yet.
- Goal: prove the address space layout works and boot is unaffected.

### Phase 2: Phys-direct-map (PHYS_OFFSET-style)

- Reserve `PHYS_DIRECT_MAP` PML4 slot.
- Map all of physical RAM into that range (1:1 with constant offset).
- Add `phys_to_kva(pa)` / `kva_to_phys(va)` helpers.
- Update obvious physical-pointer casts.
- This is the **prerequisite** for any subsequent isolation work, because
  PT walks need to load PT bytes from physical pages via SOMEthing other
  than the identity map (which we want to remove).

### Phase 3: PT_REGION

- All page table allocations route through a `pt_alloc()` helper that
  reserves a slot in `PT_REGION`, maps it to a fresh phys page, and
  returns the **VA pointer**.
- PT walker reads PTE bytes via VA pointers (was: phys-cast-to-ptr).
- CR3 still holds the PA of the active PML4, but the kernel never
  dereferences PA directly — only via PHYS_DIRECT_MAP or PT_REGION.
- Risk: kernel chicken-and-egg.  Bootstrap PT (before runtime is up) has
  to be carved out specially.  Mitigation: keep boot PTs in a separate
  small pool that's mapped both ways during bring-up.

### Phase 4: SLAB_THREAD_REGION

- `Thread`-struct slab cache uses dedicated phys pages mapped into
  `SLAB_THREAD_REGION`.
- All callers receive VA pointers (which they already get implicitly via
  the slab abstraction — just the *value* changes).
- A buggy write to Thread.saved_sp's address from extent-tree code now
  produces a page fault, because extent tree pointer arithmetic can't
  legitimately land in `SLAB_THREAD_REGION`.

### Phase 5: SLAB_SCHED_REGION + SLAB_IPC_REGION

- Sched/IPC slab caches get their own VA regions.
- The cross-domain catch is now bidirectional: Thread → sched_heap
  corruption is also caught.

### Phase 6: KSTACK_REGION

- Kernel stacks mapped into KSTACK_REGION instead of identity-mapping
  phys pages.
- Each kstack has a guard PAGE (4 KiB) above and below it for stack
  overflow detection.

## Virtual ↔ physical conversion

Each region maps phys → VA with a known offset:

- `SLAB_X_REGION` base = `PHYS_DIRECT_MAP_BASE + X_offset`
- `pt_pa_to_va(pa) = PT_REGION_BASE + (pa - PT_PHYS_POOL_BASE)`

Or simpler: each region uses a PHYS_DIRECT_MAP-style offset map (slot
mapped from a per-region phys pool).  Phys → VA conversion is just an
addition.  Reverse is a subtraction.

The hard case is "given an arbitrary phys page, where is its VA?" — that
requires either a reverse table (vmap) or restricting each region to
draw from a known phys pool.  We pick the latter.

Each region has a **dedicated phys reservation** (carved at boot from
the multiboot memory map):

- `PT_PHYS_POOL`     — 16 MiB (sufficient for ~4000 page tables)
- `SLAB_THREAD_PHYS` — 16 MiB
- `SLAB_SCHED_PHYS`  — 32 MiB
- ... etc.

Total: ~128 MiB carved.  We have 1.5 GiB so this is fine.

## What this catches

| Bug                              | Caught by                              |
|----------------------------------|----------------------------------------|
| Slab-domain confusion            | VA region check + guard fault         |
| PT page used as data             | PT_REGION guard around it             |
| Kernel stack overflow / underflow| KSTACK guard pages                     |
| Data structure stride bug        | If stride overshoots region boundary  |
| Use-after-free same domain       | NOT caught (still in same region)     |
| Spatial overflow within slab     | NOT caught (still in slab region)     |

Use-after-free / within-region overflow needs different tooling (object
canaries, deferred-free quarantine).  Out of scope here.

## Open questions

1. Should kstacks use 4 KiB guards or a full unmapped PT (2 MiB)?  Bigger
   guards are cheaper because PT pages are scarce, but smaller guards
   waste less phys.
2. Direct-map vs per-region: should we keep one big PHYS_DIRECT_MAP and
   put all slab/PT/etc. inside it, or separate top-level PML4 slots
   for each?  Separate slots are easier to invalidate independently.
3. What about user space?  User VA layout is in PML4[0..3] (currently);
   should we leave that alone?
