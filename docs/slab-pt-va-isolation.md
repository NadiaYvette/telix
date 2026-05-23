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

One PML4 entry per object TYPE (not per individual object).  PML4 slot
size = 512 GiB, generous for all object instances of a given type.

```
PML4 index   VA base               Region
 511         0xFFFFFFFF_80000000   KERNEL TEXT/DATA/BSS (existing)
 510         0xFFFFFF00_00000000   PT_REGION      (page tables)
 509         0xFFFFFE80_00000000   SLAB_REGION    (all slab caches)
 508         0xFFFFFE00_00000000   KSTACK_REGION  (all kernel stacks)
 507         0xFFFFFD80_00000000   PHYS_DIRECT_MAP (offset map for raw phys)
 ...
```

Guards BETWEEN domains are automatic — adjacent unused PML4 slots
(512 GiB each) sit unmapped between the regions, but in practice the
chosen slot indices need not be contiguous, and a buggy write that
overshoots its domain hits an unmapped PDPT/PD/PT entry and faults.

Guards WITHIN a domain are achieved by mapping each object sparsely
within a larger VA window.  Example for KSTACK_REGION:

- Each kstack occupies a 2 MiB VA window.
- Only 128 KiB of phys is backed (the actual kstack).
- Placement: kstack pages mapped at the TOP of the window so the
  high address (kstack_top) is at 2 MiB - 8 bytes.  Below the
  kstack pages is ~1.87 MiB of unmapped VA — guard against
  underflow / deep-recursion stack overrun.
- A pointer that walks past kstack_top (overflow on pop) is
  immediately at the next 2 MiB boundary, which is the start of
  the NEXT kstack's guard zone — fault.

So one PML4 holds many kstacks, each in its own 2 MiB sub-window,
with most of the VA inside the window unmapped.  Phys cost is 128 KiB
per kstack (same as today); VA cost is 2 MiB per kstack (free).

PT_REGION uses a similar per-PT window scheme (4 KiB PT page in a
16 KiB or 32 KiB VA window).

SLAB_REGION can either use per-page guards (one page mapped per 16 KiB
window) or rely purely on cross-domain guards (the PML4 boundary
catches huge misdirections; within-region overruns get caught by
existing slab header / canary checks).

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

Each region has a dedicated phys reservation carved at boot:

- `PT_PHYS_POOL`     — 16 MiB
- `KSTACK_PHYS_POOL` — 64 MiB (~500 kstacks)
- `SLAB_PHYS_POOL`   — 64 MiB
- `PHYS_DIRECT_MAP`  — all phys (offset-mapped for raw access)

Total carved: ~144 MiB.  We have 1.5 GiB so this is fine.  No grow-on-
demand.

Phys → VA conversion within a region is a single subtract-and-add:

```
let va = region_va_base + (pa - region_phys_base) * window_stride
                          / page_size
```

For KSTACK_REGION with 2 MiB windows and 128 KiB phys per kstack, the
stride is 16× the phys size — VA grows 16× faster than phys.  We have
512 GiB of VA per PML4, so we can hold up to 32 GiB worth of kstack
phys.  Plenty.

`PHYS_DIRECT_MAP` is a separate PML4 slot offset-mapping ALL physical
RAM at a fixed offset, used for accessing any phys page from anywhere
(e.g. the PT walker reading the bytes of a non-current PML4).  This
is the standard kernel design (Linux: PAGE_OFFSET).

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

## Resolved design choices

1. **Per-kstack guard granularity**: 2 MiB VA window per kstack, with
   only the top 128 KiB phys-backed.  Unmapped VA inside the window
   acts as guard.  No phys waste (just VA).
2. **PML4 layout**: one PML4 slot per object TYPE (kstack, slab, PT) +
   one for PHYS_DIRECT_MAP.  Within each PML4, individual objects get
   their own sparse windows.
3. **Fixed phys reservations** carved at boot.  No grow-on-demand.
4. **Phys guards as separate optional layer**: VA isolation catches
   VA-pointer corruptors.  Adding small phys-page guards around
   reserved phys pools catches corruptors that compute raw phys
   addresses directly (rare but possible).  Defer until Phase 7 if
   needed.

## Open questions

1. User space: PML4[0..3] currently has user mappings.  Leave alone.
2. What about IST stacks?  They're currently mapped via the high-half
   linker mapping (already in PML4[511]).  Could be migrated to
   KSTACK_REGION in a later phase.
