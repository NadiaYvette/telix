//! SEED — sub-page PLACEMENT correctness for telix's clustered VM (the #143 wrong-data class).
//!
//! telix is the other clustered-superpage VMM, so it carries the identical hazard pgcl's #143
//! exposed: a kernel page (cluster) backs `PAGE_MMUCOUNT` hardware MMUPAGEs, and the map from a
//! *virtual* sub-offset (vsub) to a *physical* sub-frame (psub) is normally the identity but need
//! NOT be — non-cluster-aligned virtual motion (the telix analogue of `mremap`/`relocate_vma_down`)
//! keeps a sub-PTE's psub while giving it a new vsub, a permutation `π : vsub ↦ psub`. Any
//! rematerialize-in path (a future swap-in / migration-in) that reconstructs psub from the faulting
//! VADDR (vsub) instead of the source loses π and feeds userspace the wrong sub-page — exactly pgcl
//! Bug 2. telix has no sub-offset encoding YET; this is the invariant it must satisfy when it grows
//! one, proved in-tree so CI catches a regression the day the code lands.
//!
//! This is the Verus twin of tessera `proof/Tessera/{Placement,Permute}.lean`, on telix's real
//! `mm::page` constants and `PhysAddr`, at the sub-frame-INDEX level (byte address = index *
//! `MMUPAGE_SIZE`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

/// telix `mm::page` constant (kernel/src/mm/page.rs): one hardware MMUPAGE is 4096 bytes; a cluster
/// is `PAGE_MMUCOUNT = PAGE_SIZE / MMUPAGE_SIZE` of them.
pub const MMUPAGE_SIZE: usize = 4096;

/// telix `mm::page::PhysAddr` — a physical address as a `usize` newtype.
#[derive(PartialEq, Eq)]
pub struct PhysAddr(pub usize);

/// The physical sub-frame INDEX backing virtual sub-offset `vsub` of a cluster based at sub-frame
/// `pbase`, under the cluster's sub-page permutation `psub`. (Byte address = this index *
/// `MMUPAGE_SIZE`.) `psub` is the identity in the normal case; virtual relocation makes it not.
pub open spec fn frame_pi(pbase: int, psub: spec_fn(int) -> int, vsub: int) -> int {
    pbase + psub(vsub)
}

/// The **identity** placement — physical sub-offset read from the VIRTUAL sub-offset (`psub(vsub)`
/// assumed `== vsub`). telix's natural linear extent translation `start + i·MMUPAGE` is exactly this,
/// and it is correct *iff* the cluster is canonically aligned.
pub open spec fn frame_identity(pbase: int, vsub: int) -> int {
    pbase + vsub
}

/// **Faithful placement — carry psub** (the fix obligation): an entry/PTE that carries the source
/// sub-offset places every vsub at its intended physical sub-frame, for ANY `psub`. This is what
/// COW/fork already do (read psub from the source PTE); swap/migration entries must do the same.
/// The Verus twin of tessera `Permute.framePi_faithful`.
pub proof fn carry_psub_faithful(pbase: int, psub: spec_fn(int) -> int, vsub: int)
    ensures
        frame_pi(pbase, psub, vsub) == pbase + psub(vsub),
{
}

/// **The #143 Bug-2 non-theorem (telix-side guard)**: reconstructing the physical sub-offset from the
/// VIRTUAL sub-offset places the WRONG physical sub-frame whenever the cluster is not canonically
/// aligned (`psub(vsub) != vsub`). So telix must never reconstruct a sub-offset from the faulting
/// address on a rematerialize-in path. The Verus twin of tessera `Permute.reconstruct_from_vaddr_wrong`.
pub proof fn reconstruct_from_vaddr_wrong(pbase: int, psub: spec_fn(int) -> int, vsub: int)
    requires
        psub(vsub) != vsub,
    ensures
        frame_identity(pbase, vsub) != frame_pi(pbase, psub, vsub),
{
}

/// A single extent entry (telix `mm::extent::ExtentEntry`, placement-relevant fields). The extent is
/// physically contiguous from `start`, so its sub-frames are linear.
pub struct ExtentEntry {
    pub start: PhysAddr,
    pub page_count: u16,
}

/// The physical sub-frame INDEX telix's extent assigns to virtual sub-offset `vsub`: the extent's
/// base sub-frame (`start / MMUPAGE_SIZE`) plus `vsub` — the LINEAR translation.
pub open spec fn extent_sub_frame(e: ExtentEntry, vsub: int) -> int {
    (e.start.0 as int) / (MMUPAGE_SIZE as int) + vsub
}

/// **telix's extent translation IS the identity placement**: `start/MMUPAGE + vsub`. So it is
/// correct exactly when the cluster is canonically aligned (`psub == vsub`); the moment telix maps a
/// cluster at `vsub != psub` (relocation) and rematerializes it by this linear rule, it hits Bug 2.
/// This pins where the guard applies in the real code.
pub proof fn extent_translation_is_identity(e: ExtentEntry, vsub: int)
    ensures
        extent_sub_frame(e, vsub)
            == frame_identity((e.start.0 as int) / (MMUPAGE_SIZE as int), vsub),
{
}

/// What userspace OBSERVES at virtual sub-offset `vsub`: the content of the physical sub-frame the
/// placement `place` maps it to, in physical memory `mem`.
pub open spec fn observed(place: spec_fn(int) -> int, mem: spec_fn(int) -> int, vsub: int) -> int {
    mem(place(vsub))
}

/// **Content-level Bug-2 (telix-side guard)**: even with the cluster's content intact in memory, a
/// reader that places via the identity rule observes DIFFERENT content than one that carries psub,
/// whenever the crossed sub-frames differ — the residual #143 wrong-data. A future telix
/// swap/migration path must place via `frame_pi` (carry psub), not `frame_identity`.
pub proof fn identity_observes_wrong(
    mem: spec_fn(int) -> int,
    pbase: int,
    psub: spec_fn(int) -> int,
    vsub: int,
)
    requires
        mem(frame_identity(pbase, vsub)) != mem(frame_pi(pbase, psub, vsub)),
    ensures
        observed(|w: int| frame_identity(pbase, w), mem, vsub)
            != observed(|w: int| frame_pi(pbase, psub, w), mem, vsub),
{
}

} // verus!
