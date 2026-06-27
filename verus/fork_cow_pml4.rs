//! SEED — the #208 fork-COW kernel-PML4 invariant (telix's own corruption family).
//!
//! On x86-64 telix the top-level page table (PML4) splits into a per-process USER half and a
//! SHARED KERNEL set: entries **507..=511** are the kernel regions — `PHYS_DIRECT_MAP` (507),
//! `KSTACK` (508), `SLAB` (509), `PT` (510), high-half (511) — wired once at boot
//! (`arch/x86_64/boot.S`) and shared by every address space. On fork, the COW pass must
//! write-protect (COW-mark) only the USER entries; the kernel entries must be left untouched
//! (shared, never marked, never descended into or freed — `arch/aarch64/mm.rs` calls the same fix
//! "the twin of x86 PML4[507..]"). #208 is a fork COW pass that marks the WHOLE PML4, COW-marking
//! the kernel's own mappings → the "5f silent triple" fault. The `vm_debug_probes` `USER-CR3-BAD`
//! check (`PML4[507..=511]`) is the runtime form of the invariant proved here.
//!
//! This is the PML4-entry-level instantiation of tessera `proof/Tessera/Fork.lean`
//! `forkKernel_breaks_userSafe` (the object-level "a kernel extent must not be COW-shared into a
//! child"). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

/// telix x86-64 kernel PML4 set: indices 507..=511 (the shared kernel regions). A user fork must
/// never COW-mark these — doing so write-protects the kernel's own mappings (the #208 5f triple).
pub open spec fn is_kernel_pml4(i: int) -> bool {
    507 <= i && i <= 511
}

/// A PML4 modeled by the bit fork's COW pass toggles: index ↦ is-this-entry-COW-marked
/// (write-protected). telix's real PML4 is `[u64; 512]`; we track the COW state per entry.
pub type Pml4 = spec_fn(int) -> bool;

/// **Correct fork COW pass**: COW-mark only the USER half (indices `0..256`); leave the kernel set
/// (and the empty middle) exactly as they were — the kernel stays shared, unmarked.
pub open spec fn fork_cow(p: Pml4) -> Pml4 {
    |i: int| if 0 <= i && i < 256 { true } else { p(i) }
}

/// **The #208 bug — the COW pass marks the WHOLE PML4**, kernel entries included.
pub open spec fn fork_cow_buggy(p: Pml4) -> Pml4 {
    |i: int| true
}

/// **Correct fork preserves every kernel PML4 entry**: no kernel entry's COW bit changes, so the
/// kernel's own mappings survive the fork intact.
pub proof fn fork_preserves_kernel(p: Pml4, i: int)
    requires
        is_kernel_pml4(i),
    ensures
        fork_cow(p)(i) == p(i),
{
}

/// **The #208 bug COW-marks a kernel entry — a provable error**: an entry that was not COW-marked
/// becomes write-protected, corrupting the shared kernel page tables (the 5f silent triple).
pub proof fn fork_buggy_corrupts_kernel(p: Pml4, i: int)
    requires
        is_kernel_pml4(i),
        !p(i),
    ensures
        fork_cow_buggy(p)(i),
        fork_cow_buggy(p)(i) != p(i),
{
}

/// **The user-PML4 safety invariant** (what the `USER-CR3-BAD` probe checks): no kernel entry is
/// COW-marked in a user address space.
pub open spec fn user_pml4_safe(p: Pml4) -> bool {
    forall|i: int| is_kernel_pml4(i) ==> !p(i)
}

/// **Correct fork preserves user-PML4 safety**: a safe PML4 forks to a safe PML4 — the child never
/// gains a COW-marked kernel entry.
pub proof fn fork_preserves_safe(p: Pml4)
    requires
        user_pml4_safe(p),
    ensures
        user_pml4_safe(fork_cow(p)),
{
    assert forall|i: int| is_kernel_pml4(i) implies !fork_cow(p)(i) by {
        fork_preserves_kernel(p, i);
    }
}

/// **The #208 bug breaks user-PML4 safety** (the invariant the runtime probe catches): the buggy
/// fork produces a PML4 with a COW-marked kernel entry.
pub proof fn fork_buggy_breaks_safe(p: Pml4)
    ensures
        !user_pml4_safe(fork_cow_buggy(p)),
{
    assert(is_kernel_pml4(507));
    assert(fork_cow_buggy(p)(507));
}

} // verus!
