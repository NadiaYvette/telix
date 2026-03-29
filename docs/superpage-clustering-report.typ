// =============================================================================
// Telix VM Architecture: Combining Page Clustering with Superpage Promotion
// =============================================================================
//
// Build: typst compile docs/superpage-clustering-report.typ
//
// Style: USENIX-flavored two-column, 10pt body.

#set document(
  title: "Bridging the Gap: Page Clustering Meets Reservation-Based Superpages",
  author: ("Nadia Yvette Chambers",),
  date: auto,
)

#set page(
  paper: "us-letter",
  margin: (x: 1in, y: 1in),
  columns: 2,
  numbering: "1",
)
#set text(font: "New Computer Modern", size: 10pt)
#set par(justify: true, leading: 0.55em)
#set heading(numbering: "1.1")
#show heading.where(level: 1): set text(size: 12pt)
#show heading.where(level: 2): set text(size: 11pt)

// Reference style
#show link: set text(fill: eastern)

// Figure helper
#let fig(body, caption: none, label: none) = {
  figure(body, caption: caption)
}

// Code block style
#show raw.where(block: true): set text(size: 8pt)
#show raw.where(block: true): block.with(
  fill: luma(245),
  inset: 6pt,
  radius: 3pt,
  width: 100%,
)

// =============================================================================
// Title Block
// =============================================================================

#align(center)[
  #text(size: 16pt, weight: "bold")[
    Bridging the Gap: Page Clustering Meets \
    Reservation-Based Superpages
  ]
  #v(0.4em)
  #text(size: 11pt)[Nadia Yvette Chambers]
  #v(0.2em)
  #text(size: 9pt, style: "italic")[Draft — \today]
]

#v(1em)

// =============================================================================
// Abstract
// =============================================================================

#heading(level: 1, numbering: none)[Abstract]

// >>> HAND-WRITE: 200-300 words covering:
//
//   - Primary goal: a pervasively extent-based memory system. Not just
//     TLB reach — physical contiguity is a first-class design target
//     across the entire kernel.
The Telix operating system kernel is an effort to manage memory in a
pervasively extent-based manner for several reasons.
//   - Why contiguity matters (multiple dimensions, not just TLB):
//     (a) TLB reach: larger mappings cover more VA space per entry
//     (b) Metadata overhead: per-page metadata (space, cache, TLB,
//         bandwidth-to-memory) grows linearly with page count. Memory
//         capacity has grown faster than cache/TLB/memory-bandwidth
//         (the "memory wall"), so linear-per-page metadata consumes an
//         increasing proportion of the resources the kernel manages.
//         Sublinear metadata (both space and time) is a design goal.
//     (c) Scatter-gather reach: contiguous physical regions extend
//         DMA scatter-gather list coverage
//     (d) Filesystem block contiguity: memory contiguity mirrors FS
//         block contiguity more closely (historically, FS block size
//         was directly limited by PAGE_SIZE in elder/legacy kernels)
While algorithmic complexity should be a readily apparent motive, in that
$O(E) subset.neq O(M)$ where $E$ is extents and $M$ is memory, metadata
furthermore carries the burdens of competing with the user workload for
the cache, the TLB, and bandwidth-to-memory. Furthermore, there are also
advantages in terms of TLB reach, IOMMU reach, and scatter-gather reach,
where here, ``reach'' means how much memory that a fixed number of
hardware-limited TLB, IOMMU or scatter-gather list entries is capable of
spanning.

//   - The gap problem and the multi-level variant (as before:
//     LoongArch 4× factor, Alpha 8× Navarro target, MIPS64 1K pages)
//   - Page clustering: allocation unit > MMU page → guaranteed physical
//     contiguity → partitions the superpage spectrum into "structurally
//     free" and "reservation-needed"
//   - No strict ordering: multiple superpage sizes can exist between
//     MMUPAGE_SIZE and PAGE_SIZE (MIPS64 1K→4K→16K→64K sub-floor chain)
//   - Novel contribution: the *combination* and the insight that it
//     qualitatively changes superpage economics (ratio shifts from
//     SUPERPAGE/MMUPAGE to SUPERPAGE/PAGE_SIZE) + the sublinear
//     metadata argument
Past efforts to support the virtual memory requirements for this have
proved difficult because of users' demands for guarantees that
allocations of small superpages won't fail due to fragmentation and wide
gaps between the minimum page size and the first large page size on
certain architectures. The author presents a solution to these two issues
by trading off increased internal fragmentation in order to reduce
external fragmentation with a larger kernel allocation unit than the
TLB's base page size. A kernel allocation unit increase for MMUs with
broad, dense page size spectra definitionally guarantees for any
successful page allocation that superpage sizes smaller than the kernel
allocation unit won't fail due to external fragmentation. A kernel
allocation unit increase for MMUs with few, widely-separated page sizes
on the other hand serves to ``bridge the gap'' between the MMU base page
size and the first nontrivial superpage size by reducing the power of two
for the number of contiguous aligned kernel allocation units required to
assemble a superpage of the first nontrivial superpage size, a critical
factor that could be called the ``assembly ratio''. The observations in
this report confirm improved success in superpage allocation via assembly
ratio reduction expected from the well-established steep decline of
available memory fragments of aligned sizes as the assembly ratio
increases. For instance, with a kernel allocation unit of 4 KiB, there
may be some difficulty lining up the assembly ratio of 512 base pages in
order to reach the first nontrivial superpage size of 2 MiB. This method
reduces that assembly ratio, so the indivisible fragments might be 64 KiB
or 128 KiB size, of which only 32 or 16 need to be lined up. Furthermore,
not only are small superpage sizes guaranteed not to fail due to external
fragmentation, but where there are multiple superpage sizes smaller than
the kernel allocation unit, promotion is guaranteed successful, subject
to constraints of alignment and fitting within mappings. For instance, a
MIPS core with power-of-4 pages starting at 1 KiB, there are small
superpage sizes of 4 KiB, 16 KiB, and 64 KiB within a 128 KiB kernel
allocation unit. Even where mappings are offset by some margin instead of
aligned, promotion within the sub-spectrum of smaller superpage sizes is
always possible with allocation units of at least double the size of a
superpage size to be made small by the choice of allocation unit.

//   - Implementation: Telix microkernel (seL4-inspired fast IPC +
//     Mach-lineage VM), 3 arches, single-level (2M) realized,
//     multi-level designed
To demonstrate this, the author has implemented such a virtual memory
management system within a microkernel, where the microkernel framework
was used to facilitate rapid development (there are more reasons). The
overall basic design was taken from seL4 and various ideas for it were
borrowed from Mach. Ports were initially devised for 64-bit RISC-V,
64-bit ARM and 64-bit x86, and additional ports for 64-bit LoongArch,
64-bit MIPS and IBM POWER are planned. Reservations in the style of
Navarro et al \[1\] were used to augment mappings of already-populated
memory objects with superpages with speculative allocations to facilitate
promotions of page sizes. Mel Gorman's fragmentation analysis
infrastructure, measurements of proportions of caches and TLBs devoted to
memory management metadata, and other performance measurements will be
used to show improvements over more conventional operating systems.

//   - Historical arc: dense page-size spectra (Itanium 11, MIPS 10,
//     SPARC 6-8, PA-RISC 9) were common in 1990s-2000s HW; abandoned
//     by modern HW because no OS exploited them. This design aims to
//     demonstrate the software was missing, not the hardware need.
//   - MIPS64 as the densest genuinely flexible spectrum; LoongArch as
//     transitional (ISA dense, STLB constrains practice); Itanium as
//     historical high-water mark; Alpha as Navarro et al. connection.
Historically, many RISC and RISC-derived architectures featured dense
page size spectra. Furthermore, recent hardware trends have unfortunately
been toward replicating the problem of having a large gap between the MMU
base page size and the first nontrivial superpage size. This project
hopes to demonstrate that the software was merely missing, that the
motivation of the hardware feature is in fact sound, and to demonstrate
the implementation of operating system usage thereof in concrete, open
source and reusable form.

#text(fill: red)[\[TODO: Hand-write abstract\]]

#v(1em)

// =============================================================================
// 1  Introduction
// =============================================================================

= Introduction

// >>> HAND-WRITE this section. Points to cover (bullet list, not prose):
//
//   - FRAMING: The primary goal is a pervasively extent-based memory
//     system. Physical contiguity is a first-class design target, not
//     just a TLB optimization. TLB reach is one benefit among several.
//
//   - WHY CONTIGUITY MATTERS (multiple dimensions):
//     (a) TLB reach: small TLBs (64-entry L1 DTLB) vs. growing working
//         sets. Superpages extend effective TLB coverage.
//     (b) Metadata overhead: per-page structures (struct page, PTE,
//         allocator state) scale linearly with page count. Memory
//         capacity has grown faster than cache size, TLB entry count,
//         and memory bandwidth — the "memory wall." Linear-per-page
//         metadata therefore consumes an increasing proportion of the
//         very cache/TLB/bandwidth resources the kernel manages.
//         Sublinear metadata is a design goal (both space and time).
//     (c) DMA scatter-gather reach: physically contiguous regions
//         extend scatter-gather list coverage, reducing IOMMU pressure
//         and enabling larger DMA transfers.
//     (d) Filesystem block contiguity: memory contiguity can mirror FS
//         block layout more closely. In elder/legacy kernels, FS block
//         size was directly limited by PAGE_SIZE. Larger allocation
//         units remove this historical constraint.
//     (e) Algorithmic sublinearity: extent-based tracking (one
//         descriptor per contiguous run, not per page) yields sublinear
//         time and space if contiguity is maintained.
//
//   - HISTORICAL TREND: dense superpage spectra have become LESS
//     common over time. 1990s-2000s hardware (Itanium: 11 sizes,
//     320 FA TLB entries; MIPS64: 10 sizes, per-entry PageMask;
//     SPARC64: 6-8 sizes; PA-RISC: 9 sizes; Alpha: 4 sizes)
//     assumed OSes would exploit the full spectrum. They did not.
//     Modern architectures converged on ~3 widely-separated sizes
//     (4K, 2M, 1G) because no mainstream OS effectively used
//     intermediate sizes. The dense spectra were abandoned by HW
//     designers for lack of software demand. LoongArch's STLB
//     (locked to one base size, 97% of TLB) reflects this.
//     This paper argues the opportunity was real but the software
//     design was missing — the combination of clustering + reservations
//     makes dense spectra genuinely exploitable.
//
//   - THE GAP PROBLEM:
//     The gap between MMUPAGE_SIZE and the first hardware superpage
//     size varies dramatically across architectures:
//       Sparse spectra:  x86-64, aarch64, riscv64: 4K → 2M (512×)
//       Dense spectra:   MIPS64: 1K → 4K (4×), 10 per-entry-flexible levels
//                        Alpha: 8K → 64K (8×), 4 levels — Navarro et al's target
//                        SPARC64: 8K → 64K (8×), 6+ levels per-entry
//       Misleading:      LoongArch encodes ~18 sizes but STLB (2048 of 2112
//                        entries) locked to ONE size; only 64 MTLB entries
//                        support variable sizes. In practice: 1 base + 1 huge.
//       Enterprise:      IBM POWER: 4K/64K base, 2M, 1G (irregular)
//       MIPS64 with 1K pages is only 2× the VAX 512B page that
//       motivated McKusick's original clustering code.
//     NOTE: The LoongArch STLB limitation is a cautionary example —
//     encoding support ≠ practical support. MIPS64's fully-associative
//     TLB with per-entry PageMask is genuinely flexible.
//     The wider the gap, the harder it is to assemble contiguous physical
//     regions for promotion.
//
//   - Many architectures support MULTIPLE superpage sizes simultaneously.
//     This is not an edge case — it's the common case. The OS should use
//     all available sizes, not just the smallest or largest.
//
//   - TWO PRIOR BODIES OF WORK attack different parts of this:
//       (a) BSD-lineage page clustering (allocation granularity > MMU page)
//           guarantees contiguity within each allocation page
//       (b) Navarro et al. reservation-based superpages handle contiguity
//           across allocation pages, including through fork/COW
//
//   - KEY INSIGHT: combining (a) and (b) yields a unified multi-level
//     architecture. Clustering provides a "contiguity floor" that
//     partitions the superpage spectrum: sizes at or below PAGE_SIZE are
//     free (structural invariant), sizes above use reservations. The ratio
//     that matters shifts from SUPERPAGE/MMUPAGE to SUPERPAGE/PAGE_SIZE.
//
//   - The design is multi-level and heterogeneous from the start.
//     An architecture provides a table of superpage sizes. Some fall
//     below the floor (free). Others form a promotion chain above it.
//     The same reservation mechanism serves all levels.
//
//   - MICROKERNEL CONTEXT: Telix is a microkernel drawing on seL4's
//     fast-IPC techniques and Mach's VM object/pager architecture.
//     The microkernel structure may specifically benefit the extent-based
//     design: the minimal kernel footprint reduces metadata baseline;
//     capability-based memory management isolates MM policy from
//     mechanism; user-level pagers can implement workload-specific
//     promotion policies.
//
//   - CONTRIBUTIONS:
//     (1) A unified design that integrates page clustering and
//         reservation-based superpages into a single multi-level framework
//     (2) The contiguity floor concept and its sublinear-metadata
//         implications
//     (3) Reservation-aware COW that preserves promotability across fork,
//         including epoch-based multi-fork tracking and straggler
//         consolidation
//     (4) Multi-level graduated demotion for page reclamation
//     (5) Implementation in a microkernel (Telix) on 3 architectures
//
//   - NEAR-TERM DESIGN TARGETS (beyond scope of this paper but
//     part of the broader system):
//     - Page-table-free operation for inverted page table and software
//       TLB refill architectures (MIPS, SPARC, PA-RISC, OpenRISC)
//     - Shared page tables for radix-tree architectures (x86-64, aarch64,
//       RISC-V) — further metadata reduction
//
//   - Road map of the paper

#text(fill: red)[\[TODO: Hand-write introduction\]]


// =============================================================================
// 2  Background
// =============================================================================

= Background <sec:background>

== Hardware Page Table Structures <sec:hw-pagetables>

Modern architectures use radix-tree page tables to translate virtual
addresses to physical addresses. Each level of the tree indexes a
portion of the virtual address, with 9 bits per level being typical
(yielding 512-entry tables). A leaf entry at level $n$ maps a
contiguous region of $2^(12 + 9n)$ bytes on architectures with
4~KiB base pages.

@tbl:arch-sizes summarizes the page sizes available on the three
architectures Telix currently supports, alongside several that
illustrate the diversity — and historical trajectory — of superpage
size spectra. Alpha is included as Navarro et al.'s original
target~[1]; MIPS64 has the densest genuinely flexible spectrum;
Itanium represents the high-water mark of TLB flexibility.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: (left, left, left, left),
    table.header[*Architecture*][*Page Table*][*Leaf Sizes*][*Levels*],
    table.hline(),
    [x86-64], [4-level radix (PML4)], [4K, 2M, 1G], [3],
    [AArch64], [4-level radix (L0--L3)], [4K, 64K#super[†], 2M, 1G], [4#super[†]],
    [RISC-V Sv39], [3-level radix], [4K, 2M, 1G], [3],
    table.hline(),
    [Alpha (21264)], [3-level radix], [8K, 64K, 512K, 4M], [4],
    [IA-64 (Itanium 2)], [VHPT + FA TLB], [4K, 8K, 16K, 64K, 256K, 1M, 4M, 16M, 64M, 256M, 1G], [11],
    [MIPS64 (R4000+)], [Software TLB + PageMask], [1K#super[‡], 4K, 16K, 64K, 256K, 1M, 4M, 16M, 64M, 256M], [10],
    [LoongArch#super[¶]], [STLB + MTLB + radix], [4K ... 1G (19 sizes)], [19#super[¶]],
    [SPARC64], [TSB + TTE], [8K, 64K, 512K, 4M, 32M, 256M], [6],
    [IBM POWER (radix)], [4-level radix], [4K, 64K#super[§], 2M, 1G], [4],
  ),
  caption: [Hardware page sizes by architecture.
    #super[†]AArch64 64K is a contiguous hint on 16 L3 PTEs, not a
    distinct page table level.
    #super[‡]MIPS paired TLB entries each map two adjacent pages;
    a "1K page" entry covers 2K.
    #super[§]POWER supports 4K or 64K as a per-process base page size.
    #super[¶]LoongArch ISA _encodes_ ~18 page sizes (4K--1G in 4× steps),
    but the 2048-entry STLB is locked to a single globally-configured
    base size; only the 64-entry fully-associative MTLB supports
    variable sizes. In practice, only one base + one huge page size
    are used concurrently.],
) <tbl:arch-sizes>

The spectrum density varies dramatically — and, notably, has
*decreased* over time. Architectures from the 1990s and early 2000s
typically offered broad, dense spectra: Itanium had 11 sizes with
every TLB entry independently typed across 320 fully-associative
entries; MIPS64 offered 10 sizes via per-entry PageMask; SPARC64
had 6--8 sizes with 8× growth; Alpha had 4 sizes; PA-RISC had 9.
These architectures assumed that operating systems would exploit
the full spectrum.

They did not. No mainstream OS effectively used more than two or
three page sizes. Modern architectures have converged on the
now-common pattern of roughly three widely-separated sizes
(e.g., x86-64: 4K, 2M, 1G), where the base page is small, the
first superpage is large enough that fragmentation makes promotion
difficult, and the second is so large as to be useful only through
early boot-time reservation or on machines with vast memory.
The dense intermediate sizes that earlier hardware provided have
been abandoned by hardware designers for lack of software demand.

LoongArch illustrates this transition. The ISA encoding supports
19 page sizes (every power of two from 4K to 1G), and the
Loongson 3A5000's 64-entry fully-associative MTLB genuinely
supports per-entry page sizes across this range. But the 2048-entry
STLB — 97% of TLB capacity — is locked to a single globally-configured
size. Linux accordingly uses exactly two (e.g., 16K + 16M). The
dense spectrum exists in the ISA and the MTLB, but the STLB design
reflects the expectation that one base size is enough.

MIPS64's 1~KiB minimum page size --- only twice the 512-byte
VAX page that motivated McKusick's original page clustering code ---
is a striking illustration of the same underlying pressure that
originally drove page clustering.

The key observation is that most architectures provide a *spectrum*
of superpage sizes, not just one. An OS that exploits only one level
leaves performance on the table.

== Superpage Promotion and Demotion

The seminal Navarro--Iyer--Druschel--Cox system~\[1\]
introduced *reservation-based* superpage management:

- When a process first touches a superpage-aligned region, the OS
  *reserves* a contiguous physical region of the target superpage size.
- Individual pages within the reservation are allocated on demand, but
  always placed within the reserved region, guaranteeing contiguity.
- Once all constituent pages are present, the OS *promotes* the region
  by replacing the individual PTEs with a single superpage PTE.
- When fine-grained operations are needed (e.g., page-level protection
  changes, eviction of a single page), the superpage is *demoted* back
  to individual PTEs.

Their system targeted FreeBSD on Alpha (8K pages, 8M superpages — a
1024× ratio) and demonstrated significant TLB miss reductions.

The key challenge is maintaining reservations across `fork()`.
Copy-on-write (COW) breaks physical sharing, scattering the child's
pages across non-contiguous locations. Navarro et al.\ proposed
*preemptive demotion* at fork time for large processes, but this is
expensive. Their system also targeted a single superpage size.

== Page Clustering in BSD <sec:bsd-clustering>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - History: 4.4BSD and FreeBSD VM used clustering for I/O coalescing
//     (multiple MMU pages per VM page object)
//   - McKusick's work (cite appropriately) — you coined
//     "McKusick-Dickins page clustering" informally ~2003 because no
//     published name seemed to exist
//   - The kernel allocates and frees memory in units of PAGE_SIZE
//     (a multiple of MMUPAGE_SIZE), even though PTEs are installed
//     at MMUPAGE_SIZE granularity
//   - Consequence: within each allocation page, physical frames are
//     *always* contiguous — this is a structural invariant, not an
//     optimization
//   - Historical motivation was I/O batching and reducing per-page
//     overhead. Filesystem block sizes were historically limited by
//     PAGE_SIZE in elder/legacy kernels — clustering removed this
//     constraint by making larger allocation units viable.
//   - The trade-off: internal fragmentation (a 1-byte allocation
//     wastes up to PAGE_SIZE - 1 bytes of physical memory)
//   - Broader benefit beyond I/O: clustering also reduces metadata
//     overhead. Every per-page structure (page array entries, allocator
//     bookkeeping, refcounts) scales with page count. Fewer, larger
//     allocation pages → fewer metadata entries → reduced cache/TLB/
//     bandwidth-to-memory consumption by the kernel itself.
//   - The metadata scaling argument: memory capacity has grown faster
//     than cache/TLB/memory-bandwidth (the "memory wall"). Linear
//     per-page metadata means the kernel's own overhead grows as a
//     proportion of the resources it manages. Clustering addresses
//     this directly.
//   - Connection to this work: we observe that this contiguity guarantee
//     is exactly what superpage promotion needs — and it comes for free
//     for superpage sizes at or below PAGE_SIZE
//   - No prior work (that you are aware of) has made this connection
//     explicit

#text(fill: red)[\[TODO: Hand-write BSD clustering subsection\]]


// =============================================================================
// 3  Design
// =============================================================================

= Design <sec:design>

// >>> HAND-WRITE the preamble to this section (2-3 sentences). Frame:
//   - This section presents the complete multi-level design.
//   - The design treats heterogeneous superpage sizes as the normal case.
//   - An architecture provides an ordered table of superpage sizes;
//     the kernel handles all of them through a single unified mechanism.

#text(fill: red)[\[TODO: Hand-write section preamble\]]


== The Superpage Level Table <sec:level-table>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - The architecture provides an ordered array of superpage descriptors:
//       struct SuperpageLevel { size, shift, pt_level, alloc_pages }
//     sorted by size ascending.
//
//   - Each entry describes one hardware superpage size: its byte size,
//     log2(size), which page table level it corresponds to, and how many
//     allocation pages (PAGE_SIZE units) compose it.
//
//   - alloc_pages = size / PAGE_SIZE. When alloc_pages <= 1, the size
//     is at or below the contiguity floor — free by construction.
//     When alloc_pages > 1, reservation-based assembly is needed.
//
//   - IMPORTANT: There is NO strict ordering requirement between superpage
//     sizes and PAGE_SIZE. Multiple superpage sizes can exist strictly
//     between MMUPAGE_SIZE and PAGE_SIZE. These are sub-floor sizes:
//     free by the contiguity invariant, but they are still distinct
//     promotion levels with distinct PTE encodings.
//
//   - MIPS64 with 1K MMUPAGE_SIZE and PAGE_SIZE=64K is the extreme example:
//     1K → 4K → 16K → 64K is a chain of THREE promotions entirely within
//     a single allocation page. Each is a distinct TLB entry size. All are
//     free (no reservation needed), but each requires installing a different
//     PageMask value. The promotion logic still iterates sub-floor levels.
//
//   - Generic kernel code iterates this table. No #[cfg(target_arch)]
//     in the promotion/demotion/reservation logic. The floor partitions
//     the table into "free" and "reservation-needed" entries but does
//     NOT skip the free entries — they still represent real promotions
//     with real TLB coverage benefits.
//
//   - Concrete examples (show as table or figure):
//       AArch64 at PAGE_SIZE=64K:
//         64K  → alloc_pages=1  (floor, free)
//         2M   → alloc_pages=32 (reservation)
//         1G   → alloc_pages=16384 (reservation)
//
//       MIPS64 at MMUPAGE_SIZE=1K, PAGE_SIZE=64K:
//         4K   → alloc_pages=0  (sub-floor, free — within one alloc page)
//         16K  → alloc_pages=0  (sub-floor, free — within one alloc page)
//         64K  → alloc_pages=1  (floor, free)
//         256K ��� alloc_pages=4  (reservation)
//         1M   → alloc_pages=16 (reservation)
//         ...10 levels total
//
//       LoongArch at PAGE_SIZE=64K (CAVEAT — see below):
//         In theory, same dense 4× spectrum as MIPS. In practice,
//         the 2048-entry STLB is locked to one base size; only 64
//         fully-associative MTLB entries support other sizes. Linux
//         uses exactly 2 sizes (64K base + 256M huge). The dense
//         spectrum is an ISA encoding, not a practical capability.
//         This is a cautionary example for the table: encoding
//         support ≠ TLB support ≠ practical usability.
//
//       Alpha at PAGE_SIZE=64K:
//         64K  → alloc_pages=1  (floor, free — matches first superpage!)
//         512K → alloc_pages=8  (reservation)
//         4M   → alloc_pages=64 (reservation)

#text(fill: red)[\[TODO: Hand-write level table section\]]

#v(0.5em)

// Diagram: Level table examples
#figure(
  table(
    columns: (auto, auto, auto, auto, auto),
    align: (left, right, right, right, left),
    table.header[*Arch (PAGE\_SIZE)*][*Size*][*PT Level*][*Alloc Pages*][*Mechanism*],
    table.hline(),
    [MIPS64 1K (64K)], [4K],   [PageMask], [< 1],  [_sub-floor_ (free)],
    [],              [16K],  [PageMask], [< 1],  [_sub-floor_ (free)],
    [],              [64K],  [PageMask], [1],     [_floor_ (free)],
    [],              [256K], [PageMask], [4],     [reservation],
    [],              [1M],   [PageMask], [16],    [reservation],
    [],              [4M],   [PageMask], [64],    [reservation],
    table.hline(),
    [LoongArch (64K)#super[¶]], [64K],  [STLB],   [1],     [_floor_ (base size)],
    [],              [256M], [MTLB],    [4096],  [huge (64 MTLB entries only)],
    table.hline(),
    [AArch64 (64K)], [64K],  [L3 hint], [1],     [_floor_ (free)],
    [],              [2M],   [L2],      [32],    [reservation],
    [],              [1G],   [L1],      [16384], [reservation],
    table.hline(),
    [Alpha (64K)],   [64K],  [L2],      [1],     [_floor_ (free)],
    [],              [512K], [L1],      [8],     [reservation],
    [],              [4M],   [L0],      [64],    [reservation],
    table.hline(),
    [x86-64 (64K)],  [2M],   [PD],      [32],    [reservation],
    [],              [1G],   [PDPT],    [16384], [reservation],
    table.hline(),
    [RISC-V (64K)],  [2M],   [L1],      [32],    [reservation],
    [],              [1G],   [L2],      [16384], [reservation],
  ),
  caption: [Superpage level tables at `PAGE_SIZE = 64K`. Levels with
    `alloc_pages < 1` are sub-floor (multiple promotions within a single
    allocation page); `alloc_pages = 1` is the floor itself. MIPS64 with
    1K base pages has three sub-floor promotion levels --- each a distinct
    TLB entry, all structurally free. #super[¶]LoongArch is shown with its
    practical configuration: only 1 base + 1 huge size are usable despite
    the ISA encoding 18 sizes (see @tbl:arch-sizes footnote).],
) <tbl:level-tables>


== The Contiguity Floor <sec:contiguity-floor>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - Define "contiguity floor": the largest region guaranteed physically
//     contiguous by construction, without any explicit promotion or
//     reservation. Floor = PAGE_SIZE.
//
//   - This is a structural invariant of the allocator, not a runtime
//     optimization. Every allocation page is contiguous because the
//     physical allocator allocates PAGE_SIZE-aligned, PAGE_SIZE-sized
//     regions atomically.
//
//   - Consequence: any superpage size S where S <= PAGE_SIZE is
//     "free" — it can be formed without any contiguity assembly.
//     The only cost is installing the appropriate PTE (block descriptor,
//     contiguous hint, etc.) instead of individual PTEs.
//
//   - Sub-floor promotions are still REAL promotions. On MIPS64 with
//     1K MMUPAGE_SIZE and PAGE_SIZE=64K, within a single allocation page
//     there are three distinct promotion levels: 1K→4K, 4K→16K, 16K→64K.
//     Each installs a different PageMask value in the TLB entry, covering
//     progressively larger regions. All are structurally free — no
//     reservation, no contiguity assembly — but the promotion logic still
//     iterates them and each yields real TLB coverage improvement.
//
//   - On aarch64 with PAGE_SIZE=64K and 4K MMU pages:
//     Each allocation page provides 16 contiguous 4K frames.
//     The contiguous hint (PT_CONTIGUOUS on 16 L3 PTEs) is *always*
//     applicable. It never fails. Zero-cost "promotion."
//
//   - On Alpha with 8K MMU and PAGE_SIZE=64K (Navarro et al's target):
//     Each allocation page provides 8 contiguous 8K frames.
//     The 64K superpage (first level above MMUPAGE_SIZE) is
//     unconditionally available — first superpage is literally free.
//
//   - On MIPS64 with 1K MMU and PAGE_SIZE=64K:
//     Each allocation page provides 64 contiguous 1K frames.
//     The sub-floor chain 1K→4K→16K→64K is three promotions within
//     a single allocation page. The first reservation-based level is
//     256K (only 4 alloc pages). Every per-entry PageMask is
//     independently selectable — no STLB-style restrictions.
//
//   - The floor partitions the superpage spectrum into two regimes:
//       Below floor: structural, zero runtime cost
//       Above floor: reservation-based, runtime cost proportional to
//       (target_size / PAGE_SIZE), not (target_size / MMUPAGE_SIZE)
//
//   - The floor height is PAGE_SIZE. Currently compile-time (cargo feature),
//     but the goal is to make it a boot-time parameter, propagated via
//     ELF relocation processing or similar. This would allow the same
//     kernel binary to adapt to different workload profiles.
//
//   - Relationship to internal fragmentation: the floor comes at the
//     cost of rounding up allocations to PAGE_SIZE. Quantify this
//     trade-off. (A single 4K demand-zero fault wastes 60K at
//     PAGE_SIZE=64K, but the kernel's slab allocator packs small kernel
//     objects within pages, and userspace malloc amortizes across objects.)
//
//   - Note: PAGE_MMUCOUNT contiguous page mappings within an allocation
//     page apply only when the full allocation page is within the VMA.
//     VMAs with MMUPAGE_SIZE-aligned (but not PAGE_SIZE-aligned) endpoints
//     may have partial allocation pages at their edges — the "overhang"
//     case. Promotion at the floor level must check for this.

#text(fill: red)[\[TODO: Hand-write contiguity floor section\]]

#v(0.5em)

// Diagram: Size spectrum showing floor
#figure(
  block(width: 100%, inset: 8pt, stroke: 0.5pt + gray)[
    #set text(size: 8pt)
    #grid(
      columns: (1fr,),
      rows: (auto, auto),
      gutter: 6pt,
      [
        *AArch64 with PAGE\_SIZE = 64K, MMUPAGE\_SIZE = 4K:*
        #v(4pt)
        #grid(
          columns: (auto, 1fr, auto),
          align: (right, center, left),
          gutter: 2pt,
          [4K], box(width: 100%, height: 2pt, fill: eastern.lighten(70%)), [MMU page],
          [64K], box(width: 100%, height: 6pt, fill: green.lighten(40%)), [*PAGE\_SIZE (contiguity floor)*],
          [2M], box(width: 100%, height: 2pt, fill: orange.lighten(50%)), [L2 block (32 alloc pages)],
          [1G], box(width: 100%, height: 2pt, fill: red.lighten(60%)), [L1 block (16384 alloc pages)],
        )
        #v(4pt)
        #h(2em) #box(width: 8pt, height: 8pt, fill: green.lighten(40%)) Free (structural)
        #h(1em) #box(width: 8pt, height: 8pt, fill: orange.lighten(50%)) Reservation-based
      ],
      [
        *Alpha with PAGE\_SIZE = 64K, MMUPAGE\_SIZE = 8K (Navarro et al.'s target):*
        #v(4pt)
        #grid(
          columns: (auto, 1fr, auto),
          align: (right, center, left),
          gutter: 2pt,
          [8K], box(width: 100%, height: 2pt, fill: eastern.lighten(70%)), [MMU page],
          [64K], box(width: 100%, height: 6pt, fill: green.lighten(40%)), [*PAGE\_SIZE = first superpage (free!)*],
          [512K], box(width: 100%, height: 2pt, fill: orange.lighten(50%)), [8 alloc pages],
          [4M], box(width: 100%, height: 2pt, fill: orange.lighten(50%)), [64 alloc pages],
        )
      ],
      [
        *MIPS64 with PAGE\_SIZE = 64K, MMUPAGE\_SIZE = 1K:*
        #v(4pt)
        #grid(
          columns: (auto, 1fr, auto),
          align: (right, center, left),
          gutter: 2pt,
          [1K], box(width: 100%, height: 2pt, fill: eastern.lighten(70%)), [MMU page],
          [4K], box(width: 100%, height: 3pt, fill: green.lighten(60%)), [sub-floor promotion (4× MMU)],
          [16K], box(width: 100%, height: 3pt, fill: green.lighten(50%)), [sub-floor promotion (16× MMU)],
          [64K], box(width: 100%, height: 6pt, fill: green.lighten(40%)), [*PAGE\_SIZE (contiguity floor)*],
          [256K], box(width: 100%, height: 2pt, fill: orange.lighten(50%)), [4 alloc pages],
          [1M], box(width: 100%, height: 2pt, fill: orange.lighten(50%)), [16 alloc pages],
          [4M], box(width: 100%, height: 2pt, fill: orange.lighten(50%)), [64 alloc pages],
        )
        #v(4pt)
        #h(2em) #box(width: 8pt, height: 8pt, fill: green.lighten(60%)) Sub-floor (distinct promotions, all free)
      ],
      [
        *LoongArch with PAGE\_SIZE = 64K, MMUPAGE\_SIZE = 4K (STLB-limited):*
        #v(4pt)
        #grid(
          columns: (auto, 1fr, auto),
          align: (right, center, left),
          gutter: 2pt,
          [4K], box(width: 100%, height: 2pt, fill: eastern.lighten(70%)), [MMU page],
          [64K], box(width: 100%, height: 6pt, fill: green.lighten(40%)), [*STLB base (2048 entries)*],
          [256M], box(width: 100%, height: 2pt, fill: red.lighten(60%)), [MTLB huge (64 entries only)],
        )
        #v(4pt)
        #text(size: 7pt)[ISA encodes 18 sizes; hardware supports 1 base + 1 huge concurrently]
      ],
    )
  ],
  caption: [Superpage size spectrum relative to the contiguity floor.
    Sizes at or below PAGE\_SIZE are structurally guaranteed;
    sizes above require reservation-based assembly.],
) <fig:size-spectrum>


== Per-Level Reservations <sec:reservations>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - Each superpage level above the floor has its own reservation
//     mechanism. A reservation at level i tracks
//     LEVELS[i].alloc_pages slots.
//
//   - Reservation lifecycle (general, not single-level):
//     (1) First fault in a level-i-aligned VA range triggers allocation
//         of a contiguous, level-i-aligned physical destination.
//     (2) Subsequent faults place pages directly into the destination.
//     (3) When all slots populated → promote to level-i superpage.
//
//   - Key difference from Navarro: the reservation slot count is
//     LEVELS[i].size / PAGE_SIZE, not LEVELS[i].size / MMUPAGE_SIZE.
//     At PAGE_SIZE=64K, a 2M reservation is 32 slots, not 512.
//     This is a 16× reduction in the number of independently-managed
//     units.
//
//   - Bitmask representation: a u64 bitmask tracks which slots are
//     populated. This supports up to 64 slots, i.e., superpage sizes
//     up to 64 × PAGE_SIZE. At PAGE_SIZE=64K, that's 4M — sufficient
//     for MIPS64 up to 4M (64 alloc pages), and Alpha's full spectrum.
//     Beyond that (MIPS64 16M=256 slots, x86-64/aarch64 1G=16384 slots),
//     either wider bitmasks (u128, u256) or hierarchical reservations
//     are needed. (Discuss the trade-off.)
//
//   - Hierarchical reservations for large levels:
//     A level-(i+1) reservation can be viewed as a reservation whose
//     "slots" are level-i superpages. Completion of all level-i
//     reservations within a level-(i+1)-aligned range triggers
//     level-(i+1) promotion. This avoids needing enormous bitmasks.
//
//   - Physical allocator interaction: reservation destinations are
//     allocated via alloc_aligned(size, alignment). The allocator
//     tries exact-order allocation first, then falls back to
//     larger-order allocation with aligned carving.

#text(fill: red)[\[TODO: Hand-write per-level reservations section\]]


== Multi-Level Promotion and Demotion <sec:promotion>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - Promotion is bottom-up: after a page fault installs a PTE,
//     try each superpage level starting from the smallest above
//     the floor.
//
//   - For level i:
//     (a) Check: faulting VA within a level-i-aligned region of the VMA?
//     (b) Check: all constituent PTEs present? (or all constituent
//         level-(i-1) superpages present, for i > smallest)
//     (c) Check: all allocation pages allocated and not COW-shared?
//     (d) Check: physical contiguity + alignment?
//     If all pass → install level-i leaf PTE.
//     If (d) fails but (a)-(c) pass → allocate contiguous destination,
//     copy pages, install.
//
//   - On success at level i, immediately try level i+1.
//     On failure at level i, stop (no point trying larger levels).
//
//   - Demotion is top-down and graduated:
//     To evict a single page from a level-k superpage, demote to
//     level k-1 (not all the way to MMUPAGE_SIZE). This preserves
//     adjacent superpages at level k-1.
//
//   - Example (MIPS64, PAGE_SIZE=64K):
//     4M superpage contains 4 × 1M superpages, each containing
//     4 × 256K superpages, each containing 4 × 64K allocation pages.
//     To evict one page: demote 4M → four 1M superpages. Only the
//     affected 1M region is demoted further. Three levels of
//     superpages remain intact for the unaffected regions.
//
//   - Example (Alpha, PAGE_SIZE=64K):
//     4M superpage contains 8 × 512K superpages, each containing
//     8 × 64K allocation pages.
//     To evict one page: demote 4M → eight 512K superpages. Only the
//     affected 512K region is further demoted. The other seven remain.
//
//   - Promotion at and below the floor (sizes <= PAGE_SIZE):
//     No reservation needed. Just check that all MMU pages within the
//     relevant sub-range have PTEs installed, then set the appropriate
//     PTE attribute (e.g., contiguous hint on AArch64, PageMask on MIPS).
//
//   - Sub-floor promotion is a chain, not a single step. On MIPS64 with
//     1K MMUPAGE and 64K PAGE_SIZE: after installing a 1K PTE, try 4K
//     (check 4 adjacent PTEs), then 16K (check 4 adjacent 4K entries),
//     then 64K (check 4 adjacent 16K entries). All within one allocation
//     page, all structurally free. Each is a distinct TLB entry size.
//
//   - Overhang constraint: PAGE_MMUCOUNT-contiguous promotion at the
//     floor level only applies when the full allocation page falls
//     within the VMA. VMAs with MMUPAGE_SIZE-aligned but not
//     PAGE_SIZE-aligned endpoints have partial allocation pages at
//     their edges — sub-floor promotion must check VMA bounds.

#text(fill: red)[\[TODO: Hand-write multi-level promotion/demotion section\]]

#v(0.5em)

// Diagram: Promotion chain
#figure(
  block(width: 100%, inset: 8pt, stroke: 0.5pt + gray)[
    #set text(size: 8pt)
    *MIPS64 promotion chain (MMUPAGE\_SIZE = 1K, PAGE\_SIZE = 64K):*
    #v(4pt)
    #align(center)[
      #grid(
        columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto, auto, auto),
        gutter: 4pt,
        align: center + horizon,
        box(inset: 4pt, stroke: 0.5pt, fill: eastern.lighten(80%))[1K MMU],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: green.lighten(60%))[4K #linebreak() _(sub-floor)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: green.lighten(50%))[16K #linebreak() _(sub-floor)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: green.lighten(40%))[64K #linebreak() _(floor)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[256K #linebreak() _(reserve)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[1M #linebreak() _(reserve)_],
      )
      #v(4pt)
      #grid(
        columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto, auto, auto),
        gutter: 4pt,
        align: center + horizon,
        [], [], [free], [], [free], [], [free], [], [4 pgs], [], [16 pgs],
      )
      #v(2pt)
      #text(size: 7pt)[(three sub-floor promotions within a single allocation page, each a distinct PageMask)]
    ]
    #v(6pt)
    *MIPS64 above-floor chain (PAGE\_SIZE = 64K):*
    #v(4pt)
    #align(center)[
      #grid(
        columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto),
        gutter: 4pt,
        align: center + horizon,
        box(inset: 4pt, stroke: 0.5pt, fill: green.lighten(50%))[64K #linebreak() _(floor)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[256K #linebreak() _(reserve)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[1M #linebreak() _(reserve)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[4M #linebreak() _(reserve)_],
        [→ × 4],
        box(inset: 4pt, stroke: 0.5pt, fill: red.lighten(60%))[16M #linebreak() _(hier.)_],
      )
      #v(6pt)
      #grid(
        columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto),
        gutter: 4pt,
        align: center + horizon,
        [structural], [], [4 alloc pgs], [], [16 alloc pgs], [], [64 alloc pgs], [], [256 pgs],
      )
    ]
    #v(6pt)
    *AArch64 / x86-64 / RISC-V (PAGE\_SIZE = 64K):*
    #v(4pt)
    #align(center)[
      #grid(
        columns: (auto, auto, auto, auto, auto, auto, auto),
        gutter: 4pt,
        align: center + horizon,
        box(inset: 4pt, stroke: 0.5pt, fill: eastern.lighten(80%))[4K MMU],
        [→ × 16],
        box(inset: 4pt, stroke: 0.5pt, fill: green.lighten(50%))[64K #linebreak() _(floor)_],
        [→ × 32],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[2M #linebreak() _(reserve)_],
        [→ × 512],
        box(inset: 4pt, stroke: 0.5pt, fill: red.lighten(60%))[1G #linebreak() _(hier.)_],
      )
    ]
    #v(6pt)
    *Graduated demotion --- MIPS64 (4M → 1M → 256K → 64K):*
    #v(4pt)
    #align(center)[
      #grid(
        columns: (auto, auto, auto, auto, auto, auto, auto),
        gutter: 4pt,
        align: center + horizon,
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[4M],
        [demote →],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[4 × 1M],
        [demote 1 →],
        box(inset: 4pt, stroke: 0.5pt, fill: orange.lighten(50%))[4 × 256K],
        [demote 1 →],
        box(inset: 4pt, stroke: 0.5pt, fill: green.lighten(50%))[4 × 64K],
      )
      #v(2pt)
      #text(size: 7pt)[(each level: only the affected sub-superpage is demoted; others remain intact)]
    ]
  ],
  caption: [Promotion chains and graduated demotion.
    The contiguity floor eliminates the lowest promotion levels.
    Demotion proceeds one level at a time, preserving adjacent
    superpages.],
) <fig:promotion-chain>


== COW Preservation Across Fork <sec:cow>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - fork() is the enemy of superpages. COW marking makes pages
//     read-only; subsequent writes trigger copies to non-contiguous
//     locations, destroying promotability.
//
//   - The design addresses this at every level:
//
//   - Per-level COW reservations:
//     When a COW fault occurs within a level-i-aligned range, the
//     kernel allocates a NEW level-i-aligned contiguous destination
//     for the faulting process. All COW copies within that range go
//     into the new destination, preserving contiguity.
//
//   - Epoch-based multi-fork tracking:
//     Each fork creates an "epoch." A page is shared iff ANY epoch
//     marks it shared AND NEITHER parent NOR child has COW-broken
//     it in that epoch. This handles fork chains (A forks B, B forks C)
//     correctly without O(n) scanning.
//
//   - Straggler consolidation:
//     After all shared pages in a reservation range are COW-broken,
//     some slots may hold non-shared pages (demand-zero pages
//     allocated after fork, or pages private before the fork). These
//     "stragglers" are relocated into the reservation's corresponding
//     slots to achieve full contiguity, enabling promotion.
//
//   - Interaction with multi-level:
//     COW reservations exist at each level independently. Completing
//     all level-i reservations within a level-(i+1) range enables
//     level-(i+1) promotion attempt. Fork does NOT need to demote
//     existing superpages — the COW read-only protection applies at
//     the superpage PTE level; demotion happens lazily when a write
//     fault actually occurs.

#text(fill: red)[\[TODO: Hand-write COW preservation section\]]

#v(0.5em)

// Diagram: COW reservation lifecycle
#figure(
  block(width: 100%, inset: 8pt, stroke: 0.5pt + gray)[
    #set text(size: 7.5pt)
    #grid(
      columns: (1fr,),
      rows: (auto,) * 5,
      gutter: 8pt,

      // State 1: Pre-fork
      [
        *① Pre-fork:* Parent owns contiguous reservation (promoted to superpage).
        #v(2pt)
        #grid(
          columns: (1fr,) * 8,
          gutter: 1pt,
          ..range(8).map(i =>
            box(width: 100%, height: 14pt, fill: blue.lighten(60%), stroke: 0.3pt)[
              #align(center + horizon)[P#(i)]
            ]
          )
        )
        #align(center)[▲ Level-i superpage (8 allocation pages)]
      ],

      // State 2: Fork demotes
      [
        *② Fork:* Mark superpage PTE read-only. Epoch created; all 8 slots
        marked shared. (No demotion yet — superpage PTE stays.)
        #v(2pt)
        #grid(
          columns: (1fr,) * 8,
          gutter: 1pt,
          ..range(8).map(i =>
            box(width: 100%, height: 14pt, fill: purple.lighten(60%), stroke: 0.3pt)[
              #align(center + horizon)[S#(i)]
            ]
          )
        )
      ],

      // State 3: Child writes, reservation created
      [
        *③ Child write fault on slot 3:* Demote superpage (lazy). Allocate new
        level-i reservation for child. Copy page 3 to reservation.
        #v(2pt)
        Child's reservation (level-i-aligned):
        #v(2pt)
        #grid(
          columns: (1fr,) * 8,
          gutter: 1pt,
          ..range(8).map(i => {
            let (fill, label) = if i == 3 {
              (green.lighten(40%), [C3])
            } else {
              (luma(230), [--])
            }
            box(width: 100%, height: 14pt, fill: fill, stroke: 0.3pt)[
              #align(center + horizon)[#label]
            ]
          })
        )
      ],

      // State 4: All shared pages copied
      [
        *④ All 8 slots COW-broken:* Reservation complete → promote.
        #v(2pt)
        #grid(
          columns: (1fr,) * 8,
          gutter: 1pt,
          ..range(8).map(i =>
            box(width: 100%, height: 14pt, fill: green.lighten(40%), stroke: 0.3pt)[
              #align(center + horizon)[C#(i)]
            ]
          )
        )
        #align(center)[All contiguous → promote to level-i superpage ✓]
      ],

      // State 5: Mixed case with stragglers
      [
        *④′ Mixed case:* Child allocated demand-zero page 5 after fork (not shared).
        #v(2pt)
        #grid(
          columns: (1fr,) * 8,
          gutter: 1pt,
          ..range(8).map(i => {
            let (fill, label) = if i == 5 {
              (yellow.lighten(40%), [D5])
            } else {
              (green.lighten(40%), [C#(i)])
            }
            box(width: 100%, height: 14pt, fill: fill, stroke: 0.3pt)[
              #align(center + horizon)[#label]
            ]
          })
        )
        Straggler consolidation: relocate D5 → reservation slot 5, then promote.
      ],
    )
  ],
  caption: [Reservation lifecycle through fork and COW fault resolution.
    S = shared, C = COW-copied into reservation, D = demand-zero straggler.
    The diagram shows one level; the same mechanism operates independently
    at each level of the superpage hierarchy.],
) <fig:cow-lifecycle>


== Page Reclamation and Graduated Demotion <sec:wsclock>

// >>> HAND-WRITE this subsection. Points to cover:
//
//   - WSCLOCK (or any page replacement algorithm) scans at MMUPAGE_SIZE
//     granularity (clears PTE reference bits) but frees physical memory
//     at PAGE_SIZE granularity (all MMU pages in an allocation page must
//     be evicted before the physical page is freed).
//
//   - Superpage demotion before eviction:
//     WSCLOCK cannot evict individual pages from a superpage PTE. It
//     must demote first. Multi-level: demote ONE level at a time.
//     If evicting from a 4M superpage, demote to 8×512K. Only the
//     affected 512K is further demoted to 8×64K. Other 7 remain as
//     512K superpages.
//
//   - Reservation-aware eviction:
//     Pages within an active reservation (one being populated by COW
//     faults) are skipped — evicting them would destroy the contiguity
//     being assembled. This is "soft pinning."
//
//   - Trade-off: reservation-aware skipping delays reclamation of
//     reservations that will never complete (e.g., if the process dies
//     or the memory is never touched). Need a policy:
//       Option A: timeout-based (abandon reservation after N clock sweeps)
//       Option B: age-based (count sweeps since last COW fault in range)
//       Option C: pressure-based (abandon under severe pressure)
//
//   - Interaction with multi-level:
//     Demotion cost is proportional to the size ratio between adjacent
//     levels. Demoting 2M→4K creates 512 PTEs. Demoting 2M→64K (if
//     64K is a supported level) creates 32. Graduated demotion is
//     strictly cheaper.

#text(fill: red)[\[TODO: Hand-write page reclamation section\]]


// =============================================================================
// 4  Implementation
// =============================================================================

= Implementation <sec:impl>

The design is implemented in Telix, a microkernel written in Rust
targeting AArch64, RISC-V (Sv39), and x86-64. The VM subsystem
comprises approximately 5,000 lines of architecture-independent code
plus 500--700 lines per architecture for page table manipulation.

The current implementation realizes the single-level (2~MiB) case
of the multi-level design described in @sec:design.
@tbl:impl-status summarizes which design components are implemented
versus designed but not yet coded.

#figure(
  table(
    columns: (auto, auto),
    align: (left, left),
    table.header[*Component*][*Status*],
    [Contiguity floor (PAGE\_SIZE clustering)], [Implemented],
    [AArch64 contiguous hint (64K, below floor)], [Implemented],
    [Single-level promotion (2M)], [Implemented],
    [Single-level demotion (2M → 4K)], [Implemented],
    [Single-level COW reservations], [Implemented],
    [Epoch-based multi-fork tracking], [Implemented],
    [Straggler consolidation], [Implemented],
    [Reservation-aware WSCLOCK], [Implemented],
    [Superpage level table (arch-provided)], [Designed],
    [Level-parameterized HAT], [Designed],
    [Multi-level promotion chains], [Designed],
    [Graduated demotion (level-at-a-time)], [Designed],
    [Hierarchical reservations (1G+)], [Designed],
  ),
  caption: [Implementation status of design components.],
) <tbl:impl-status>

== Size Hierarchy

Telix defines three tiers of page granularity:

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, left, left),
    table.header[*Constant*][*Value*][*Role*],
    [`MMUPAGE_SIZE`], [4 KiB (fixed)], [Hardware PTE granularity],
    [`PAGE_SIZE`], [16K--256K (currently compile-time#super[\*])], [Allocation unit, contiguity floor],
    [`SUPERPAGE_SIZE`], [2 MiB (current, to become per-level)], [Promoted page size],
  ),
  caption: [Page size hierarchy in Telix.
    #super[\*]Goal is boot-time selection via ELF relocation processing;
    see @sec:discussion.],
) <tbl:size-hierarchy>

The ratio `PAGE_MMUCOUNT = PAGE_SIZE / MMUPAGE_SIZE` determines how
many hardware PTEs correspond to one allocation page. At the default
`PAGE_SIZE = 64K`, each allocation page spans 16 contiguous 4K PTEs.

The ratio `SUPERPAGE_ALLOC_PAGES = SUPERPAGE_SIZE / PAGE_SIZE`
determines how many allocation pages compose one superpage. At
`PAGE_SIZE = 64K`, a 2~MiB superpage contains 32 allocation pages,
each internally contiguous. In the multi-level design, this ratio is
computed per level from the level table.

== Virtual Memory Areas

Each process's address space is a B+ tree of VMAs. A VMA maps a
contiguous virtual range to a backing memory object. All virtual
address handling --- VMA endpoints, syscall arguments, fault
addresses --- is in `MMUPAGE_SIZE` units. VMA endpoints may be
`MMUPAGE_SIZE`-aligned but not `PAGE_SIZE`-aligned, creating
partial allocation pages ("overhang") at VMA boundaries.
`PAGE_SIZE` granularity enters only when indexing the backing
memory object's physical page array, which stores one physical
address per allocation page. The VMA mediates between these via
index transformations:

```rust
// MMU page index → allocation page index in backing object
fn obj_page_index(&self, mmu_idx: usize) -> usize {
    (self.object_offset + mmu_idx) / PAGE_MMUCOUNT
}

// Offset of MMU page within its allocation page
fn mmu_offset_in_page(&self, mmu_idx: usize) -> usize {
    (self.object_offset + mmu_idx) % PAGE_MMUCOUNT
}

// Range of MMU indices sharing the same allocation page
fn alloc_page_mmu_range(&self, mmu_idx: usize)
    -> (usize, usize)
```

These transformations are the key point where clustering enters the
page fault path: a single allocation page provides
`PAGE_MMUCOUNT` contiguous MMU page mappings, provided the full
allocation page falls within the VMA. At VMA boundaries with
`MMUPAGE_SIZE`-aligned but not `PAGE_SIZE`-aligned endpoints,
partial allocation pages ("overhang") contain fewer usable slots.

== Memory Objects and Physical Page Tracking

Each memory object holds a `PageVec` — a tiered dynamic array of
physical addresses indexed by allocation page number. The tiered
design avoids fixed-capacity arrays: objects with few pages use
inline storage (32 bytes, 4 entries), while larger objects
graduate through slab-allocated tiers (64 to 2048 bytes) up to a
full page for objects exceeding 256 allocation pages.

== Physical Allocator

The physical allocator uses an embedded sparse variant of LLFree,
a lock-free frame allocator with in-band metadata. The allocator
operates in 64-page *chunks*, where each chunk's metadata (a 64-bit
atomic state word) is stored in-band and packs the free count,
owning CPU, bitmap page index, and up to 6 inline free-page indices.
The in-band design eliminates a separate metadata array, reducing
cache, TLB, and memory-bandwidth footprint --- a key design concern
throughout. The per-CPU ownership enables contention-free fast-path
allocation.

For superpage-aligned allocation, `alloc_superpage_aligned()`
first attempts an exact-order allocation (e.g., order~5 for
32 pages at 64K). If the result is not naturally aligned, it
retries with successively larger orders, carving out the aligned
portion and returning the excess to the free pool. In the
multi-level design, this generalizes to `alloc_aligned(size, align)`
parameterized by the target level's size and alignment.

== Current Promotion and Demotion

The current implementation realizes the single-level case of the
design in @sec:promotion. After each page fault that installs a
PTE, the fault handler calls `try_superpage_promotion()`:

+ Checks that the faulting address falls within a
  2~MiB-aligned region of the VMA.
+ Verifies that all 512 PTEs in the region are present.
+ Verifies that all `SUPERPAGE_ALLOC_PAGES` allocation pages
  in the backing object are allocated and not COW-shared.
+ Checks physical contiguity. If pages are contiguous and
  superpage-aligned, installs a block descriptor directly.
  Otherwise, allocates a new contiguous region, copies pages,
  updates the object's page array, and installs the block
  descriptor.

Demotion reverses the process: a superpage block descriptor is
replaced with a freshly allocated page table containing 512
individual PTEs with the same physical addresses and permissions.
The current implementation always demotes to 4K; graduated
demotion (per @sec:wsclock) is not yet implemented.

On AArch64, an additional sub-superpage promotion sets the
contiguous hint bit on groups of 16 consecutive L3 PTEs (64K
regions). At `PAGE_SIZE >= 64K`, this hint is *unconditionally*
applicable — a direct manifestation of the contiguity floor.

== Current COW Reservations

The current implementation realizes single-level reservations
as described in @sec:cow. COW groups track sharing via epoch
bitmasks (`u64`), with per-member reservation destinations
allocated at 2~MiB alignment. Straggler consolidation and
reservation-aware WSCLOCK eviction are implemented.

The `u64` bitmask limits the superpage-to-allocation-page
ratio to 64. At `PAGE_SIZE = 64K`, this supports superpages up
to 4~MiB. The multi-level design calls for wider bitmasks
or hierarchical reservations for larger levels.

== HAT Abstraction Layer

The Hardware Address Translation (HAT) layer provides a uniform
interface over architecture-specific page table operations:

```rust
fn install_superpage(root, va, pa, flags) -> bool
fn demote_superpage(root, va, flags) -> bool
fn is_superpage(root, va) -> Option<usize>
fn try_contiguous_promotion(root, va, count) -> bool
```

Each function delegates to an architecture-specific
implementation that understands the PTE format (PS bit on x86-64,
block descriptor on AArch64, leaf-at-non-terminal on RISC-V).
The generic radix page table walker (`radix_pt.rs`) is
parameterized by a `PteFormat` trait. The multi-level design
replaces these with level-parameterized variants:

```rust
fn install_at_level(root, va, pa, flags, level) -> bool
fn demote_at_level(root, va, level, flags) -> bool
fn superpage_level(root, va) -> Option<usize>
```

// Diagram: target API
#figure(
  block(width: 100%, inset: 8pt, stroke: 0.5pt + gray)[
    #set text(size: 8pt)
    *Generalized superpage level table:*
    #v(4pt)
    ```
    // Architecture provides:
    pub struct SuperpageLevel {
        pub size: usize,       // e.g. 64K, 2M, 1G
        pub shift: usize,      // log2(size)
        pub pt_level: usize,   // page table level for block/leaf
        pub alloc_pages: usize, // size / PAGE_SIZE
    }

    // AArch64 example (PAGE_SIZE = 64K):
    LEVELS = [
        // 64K contiguous hint: FREE (size == PAGE_SIZE)
        { size: 64K, shift: 16, pt_level: 3, alloc_pages: 1 },
        // 2M block: 32 allocation pages
        { size: 2M, shift: 21, pt_level: 2, alloc_pages: 32 },
        // 1G block: 16384 allocation pages
        { size: 1G, shift: 30, pt_level: 1, alloc_pages: 16384 },
    ]
    ```
    #v(4pt)
    *Target generic promotion loop:*
    ```
    for level in arch::SUPERPAGE_LEVELS {
        if level.alloc_pages <= 1 { continue; } // floor
        if try_promote_at_level(pt_root, vma, level) {
            stats::promotions[level].incr();
        } else {
            break; // no point trying larger
        }
    }
    ```
  ],
  caption: [Architecture-parameterized superpage level table
    and generic promotion loop (target design).],
) <fig:level-table>


// =============================================================================
// 5  Discussion
// =============================================================================

= Discussion <sec:discussion>

== Internal Fragmentation Trade-Off

The contiguity floor comes at a cost: allocating a single 4K page
requires committing an entire `PAGE_SIZE` physical region. At
`PAGE_SIZE = 64K`, this represents up to 60K of waste per allocation.

In practice, the kernel's slab allocator packs small objects within
pages, and userspace allocators (malloc) amortize page-granularity
allocation across many objects. The dominant consumer of
single-page allocations is the page fault handler for anonymous
memory, where each fault maps a full `PAGE_SIZE` region —
precisely the case where the contiguity guarantee is most valuable.

The trade-off is tunable: `PAGE_SIZE = 16K` minimizes waste
(4× MMUPAGE_SIZE) but provides a narrow floor; `PAGE_SIZE = 256K`
maximizes the floor (64× MMUPAGE_SIZE) at higher fragmentation
cost, though 256K is often considered too large due to page
zeroing latency. The default of 64K (16× MMUPAGE_SIZE) balances
the two. Note that PAGE\_SIZE also controls metadata density:
larger PAGE\_SIZE means fewer entries in object page arrays,
fewer allocator chunks, and fewer per-page structures --- reducing
cache, TLB, and memory-bandwidth footprint for metadata access.

== Comparison with Transparent Huge Pages (Linux)

Linux's THP (Transparent Huge Pages) uses a different approach:
the page allocator operates at 4K granularity, and `khugepaged`
asynchronously scans for promotable regions, copying pages into
contiguous 2M regions. This avoids compile-time configuration
but pays a runtime cost for scanning and copying.

Telix's approach shifts part of this cost to compile time
(the choice of `PAGE_SIZE`) and part to fork time (COW
reservation allocation). The structural contiguity guarantee
means that no scanning is needed for sub-`PAGE_SIZE` superpages,
and the reservation system ensures COW does not destroy
above-`PAGE_SIZE` contiguity.

// >>> HAND-WRITE additional discussion points if needed:
//
//   - THE SCALING ARGUMENT (important, may deserve its own subsection):
//     Memory capacity has grown roughly with Moore's law. Cache size,
//     TLB entry count, and memory bandwidth have grown more slowly.
//     Per-page metadata (struct page equivalents, PTEs, allocator
//     bookkeeping) scales linearly with physical page count. As the
//     gap widens, the kernel's own metadata overhead — in cache lines,
//     TLB entries, and bandwidth-to-memory — consumes a growing
//     fraction of the very resources it is supposed to manage.
//     Larger PAGE_SIZE reduces this: 64K pages mean 16× fewer metadata
//     entries than 4K pages for the same physical memory. This is not
//     just a space saving — it is a cache/TLB/bandwidth saving.
//     The goal is sublinear memory management: both the space consumed
//     by metadata and the time spent manipulating it should grow slower
//     than memory capacity. Extent-based tracking (one descriptor per
//     contiguous run) achieves this when contiguity is maintained —
//     which is exactly what the contiguity floor provides.
//
//   - THE HISTORICAL ARC OF DENSE SPECTRA (may deserve subsection):
//     1990s-2000s hardware offered broad, dense page-size spectra
//     (Itanium 11 sizes, MIPS 10, SPARC 6-8, PA-RISC 9, Alpha 4)
//     because architects expected OS exploitation. No mainstream OS
//     delivered. Modern hardware converged on ~3 widely-separated
//     sizes (4K, 2M, 1G). The common case is now: base page too
//     small for TLB coverage, first superpage too large for easy
//     promotion (512× gap on x86-64), second superpage only usable
//     with boot-time reservation or huge memory. Dense intermediate
//     sizes were abandoned for lack of software demand.
//     This design argues: the opportunity was real, the software
//     design was missing. Clustering + reservations make intermediate
//     sizes genuinely exploitable. LoongArch's STLB constraint
//     (reflecting the modern expectation) is compensated by the
//     64-entry MTLB — enough for targeted superpage use.
//     If software demonstrates value, future hardware could
//     re-expand TLB flexibility.
//
//   - Comparison with HawkEye (Panwar et al., ASPLOS 2019) —
//     profile-guided superpage placement
//   - Comparison with Ingens (Kwon et al., OSDI 2016) —
//     utilization-based promotion
//   - How does the contiguity floor interact with NUMA?
//     (allocation pages are NUMA-local; reservations may
//     cross NUMA boundaries on large machines)
//   - CXL (Compute Express Link) and beyond-NUMA memory:
//     CXL-attached memory pools introduce yet another tier with
//     different latency/bandwidth characteristics. Superpage
//     promotion across CXL-local and CPU-local memory is an
//     open question. Reservation destinations should probably
//     be CXL-topology-aware. This is future work that can't
//     be avoided.
//   - Memory compaction: when should the kernel compact
//     physical memory to create contiguous regions vs.
//     waiting for natural reservation completion?
//   - Linux multi-size THP (added in 6.8+): how does it compare
//     to this design? Linux added mTHP with folio sizes 16K-2M but
//     still allocates at 4K base granularity, whereas this design
//     changes the base allocation granularity itself.
//   - Metadata footprint as a cross-cutting design concern:
//     The in-band allocator metadata, PAGE_SIZE-granularity object
//     page arrays (not MMUPAGE-granularity), and u64-packed chunk
//     state words all target cache/TLB/bandwidth reduction. A
//     variable PAGE_SIZE (per-VMA) would undermine this because
//     the allocator and object code would need to handle mixed
//     granularities. Boot-time selection preserves the invariant
//     that PAGE_SIZE is a system-wide constant for any given boot.
//   - Boot-time PAGE_SIZE selection:
//     Currently compile-time via cargo features. The plan is to
//     use ELF relocation processing (or similar link-time mechanism)
//     to propagate PAGE_SIZE as a boot parameter, so a single kernel
//     binary can adapt. The challenge is that PAGE_SIZE appears in
//     many compile-time-constant contexts (array sizing, alignment
//     constraints, bit shifts). Relocation-based propagation would
//     patch these sites at load time.
//   - MICROKERNEL CONTEXT: why a microkernel specifically benefits:
//     * Minimal kernel resident set → small metadata baseline
//     * User-level pagers can implement workload-specific promotion
//       policies without kernel modification
//     * Capability-based memory management isolates policy from mechanism
//     * seL4-style fast IPC minimizes the cost of user-level pager traps
//     * Mach-lineage VM object/pager split maps naturally to the
//       object + COW group + reservation architecture
//   - NEAR-TERM DESIGN TARGETS (future work):
//     * Page-table-free operation for inverted page table and software
//       TLB refill architectures (MIPS, SPARC, PA-RISC, OpenRISC) —
//       the kernel maintains only the object page arrays and synthesizes
//       TLB entries on miss, eliminating radix PT metadata entirely
//     * Shared page tables for radix-tree architectures (x86-64, aarch64,
//       RISC-V) — processes sharing the same memory object share the
//       same page table subtree, further reducing metadata footprint
//     Both are natural extensions of the extent-based design philosophy.


== Limitations

The current implementation has several limitations relative to the
full design:

- *Single superpage level:* Only 2~MiB superpages are implemented.
  The level table, multi-level promotion, and graduated demotion
  are designed but not yet coded.

- *u64 bitmask width:* COW reservation bitmasks are 64 bits wide,
  limiting the superpage-to-allocation-page ratio to 64. At
  `PAGE_SIZE = 64K`, the largest trackable superpage is 4~MiB.
  1~GiB superpages would require hierarchical reservations or
  wider bitmasks.

- *No user-space control:* Applications cannot request specific
  superpage sizes or opt out of promotion. Adding `madvise`-style
  hints is straightforward but not yet implemented.

- *Fixed `PAGE_SIZE`:* The clustering granularity is currently a
  compile-time choice (cargo feature). The goal is to make it a
  boot-time parameter, propagated via ELF relocation processing or
  similar, allowing a single kernel binary to adapt to different
  workloads. Variable PAGE\_SIZE (per-VMA or per-object) is a
  non-goal: it conflicts with the metadata footprint reduction
  that motivates the in-band allocator design, and would
  substantially complicate the physical allocator and page table
  management.

- *Demotion to 4K only:* The current demotion always produces
  individual 4K PTEs. Graduated demotion (e.g., 2M → 64K contiguous
  groups on AArch64) is not yet implemented.

- *Radix page tables only:* The current HAT assumes radix-tree
  page tables. Software TLB refill architectures (MIPS, SPARC,
  PA-RISC, OpenRISC) could operate page-table-free, synthesizing
  TLB entries directly from the object page arrays on miss. This
  would eliminate radix PT metadata entirely — a significant
  metadata reduction — but is not yet designed.

- *No shared page tables:* Processes mapping the same memory object
  each maintain independent page table subtrees. Sharing page
  tables across processes would further reduce metadata footprint
  on radix-tree architectures.


// =============================================================================
// 6  Conclusion
// =============================================================================

= Conclusion

// >>> HAND-WRITE: ~250 words summarizing:
//   - The broader goal: a pervasively extent-based memory system that
//     achieves sublinear metadata overhead as memory capacity grows.
//     Physical contiguity is a first-class design target with benefits
//     spanning TLB reach, metadata footprint (cache/TLB/bandwidth),
//     DMA scatter-gather, and filesystem block alignment.
//
//   - The key insight: page clustering and reservation-based superpages
//     are not independent techniques — they are two facets of a single
//     multi-level superpage architecture.
//
//   - The contiguity floor partitions the superpage spectrum into
//     "free" (structural) and "reservation-needed" — but sub-floor
//     levels are still real promotions (MIPS64 has three within one
//     allocation page). No strict ordering between superpage sizes
//     and PAGE_SIZE.
//
//   - Reservations operate at PAGE_SIZE granularity, not MMUPAGE
//     granularity, reducing the assembly problem by PAGE_MMUCOUNT×
//
//   - The microkernel structure (seL4-inspired fast IPC, Mach-lineage
//     VM objects) provides a natural substrate: minimal kernel metadata
//     footprint, capability-isolated memory management, user-level
//     pager extensibility.
//
//   - Current implementation realizes the single-level case; the
//     multi-level generalization is a matter of parameterization,
//     not redesign.
//
//   - Future work: implement multi-level, boot-time PAGE_SIZE selection
//     (ELF relocation), page-table-free operation for software-TLB
//     architectures, shared page tables for radix architectures,
//     CXL-topology-aware reservations, workload evaluation.

#text(fill: red)[\[TODO: Hand-write conclusion\]]


// =============================================================================
// References
// =============================================================================

#heading(level: 1, numbering: none)[References]

// Placeholder bibliography — convert to proper .bib or typst
// bibliography once references are finalized.

#set text(size: 9pt)

#block(inset: (left: 1.5em, top: 0pt))[
  #set par(hanging-indent: 1.5em)

  \[1\] J. Navarro, S. Iyer, P. Druschel, and A. Cox,
  "Practical, transparent operating system support for superpages,"
  in _Proc. 5th OSDI_, 2002, pp. 89--104.
  #label("navarro2002")

  \[2\] M. K. McKusick, K. Bostic, M. J. Karels, and J. S. Quarterman,
  _The Design and Implementation of the 4.4BSD Operating System_.
  Addison-Wesley, 1996.
  #label("mckusick1996")

  \[3\] M. K. McKusick and G. V. Neville-Neil,
  _The Design and Implementation of the FreeBSD Operating System_.
  Addison-Wesley, 2004.
  #label("mckusick2004")

  \[4\] A. Arcangeli, "Transparent hugepage support,"
  in _Proc. KVM Forum_, 2010.
  #label("arcangeli2010")

  \[5\] B. Pham, V. Vaidyanathan, A. Jaleel, and A. Bhattacharjee,
  "CoLT: Coalesced large-reach TLBs,"
  in _Proc. 45th MICRO_, 2012, pp. 258--269.
  #label("pham2012")

  \[6\] B. Pham, J. Veselý, G. H. Loh, and A. Bhattacharjee,
  "Large pages and lightweight memory management in virtualized environments: Can you have it both ways?"
  in _Proc. 48th MICRO_, 2015, pp. 1--12.
  #label("pham2015")

  \[7\] Y. Kwon, H. Yu, S. Peter, C. J. Rossbach, and E. Witchel,
  "Coordinated and efficient huge page management with Ingens,"
  in _Proc. 12th OSDI_, 2016, pp. 705--721.
  #label("kwon2016")

  \[8\] S. Panwar, S. Basu, and A. Ganguly,
  "HawkEye: Efficient fine-grained OS support for huge pages,"
  in _Proc. 24th ASPLOS_, 2019, pp. 347--360.
  #label("panwar2019")

  // >>> ADD: Whatever the actual McKusick/Dickins page clustering
  // reference turns out to be. Check:
  // - Cranor & Parulkar, "The UVM Virtual Memory System" (1999)
  // - Tulloch & Robinson, "FreeBSD VM system" (various)
  // - If no published name, define the concept and cite McKusick 1996/2004.
  //
  // >>> ALSO CONSIDER:
  // - Linux multi-size THP (mTHP) patches, LWN coverage ~2023-2024
  // - Ganapathy & Schimmel, "General purpose operating system support
  //   for multiple page sizes" (USENIX ATC 1998) — early multi-size work
  // - Chapman, Wienand, Heiser, "Itanium Page Tables and TLB"
  //   (UNSW-CSE-TR-0307, 2003) — Itanium TLB/VHPT analysis, relevant
  //   to the historical dense-spectrum discussion

  \[9\] G. Klein, K. Elphinstone, G. Heiser, et al.,
  "seL4: Formal verification of an OS kernel,"
  in _Proc. 22nd SOSP_, 2009, pp. 207--220.
  #label("klein2009")

  \[10\] M. Accetta, R. Baron, W. Bolosky, D. Golub, R. Rashid,
  A. Tevanian, and M. Young,
  "Mach: A new kernel foundation for UNIX development,"
  in _Proc. USENIX Summer Conf._, 1986, pp. 93--113.
  #label("accetta1986")

  \[11\] J. Liedtke,
  "Improving IPC by kernel design,"
  in _Proc. 14th SOSP_, 1993, pp. 175--188.
  #label("liedtke1993")

  \[12\] T. E. Anderson, B. N. Bershad, E. D. Lazowska,
  and H. M. Levy,
  "Scheduler activations: Effective kernel support for the
  user-level management of parallelism,"
  in _ACM Trans. Comput. Syst._, vol. 10, no. 1, 1992, pp. 53--79.
  #label("anderson1992")

  \[13\] L. Wrenger, S. Bösenberg, S. Ilsche, and D. Lohmann,
  "LLFree: Scalable and optionally-persistent page-frame allocation,"
  in _Proc. USENIX ATC_, 2023, pp. 17--31.
  #label("wrenger2023")

  \[14\] R. W. Carr and J. L. Hennessy,
  "WSClock --- a simple and effective algorithm for virtual memory
  management,"
  in _Proc. 8th SOSP_, 1981, pp. 87--95.
  #label("carr1981")
]


// =============================================================================
// Appendix A: Architecture-Specific PTE Formats
// =============================================================================

#heading(level: 1, numbering: "A")[Architecture-Specific PTE Formats]

This appendix details the page table entry encoding for each supported
architecture, focusing on the bits that distinguish leaf (page/block)
entries from table (non-leaf) entries and the flags relevant to
superpage installation.

== x86-64

x86-64 uses a 4-level radix tree (PML4 → PDPT → PD → PT), with
9 bits of virtual address indexed at each level. A *large page*
is a leaf entry at the PD level (2~MiB) or PDPT level (1~GiB),
distinguished by the Page Size (PS) bit (bit 7):

```
Bit  63: NX (No Execute)
Bits 51:12: Physical address (4K-aligned for PT, 2M/1G for large)
Bit  7: PS (Page Size; 1 = large page, 0 = table pointer)
Bit  6: D (Dirty)
Bit  5: A (Accessed)
Bit  2: U/S (User/Supervisor)
Bit  1: R/W (Read/Write)
Bit  0: P (Present)
```

Superpage installation sets `PS = 1` at the PD level and writes
the 2~MiB-aligned physical address. If a PT page previously
occupied the slot, it is freed.

== AArch64

AArch64 uses a 4-level radix tree (L0 → L1 → L2 → L3) with
4K granule. Entries at L1 and L2 can be either *table descriptors*
(bit 1 = 1, pointing to next level) or *block descriptors*
(bit 1 = 0, mapping 1~GiB or 2~MiB respectively):

```
Bits 47:12: Output address
Bit  52: Contiguous (TLB coalescing hint)
Bit  54: UXN (User Execute Never)
Bit  53: PXN (Privileged Execute Never)
Bit  10: AF (Access Flag)
Bits 9:8: SH (Shareability)
Bits 7:6: AP (Access Permissions)
Bits 4:2: AttrIndx (MAIR index)
Bit  1: Table/Block (1 = table, 0 = block)
Bit  0: Valid
```

L3 entries use bit 1 = 1 for page descriptors (confusingly, the
opposite convention from L1/L2). The *contiguous hint* (bit 52)
on L3 entries tells the TLB that 16 consecutive entries map a
physically contiguous 64~KiB region.

== RISC-V Sv39

RISC-V Sv39 uses a 3-level radix tree with 9 bits per level.
A leaf entry at any level is identified by having at least one of
R, W, or X bits set; a non-leaf (table pointer) has all three
clear:

```
Bits 53:10: PPN (Physical Page Number)
Bits 7:0: Flags
  Bit 7: D (Dirty)
  Bit 6: A (Accessed)
  Bit 5: G (Global)
  Bit 4: U (User)
  Bit 3: X (Execute)
  Bit 2: W (Write)
  Bit 1: R (Read)
  Bit 0: V (Valid)
```

A leaf at level 1 (L1) maps 2~MiB (megapage); at level 2 (L2),
1~GiB (gigapage). No explicit "large page" bit is needed — the
R/W/X encoding serves double duty.


// =============================================================================
// Appendix B: Physical Allocator Internals
// =============================================================================

#heading(level: 1, numbering: "A")[Physical Allocator: Embedded Sparse LLFree]

The physical allocator uses 64-page chunks with an atomic state word
packing multiple fields into a single `u64` for lock-free operation:

#figure(
  block(width: 100%, inset: 6pt, stroke: 0.5pt + gray)[
    #set text(size: 7.5pt)
    ```
    u64 ChunkNode.state:
    ┌──────────┬──────────┬───────────┬─────────────┬─────────────────┐
    │ [6:0]    │ [13:7]   │ [14]      │ [20:15]     │ [63:21]         │
    │ free_cnt │ owner_cpu│ has_bitmap│ bitmap_page  │ inline_data     │
    │ (0..64)  │ (0..126) │ (0 or 1)  │ (0..63)     │ (6×6-bit idx)   │
    └──────────┴──────────┴───────────┴─────────────┴─────────────────┘
    ```
    #v(4pt)
    *Modes:*
    - All-free (fc=64): No metadata, entire chunk available
    - Inline (fc ≤ 6): Up to 6 free-page indices packed in bits [63:21]
    - Bitmap (has\_bitmap=1): One chunk page reserved as 64-bit bitmap
    - All-allocated (fc=0): No metadata needed
  ],
  caption: [Chunk state word encoding. Transitions between modes are
    performed atomically via compare-and-swap.],
) <fig:chunk-state>

Each chunk spans `64 × PAGE_SIZE` bytes. At `PAGE_SIZE = 64K`, a
chunk is 4~MiB — exactly two superpage regions. The per-CPU
ownership field enables contention-free allocation on the fast path:
a CPU "owns" a chunk and allocates from it without atomic
contention until the chunk is exhausted.

For multi-page allocation (`alloc_pages(order)`), the allocator
scans within a single chunk's bitmap for `2^order` contiguous free
pages when the request fits within 64 pages. Larger requests scan
across multiple chunks under a bulk lock.


// =============================================================================
// Appendix C: Telix Kernel Architecture Overview
// =============================================================================

#heading(level: 1, numbering: "A")[Telix Kernel Architecture]

Telix is a capability-based microkernel written in Rust (`no_std`),
drawing on two primary influences: seL4~[9] for capability-based
access control and fast IPC, and Mach~[10] for the VM object/pager
architecture and port-based namespace. The kernel runs on AArch64,
RISC-V~64, and x86-64, with SMP support on all three.

==== IPC

Inter-process communication uses synchronous send/receive over
kernel-managed _ports_. A port is a bounded multi-producer
single-consumer message queue; each message carries a 64-bit tag
and six data words (48~bytes total), sized to fit in registers for
fast-path transfer. When a receiver is already waiting on a port,
the kernel performs a _direct thread handoff_ --- a context switch
from sender to receiver that bypasses the scheduler entirely,
following the L4 tradition~[11]. Safe handoff under SMP uses a
CAS-based park state machine (`NONE` → `ENQUEUED` → `COMMITTED`)
to prevent concurrent kernel stack use between the handoff path
and an asynchronous wake.

Ports can be aggregated into _port sets_, allowing a server to
wait for messages on multiple ports simultaneously (analogous to
Mach port sets or `epoll`). Port IDs are 64-bit, structured as
(node | local) to permit future network-transparent IPC.

==== Capabilities

Every kernel object --- port, memory object, address space, thread,
interrupt line --- is accessed through typed capabilities with
explicit rights (send, receive, grant, read, write, execute,
manage). Capabilities are stored in per-task _CNodes_ (capability
nodes) and tracked globally in a _Capability Derivation Tree_
(CDT) that records parent--child derivation relationships.
Revoking a parent capability recursively invalidates all
descendants, following the seL4 model~[9]. A lock-free _CapSet_
provides O(1) port-capability lookup for the IPC fast path.

==== Scheduling

The scheduler uses priority-based round-robin with 256 priority
levels and timer-driven preemption. Run queues are shared across
CPUs, protected by a scheduler spinlock. Each thread has a
configurable quantum (default 10 ticks). The IPC direct-handoff
path amortizes scheduling overhead for request--reply patterns.
Per-thread CPU affinity masks and co-scheduling groups support
NUMA-aware placement. An optional _scheduler activation_
mechanism~[12] allows user-level thread libraries to receive
upcalls on blocking events.

==== Memory Management

The VM subsystem follows the Mach object/pager split~[10]. Each
virtual region (VMA) maps a range of virtual addresses to a
_memory object_, which stores physical page addresses in a tiered
`PageVec` (inline for ≤4 pages, slab-allocated beyond). Objects
are either _anonymous_ (demand-zero, COW-shared across fork) or
_pager-backed_ (faults forwarded to a user-level server that
fills the page and calls `fault_complete`). This external pager
interface allows filesystem servers to act as backing stores
without kernel involvement in I/O policy.

The physical allocator is an embedded sparse variant of
LLFree~[13] with in-band metadata: each 64-page chunk packs its
free count, owning CPU, and bitmap index into a single atomic
`u64` state word. The allocator operates at `PAGE_SIZE`
granularity (16K--256K), not `MMUPAGE_SIZE` (4K), and supports
multi-order allocation up to $2^(11)$ contiguous pages for
superpage assembly. The page clustering and superpage
architecture described in the body of this paper are part of
this subsystem.

Working-set management uses a per-address-space WSCLOCK~[14]
algorithm that walks the VMA tree, checking hardware reference
bits at `MMUPAGE_SIZE` granularity and demoting superpages before
evicting individual pages.

==== User-Level Servers

Following the microkernel principle, all I/O and filesystem logic
runs in user space. The kernel spawns device drivers (VirtIO MMIO
block and network on AArch64/RISC-V; PCI virtio on x86-64) as
unprivileged processes that communicate with the kernel via IRQ
wait syscalls and with other servers via IPC. The userspace
complement includes:

- *Storage:* block device server, page cache, RAM disk
- *Filesystems:* ext2, FAT16, tmpfs, initramfs (CPIO), devfs, procfs
- *Networking:* network protocol stack server
- *IPC services:* Unix domain sockets, pipes, shared memory, System~V IPC
- *Terminal:* console multiplexer, PTY allocator, getty/login, shell (tsh)

An init process orchestrates startup, and a kernel-resident
name server provides service registration and lookup.

==== Architecture Support

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: (left, left, left, left),
    table.header[*Arch*][*Machine*][*Interrupt*][*Boot*],
    [AArch64], [QEMU virt], [GICv3], [DTB],
    [RISC-V 64], [QEMU virt, Sv39], [PLIC], [DTB via OpenSBI],
    [x86-64], [QEMU q35], [LAPIC/IOAPIC], [Multiboot + ACPI],
  ),
  caption: [Supported architectures.],
)

Each architecture provides a platform abstraction layer
(`arch::platform`) with entry points for early initialization,
firmware parsing, MMU setup, secondary CPU startup, and idle. The
page table walker (`radix_pt`) and hardware address translation
layer (`hat`) are parameterized over a `PteFormat` trait,
isolating architecture-specific PTE encodings from generic VM
code.

==== Implementation Scale

The kernel comprises approximately 20,000 lines of Rust
(excluding comments and blanks), with an additional ~8,000 lines
of userspace server and utility code. The 102-syscall interface
covers IPC (send, receive, port management), memory (mmap,
munmap, grant, mprotect), process control (fork, exec, wait),
POSIX signals, futex synchronization, and capability management.
