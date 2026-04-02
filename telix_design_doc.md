# Telix Kernel Design Document

**Working Draft — March 2026**

*Alternative working names under consideration: Tessix, Nitix, Weft*

---

## 1. Overview and Goals

This document describes the design of Telix, a ground-up operating system kernel whose primary architectural contributions lie in two areas: a virtual memory subsystem with sublinear reserved memory footprint built around configurable page clustering, and a network-unified I/O architecture that eliminates the impedance mismatch between synchronous Unix VFS conventions and asynchronous I/O. The name derives from Latin *tela* (web, fabric, the warp on a loom), evoking the message-passing fabric that weaves the kernel's components together.

The kernel's virtual memory subsystem eliminates the traditional per-page `struct page` array (also known as the PFN database or resident page table) in favour of extent-based data structures. Physical memory is managed at a configurable allocation page size (`PAGE_SIZE`), a compile-time or boot-time chosen multiple of the hardware MMU page size (`MMUPAGE_SIZE`). This guarantees that superpage sizes at or below `PAGE_SIZE` succeed unconditionally by construction, while dramatically improving the probability of assembling superpages above `PAGE_SIZE` by reducing the number of contiguous pieces required.

The I/O architecture treats all I/O — file, block, and device — as asynchronous message-passing to endpoints, analogous to a network protocol. This eliminates the fundamental tension in legacy kernels where a synchronous Unix VFS call stack must be retrofitted for asynchronous operation, avoiding the engineering burden and architectural compromises seen in facilities such as Linux's `io_uring` worker thread fallback.

The kernel follows a microkernel architecture. Major subsystems — filesystem servers, the page cache, block device drivers — run as privileged servers communicating via message passing. The kernel itself provides the minimal set of primitives: IPC, memory management, scheduling, and capability-based access control.

---

## 2. Non-goals and Scope Boundaries

Telix is not intended to be a general-purpose desktop operating system. Its scope is sufficient to demonstrate its architectural claims through meaningful benchmarks against Linux on the specific subsystems where it makes novel contributions. Full POSIX compliance is not a goal, though a compatibility surface adequate for benchmark workloads and basic userland is expected. POSIX emulation is provided by userspace `libc` layered atop the kernel's native message-passing syscall interface, with the requirement that the native interface be powerful enough to enable faithful emulation.

Heterogeneous core scheduling (P-core/E-core) and heterogeneous memory tiering (CXL, multi-tier NUMA) are intended to be handled at a level consistent with current baseline expectations. These are engineering requirements, not research contributions.

*[To be expanded: explicit list of out-of-scope features.]*

---

## 3. Target Hardware

**Primary architecture:** ARM64. This architecture benefits most from configurable page clustering due to its hardware support for contiguous PTE hints at intermediate superpage sizes (64 KiB). The gap between 4 KiB MMU page size and the 2 MiB first full superpage is the widest among common architectures, making ARM64 the strongest demonstration platform for the page clustering contribution.

**Secondary architecture:** x86-64, for comparative benchmarking against Linux. The 4 KiB-to-2 MiB gap exists here as well but without hardware intermediate superpage support, so the benefit profile differs.

**Stretch goal:** RISC-V, whose modular ISA and evolving hypervisor extension present an interesting testbed but are not required for the core claims.

**Target machine class:** Servers and workstations with multi-socket or chiplet-based NUMA topologies. I/O hardware of interest includes NVMe and NVMe-oF (NVMe over Fabrics), with CXL-attached memory as a future consideration for memory tiering.

---

## 4. Memory Management Subsystem

### 4.1. Page Size Hierarchy

The memory management subsystem defines a three-level page size hierarchy:

**`MMUPAGE_SIZE`** — The finest-grained translation the hardware MMU/TLB supports. Fixed by the architecture (e.g. 4 KiB on ARM64 and x86-64). This is not configurable.

**`PAGE_SIZE`** — The allocation unit. A compile-time or boot-time configurable multiple of `MMUPAGE_SIZE`. The ratio is expressed as `PAGE_MMUCOUNT` (the number of MMU pages per allocation page). The base shift is specified as `PAGE_MMUSHIFT`. All physical memory allocation operates at this granularity. The physical page allocator never deals in units smaller than `PAGE_SIZE`. Sub-`PAGE_SIZE` allocations are handled by a slab allocator layer. Representative values under consideration are 64 KiB and 256 KiB on ARM64.

**Superpage sizes** — Architecture-defined sizes above `MMUPAGE_SIZE` that the TLB can exploit for reduced translation overhead. Crucially, superpage sizes are not required to be larger than `PAGE_SIZE`. On ARM64 with a 256 KiB `PAGE_SIZE`, the 64 KiB contiguous PTE superpage is *contained within* every allocation page and succeeds unconditionally by construction.

### 4.2. Superpage Guarantees and Fragmentation Trade-offs

The configurable `PAGE_SIZE` creates two distinct regimes for superpage management:

**Subpage superpages** (superpage size ≤ `PAGE_SIZE`): These are guaranteed to succeed by construction. Because the allocator never hands out anything smaller than `PAGE_SIZE` and the superpage size divides evenly into it, the physical contiguity and alignment required for the superpage are inherent properties of every allocation page. No promotion, reservation, or contiguity luck is needed. On ARM64 with 256 KiB `PAGE_SIZE`, the 64 KiB contiguous PTE hint is always available.

**Superpage superpages** (superpage size > `PAGE_SIZE`): These still require physical contiguity across multiple allocation pages, but the number of pieces to assemble is dramatically reduced. A 2 MiB superpage from 64 KiB allocation pages requires aligning 32 pages; from 256 KiB pages, only 8. Compare 512 pages at the 4 KiB baseline. The probability of achieving and maintaining contiguity scales nonlinearly with the reduction in piece count.

The cost of this scheme is **internal fragmentation**: memory within an allocation page that is allocated but unused. The design explicitly trades increased internal fragmentation for dramatically reduced external fragmentation and reliable superpage availability. This trade-off is tunable via the choice of `PAGE_SIZE` at compile or boot time, allowing workload-specific tuning.

#### 4.2.1. Bridging the Superpage Gap

Architectures such as ARM64 (4 KiB to 2 MiB, a 512× gap) and x86-64 (4 KiB to 2 MiB, same) suffer from a very large gap between the base MMU page size and the first superpage size. At the base 4 KiB page size, assembling a 2 MiB superpage requires finding or maintaining contiguity across 512 page frames — a fragile proposition under memory pressure.

Page clustering bridges this gap in two ways. First, by guaranteeing subpage superpages (e.g. 64 KiB contiguous PTEs on ARM64 with `PAGE_SIZE` ≥ 64 KiB), it provides an intermediate TLB efficiency benefit that is unconditionally available. Second, by reducing the piece count for the 2 MiB superpage (32 pieces at 64 KiB, 8 at 256 KiB), it makes active contiguity management in the allocator substantially more effective. ARM64 is the greatest beneficiary, as it has hardware support for the intermediate 64 KiB contiguous PTE hint that x86-64 lacks.

> **Novelty assessment:** Novel combination. McKusick–Dickins page clustering applied to guarantee Navarro-style subpage superpage sizes and improve superpage assembly. Not previously published in this specific form; the closest prior work is Linux multi-size THP (6.8), which attacks the same gap from the allocator side rather than by construction.

### 4.3. VM Architecture with Sublinear Reserved Memory Footprint

Traditional BSD and Linux kernels maintain a per-page metadata array: a flat array indexed by physical page frame number (PFN) containing per-page metadata (reference counts, flags, reverse mapping back-pointers, LRU list linkage, page cache membership). In Linux, this is the `struct page` array (partially superseded by `struct folio`), also known as the PFN database or resident page table. This design document describes an architecture that eliminates this per-page array entirely.

#### 4.3.1. Motivations

**Historical:** On large-memory 32-bit systems, the per-page struct array overran kernel virtual address space — a direct and fatal scaling limitation. While 64-bit systems have abundant virtual space, the remaining problems are not resolved by the address space expansion.

**Cache footprint:** Traversing millions of per-page structures during reclaim, migration, or writeback pollutes the data cache with metadata that has poor spatial locality relative to the operations being performed.

**LRU list pathology:** Traditional LRU reclaim walks linked lists threaded through per-page structures in effectively random physical memory order, resulting in catastrophic cache line and TLB utilisation during scans.

**Algorithmic incompatibility:** The per-page struct array is an inherently pointwise data structure. It represents per-frame state and can only be iterated frame by frame. Modern memory management increasingly needs to reason about *extents* — contiguous physical ranges with uniform properties. Operations like superpage promotion, contiguity assessment, memory tiering decisions, and range-based writeback are naturally extent-oriented. A per-page array forces pointwise iteration over what should be a single range query or update, imposing ceilings on algorithmic efficiency that cannot be overcome by coarsening granularity alone.

#### 4.3.2. Extent-Based Metadata Structures

Physical memory metadata is represented by extent-based data structures — each entry describes a contiguous range of physical memory with uniform properties, rather than a single frame. Candidate data structures include:

**B+ trees of intervals:** Leaf-level sibling pointers provide cache-friendly sequential access for range scans. Interior nodes pack many keys per cache line, minimising pointer-chasing. Well-suited to range queries ("find all extents in this physical address range") and bulk operations.

**Adaptive radix trees (ARTs):** Power-of-two-aligned and -sized chunks map naturally onto the address structure of physical memory and the hierarchical structure of page table translations. Prefix compression avoids storing redundant high-order bits across entries describing nearby memory.

Both structures avoid the back-pointers that complicate lock-free algorithms and are amenable to RCU-protected read paths with top-down and leaf-sequential traversal patterns.

> **Design status:** Open question: final data structure selection. B+ trees and ARTs are both viable; the choice may depend on workload-specific access pattern benchmarks. Hybrid approaches are not excluded.

#### 4.3.3. What Replaces Coremap Functions

**Reverse mapping:** Object-based. Page cache objects and anonymous memory objects track their own mappings. To unmap a physical extent for reclaim or migration, the system identifies the owning object, queries it for its mapping list, and walks the relevant page tables. This is the sole reverse mapping path — there is no per-physical-page rmap.

**Reference counting:** Tracked per memory object and per extent, not per physical frame.

**Page state (dirty, writeback, locked):** Properties of extents within memory objects, not of physical frames.

**Reclaim list membership:** Replaced by process-local WSCLOCK scanning (see §4.5). No global LRU list.

### 4.4. Physical Memory Allocator

The physical allocator operates exclusively in units of `PAGE_SIZE` allocation pages. It maintains full active contiguity management, including mobility-based grouping and compaction, to support superpage assembly for sizes above `PAGE_SIZE`. The larger allocation granularity does not replace contiguity management but augments it, making the contiguity management more effective by reducing the piece count.

The interaction between large allocation pages and unmovable kernel allocations is an area requiring careful analysis. A single unmovable 256 KiB allocation page in a 2 MiB aligned region blocks superpage promotion for that region. The probability of having at least one unmovable page in a target region may be lower than at 4 KiB granularity (fewer pages to go wrong), but each unmovable page blocks a proportionally larger fraction of the target.

> **Design status:** Open question: quantitative analysis of unmovable allocation impact at large PAGE_SIZE is needed. The interaction between mobility grouping effectiveness and allocation granularity is not well characterised in existing literature.

### 4.5. Reclaim: Process-Local WSCLOCK

Page reclaim uses a process-local working-set clock algorithm in the style of Carr's WSCLOCK. Each address space maintains its own clock hand, making reclaim decisions local rather than requiring a global LRU list that mixes all pages and incurs cache-thrashing scans.

#### 4.5.1. Reference Bit Scanning

Reference bits reside in hardware MMU PTEs at `MMUPAGE_SIZE` granularity. The clock hand advances through a per-address-space tracking structure (an ART-like structure, discussed in §4.6) that accounts for both individual MMU translations and subpage superpage mappings (contiguous PTE groups). When contiguous PTE hints are active, the referenced state of the group may require checking all constituent PTEs, as the architecture does not guarantee which PTE in the group receives the hardware-set reference bit.

#### 4.5.2. Eviction Granularity

WSCLOCK unmapping operates at `MMUPAGE_SIZE` granularity: individual MMU translations can be removed without freeing the underlying allocation page. If the data is re-accessed, a minor fault reinstalls the PTE with no I/O required, as the physical data is still resident in the allocation page. Actual physical page freeing occurs only when all MMU translations into an allocation page have been removed and the page is otherwise reclaimable. This allows fine-grained working set management without forcing premature eviction of co-resident data.

#### 4.5.3. Shared Reference Bits

When page tables are shared between processes (§4.7), reference bits set by one process's accesses are visible to another process's WSCLOCK scan, conflating their working sets. This inaccuracy is considered tolerable for shared regions. If it proves problematic in practice, controlled minor faults can be used to re-establish per-process reference information.

> **Design status:** Open question: interaction between WSCLOCK, subpage superpages, and the per-mapping ART structure requires detailed design. Navarro-style superpage promotion/demotion state tracking needs adaptation for a context where pages lack individual metadata objects.

### 4.6. Per-Mapping Translation Tracking

Each virtual address space mapping (VMA equivalent) maintains an ART-like structure that tracks active translations, including subpage superpage (contiguous PTE) groups. The address key in the ART decomposes naturally into levels corresponding to different translation sizes — the bits selecting the superpage region, the allocation page within it, and the MMU page within that — mirroring the translation hierarchy.

This structure serves as the basis for WSCLOCK reference bit scanning, superpage promotion and demotion tracking, and coordination with page table sharing. Superpage promotion and demotion state is tracked per memory object (page cache or anonymous memory object), with the per-mapping ART providing the address-space-specific translation state.

### 4.7. Page Table Sharing

Page table sharing is aggressive by default. Multiple processes mapping the same memory object with compatible permissions and alignment share the same physical page table pages, with reference counting to track sharers. This covers shared libraries (text segments), file mappings, and post-fork copy-on-write (COW) sharing.

#### 4.7.1. Fork and Copy-on-Write

Fork does not copy page tables. Both parent and child reference the same page table pages, with entries marked read-only for COW. On a write fault, the faulting process's page table page is unshared (copied), and then the COW fault is handled on the individual data page in the new private copy. This makes fork very cheap — the cost is deferred to write faults, which are more expensive (copying a full `PAGE_SIZE` allocation page, potentially 64–256 KiB) but occur less frequently.

#### 4.7.2. Superpage Interaction

When page tables are shared, superpage promotions and demotions affect all sharers simultaneously. Barring mismatches in the alignment of memory object mappings, promoting or demoting TLB mappings for all sharers is generally acceptable. Where mapping alignments diverge, the per-memory-object accounting structure tracks alignment classes so that promotion and demotion decisions are made within compatible groups of mappings.

#### 4.7.3. Unsharing Triggers

Page table unsharing is triggered by: write faults (COW), per-process permission changes (`mprotect` on one process's mapping when others do not want the same change), and alignment mismatches that prevent shared superpage management. TLB invalidation after modification of a shared page table entry must target all processes sharing that table.

### 4.8. Page Cache and Small File Handling

The page cache supports **tail packing** of small files within allocation pages. Multiple small files (or the tail fragments of larger files) may share a single physical allocation page, managed at the page cache layer. The page cache has the semantic knowledge of file sizes required to make packing decisions; the physical allocator is unaware of sub-page packing.

For buffered I/O (the common case for small files), tail-packed data is never mapped into userspace; it is read and written through kernel buffer operations. Reclaim operates on whole allocation pages — if any packed files are cold enough to trigger eviction, all files sharing that page are evicted together. This co-eviction is acceptable because the files are small by definition and the waste from evicting a warm small file alongside a cold one is bounded.

For the rarer case of memory-mapping a tiny file, an `MMUPAGE_SIZE` extent is instantiated with zero-fill past the end of the file. Optimising the memory-mapped tiny file case is not considered worthwhile.

### 4.9. Page Zeroing

At large `PAGE_SIZE` (64–256 KiB), zeroing an entire allocation page synchronously on a page fault is a significant latency event. The design favours **incremental zeroing**: zeroing at `MMUPAGE_SIZE` granularity on demand. When a fault touches a particular MMU page within an allocation page, that fragment is zeroed and its PTE installed; the remainder of the allocation page is left unmapped. The zeroing cost is spread across multiple faults for allocations that gradually touch the full page, and avoided entirely for regions that are never touched.

> **Design status:** Open question: the precise zeroing strategy (purely on-demand, background pre-zeroing daemon, or hybrid) is not yet determined. The interaction between incremental zeroing and superpage promotion (which wants all constituent MMU pages to be present and identically mapped) requires careful design.

### 4.10. Slab Allocator

Sub-`PAGE_SIZE` kernel allocations are handled by a slab allocator in the Solaris tradition (Bonwick). The slab layer subdivides allocation pages into object caches with per-CPU magazine caching for fast, contention-free allocation and free in the common case. The larger base page size gives each slab more objects per page, potentially improving cache utilisation within individual slabs.

### 4.11. Subpage Management and ABI Preservation

Where managing mappings at sub-`PAGE_SIZE` granularity is required — for instance, to preserve ABI for operations like `mprotect` on regions smaller than `PAGE_SIZE`, or for guard pages — the VM operates on individual MMU PTEs within an allocation page. The allocator and physical memory metadata remain unaware of these sub-page distinctions; they are handled entirely in the page table and per-mapping tracking structures.

At sufficiently large `PAGE_SIZE` values, some application code would require changes were the ABI not preserved by sub-page MMU management. The ABI is not dispensable, as real applications depend on `PAGE_SIZE`-related behaviour; the system is designed so that the common cases are handled transparently through sub-page MMU management, and the larger allocation page size is not directly visible to userspace.

---

## 5. I/O Architecture

### 5.1. Design Rationale

The dominant engineering effort in retrofitting asynchronous I/O onto legacy Unix-derived kernels is not the I/O mechanism itself but the pervasive assumptions of the synchronous VFS call stack. In a traditional Unix kernel, a syscall enters the kernel, walks down through the VFS layer into the filesystem, through the block layer to the device driver, blocks waiting for I/O completion, and returns up the same call stack. Error handling, locking, credential checking, and resource cleanup are all structured around the assumption that a blocking process context is present throughout.

When asynchronous I/O is added to such a kernel, every filesystem, every driver, and every intermediate layer must be audited and potentially rewritten to operate without a blocking process context. Linux's `io_uring` addresses this pragmatically by detecting operations that would block and punting them to kernel worker threads — simulating asynchronous operation atop a fundamentally synchronous architecture. This works but is an architectural admission of defeat: the VFS's synchronous assumptions remain, and the worker thread pool introduces its own overhead and complexity.

Telix eliminates the problem by never having a synchronous VFS. All I/O — file, block, and device — is modelled as asynchronous message passing from its inception. There is no blocking call stack to retrofit, no legacy synchronous codepath to maintain alongside an asynchronous one, and no need for worker thread fallbacks. Filesystem servers and block device servers are written from the start to receive request messages and produce completion messages.

### 5.2. Unified I/O Model

The I/O architecture unifies file I/O, block I/O, and network I/O under a single message-passing abstraction. The historical divergence between the file API (`open`/`read`/`write`/`close`) and the network API (`socket`/`connect`/`send`/`recv`) is treated as an accident of Unix history rather than a reflection of fundamentally different operations. The unified model recognises that both are instances of "open a channel to an endpoint, exchange data, close the channel."

The correspondence between traditional operations and the unified model is:

**Connect** (analogous to `open` and `connect`): Establish a channel to an endpoint. The endpoint may be a file on a filesystem server, a block device server, a network protocol server, or any other service. Connection establishment creates a per-client session on the server side.

**Send** (analogous to `write` and `send`): Submit data to the endpoint via the channel. The message carries an explicit position within the channel when applicable (generalising the file offset and the network sequence number), or operates sequentially when position is implicit.

**Receive** (analogous to `read` and `recv`): Request data from the endpoint. As with send, an explicit position may be specified (generalising `preadv`/`pwritev`-style positioned I/O) or the operation may advance a sequential position maintained by the session.

**Shutdown** (analogous to `close` and `shutdown`): Tear down the channel and release associated resources on both client and server.

**Control messages** (analogous to `stat`, `fstat`, `truncate`, `setsockopt`, etc.): Operations that do not transfer file or stream data are modelled as typed messages on the same channel. A metadata query (`stat`) is a "query metadata" request message; a durability request (`fsync`) is a barrier message; a resize (`truncate`) is a "resize endpoint" request. Each receives a typed completion. This avoids introducing a separate control plane: everything flows through the same message-passing infrastructure.

#### 5.2.1. Position and Offset Generalisation

Every I/O message may optionally carry an explicit position within the channel. For file-backed channels, this corresponds to the byte offset in the file. For stream-oriented channels (network connections, pipes), the position may be implicit and maintained by the session, or may correspond to a sequence identifier. The `preadv`/`pwritev` pattern — positioned I/O that does not disturb the session's sequential position — generalises naturally: positioned operations carry an explicit offset, while sequential operations omit it and advance the session state.

### 5.3. Microkernel I/O Structure

Consistent with the kernel's microkernel architecture, major I/O subsystems run as privileged servers communicating via message passing. The kernel provides the IPC primitives; servers implement I/O policy and logic. The principal servers are:

**Filesystem servers:** Each mounted filesystem is served by a filesystem server that handles path resolution within its namespace, file data operations (read, write, truncate), metadata operations (stat, chmod), and directory operations. Filesystem servers do not manage physical storage directly; they send block I/O requests to block device servers.

**Cache server:** A dedicated server that manages the page cache — the kernel's cache of file and block data in physical memory. The cache server owns the tail-packing logic for small files (§4.8), the extent-based metadata for cached data, and the interaction with the VM subsystem's reclaim mechanisms. Filesystem servers request data through the cache server rather than managing their own caches. The cache server is a privileged server with a close relationship to the kernel's physical memory allocator.

**Block device servers:** Each block device (or class of block devices) is served by a server that translates block I/O request messages into hardware operations. The block device server receives messages from filesystem servers (typically mediated through the cache server) and returns completions when hardware I/O is done.

This structure means a typical cached file read traverses the following path: the client sends a read request to the filesystem server; the filesystem server requests the relevant data from the cache server; if the data is cached, the cache server grants/maps the page cache allocation pages into the client's address space (zero-copy) and returns a completion; if not cached, the cache server sends a block read request to the block device server, receives the data, caches it, and then grants/maps it to the client. Write paths are analogous, with dirty tracking managed by the cache server and writeback to the block device server occurring asynchronously.

> **Design status:** The block device server architecture is adequate for initial benchmarks with available hardware. For production-quality database benchmarks requiring high-throughput block I/O, optimisation of the filesystem-to-block-device message path would be needed.

### 5.4. IPC Mechanism

#### 5.4.1. Ports and Port Sets

The fundamental IPC abstraction is the **port**: a kernel-managed message queue that can receive messages from any holder of a send capability to that port. Processes may hold multiple ports. A **port set** (in the style of Mach port sets) allows a process to wait for messages arriving on any port in the set, providing the multiplexing facility needed for servers that handle requests from many clients simultaneously and for clients that have outstanding requests to multiple servers.

Port sets replace the role of `select`/`poll`/`epoll` in traditional Unix: rather than multiplexing over file descriptors (which are proxies for kernel objects), the process multiplexes directly over the message queues that are the native I/O mechanism.

#### 5.4.2. Message Format and Data Transfer

Messages follow L4-family conventions for performance. Short messages (control operations, metadata queries, completions without large data payloads) are transferred in registers via direct process switch, avoiding memory copies entirely. The kernel performs a direct context switch from sender to receiver when the receiver is waiting, minimising scheduling overhead.

For large data transfers (file reads, bulk writes), **zero-copy memory grant/map** is used. Rather than copying data through the message, the sender grants or maps memory pages into the receiver's address space, transferring or sharing the memory capability. For a cached file read, this means the cache server maps page cache allocation pages directly into the client's address space — the client reads file data from the page cache's physical memory with no data copying at any point in the path.

This zero-copy mechanism connects directly to the VM subsystem: mapped page cache pages participate in page table sharing (§4.7), are subject to WSCLOCK reclaim (§4.5), and their superpage promotion state is tracked by the per-memory-object accounting structures (§4.6). The I/O and VM subsystems are tightly integrated through the memory grant mechanism.

#### 5.4.3. Flow Control and Backpressure

Ports have **bounded capacity**. When a port's message queue is full, a sending process may either block (the default, waiting until space is available) or receive an immediate failure indication if non-blocking send is requested. This provides natural backpressure: a client that submits I/O requests faster than a server can process them will eventually stall on a full port, and a server that produces completions faster than a client consumes them will stall similarly. The bounded capacity is configurable per port to allow tuning for different workload characteristics.

Non-blocking send is essential for servers and for any context where blocking is unacceptable (interrupt handlers, real-time paths). The availability of both blocking and non-blocking send modes ensures that flow control does not introduce involuntary blocking in contexts that cannot tolerate it.

### 5.5. Completion Model

Every I/O request message receives **exactly one completion message**. The completion indicates either success (with associated data or data mapping, if applicable) or an error status code. There are no implicit completions, no callbacks, no upcalls, and no side-channel error reporting. The one-request-one-completion invariant simplifies both client and server logic and makes the state machine of any I/O operation trivially observable.

#### 5.5.1. Ordering and Barriers

Completions may arrive **out of order** with respect to the sequence in which requests were submitted. A client that submits read requests for offsets A, B, and C may receive completions in order B, A, C, depending on the server's internal scheduling and the underlying storage device's reordering. This permits servers and hardware to optimise I/O scheduling (e.g. elevator algorithms, NCQ reordering) without artificial serialisation.

When ordering is required, the client submits a **barrier (fence) message**. A barrier guarantees that all requests submitted before the barrier complete before any request submitted after the barrier is initiated. The `fsync` operation is modelled as a barrier with durability semantics: all prior write requests to this channel must reach stable storage before the barrier completion is delivered. This gives applications explicit control over the ordering/performance trade-off, rather than imposing implicit ordering that pessimises the common case.

### 5.6. Namespace and Endpoint Resolution

Endpoint resolution uses a **hybrid kernel/userspace namespace model**. The kernel provides a minimal capability space: each process receives, at creation, a set of initial port capabilities from its parent (analogous to inherited file descriptors, but providing access to services rather than files). This set includes a capability to the **name server**, a privileged userspace server that manages hierarchical path resolution.

To open a file by path, a client sends a path resolution request to the name server. The name server resolves the path, determines which filesystem server owns the relevant subtree, and returns a port capability for that filesystem server (or brokers the connection directly). The client then sends a connect message to the filesystem server to establish a session. For long-lived connections (an open file), the name server round-trip is paid once at open time; subsequent I/O on the channel goes directly between the client and the filesystem server.

The kernel itself does not understand path syntax, mount points, or namespace structure — these are entirely the name server's responsibility. The kernel's role is limited to managing the capability space and providing the IPC primitives through which the name server and other servers communicate. This keeps the kernel minimal while the capability space provides the bootstrapping mechanism for service discovery.

This design is influenced by seL4's CNode/capability model, where the kernel manages typed capabilities and userspace policy servers determine how they are distributed and named.

### 5.7. Session State

Each connection (channel) between a client and a server creates a **per-client session object** on the server side. The session tracks: the identity and credentials of the connected client, the current sequential position within the channel (the file offset, for file-backed channels), any server-side state associated with the connection (open flags, advisory locks, buffered data), and the client's port capability for sending completions back.

The session model provides the statefulness that makes sequential I/O natural (read advances the position, just as in traditional Unix) while also supporting positioned I/O (explicit offsets bypass the session position, as with `preadv`/`pwritev`). Stateless interaction patterns (e.g. a simple query service that does not track per-client state) are supported trivially by servers that create lightweight sessions with no persistent state.

### 5.8. Native Syscall Interface

The kernel's native syscall interface provides the minimal set of primitives required to support the I/O architecture and general process management. The initial set comprises:

**Port management:** Create port, destroy port, create port set, destroy port set, add port to set, remove port from set.

**Message passing:** Send message to port (blocking and non-blocking variants), wait for message on port set (with timeout).

**Memory capabilities:** Grant memory region to another process, map granted memory, unmap memory.

**Channel management:** Create channel (connect to endpoint), destroy channel (shutdown).

**Process management:** Create process (with initial capability set), destroy process, basic thread management.

This set is deliberately minimal. POSIX-compatible `open`/`read`/`write`/`close`/`stat` and the full range of traditional Unix syscalls are implemented by userspace `libc`, which translates POSIX calls into sequences of native message-passing operations. The requirement on the native interface is that it be *powerful enough* to enable faithful POSIX emulation; the native interface itself is not POSIX-shaped.

> **Design status:** The native syscall set is intentionally minimal and expected to grow as implementation reveals operations that cannot be efficiently composed from the initial primitives. The boundary between "kernel primitive" and "composable from existing primitives" will be determined empirically.

### 5.9. Interaction with the VM Subsystem

The I/O and VM subsystems are coupled through two primary mechanisms:

**Zero-copy memory grants:** The cache server's grant/map of page cache allocation pages into client address spaces means that page cache memory appears in client page tables, participates in page table sharing, and is visible to WSCLOCK reclaim. The VM subsystem's reclaim decisions and the cache server's caching decisions must be coordinated: when the VM reclaims a page cache page, the cache server must be notified (or must be the entity that initiated reclaim); when the cache server evicts a cached page, client mappings must be torn down via the object-based reverse mapping path.

**Cache server as VM participant:** The cache server is a privileged server with a close relationship to the kernel's physical memory allocator. It requests allocation pages from the allocator, manages their contents (tail packing, caching, writeback scheduling), and releases them under memory pressure. It is, in effect, the primary consumer of the physical memory allocator outside of anonymous memory allocation for processes. The extent-based metadata structures that replace the per-page struct array (§4.3.2) must be accessible to the cache server, either through shared memory or through a kernel interface that the cache server uses as a privileged client.

> **Design status:** Open question: the precise interface between the cache server and the kernel's physical memory allocator requires detailed design. Whether the cache server operates as a true userspace server with kernel-mediated memory allocation, or as a quasi-kernel component with direct allocator access, is an architectural decision with significant implications for fault isolation and complexity.

---

## 6. Process Model and Scheduling

### 6.1. Task and Thread Model

The kernel adopts a Mach-style task/thread model. A **task** is a resource container: it holds an address space, a port namespace (the set of port capabilities the task can access), and memory capabilities. A task does not execute code; it is a passive container. A **thread** is a schedulable entity that executes within a task. Multiple threads within a task share the task's address space, port namespace, and memory capabilities. Threads are the unit of scheduling; tasks are the unit of resource accounting and protection.

This separation is well-motivated for the microkernel architecture. A server task (e.g. the filesystem server) contains multiple threads handling concurrent client requests on its port set. The task boundary defines the protection domain; the thread boundary defines the scheduling domain. Creating a new thread within an existing task is lightweight (no address space setup), while creating a new task establishes a new protection domain.

### 6.2. M:N Threading and Scheduler Activations

The kernel supports **M:N threading**: a large number of user-level threads (M) are multiplexed onto a smaller number of kernel threads (N) by a userspace thread scheduler within each task. The kernel is aware of kernel threads only; user-level threads are invisible to the kernel and are managed entirely by the task's userspace threading library.

The expected number of kernel threads per task is a small multiple (possibly as low as one) of the number of processors the task is allowed to run on, plus a small fixed or per-resource pool for auxiliary work (background writeback, asynchronous cleanup, etc.). The userspace scheduler decides which user-level threads to run on the available kernel threads.

#### 6.2.1. Scheduler Activations

Effective M:N threading requires a notification mechanism from the kernel to the userspace thread scheduler: when a kernel thread blocks (e.g. on a page fault or a kernel-mediated operation), the userspace scheduler must be informed so it can run a different user-level thread on that processor rather than leaving it idle. Without this, M:N threading suffers from the pathology where a blocked kernel thread silently removes a processor from the task's available pool.

The kernel provides **scheduler activations** (Anderson et al.) as a specialised upcall mechanism. When a scheduling-relevant event occurs — a kernel thread blocks, a previously blocked kernel thread becomes runnable, a processor is preempted — the kernel forces a context switch to a designated upcall handler in the task at a known entry point, passing event information in registers. This is *not* a message delivered through the general-purpose port/message infrastructure; the upcall is a dedicated fast path because thread switching is exercised so intensively that the latency of general message delivery would be unacceptable.

The upcall handler runs in the task's address space with access to the userspace scheduler's data structures. It makes a local scheduling decision (which user-level thread to run next) and returns to user-level execution without further kernel involvement. The kernel's role is limited to delivering the activation event; all thread scheduling policy is in userspace.

### 6.3. Scheduling Fundamentals

#### 6.3.1. Priority Model

The base scheduling model uses a **fixed external priority** (analogous to the Unix nice value, set by the user or administrator) combined with a **dynamic internal priority** that the scheduler adjusts based on runtime behaviour (CPU usage, sleep/wake patterns, interactivity heuristics). The dynamic priority provides responsive scheduling for interactive and I/O-bound workloads without requiring manual priority assignment for every thread.

The dynamic priority is the scheduler's primary dispatch key; the fixed external priority biases the dynamic calculation. Threads that frequently sleep (I/O-bound, interactive) drift toward higher dynamic priority; threads that consume their full time quantum (CPU-bound) drift toward lower dynamic priority. This is the standard Unix multilevel feedback queue approach, adapted for the microkernel context where "I/O-bound" often means "waiting for IPC completions."

#### 6.3.2. L4-Style Handoff Scheduling

When a thread sends a synchronous IPC message (e.g. a client sending a request to a server) and the receiving thread is waiting for a message, the kernel performs a **direct process switch** from the sender to the receiver. The sender's remaining time quantum is donated to the receiver. This bypasses the scheduler's run queue entirely: no enqueue, no scheduling decision, no dispatch latency. The receiver begins executing immediately on the same processor.

Handoff scheduling is critical for microkernel IPC performance. A client–server round trip (send request, server processes, server replies) can complete in two direct switches without the scheduler being involved at all. This eliminates the scheduling overhead that historically made microkernel IPC expensive compared to monolithic kernel function calls.

#### 6.3.3. Priority Inheritance and Donation

When a client sends a request to a server via IPC, the server thread handling the request inherits the client's effective priority if it is higher than the server thread's own priority. This is a natural extension of handoff scheduling: the time quantum was already donated, and priority donation ensures that the server thread is not preempted by medium-priority work while holding the high-priority client's request. Priority inheritance is transitive: if server A, while handling a high-priority request, sends a message to server B, server B inherits the propagated priority.

This mechanism prevents priority inversion across the IPC boundaries that are pervasive in a microkernel. In a monolithic kernel, a high-priority process calling into a filesystem function executes that code at its own priority. In a microkernel, the equivalent operation is an IPC to a filesystem server, and without priority donation, the server might run at a default low priority regardless of who is waiting for it.

### 6.4. Kernel-Assisted Turnstiles

Privileged servers frequently need internal locks (protecting shared data structures, serialising access to resources). When a server thread blocks on an internal lock held by another server thread, the same priority inversion problem arises: a high-priority request may be stalled because the lock-holding thread is running at low priority.

**Turnstiles** provide priority inheritance for lock-based synchronization, ensuring that a lock holder's effective priority reflects the highest priority of any thread waiting for the lock. In this design, turnstiles require **kernel assistance**. A purely userspace turnstile cannot propagate priorities correctly because the kernel scheduler is unaware of the dependency: if thread A in the filesystem server is blocked on a turnstile waiting for thread B, and thread B is descheduled by the kernel, the kernel has no way to know that B's effective priority should reflect A's priority (and transitively, A's client's priority via IPC donation).

The kernel therefore provides a **turnstile primitive**: servers register lock dependencies with the kernel, and the kernel incorporates these dependencies into its priority inheritance chain. When a server thread acquires a lock via the kernel turnstile interface, the kernel tracks the holder. When another thread blocks on that lock, the kernel adjusts the holder's effective priority. The dependency chain extends seamlessly from IPC-based priority donation through lock-based turnstile inheritance, ensuring that a high-priority client's request is not stalled at any point in the server's processing path.

> **Design status:** Open question: the precise turnstile API and the extent of kernel involvement (full lock management vs. lightweight priority lending hints) require detailed design. The goal is minimal kernel complexity while providing correct priority propagation.

### 6.5. Coscheduling for Virtual Machine Workloads

The scheduler supports **coscheduling** of related thread groups: an advisory mechanism that encourages the scheduler to run all threads in a group simultaneously across different processors. Coscheduling is not strict gang scheduling (all-or-nothing); it is a best-effort bias that makes simultaneous execution likely without wasting processor time when strict co-execution is not achievable.

The motivating case is virtual machine emulation. A virtual machine's vCPU threads may be running guest operating system code that uses spinlocks or other busy-waiting synchronization. If one vCPU thread is descheduled while holding a guest spinlock, all other vCPU threads spinning on that lock waste their time quanta. When the guest is running an operating system that lacks paravirtualization support (no hypervisor yield calls), the guest cannot signal that it is busy-waiting, making the problem invisible to the host scheduler without coscheduling.

Coscheduling does not need to be perfect to resolve busy-waiting pathologies. Even approximate simultaneous execution — making it likely that all vCPU threads are running in overlapping time windows — dramatically reduces the probability that a lock holder is descheduled while waiters spin.

#### 6.5.1. Interaction with Handoff Scheduling

When a thread in a coscheduled group performs a directed yield (L4-style handoff) to a server, the kernel counts execution on the task's behalf by the server as satisfying the coscheduling constraint. The group has not lost a member in a meaningful sense: the processor is still doing work for the task, just in a different protection domain. The coscheduling constraint is "don't schedule a group member's processor to *unrelated* work while other group members are running," not "every group member must be executing its own code simultaneously."

### 6.6. Topology-Aware Scheduling

#### 6.6.1. NUMA Awareness

The scheduler is aware of NUMA topology: which processors share memory controllers, which memory domains are local to which processor groups, and the relative latency and bandwidth between NUMA nodes. Scheduling decisions prefer to keep a thread running on processors local to its memory, and migration across NUMA boundaries incurs a penalty in the scheduler's placement heuristic. This is baseline engineering consistent with current expectations for any multi-socket or chiplet-based system.

#### 6.6.2. SMT Awareness

The scheduler understands SMT (simultaneous multithreading / hyper-threading) sibling relationships. SMT siblings share execution resources (ALUs, caches, branch predictors), so scheduling two CPU-intensive threads on siblings of the same core yields less throughput than spreading them across physical cores. The scheduler uses SMT topology to make intelligent placement decisions: preferring to spread work across physical cores under moderate load, and filling SMT siblings under high load when all physical cores are occupied.

#### 6.6.3. Heterogeneous Core Scheduling

On architectures with heterogeneous core types (ARM big.LITTLE, Intel P-core/E-core), the scheduler accounts for differing performance and power characteristics. High-priority and latency-sensitive threads are preferentially placed on high-performance cores; background and throughput-oriented work is directed to efficiency cores. This is treated as baseline engineering, not a research contribution.

#### 6.6.4. Capability-Based Placement

The scheduler handles hardware capability differences between processors. In the historical example of DYNIX/ptx, tasks requiring floating-point operations were migrated from nodes whose CPUs lacked FPUs (386 SX) to nodes whose CPUs had them (386 DX). While modern architectures are more uniform, analogous situations arise with instruction set extensions (e.g. AVX-512 availability varying by core type on some Intel processors), accelerator affinity, and potentially future heterogeneous architectures with varying capabilities per core cluster.

Capability-based placement is a kernel responsibility because the kernel must ensure correct execution: scheduling a thread on a processor that lacks a required capability would cause a fault. The kernel maintains a per-processor capability mask and matches thread requirements (detected from trap-on-use or declared explicitly) against available processors. This is distinct from the performance-oriented topology scheduling (§6.6.1–6.6.3), which optimises for efficiency; capability-based placement is a correctness requirement.

### 6.7. Topology Information for Userspace Schedulers

Beyond the kernel's own scheduling decisions, topology information is exposed to userspace thread schedulers (via scheduler activations or queryable interfaces) so that M:N threading libraries can make informed placement decisions for user-level threads. A userspace scheduler that knows which kernel threads are on NUMA-local processors can co-locate cooperating user-level threads for better cache and memory locality. The kernel provides the topology map; userspace interprets it according to application-specific knowledge that the kernel lacks.

### 6.8. Future Work

The following scheduling-related topics are identified for future development:

**Virtualisation guest yield calls:** Support for paravirtualized guests that can issue explicit yield or idle hints to the host scheduler, complementing the coscheduling mechanism for guests that lack paravirtualization.

**CPU hotplug:** Dynamic addition and removal of processors at runtime, requiring the scheduler to adjust its topology model, redistribute work, and handle in-flight scheduling decisions for removed processors.

**Userspace locking helpers:** Kernel-assisted primitives beyond turnstiles for common userspace synchronization patterns (futex-like wait/wake, reader-writer locks with priority awareness).

**Energy-aware scheduling:** Integration of power domain and thermal constraint information into scheduling decisions, beyond the basic P-core/E-core placement heuristic.

---

## 7. Security and Capabilities Model

### 7.1. Overview and Provenance

The security model is capability-based, following seL4's design closely. Capabilities are the sole mechanism by which tasks access kernel objects and communicate with other tasks. The kernel does not implement user identity, access control lists, or discretionary permissions; these are userspace policy concerns implemented by appropriate servers (login services, permission-checking libraries). The kernel's role is to manage capabilities correctly and enforce their rights.

This section describes the capability model and highlights where the design adapts seL4's approach to the specific requirements of this kernel's IPC, memory grant, and I/O architecture. Where no adaptation is noted, seL4's design is followed as specified in Klein et al. and subsequent seL4 documentation.

### 7.2. Capability Properties

Capabilities are **unforgeable kernel-managed tokens**. A capability is a reference to a kernel object (a port, a memory region, a task, a thread, a CNode) paired with a set of rights that determine what operations the holder may perform on that object. Capabilities cannot be manufactured by userspace; they can only be obtained by receiving them from the kernel at task creation, by receiving them via IPC from another task, or by deriving them (with equal or reduced rights) from a capability already held.

Capabilities support **rights attenuation**: a holder of a capability with broad rights (e.g. send + receive + grant on a port) can derive a new capability with a subset of those rights (e.g. send-only) and transfer the restricted capability to another task. The recipient cannot escalate the rights beyond what was granted. This is the fundamental mechanism for implementing the principle of least privilege: a server that needs to send completions to a client receives only a send capability to the client's reply port, not a receive capability.

Capabilities are **transferable via IPC**. A message sent through the IPC mechanism may include capabilities alongside data. When a task sends a message containing a capability, the kernel transfers (or copies, depending on the operation) the capability into the recipient's capability space. This is the mechanism by which the name server returns a port capability for a filesystem server to a client: the capability is embedded in the reply message.

### 7.3. Capability Types

The kernel manages typed capabilities corresponding to its kernel objects. The principal types are:

**Port capabilities:** Grant access to IPC ports. Rights include *send* (enqueue a message), *receive* (dequeue a message), and *grant* (transfer this capability to a third party via IPC). A client connecting to a server typically holds a send+grant capability; the server holds the receive capability.

**Memory capabilities:** Grant access to physical memory regions. Rights include *read*, *write*, and *execute*, corresponding to MMU permission bits. When the cache server grants a page cache page to a client for zero-copy read, it transfers a read-only memory capability; the VM subsystem enforces this through read-only PTE mappings. A read-write grant (for writable file mappings) permits the client to dirty the page, which the cache server must then track for writeback.

**Task and thread capabilities:** Grant control over tasks and threads. A parent task holds capabilities to its children, permitting operations like suspension, termination, and capability space manipulation.

**CNode capabilities:** Grant access to capability storage nodes (see §7.4). Used for managing another task's capability space, typically by a parent or a privileged server.

### 7.4. Capability Storage

Capabilities are stored in **CNodes** (capability nodes): kernel objects that are arrays of capability slots. A task's capability space is a tree of CNodes, following seL4's structure. The CNode tree is opaque to the task in normal operation — tasks refer to capabilities by slot addresses within their capability space, and the kernel resolves these addresses through the CNode tree. The internal structure of the CNode tree is managed by the task's parent or by privileged servers that hold CNode capabilities for the task.

This design gives privileged system software (the initial server, process managers) fine-grained control over what capabilities each task holds, while keeping the common-case capability lookup fast: a task references a capability by a small integer (the slot index), and the kernel performs a direct lookup in the task's root CNode for the common single-level case.

### 7.5. Capability Derivation and Revocation

The kernel maintains a **capability derivation tree (CDT)** that tracks parent-child relationships among capabilities. When a capability is derived (copied with attenuated rights) or transferred, the derived capability is recorded as a child of the original. This tree enables **revocation**: a task holding a parent capability can revoke all capabilities derived from it, recursively removing them from every task that holds a derived copy.

Revocation is critical for several interactions with the I/O and VM subsystems:

**File deletion or permission change:** When a file is deleted or its permissions are changed, the filesystem server must revoke memory capabilities that were granted to clients for zero-copy access to that file's page cache pages. The CDT allows the server to revoke all derived grants in a single operation, and the VM subsystem tears down the corresponding client-side mappings.

**Server shutdown:** When a server is terminated or restarted, all capabilities it granted to clients must be revoked to prevent dangling references.

**Session teardown:** When a client disconnects from a server, capabilities associated with that session (granted memory regions, derived port capabilities) are revoked.

### 7.6. Interaction with IPC and the I/O Architecture

The capability model integrates tightly with the IPC mechanism described in §5. Every port is accessed through a capability; every IPC operation requires the sender to hold an appropriate capability to the destination port. The rights on the capability determine what operations are permitted: a send capability allows submitting requests, a receive capability allows dequeuing them.

The **name server** (§5.6) acts as a capability broker: clients send path resolution requests to the name server, and the name server returns port capabilities for the appropriate servers. The name server holds a broad set of server port capabilities and distributes restricted (typically send-only) copies to clients. The name server's own capability is part of every task's initial capability set, placed there by the parent task at creation.

The **zero-copy memory grant path** (§5.4.2) creates memory capabilities dynamically: when the cache server maps a page cache page into a client's address space, it creates a memory capability with the appropriate rights (read-only for read operations, read-write for writable mappings) and transfers it to the client. The capability is recorded in the CDT as derived from the cache server's master capability for that memory region, enabling revocation when the underlying page is reclaimed or the file's permissions change.

### 7.7. User Identity and Access Control

The kernel has **no concept of user identity**. There are no UIDs, GIDs, or kernel-level permission checks based on identity. All access control is mediated by capabilities: if a task holds a capability with sufficient rights, the operation is permitted; otherwise it is not.

User identity, authentication, and discretionary access control are implemented by **userspace policy servers**. A login server authenticates users and grants capabilities appropriate to the authenticated identity. A permission-checking service can mediate access to sensitive resources by requiring clients to present credentials (themselves capabilities obtained through authentication) before granting further capabilities. The traditional Unix security model (uid/gid-based file permissions) can be emulated entirely in userspace by a filesystem server that checks caller credentials before honouring requests.

This approach places the security policy in userspace, where it can be replaced, extended, or formally verified independently of the kernel. The kernel's security obligation is limited to correctly implementing the capability mechanism: ensuring unforgeability, enforcing rights, and performing revocation correctly. This is a much smaller and more verifiable obligation than implementing a full access control policy in the kernel.

### 7.8. Security Considerations for Privileged Servers

Privileged servers (the cache server, filesystem servers, the name server) hold broad capabilities and operate with elevated trust. A compromised cache server, for instance, could grant arbitrary memory to any client. The microkernel architecture confines the damage of a compromised server to the capabilities that server holds — it cannot forge new capabilities or access kernel objects for which it has no capability — but the capabilities held by core servers are broad enough that a compromise is still serious.

Mitigations include minimising the capability set of each server (principle of least privilege applied to servers themselves), structuring servers so that the most privileged operations are isolated in small, auditable components, and potentially applying formal verification techniques to critical servers (following seL4's example of verifying the most security-critical code). These mitigations are engineering practices rather than novel architectural features.

---

## 8. Bootstrapping and Development Plan

### 8.1. Boot Sequence

The kernel boots via a conventional bootloader (UEFI application or platform-specific loader) that loads the kernel image and an **initial RAM filesystem (initramfs)** into known physical memory regions. The kernel initialises its core subsystems — the physical memory allocator, the capability system, the IPC mechanism, and the scheduler — then creates a single **root task** (the initial server) whose binary is loaded from the initramfs.

The root task is the first userspace process. It receives an initial capability set from the kernel comprising: a capability to its own task and thread objects, capabilities to the physical memory regions described by the firmware memory map, a capability to the initramfs memory region, and capabilities to any platform-specific kernel services (debug console, interrupt management). The root task is responsible for bootstrapping all other system services.

#### 8.1.1. Server Startup Order

The root task starts system servers from the initramfs in dependency order:

**1. Cache server:** Started first among the I/O servers, as all other I/O servers depend on it for memory management of cached data. The cache server receives capabilities to physical memory from the root task and establishes its extent-based metadata structures.

**2. Block device server(s):** Started next, receiving capabilities to device memory regions (MMIO) and interrupt lines. The block device server initialises hardware and registers its service port with the root task.

**3. Initramfs filesystem server:** A minimal read-only filesystem server that serves files from the in-memory initramfs. This provides the filesystem interface needed to load subsequent server binaries and configuration before a persistent filesystem is available.

**4. Name server:** Started once the initramfs filesystem server is operational. The name server registers the initramfs filesystem and block device server ports in its namespace, making them discoverable by subsequent processes.

**5. Persistent filesystem server(s):** Started once the name server and block device servers are available. The persistent filesystem server mounts on-disc filesystems and registers them with the name server, completing the transition from the bootstrap initramfs to normal operation.

**6. Additional servers:** Network servers, login services, and other system services are started as needed, receiving capabilities brokered through the name server.

The root task may remain running as a process manager or may transfer its responsibilities to a dedicated process manager server and exit. The root task's role is purely to bootstrap; it does not participate in normal system operation.

### 8.2. Implementation Language

**Core kernel and low-level servers: Rust.** The kernel itself and the privileged servers (cache server, block device servers) are implemented in Rust. Rust's ownership model and type system provide memory safety guarantees that eliminate the dominant classes of kernel bugs (use-after-free, buffer overflows, data races) while permitting the low-level control (inline assembly, MMIO, direct hardware interaction) required for kernel code. The `unsafe` surface is kept as small as practicable and concentrated in well-identified modules (architecture-specific code, hardware interaction, certain lock-free data structures).

**Higher-level servers: Rust or other languages as appropriate.** Because servers are separate executables communicating via IPC, they are not required to share a language with the kernel. In principle, a filesystem server or name server could be written in any language that can perform IPC via the native syscall interface. In practice, Rust is expected to be the default for all servers in the initial implementation, with the possibility of higher-level languages for components that operate atop sufficiently high-level abstractions.

### 8.3. Development Phases

Development is structured in phases ordered by subsystem dependency and the ability to test and demonstrate progress incrementally.

#### 8.3.1. Phase 1: Core Kernel

The initial phase delivers the microkernel itself: the physical memory allocator with configurable `PAGE_SIZE`, the capability system, the IPC mechanism (ports, port sets, L4-style handoff), the scheduler (priority model, basic SMP support), and the thread and task management primitives. The target is ARM64, with x86-64 as a secondary target.

At the end of Phase 1, the kernel can create tasks, send and receive messages, and allocate memory. There are no servers yet; testing is done with synthetic in-kernel test tasks or minimal userspace programs loaded from a hardcoded memory image.

#### 8.3.2. Phase 2: VM Subsystem Novelties

The VM subsystem is developed to the point where the novel contributions can be demonstrated: extent-based metadata replacing the per-page struct array, configurable `PAGE_SIZE` with subpage superpage guarantees, incremental page zeroing, and WSCLOCK reclaim. The VM subsystem is more self-contained than the I/O architecture and can be tested with synthetic memory allocation and access workloads without requiring a full server stack.

At the end of Phase 2, the system can demonstrate: superpage allocation success rates at various `PAGE_SIZE` configurations, TLB miss rates under controlled workloads, the extent-based metadata operating correctly (coalescing, splitting, range queries), and WSCLOCK reclaim functioning without a per-page struct array.

#### 8.3.3. Phase 3: I/O Server Stack

The cache server, a block device server (NVMe or virtio-blk for testing under emulation), and a minimal filesystem server are implemented. The initramfs server provides initial file access. Zero-copy memory grants between the cache server and clients are implemented and connected to the VM subsystem.

At the end of Phase 3, the system can boot to a basic userspace with file I/O, demonstrating the full message-passing I/O path including zero-copy reads.

#### 8.3.4. Phase 4: Completeness and Evaluation

The name server, page table sharing, M:N threading with scheduler activations, coscheduling, turnstiles, and NUMA-aware scheduling are implemented. A POSIX compatibility library (`libc` shim) is developed to the extent needed to run evaluation workloads. Profiling and tracing infrastructure is built to support the attribution-based evaluation approach (§10).

### 8.4. Development and Testing Environment

Given the constraint of no dedicated victim machines, initial development and testing targets **emulation and virtualisation**: QEMU for ARM64 and x86-64 emulation, with hardware-accelerated virtualisation (KVM) when running on an x86-64 host. QEMU provides virtio devices (block, network, console) that are straightforward to write drivers for, and its GDB stub enables kernel debugging.

Performance evaluation under emulation is indicative but not definitive. QEMU does not accurately model TLB behaviour, cache hierarchy, or NUMA topology — all of which are central to the VM subsystem's claims. Cycle-accurate simulation (e.g. gem5) could provide more meaningful architectural measurements but at very high runtime cost. Performance results from emulation are presented with appropriate caveats; definitive performance claims would require real hardware.

### 8.5. Prior Work and Influences

This design draws on a broad body of prior work across its subsystems. The following summarises the principal influences beyond those already cited in individual sections:

**Page clustering:** The pgcl (page clustering) patches for Linux, originally developed in the early 2000s and forward-ported to modern Linux by the author (NadiaYvette/linux on GitHub). Hugh Dickins' original page clustering work for Linux. The SGI IRIX variable page size support exploiting MIPS R4000 TLB capabilities. IBM AIX's aggressive use of multiple page sizes on POWER.

**Coremap-free design:** The Linux folio conversion (Matthew Wilcox) as an incremental step away from per-page metadata. The Mach VM object/memory map architecture, which separated virtual memory description from physical page tracking.

**Network-unified I/O:** Plan 9 (Bell Labs) and its 9P protocol for uniform resource access. QNX's resource manager model for userspace filesystem and device servers accessed via message passing. The Spring OS (Sun Microsystems) uniform object interface.

**Microkernel and IPC:** The L4 microkernel family (Liedtke, Fiasco.OC, NOVA, seL4). Mach (CMU) for the task/thread model and port set abstraction. The Genode OS framework for component co-location strategies.

**Coscheduling:** Ousterhout's gang scheduling. VMware relaxed coscheduling for virtual machine workloads.

---

## 9. Retrenchment Strategies

A ground-up kernel design involves significant architectural risk. Several design choices in Telix are ambitious and may prove to have unacceptable overheads or unforeseen complications under real workloads. This section identifies the principal risks and describes fallback strategies that allow the design to degrade gracefully toward more conventional approaches without requiring wholesale redesign.

### 9.1. Page Clustering: Reducing PAGE_SIZE

**Risk:** Internal fragmentation at large `PAGE_SIZE` proves unacceptable for workloads with many small allocations (small file caching, many small anonymous mappings, processes with sparse address spaces).

**Retrenchment:** Reduce `PAGE_SIZE` at compile time. The design supports a configurable `PAGE_SIZE` as a first-class feature, so this is not a retrofit but a tuning decision. At 64 KiB, the internal fragmentation is one-quarter of the 256 KiB case, while the superpage gap-bridging benefit is retained (32-way assembly for 2 MiB instead of 512-way). Dropping to `MMUPAGE_SIZE` (4 KiB) recovers entirely conventional behaviour: no subpage superpage guarantees, no gap-bridging benefit, but also no internal fragmentation penalty. The system degrades gracefully along a continuum rather than failing abruptly.

### 9.2. Coremap-Free VM: Hybrid Extent/Flat Metadata

**Risk:** Extent fragmentation under adversarial or pathological workloads causes the extent tree to degenerate toward one entry per physical page, losing the efficiency advantage and adding tree traversal overhead on top of what a flat per-page struct array would cost.

**Retrenchment:** Introduce a hybrid scheme: use a flat per-page struct array for physical regions where extent coalescing consistently fails, while retaining extent-based tracking for regions where it works well. This can be partitioned per zone or per NUMA node — heavily fragmented zones fall back to per-page metadata while well-coalesced zones continue to benefit from extent-based structures. The extent-based path remains the default; the per-page array is a localised fallback, not a wholesale reversion.

### 9.3. Microkernel IPC Overhead: Server Co-location

**Risk:** The multi-hop message-passing path for I/O (client → filesystem server → cache server → block device server) incurs IPC overhead that substantially degrades I/O throughput or latency compared to a monolithic kernel's direct function calls.

**Retrenchment:** Selectively co-locate servers that are on the hot I/O path. The filesystem server and cache server, for example, could be merged into a single address space (a single task with a combined server), eliminating the IPC hop between them while preserving the external IPC interface to clients and to block device servers. In the limit, all core I/O servers could be co-located into a single "I/O server" task, recovering a monolithic I/O path internally while retaining the message-passing interface externally. This follows the precedent of Genode's component co-location and L4Linux's single-server approach. The architectural separation in the design document is maintained in the API; co-location is an implementation optimisation that does not change the client-visible interface.

### 9.4. Zero-Copy Memory Grants: Size-Threshold Fallback

**Risk:** The overhead of setting up memory grants (capability creation, page table manipulation, TLB invalidation) exceeds the cost of simply copying data for small I/O operations.

**Retrenchment:** Introduce a size threshold. Below the threshold (perhaps one or two `MMUPAGE_SIZE` units of data), the data is copied inline in the IPC message, avoiding the grant machinery entirely. Above the threshold, zero-copy grants are used. This is analogous to how network stacks use different paths for small and large payloads, and to L4 IPC's distinction between short (register) messages and long (memory) transfers. The threshold can be tuned empirically.

### 9.5. Coscheduling: Relaxation to Advisory Hints

**Risk:** Coscheduling constraints cause processor underutilisation (processors sitting idle waiting for gang members to be schedulable) or interact poorly with other scheduling goals (NUMA affinity, priority inheritance).

**Retrenchment:** Since coscheduling is already advisory rather than strict, the retrenchment is simply reducing the scheduler's bias toward co-placement. The coscheduling hint can be weakened to a tie-breaking preference (when the scheduler has a free choice, prefer to run a coscheduled group member) or disabled entirely for specific workloads or task groups. Because the mechanism is a bias rather than a constraint, relaxation is continuous and does not require architectural changes.

### 9.6. WSCLOCK Reclaim: Supplementary Global Reclaim

**Risk:** Process-local WSCLOCK is insufficient for global memory pressure situations where no single process's working set is large enough to reclaim from, but aggregate memory consumption exceeds physical capacity. This is the classic problem with purely local reclaim policies.

**Retrenchment:** Supplement WSCLOCK with a global reclaim daemon that operates under severe memory pressure. The daemon would scan extent metadata (not a per-page LRU list) to identify globally cold regions, targeting extents that have not been referenced across any address space. This is not a replacement for WSCLOCK but an emergency backstop. The daemon operates only when free memory drops below a configurable threshold and is expected to be invoked infrequently in well-sized systems.

---

## 10. Evaluation Strategy

Evaluation of Telix must be approached with care. A ground-up research kernel without years of optimisation will not win straightforward benchmark comparisons against Linux or FreeBSD, which have decades of performance engineering. Attempting to present such comparisons at face value would be misleading. Instead, the evaluation strategy focuses on two complementary approaches: **mechanism verification** (demonstrating that the novel mechanisms work as designed and produce their intended effects) and **attribution-based profiling** (understanding *where* time is spent, so that performance differences can be explained rather than merely measured).

### 10.1. Mechanism Verification

The primary evaluation goal is to demonstrate that the kernel's novel mechanisms are operational and produce measurable effects:

**Superpage allocation success:** Measure the rate at which superpages are successfully allocated and used under controlled workloads at various `PAGE_SIZE` configurations. Compare against Linux's THP promotion success rate under equivalent workloads. The claim to verify is that subpage superpages succeed unconditionally at `PAGE_SIZE` ≥ superpage size, and that larger-than-`PAGE_SIZE` superpages succeed more reliably than Linux's THP promotion at 4 KiB base pages.

**TLB miss rates:** Measure TLB miss rates (via hardware performance counters where available, or via instrumentation under emulation) to verify that superpage usage translates into the expected TLB efficiency improvement.

**Extent metadata efficiency:** Measure the number of extent entries versus the equivalent number of per-page struct array entries for representative physical memory states. Demonstrate that the extent-based representation is compact for typical workloads and characterise the workloads that cause degeneration.

**Asynchronous I/O path:** Demonstrate that I/O operations complete asynchronously through the message-passing path without worker thread fallbacks. Measure I/O completion latency distribution and verify the absence of the tail-latency pathologies caused by synchronous-to-async conversion in conventional kernels.

**Zero-copy verification:** Confirm via instrumentation that large reads result in memory grants (page table sharing) rather than data copies, and measure the resulting reduction in memory bus traffic.

**Coscheduling effectiveness:** For virtual machine workloads, measure the reduction in guest spinlock wait time under coscheduling versus standard scheduling.

### 10.2. Attribution-Based Profiling

When benchmark results show that the kernel is slower than Linux for a given workload (as is expected for many workloads), the evaluation must explain *why*. This requires detailed profiling and attribution:

**IPC overhead attribution:** Measure the fraction of total execution time spent in IPC (message send, receive, context switch). Distinguish between IPC overhead inherent to the microkernel architecture and overhead due to implementation immaturity (e.g. unoptimised message copying, cache-cold context switches).

**Server overhead attribution:** Profile individual servers (filesystem, cache, block device) to identify hot functions. Distinguish between overhead inherent to the server model (serialisation, capability checks) and overhead due to untuned implementation.

**VM subsystem attribution:** Profile the extent-based metadata operations, WSCLOCK scanning, and superpage promotion/demotion paths. Identify whether any overhead comes from the novel data structures versus from insufficient optimisation of those structures.

The goal is to produce an honest accounting: for each workload, what fraction of any performance gap is architectural (inherent to the design choices and would not improve with more engineering) versus implementational (would improve with more optimisation time). This is a more valuable contribution than raw benchmark numbers, as it informs future work and helps the community understand the real costs of the architectural choices.

### 10.3. Hardware Constraints

Development and initial evaluation are constrained to emulation (QEMU) and virtualisation due to the absence of dedicated hardware. This limits the definitiveness of performance results — QEMU does not accurately model TLB behaviour, cache hierarchy, or NUMA topology. Performance measurements from emulation are presented as indicative with explicit caveats. Definitive architectural measurements (TLB miss rates, NUMA locality effects) would require either real hardware or cycle-accurate simulation (gem5), both of which are identified as future work contingent on resource availability.

---

## 11. Future Work

The following topics are identified for future development, beyond the scope of the initial implementation:

### 11.1. Single System Image (SSI)

Single System Image clustering (Milojičić et al.) aims to make a cluster of machines appear as a single operating system instance. SSI was largely abandoned by the research community in the 2000s due to the intractable complexity of maintaining full system-wide coherence. However, the core motivations remain relevant, and several aspects of this kernel's design are more amenable to SSI than traditional monolithic kernels:

The message-passing I/O architecture (§5) already abstracts I/O endpoints in a location-transparent manner: a client sends messages to a port, and whether the server behind that port is local or remote is not visible at the API level. Extending the IPC mechanism to support transparent remote messaging would enable remote server access without client-side changes.

The capability model (§7) provides a natural mechanism for distributed resource naming: capabilities can refer to remote objects if the kernel's capability resolution can be extended to span nodes.

The extent-based VM metadata (§4.3) could potentially describe remote memory (CXL-attached, RDMA-accessible) alongside local memory, enabling transparent remote memory access at the VM level without the per-page struct array's assumption of a single flat physical address space.

A prudent approach would not attempt full SSI but would identify specific SSI capabilities (transparent remote IPC, remote memory mapping, process migration for specific resource types) that can be added incrementally without the all-or-nothing coherence burden that killed earlier SSI projects. This is an explicitly long-term goal.

### 11.2. Additional Future Topics

**Formal verification:** Applying formal verification techniques to the core kernel, following seL4's precedent. The microkernel's small trusted computing base makes this more feasible than for a monolithic kernel.

**Persistent memory support:** Integrating persistent memory (or its successors) into the extent-based VM and cache server architecture.

**Real hardware evaluation:** Porting to and evaluating on real ARM64 and x86-64 hardware, including systems with large NUMA topologies and heterogeneous core configurations.

**Network stack:** A network protocol stack implemented as a server, demonstrating the I/O architecture's uniformity by handling network and file I/O through the same message-passing framework.

**Virtualisation support:** Hosting virtual machines, leveraging the coscheduling mechanism and potentially the capability model for fine-grained VM resource control.

---

## 12. References and Prior Work

Accetta, M. et al. "Mach: a new kernel foundation for UNIX development." USENIX Summer 1986.

Anderson, T., Bershad, B., Lazowska, E., and Levy, H. "Scheduler activations: effective kernel support for the user-level management of parallelism." SOSP 1991.

Baumann, A. et al. "The multikernel: a new OS architecture for scalable multicore systems." SOSP 2009.

Black, D.L. "Scheduling support for concurrency and parallelism in the Mach operating system." IEEE Computer 1990.

Bonwick, J. "The slab allocator: an object-caching kernel memory allocator." USENIX Summer 1994.

Bonwick, J. and Adams, J. "Magazines and vmem: extending the slab allocator to many CPUs and arbitrary resources." USENIX 2001.

Boos, K., Liber, N., and Zhong, L. "Theseus: an experiment in operating system structure and state management." OSDI 2020.

Carr, R. and Hennessy, J. "WSCLOCK — a simple and effective algorithm for virtual memory management." SOSP 1981.

Dickins, H. Page clustering patches for the Linux kernel.

Hamilton, G. and Kougiouris, P. "The Spring nucleus: a microkernel for objects." USENIX Summer 1993.

Heiser, G. and Elphinstone, K. "L4 microkernels: the lessons from 20 years of research and deployment." TOCS 2016.

Klein, G. et al. "seL4: formal verification of an OS kernel." SOSP 2009.

Kuenning, G. et al. "The Genode OS framework."

Liedtke, J. "On µ-kernel construction." SOSP 1995.

McKusick, M.K. and Neville-Neil, G.V. "The Design and Implementation of the FreeBSD Operating System." Addison-Wesley.

Milojičić, D.S. et al. "Single System Image."

Navarro, J., Iyer, S., Druschel, P., and Cox, A. "Practical, transparent operating system support for superpages." OSDI 2002.

Ousterhout, J. "Scheduling techniques for concurrent systems." ICDCS 1982.

Pike, R. et al. "Plan 9 from Bell Labs." Computing Systems 1995.

Roberts, R. et al. Multi-size THP patches for the Linux kernel, merged in Linux 6.8.

Solaris Internals. Turnstiles and priority inheritance in the Solaris kernel.

Wilcox, M. Folio conversion patches for the Linux kernel.

*[To be expanded with additional references as development progresses.]*
