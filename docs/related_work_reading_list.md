# Related Work Reading List for Telix / Frankenstein Co-Design

A bibliography for the language+OS co-design tradition relevant to
the Telix microkernel, the Frankenstein polyglot compiler, the
completion-based syscall design
(`docs/completion_based_syscalls.md`), and the activation/Perceus
demotion proposal (`docs/activation_perceus_demotion.md`).

This is a reading list, not a survey — entries are pointers, not
summaries. Where one paper is the "right starting point" for a
thread, it is noted.

For each cluster, the **most directly relevant** projects to current
Telix work are bolded. Citations are author/year/venue rather than
full BibTeX.

---

## 1. The Midori lineage

The closest single body of work to the Telix+Frankenstein endpoint:
a managed-code capability-microkernel research program with an
in-house systems language.

- **Singularity** (Hunt & Larus, MSR, 2003–2010). OSDI '07: *Sealing
  OS Processes to Improve Dependability and Safety*. Design notes
  in MSR-TR-2005-135. SIPs (Software-Isolated Processes) as the
  precursor to Midori's process model.
- **Sing#** as the systems language. Fähndrich et al., EuroSys '06:
  *Language Support for Fast and Reliable Message-Based
  Communication in Singularity OS*. The contract-based channel
  types are an early form of session-typed IPC.
- **Midori** (MSR, late 2000s through ~2015). Essentially zero
  peer-reviewed publications; Joe Duffy's blog series is the
  canonical literature:
  - *15 Years of Concurrency*
  - *Asynchronous Everything* (most directly relevant to the
    completion-based syscall design — async-await all the way down
    the stack, no blocking primitives below the language runtime)
  - *Safe Native Code* (M#/Bartok pipeline)
  - *Objects as Secure Capabilities* (object-capability discipline
    applied uniformly)
- **Verona** (MSR, ongoing). The direct intellectual descendant of
  Midori's concurrency work.
  - Parkinson et al., *Project Verona: Concurrent Programming Made
    Safe*.
  - **Cheeseman et al., OOPSLA '23: *When Concurrency Matters:
    Behaviour-Oriented Concurrency*.** This is the most actively
    relevant single paper to the activation/demotion thinking —
    regions, behaviours, deterministic-by-default concurrency, and
    capability-discipline updated for a modern language frontend.

**Where to start:** Duffy's *Asynchronous Everything* and *Objects
as Secure Capabilities* essays for the conceptual frame; then the
OOPSLA '23 Verona paper for current state of the line.

---

## 2. Rust-microkernel / safe-systems-language OSes

Closest to Telix's implementation language and architectural
ambition.

- **Theseus** (Kevin Boos, Rice 2020). OSDI '20: *Theseus: an
  Experiment in Operating System Structure and State Management*.
  PhD thesis available; longer and more detailed than the paper.
  **Intralingual** design: rather than using hardware privilege
  rings to isolate kernel from user, Theseus uses the Rust type
  system to provide isolation between *cells* (its unit of
  modularity). Most directly relevant single project to where the
  Telix+Frankenstein endpoint could go.
- **Tock** (Stanford / Cambridge / Princeton). Levy et al., SOSP
  '17: *Multiprogramming a 64KB Computer Safely and Efficiently*.
  Embedded but the kernel-Rust + capsules-Rust + arbitrary-userspace
  three-layer model is structurally close to Telix's
  Telix-native + Linux-personality split.
- **Hermit / HermitCore** (RWTH Aachen). Lankes et al. Rust
  unikernel for HPC. Worth scanning if Frankenstein ends up
  generating standalone unikernels.
- **Redox OS** (non-academic but public). Microkernel,
  capability-influenced IPC. Useful as a *contrast* to Telix's
  design choices — both are Rust microkernels but with different
  IPC and userspace conventions.

**Where to start:** Boos's Theseus thesis. It's long but
specifically grapples with what hardware-isolation costs and what
language-based isolation gives you back, which is the exact
analysis Telix will eventually face.

---

## 3. Capability-language tradition

For the IPC discipline, the parent-constructs-child pattern, and
the cap-table design.

- **EROS / Coyotos / CapROS** (Jonathan Shapiro et al.). EROS
  thesis (UPenn 1999). Shapiro & Sridhar's BitC language design
  notes (BitC was Coyotos's planned systems language; never
  finished, but the design lessons are documented). EROS-Verifying
  paper (S&P '06).
- **seL4** (NICTA / Data61 / now Proofcraft + Trustworthy Systems).
  - Klein et al., TOCS '14: *Comprehensive Formal Verification of
    an OS Microkernel*.
  - **seL4 Reference Manual** — the actual ABI definition.
  - **Microkit (seL4 Core Platform)** — the modern way the
    community thinks about parent-constructs-child component
    composition.
- **Pony** (Sylvan Clebsch, Imperial). PhD thesis: *The Pony
  Programming Language*. Clebsch et al., AGERE '15: *Deny
  Capabilities for Safe, Fast Actors*. Reference capabilities (iso,
  val, ref, box, tag, trn) for safe actor-actor sharing.
  Influential on Verona's design.
- **E / Joe-E** (Mark Miller et al.). **Miller PhD thesis 2006:
  *Robust Composition: Towards a Unified Approach to Access
  Control and Concurrency Control*.** The foundational read for
  object-capability semantics — what counts as a capability, why
  ambient authority is dangerous, why eventual sends are the right
  default. Caja and Joe-E (capability-safe Java subset) are the
  practical follow-ons.
- **Genode** (Norman Feske et al., Genode Labs). **Feske, *Genode
  Foundations* book — freely downloadable.** The most readable
  introduction to component-based microkernel design;
  parent-constructs-child is fundamental to the model.
- **Composite** (Gabriel Parmer, GWU). Components-as-first-class
  microkernel. Relevant to Telix's discovery_srv/proxy_srv design.

**Where to start:** Miller's *Robust Composition* if you want the
foundational object-capability theory; the *Genode Foundations*
book if you want a worked example of a real component-based
microkernel; the seL4 Reference Manual if you want to compare ABI
choices against Telix's.

---

## 4. Polyglot / managed-runtime literature

Most relevant to Frankenstein's "many frontends, one runtime"
agenda.

- **Truffle / GraalVM** (Würthinger et al., Oracle Labs / JKU
  Linz).
  - Würthinger et al., Onward! '13: *One VM to Rule Them All*.
  - Würthinger et al., PLDI '17: *Practical Partial Evaluation for
    High-Performance Dynamic Language Runtimes*.
  - The Truffle Language Implementation Framework documentation.
  Closest published "many source languages, one runtime" work,
  even though Truffle goes via interpretation+partial-evaluation
  rather than typed-IR linking.
- **MLton** (whole-program optimizing SML compiler). The MLton
  source itself is documented; the various retargeting and
  Cilk-meets-MLton experiments are good case studies for what
  whole-program optimization opens up.
- **JikesRVM** (IBM / Anu Singh + Alpern et al.). IBM Systems
  Journal '00: *The Jikes Research Virtual Machine*. Meta-circular
  Java VM. The meta-circularity discipline (system software
  written in the same language it runs) is the lineage that fed
  Singularity/Midori.
- **MirageOS** (Madhavapeddy et al., Cambridge / Citrix). **ASPLOS
  '13: *Unikernels: Library Operating Systems for the Cloud*.**
  OCaml-based, single-language-image-as-OS. Demonstrates how much
  you can strip out when the kernel and the application share a
  type system.
- **HaLVM** (Galois). Haskell unikernel. Less prolific in formal
  publication; engineering notes findable.
- **OSv** (Cloudius Systems). USENIX ATC '14. JVM-tailored
  unikernel.

**Where to start:** The MirageOS ASPLOS '13 paper for the
strongest argument that single-language-runtime OS pays off,
followed by the GraalVM/Truffle Onward! '13 paper for the
multiple-frontends-one-runtime angle that's closest to Frankenstein.

---

## 5. Kernel + runtime co-design

Closest to the activations / non-blocking-syscall design.

- **K42** (IBM Research). Krieger et al., EuroSys '06: *K42:
  Building a Complete Operating System*. Predecessors:
  - **Gamsa et al., OSDI '99: *Tornado: Maximizing Locality and
    Concurrency in a Shared Memory Multiprocessor Operating
    System*.** The clustered-object pattern.
  - The original scheduler-activation paper: **Anderson, Bershad,
    Lazowska, Levy, SOSP '91: *Scheduler Activations: Effective
    Kernel Support for the User-Level Management of Parallelism*.**
- **Akaros** (Barret Rhoden, Berkeley 2014). PhD thesis and OSDI
  '14: *Improving Per-Node Efficiency in the Datacenter with
  NewWorld OS Abstractions*. Many-core, MCP (multi-core process),
  kernel hands scheduling decisions to userspace runtimes. **The
  closest published work to what Telix's activation upcalls
  should look like in practice.**
- **Tessellation** (Liu et al., Berkeley). Space-time partitioned
  OS, channels, cells. Less mature than Akaros.
- **Barrelfish / Multikernel** (ETH Zurich + MSR Cambridge).
  Baumann et al., SOSP '09: *The Multikernel: A New OS Architecture
  for Scalable Multicore Systems*. Message-passing-only between
  cores; treats a manycore machine as a distributed system.
  Directly relevant to Telix's distributed strategy.
- **Demikernel** (MSR). Zhang et al., SOSP '21: *The Demikernel
  Datapath Architecture for Microsecond-Scale Datacenter Systems*.
  Library OS for kernel-bypass.
- **Arrakis** (UW). Peter et al., OSDI '14: *Arrakis: The Operating
  System is the Control Plane*. High-performance network stack with
  data-plane bypass.
- **IX** (Stanford). Belay et al., OSDI '14: *IX: A Protected
  Dataplane Operating System for High Throughput and Low Latency*.
- **Mach continuations** (Draves, Bershad, Rashid, Dean). USENIX
  Mach Symp. '91: *Using Continuations to Implement Thread
  Management and Communication in Operating Systems*. The original
  CPS-style kernel-threading mechanism that the
  continuation-passing runtime model in
  `completion_based_syscalls.md` §2.5 ultimately traces to.

**Where to start:** Anderson et al. SOSP '91 for the foundational
activation paper, then Rhoden's Akaros thesis as the most
developed implementation, then Draves et al. on Mach continuations
for the continuation-passing dispatch model.

---

## 6. OS-in-language-X tradition more broadly

Background reading on the genealogy of "language and OS as one
system."

- **Symbolics Genera / Lisp Machines** (1980s). Limited current
  bibliography; the Symbolics manuals are on bitsavers.org. The
  deepest single-image system ever shipped.
- **Native Oberon / A2 Bluebottle** (Wirth, Gutknecht et al., ETH).
  **Wirth & Gutknecht, *Project Oberon* book — freely available.**
  The complete-OS-in-one-language exemplar.
- **House** (PSU, Hallgren et al.). Haskell '05: *House: an
  Operating System Written in Haskell*. The Galois lineage.
- **JX** (Erlangen). Golm et al., USENIX ATC '02: *The JX Operating
  System*. Java microkernel with multiple Java teams of various
  safety levels.
- **JNode**, **JOS**, **Squawk** — less academic Java-OS attempts.
- **Smalltalk-80 / Squeak / Pharo** (Goldberg, Robson, et al.). The
  image-based programming model and the lack of OS/language
  boundary. *Smalltalk-80: The Language and its Implementation* is
  the foundational text.
- **Inferno / Limbo** (Bell Labs, Pike et al.). Pike et al., Bell
  Labs Tech Journal '97: *The Inferno Operating System*. The Dis
  VM. CSP-derived concurrency in Limbo — the direct ancestor of
  Go's goroutines.

---

## 7. Plan 9 / Inferno (for distributed/namespace angle)

Relevant to `docs/telix_distributed_strategy.md` more than most
people realize.

- Pike et al., USENIX '90: *Plan 9 from Bell Labs* (the short paper)
  and the longer follow-on.
- Pike, *The Use of Name Spaces in Plan 9*.
- Pike et al., USENIX '95: *Plan 9 from Bell Labs* (the polished
  longer version).
- Pike, USENIX '00 Invited Talk: *Systems Software Research is
  Irrelevant*. Provocation, but worth reading for the framing.

The "everything is a hierarchical namespace, mountable from
anywhere, including over the network" model is what gives Plan 9
its programmability advantage. Inferno extended it with portable
code (Dis bytecode, Limbo) — directly relevant to the
ring-entries-as-messages-routable-by-proxy_srv observation in
`completion_based_syscalls.md` §A.4.

---

## 8. Erlang / OTP / BEAM

Async-everything as a complete language+runtime+OS framework. The
single best worked example of what the "no blocking primitives in
user code, supervised actor hierarchies" design looks like at
scale.

- **Joe Armstrong's PhD thesis (2003): *Making Reliable Distributed
  Systems in the Presence of Software Errors*.** Free PDF widely
  available. Foundational reading; "let it crash," supervision
  trees, message passing as the only sharing primitive.
- *Programming Erlang* (Armstrong) and *Designing for Scalability
  with Erlang/OTP* (Cesarini & Vinoski) as the practical companions.
- The BEAM internals are documented in *The BEAM Book* (Lundin,
  available online) — useful for understanding how the actor model
  is actually implemented underneath the language.

---

## 9. Specific topic threads worth following

### 9.1 Async / continuation-passing dispatch

- Mach continuations (Draves et al. as in §5).
- **Joe Duffy, *Asynchronous Everything* (Midori blog).**
- Boehm, *Threads Cannot be Implemented as a Library* (PLDI '05) —
  cautionary on what happens when the language and the kernel
  disagree about scheduling.

### 9.2 Reference counting + activations

- Leijen & Reinking et al., PLDI '21: *Perceus: Garbage Free
  Reference Counting with Reuse* — the foundational Perceus paper.
- Reinking et al., PLDI '21 companion: *FBIP: Functional but
  In-Place*.
- de Moura & Ullrich, *The Lean 4 Theorem Prover and Programming
  Language* (CADE '21) — Lean's RC scheme.
- Jiménez, OOPSLA '17: *Biased Reference Counting: Minimizing
  Atomic Operations in Garbage Collection*. The closest
  pre-existing work on demotion-style optimization.
- Swift's RC: *Reference Counts in Swift* (various Swift Evolution
  proposals; Lattner & Groff have given talks).

### 9.3 Capabilities and parent-constructs-child

- Miller thesis as in §3.
- The seL4 Reference Manual and Microkit docs.
- Genode Foundations book as in §3.
- The `posix_spawn` rationale documents (POSIX.1-2024) for the
  most accessible worked example of parent-side file-actions
  before child execution.

### 9.4 Polyglot compilation

- Truffle / GraalVM corpus as in §4.
- Lattner & Pienaar, *MLIR: A Compiler Infrastructure for the End
  of Moore's Law* (arXiv '20). Multi-level IR composition — closer
  to Frankenstein's typed-IR-linking model than Truffle.
- The Hermes / Compcert lineage of verified compilers, if the
  Frankenstein endpoint cares about formal correctness of the IR
  composition.

---

## 10. Systems venues to scan

These are the right venues to monitor for new work on this
intersection.

- **SOSP**, **OSDI**, **EuroSys**, **ASPLOS** — systems mainline.
  Every other year for SOSP; every year for the others.
- **PLOS** (Programming Languages and Operating Systems
  workshop, colocated with SOSP) — exactly the language+OS
  intersection. Worth scanning every proceedings end-to-end.
- **OOPSLA**, **PLDI**, **POPL** — language side. Verona, Pony,
  Perceus, Cilk, region work, etc., live here.
- **Onward!** (the speculative-ideas track of OOPSLA) — Truffle,
  region-based things, capability-language work tend to surface
  here first.
- **HotOS** (every other year) — the two-page position-papers
  venue. Often where these ideas first appear before they're
  developed into full papers.
- **USENIX ATC** — applied systems; useful for the engineering
  experience-reports.

---

## Recommended starting subset

If picking three or four entries to read first, in priority order
against the current Telix design docs:

1. **Joe Duffy's Midori blog series**, particularly *Asynchronous
   Everything* and *Objects as Secure Capabilities*. Closest single
   body of work to the Telix+Frankenstein endpoint with substantial
   relevance to both design docs.

2. **Kevin Boos's Theseus thesis** (Rice 2020). The Rust-microkernel
   that's closest in implementation language and architectural
   ambition to where Telix is heading. The intralingual framing is
   a useful counterpoint to Telix's current hardware-isolation
   default.

3. **Verona's OOPSLA '23 *When Concurrency Matters* paper**
   (Cheeseman et al.). Current MSR work directly on the post-Midori
   shape, with regions/behaviours/capabilities that overlap with
   where the activation/Perceus demotion idea wants to go.

4. **Anderson et al. SOSP '91 (scheduler activations)** followed by
   **Rhoden's Akaros thesis (Berkeley 2014)**. The foundational
   activation paper and the most-developed implementation. Read
   together they cover the design space the
   `completion_based_syscalls.md` upcall mechanism is in.

After those, branch into whichever cluster matches what's most
active in your current work:

- For polyglot Frankenstein questions → GraalVM/Truffle, MLton,
  MirageOS.
- For capability discipline → Miller's *Robust Composition*,
  Genode Foundations.
- For distributed strategy → Inferno/Limbo, Barrelfish.
- For async-everything as a complete design → Armstrong's Erlang
  thesis.
