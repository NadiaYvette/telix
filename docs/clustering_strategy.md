# Telix Clustering Strategy: Architecture

**Status: DRAFT.** Architectural framing for Telix's multi-node
operation. Companion to (but distinct from)
`docs/telix_distributed_strategy.md`, which sets milestones. This
document is about *what gets shared between cluster nodes and what
explicitly does not*, the layering of that decision, and how it
maps to existing Telix primitives.

The short version: Telix clusters share *services and data*
(capability remoting, message routing, filesystem layering),
explicitly do NOT share memory or processes, and the architectural
goal is parity with the modern "multi-device IoT" pattern
(HarmonyOS / Fuchsia / Genode-Sculpt) rather than the historical
"single-system-image cluster" pattern (MOSIX / openSSI /
Kerrighed). The two patterns target different problems, and the
former is both more useful for our intended workloads and far less
expensive to implement.

---

## 1. Goals and Non-Goals

### 1.1 Goals

- Establish the **vocabulary and layering** of distributed sharing
  so that design discussions have a shared frame.
- Identify the **subset of those layers Telix targets** for
  cluster operation, and the order in which we'd build them.
- Be explicit about the **anti-goals** — what Telix's clustering
  will not attempt, and why — so the design surface stays bounded.
- Connect the proposed approach to existing Telix primitives
  (`proxy_srv`, `discovery_srv`, `router_srv`, capability IPC, VFS)
  so that "cluster" is mostly a generalisation of what already
  works locally, not a parallel construction.

### 1.2 Non-Goals

- This document does not specify wire protocols. Whether cross-node
  capability invocation uses a custom protocol, 9P, gRPC, or
  something else is a separate decision and deferred.
- This document does not pick a cluster-membership / consensus
  mechanism. Several reasonable options exist (Raft, gossip,
  static config); the architectural framework needs to support
  one without prescribing which.
- This document does not address security model in detail (mutual
  authentication, capability transmission semantics across trust
  boundaries). That belongs in a separate cluster-security doc.
- This document does not duplicate the milestones in
  `docs/telix_distributed_strategy.md`; the two are complementary.

### 1.3 Why this framing now

Telix has discovery_srv, proxy_srv, and router_srv already, plus
a capability-based IPC layer that doesn't materially distinguish
local from remote operations. The completion-based syscall
redesign (`docs/completion_based_syscalls.md`) explicitly routes
remote operations via destination-3 port-message delivery. So
"clustering" for Telix is largely *generalising* what already
works, not building a parallel substrate. The architectural
question is which generalisations to invest in, and which
historically-popular ones to deliberately skip.

---

## 2. The Layering of Shared Resources

Distributed systems have a well-trodden axis of "what gets shared
between nodes," from tightest to loosest:

| Layer | What's shared | Examples |
|---|---|---|
| 1 | **Cache-coherent memory** across hosts | SGI Origin, ScaleMP, hardware NUMA |
| 2 | **Distributed shared memory** (software-coherent pages) | Munin, TreadMarks, Mungi |
| 3 | **Single System Image at OS level** (one PID namespace, one FS tree, one network identity, possibly migratable processes) | MOSIX, openSSI, Kerrighed, openMosix |
| 4 | **Filesystem and services** (files appear at the same path; services invocable across nodes) | NFS, AFS, 9P/Plan 9, CephFS, Mach NetMsgServer, Erlang/OTP, HarmonyOS DSoftBus |
| 5 | **Explicit RPC** (no shared state; messages only) | gRPC, REST microservices, ZeroMQ |

The latency budgets these layers demand are radically different:

- Layer 1 needs **sub-microsecond** access latencies. Custom
  interconnect, custom silicon, or NUMA within a single rack.
- Layer 2 needs **sub-millisecond** access latencies with
  page-granularity coherence traffic. RDMA / InfiniBand makes this
  borderline feasible; commodity Ethernet does not.
- Layers 3-5 work at **message latencies** (tens of microseconds
  to tens of milliseconds), which any modern network supports.

The empirical industry observation, repeated across the cluster
operating-systems research line from the 1980s through the early
2000s, is that *layer ≥3 gets you the same results as layer 1-2
with much less hardware sensitivity and much simpler fault
behaviour*. Almost every cluster product that shipped commercially
and survived a decade is at layer 4 or higher. The systems built
at layers 1-2 either failed to ship, failed to maintain, or
migrated upward over time.

Telix sits structurally at layer 4 today: capability IPC,
proxy_srv-mediated message forwarding, discovery_srv for service
naming, VFS for hierarchical file access. The architectural
proposal in this document is that **Telix's cluster operation
stays at layer 4 and grows incrementally within it**, rather than
descending toward layers 1-2 or migrating up to layer 5 (which
would mean discarding the local capability machinery that already
works).

---

## 3. Why Hardware-Level Sharing Loses

The case against layers 1 and 2 is decisive enough to dispose of
quickly. Both rest on the same set of failures.

### 3.1 The economics of network latency

A local memory access on current hardware is ~100 ns. A page
fault on a local NVMe is ~10 μs. A page fault on a remote node
over 100 Gbit Ethernet is ~50 μs at best. A page fault on a
remote node over a "good" software DSM stack is ~200 μs and up.

For random-access workloads, that's a 1000-2000× slowdown vs
local memory. The DSM literature spent a decade trying to hide
this with prefetching, release consistency, and migration
heuristics. The results were always: "it works fine when the
workload happens to have spatial locality, and falls off a cliff
otherwise." Real workloads don't have spatial locality
predictably; the DSM tax is unavoidable in the general case.

### 3.2 The consistency model is intractable

Sequential consistency across nodes means every write goes to
every replica before any subsequent read returns. That's a
synchronous-RPC-per-store. Performance is unusable.

Release consistency (acquire-fence, release-fence semantics)
allows much better throughput but requires the programmer to think
about distribution explicitly — at which point the SSI promise
("just run unmodified multithreaded code on a cluster") is
broken. The programming model is essentially "treat this like a
multithreaded program with explicit acquire/release," which is
what you'd be writing anyway if you'd used message passing.

### 3.3 Fault domains

When a DSM node dies, what happens to its share of the address
space? Two choices:

- **Drop the pages it owned.** Any process anywhere that touches
  those pages SEGV's. Application-visible failure.
- **Reconstruct from replicas / re-fetch from disk.** Now you need
  a consensus protocol underneath the DSM to decide which replica
  is canonical, which means you've added layer-4 machinery
  underneath your layer-1 facade.

Layer-3 (process migration) has the equivalent problem: when a
node dies mid-migration, the migrating process's state has to be
reconstructed from somewhere, and the obvious places are either
the source node (which may also be down) or a replicated journal
(which is layer-4 again).

### 3.4 Application porting

The transparent-SSI promise was: take existing pthreads code,
run it on a cluster, get more performance. The reality was: the
locking patterns in existing code (futex contention, mutex
hot-spots, cache-line ping-pong) don't tolerate distribution.
Almost every workload that anybody ported to SSI was rewritten to
respect locality anyway — at which point the SSI substrate had
saved no engineering effort.

### 3.5 What Telix gives up by skipping layers 1-2

In practical terms: **almost nothing for the workloads Telix
targets**. The use cases that benefit most from layer 1-2
(in-memory analytics on cluster-sized datasets, HPC numerical
simulations) are not where Telix is heading. The use cases
Telix does target — multi-device IoT, distributed services,
language-runtime experimentation — all work at layer 4.

---

## 4. SSI Specifically: The Milojičić Lineage and Its Disposition

The Single System Image research line — most associated with
Dejan Milojičić, but also Andrew Tanenbaum (Amoeba), John
Ousterhout (Sprite), Andrzej Goscinski (RHODOS) — is
intellectually important and worth knowing about even though
Telix won't implement it.

### 4.1 What SSI promised

- One process namespace across nodes; `ps` from any node lists
  every process in the cluster.
- One filesystem tree, identical paths everywhere.
- Process migration: live, transparent, with all file
  descriptors / signals / capabilities preserved.
- Network identity: the cluster has one IP/hostname for
  outside-world purposes; internal balancing is automatic.
- Distributed scheduling: a process spawned on any node may be
  placed on any node, with load-balancing.

### 4.2 What actually shipped

- **Amoeba** (Tanenbaum et al., VU Amsterdam, late 80s—90s).
  Achieved most of SSI's goals as a research system. Did not
  reach commercial relevance. Lessons: the file system worked
  well; process migration worked but rarely earned its keep.
- **Sprite** (Ousterhout, Berkeley, late 80s). Demonstrated
  process migration for idle-CPU harvesting; users would migrate
  their long-running jobs to coworkers' idle workstations. Worked
  but the use case evaporated when workstations got fast enough
  to do their own work overnight.
- **MOSIX / openMosix / Kerrighed / openSSI** (1980s—2010s).
  Long-running Linux-based SSI projects. All eventually slowed
  to a crawl or stopped. The user community migrated to
  containers + orchestration (Kubernetes/Mesos), which are
  layer-4 systems with a partial layer-3 facade for orchestration
  convenience.

### 4.3 Milojičić's own 2000 retrospective

The Milojičić et al. paper *Process Migration* (ACM Computing
Surveys 32(3), 2000) is the canonical literature survey. It
honestly catalogues:

- The systems that tried (V, Sprite, Locus, Amoeba, Mach, OSF/1
  AD, ...).
- The kinds of state migration handled (open files, network
  connections, IPC channels, virtual memory, signals).
- The cost / benefit analysis, which by 2000 was already pointing
  toward "the benefit is application-specific and the cost is
  near-universal."

The conclusion is essentially: process migration is achievable
but rarely worth it; the use cases that motivated it (idle-CPU
harvesting, load balancing) were better solved by other means
(virtual machines, containerisation, application-level
scheduling).

### 4.4 What survived from SSI

The patterns that survived as discrete features rather than full
SSI substrates:

- **Distributed filesystems** (layer 4). NFS, AFS, 9P, Lustre,
  Ceph. Files at common paths across nodes, but processes are
  local. This works and is widely deployed.
- **Distributed naming** (DNS, ZooKeeper, etcd, Consul). One
  globally-meaningful name space for services and data items.
- **Distributed scheduling** (Mesos, Kubernetes, YARN). One
  cluster-wide view of compute resources; the scheduler places
  workloads. Workloads themselves stay local once placed.
- **Live VM migration** (VMware vMotion, KVM live migration).
  The narrow case that did work — migrating a virtual machine
  is feasible because the boundaries are clean (one address
  space, one kernel, no shared host state) and the use case
  (datacentre rebalancing) is concrete.

Telix takes the survivors. Phase 2 below is distributed
filesystem; phase 4 is distributed naming + data; live VM
migration is irrelevant since Telix doesn't run as a hypervisor.

### 4.5 Citing SSI in Telix's architectural record

The right move is *acknowledge and dispose*: cite Milojičić as
the canonical source for the SSI design space, note the four
failure modes (§3 of this document), and explicitly choose the
layer-4 path. Pretending SSI doesn't exist would look uninformed;
addressing it directly demonstrates the design has considered the
option space.

---

## 5. What Modern Industrial Clusters Deliver

The interesting cluster-OS work in the 2020s is not coming from
the SSI lineage. It's coming from the **multi-device IoT**
direction: Huawei's HarmonyOS, Google's Fuchsia, Apple's
Continuity, and the open-source Genode-with-Sculpt experiment.

### 5.1 HarmonyOS as the most-developed example

HarmonyOS's "super-device" concept stitches multiple physical
devices (phone, tablet, TV, car, watch, smart speaker) into a
single user-perceptible experience. The architecture pieces:

- **DSoftBus** — discovery + transport + authentication. Devices
  on the same LAN/Bluetooth find each other and establish
  encrypted channels. The substrate beneath everything else.
- **Distributed Data Management (DDM)** — replicated KV/relational
  data with selectable consistency models (strong, eventual,
  last-writer-wins). Application data, not OS data.
- **Distributed File Management** — files accessible across
  devices by path, with offline-edit and sync semantics.
- **Distributed Task Scheduling** — a task declares its
  requirements (display, microphone, location, compute capacity)
  and the system picks which device(s) host it.
- **Cross-device migration ("seamless flow")** — a running app
  state can transfer to another device mid-session. Implemented
  by snapshot-and-ship of a *declared serialisable state*, not
  full process state.
- **Cross-device IO** — a phone uses the TV's camera, a watch
  uses the phone's microphone, etc. Capabilities exposed across
  devices.

The unifying conceptual move: **the unit of distribution is the
service or atomic ability, not the process or the memory page**.
HarmonyOS doesn't migrate Linux processes across phones. It
migrates declared *service interfaces* with explicit
serialisation contracts and well-defined input/output schemas.

### 5.2 Fuchsia, Genode, Cangjie

- **Fuchsia** (Google). Component framework over Zircon's
  capability-based IPC. Structurally similar to what Telix
  could be. Less ambitious public cross-device story than
  HarmonyOS, though much of that may be unreleased internal
  work. Worth tracking.
- **Genode / Sculpt OS** (Genode Labs). The closest open-source
  analogue: capability-based microkernel with component
  composition, a desktop face (Sculpt), and beginning cross-device
  work. Genode Foundations book documents the design.
- **Cangjie** (Huawei, 2024). Language-level support for
  HarmonyOS clustering: `@Component`, cross-device async/await,
  distributed event subscriptions, atomic-service annotations.
  Showing that the language and the cluster substrate co-design.

The pattern across these: capability-based remoting + service
discovery + a declared serialisation contract for state =
multi-device continuity. None of them try DSM or full process
migration.

### 5.3 What this means for Telix

The Telix architectural pieces map cleanly:

- `proxy_srv` ≈ DSoftBus's transport layer
- `discovery_srv` ≈ DSoftBus's discovery + naming
- Capability IPC ≈ Fuchsia/Zircon channels, HarmonyOS atomic
  services
- VFS ≈ HarmonyOS Distributed File Management's substrate

Achieving parity with HarmonyOS-class clustering is therefore a
matter of generalising these existing pieces to handle cross-node
operation, plus adding two new things (a distributed-data layer
and an explicit service-migration protocol). Most of the way
there already.

---

## 6. Telix's Existing Foundation

The pieces in the tree today that the cluster strategy builds on:

### 6.1 Capability IPC (`kernel/src/ipc/`)

- `port.rs` — ports as endpoints; messages routed by port id.
- `call_reply.rs` — reply caps with generation counters, the
  unforgeable response mechanism.
- `art.rs` — adaptive radix tree for port lookup.
- `message.rs` — the `Message` struct with 4 data words +
  control fields.

For cluster operation, the existing primitives generalise: a
port id is opaque to userspace, so making it route remotely
through proxy_srv is a forwarding-side change, not a
userspace-side one.

### 6.2 Service routing (`userlib/bin/`)

- `discovery_srv` — service naming; today local, would extend to
  global discovery via gossip or static config.
- `proxy_srv` — message forwarder; today between local processes,
  would extend to cross-node forwarding.
- `router_srv` — packet routing; useful for the underlying network
  transport.
- `namesrv` — name → port resolution; the substrate that
  discovery_srv builds on.

### 6.3 Filesystem layering (`kernel/src/io/`, `userlib/bin/*_srv.rs`)

- VFS with multiple backends (ext_srv, fat_srv, initramfs_srv,
  XFS, NTFS planned).
- Mount points let different parts of the tree have different
  backends.
- A "remote mount" type that forwards file operations to a remote
  node's filesystem servers is a backend-plugin-shaped extension.

### 6.4 Completion-based syscall ABI (planned, see
`docs/completion_based_syscalls.md`)

Particularly destination-3 (port message delivery) which is
*already* the layer at which local and remote completion delivery
look identical to the caller. The redesign there is the natural
substrate for layer-4 cluster operation.

---

## 7. The Four-Phase Progression

Given the architectural framing above, the realistic phased path
for Telix's cluster operation.

### 7.1 Phase 1 — Capability remoting solidified

**What:** proxy_srv treats "port lives on node N" as a first-class
case rather than a special path. discovery_srv maintains a global
service registry across nodes (eventually consistent fine; vector
clocks for ordering). Capability transmission (the equivalent of
SCM_RIGHTS for ports) works for cross-node grants.

**Concretely:**
- Port id encoding gains a node-prefix bit pattern (top bits =
  origin node, low bits = local port).
- Cross-node send routes via proxy_srv → network transport → 
  remote proxy_srv → local port queue.
- Reply caps work across nodes (the reply cap encodes which node
  to route back to; generation counter on the original node still
  enforces correctness).
- Operations that succeed locally (call, message delivery)
  succeed across nodes too, with extra latency.

**Why this first:** every other cluster feature depends on having
cross-node capability invocation working reliably. Also the
smallest delta — most of the machinery exists.

**Existing precedent in code:** proxy_srv already has the
forwarding pattern; today it routes between local processes.
Generalising the destination is the principal work.

### 7.2 Phase 2 — Filesystem layering across nodes

**What:** VFS gains a "remote mount" type. Operations on paths
under that mount route to a remote node's filesystem service. A
file opened across the mount returns a handle that subsequent
reads/writes route to the remote backend.

**Concretely:**
- New backend: `remote_fs_srv` (or a backend variant of
  existing servers).
- Wire protocol: most likely 9P (well-understood,
  multi-implementation, Plan 9 lineage; protocols.md captures
  this), unless we have a compelling reason to invent.
- Mount points configured statically at first; later via
  discovery_srv.

**Why this phase:** the second-most-impactful cluster feature
after capability remoting. Lets a process on node A read a
configuration file that lives on node B without anyone writing
distribution-specific code. This is what NFS gave Unix and is
hard to overstate as an enabler.

**Existing precedent:** VFS already supports multiple backends;
the backend interface is the right hook point.

### 7.3 Phase 3 — Service migration / continuity

**What:** A service can declare its serialisable state and the
runtime can pause/snapshot/migrate/resume across nodes. The
HarmonyOS "atomic service" model.

**Concretely:**
- Service implementation declares: "my state is { ... }"
  (typed, serialisable, with size bounds).
- Cluster registry can pick which node hosts a service at
  any time; migration is a service-API operation.
- For migration: source node snapshots state → transport →
  destination node deserialises → resumes serving on new port,
  old port becomes a redirector for a grace window.
- Capabilities held against the migrating service need to be
  re-bindable (the cluster registry indirection makes this
  work — caps reference a service identity, not a port directly).

**Why this phase:** this is the layer where Telix achieves
multi-device-IoT parity with HarmonyOS. The user can start an
operation on one node and continue it on another, transparently
to the application.

**Open design questions for Phase 3** — see §9.

### 7.4 Phase 4 — Distributed data with explicit consistency

**What:** A KV / relational layer accessible across nodes with
selectable consistency models. Like HarmonyOS DDM, or Akka
Distributed Data, or Riak/Cassandra at smaller scale.

**Concretely:**
- A new service (`ddata_srv` or similar) on each node.
- Operations: get, put, delete, range scan, atomic compare-and-set.
- Consistency models: strong (via Raft consensus over a
  replication group), eventual (gossip-based), last-writer-wins
  (timestamp-ordered).
- Built on top of phase-1 capability remoting and phase-2
  filesystem layering for persistence.

**Why this phase:** application-level data sharing without
requiring applications to implement their own replication. Not
strictly necessary for cluster operation but a strong enabler
for higher-level multi-device features.

**Why this phase last:** distributed data with strong consistency
implies a consensus mechanism, which is a serious engineering
commitment. Earlier phases work without it.

---

## 8. Anti-Goals

What Telix's clustering explicitly will not attempt, with
justification for each.

### 8.1 No distributed shared memory (DSM)

Per §3, DSM's economic and consistency arguments don't survive
contact with modern networks. Telix programs that need
cluster-wide data use phase-4 distributed data with explicit
consistency, not implicit memory sharing.

If a future use case really does need DSM (HPC-style large
in-memory analytics is the only plausible one), the right answer
is RDMA-based explicit data shipping with the locality made
visible to the programmer (PGAS languages — UPC, Chapel — model
this), not transparent OS-level paging.

### 8.2 No full process migration

A full Linux process has a vast amount of state: open file
descriptors, signal masks, futex-blocked threads, mapped
libraries, JIT'd code, kernel-side scheduling state, network
connection state, capability slots with generation counters.
Migrating it transparently is a research-grade engineering
problem that almost never pays its keep.

Telix does phase-3 service migration instead: the unit of
migration is a *declared service interface with explicit
serialisable state*, not a process. The service interface
discipline does the heavy lifting; the runtime ships the
declared state, not the implicit state of an OS process.

### 8.3 No strong consistency by default

Most cluster operations are fine with eventual consistency or
even no consistency guarantee at all. Forcing every operation
to participate in a consensus protocol makes the common case
pay for what only the rare case needs.

The few places that need strong consistency (cluster
membership, schema changes for distributed data, security
policy) opt into it explicitly via a Raft-backed consensus
service. Everything else is eventually consistent or
explicitly partitioned.

### 8.4 No transparent failover by default

When a node dies, in-flight operations against its services
should *fail visibly* by default — the caller sees
`ECONNRESET` or its equivalent. Applications that want
transparent failover (e.g., a stateless web service) opt in
via the cluster registry's "retry on another instance"
semantics.

The reason: silent failover makes consistency bugs invisible.
Visible failure surfaces them.

### 8.5 No cross-architecture migration in the same node

A cluster spans architectures (some nodes x86_64, some aarch64,
some riscv64). Services declared with explicit serialisable
state work fine across architectures (the state is wire-format,
not in-memory format). But a *single* service does not migrate
across architectures unless the service implementation provides
multi-arch binaries.

This is a smaller restriction than it sounds — the
cluster-registry chooses among service instances; one of them
just has to be the right architecture for the migration target.

---

## 9. Open Design Questions

These are decisions worth flagging now so the implementation work
addresses them deliberately.

### 9.1 Cluster identity and membership

How do nodes know about each other? Several reasonable options:

- **Static config.** Each node's config file lists peers.
  Simplest, no consensus needed for membership. Doesn't handle
  dynamic clusters.
- **Gossip discovery.** Nodes advertise via multicast; new nodes
  discover existing ones. Doesn't need a central authority. Used
  by Cassandra, Consul, Serf.
- **Anchor + join token.** A new node presents a token issued
  by a trusted node to be admitted. Used by Kubernetes, SmartOS.
  Trust-anchored; small consensus group decides admission.
- **Hybrid.** Static for initial bootstrap, gossip for steady
  state.

Most likely answer: start with static config, add gossip later.

### 9.2 Authentication and capability transmission

When node A sends a capability to node B, what guarantees does
B have about A's authority? Several options:

- **Shared secret per cluster.** All nodes trust each other; one
  compromised node compromises all.
- **Per-node certificate hierarchy** with a cluster CA. Standard
  PKI. Per-capability authentication piggybacks on the channel.
- **Object capability semantics across nodes** — capabilities are
  unforgeable wire tokens; possessing one is authority. Requires
  the wire format to be unforgeable (HMAC or signature) and
  expiry-bound.

The third is most in keeping with Telix's existing capability
model, but it's the most invasive to implement. Probably layered.

### 9.3 Failure semantics for in-flight operations

When a remote node disappears mid-operation, what does the caller
see? Options:

- **Operation returns an error** (`ECONNRESET`-equivalent). Caller
  decides what to do.
- **Operation hangs forever** until reconnect or explicit cancel.
- **Operation auto-retries on another instance** if one exists.

Default should be the first; the third is opt-in via cluster
registry indirection.

### 9.4 The proxy_srv overhead amplification problem

Every cross-node operation today routes via proxy_srv on the
sender side, then proxy_srv on the receiver side. That's two
extra IPC hops. For low-throughput control traffic this is fine;
for high-throughput data flows it's a problem.

Possible mitigations:

- **Kernel-side fast path** for cross-node routing once the
  destination is known. The kernel reads the port-id-encoding,
  routes directly to network transport, skipping userspace.
- **Per-flow caching** in proxy_srv: once a remote endpoint is
  established, subsequent messages take a shorter path.
- **Bypass for bulk data**: large messages use a separate transport
  (RDMA, virtio_net with offload) while metadata flows via
  proxy_srv.

Deferred until phase 1 is solid and the bottleneck is measured.

### 9.5 Naming hierarchy: flat or hierarchical?

discovery_srv today exposes names as flat strings ("linux", "uds",
"vfs"). For multi-node operation, names need disambiguation.
Options:

- **Hierarchical namespace** ("/cluster/node-A/svc/linux"). DNS-like.
- **Flat with explicit node tag** ("linux@node-A").
- **Globally-unique, location-hidden** ("linux-xyz123"); the
  registry resolves to a location at lookup time.

The third option matches HarmonyOS's "any-instance" semantic best
and is probably right; the registry can prefer local instances on
lookup, with explicit options for "I want this specific instance."

---

## 10. Conclusion

Telix's clustering strategy is to **stay at layer 4 of the
shared-resource hierarchy** — capability remoting, filesystem
layering, service migration, distributed data — and to
deliberately skip the historically-prominent layers 1-3 (DSM,
SSI, full process migration). The pragmatic case for this is
overwhelming: the latency economics, the consistency-model
intractability, and the failure-mode complexity of layers 1-3
have been documented for thirty years, with substantial
empirical evidence that the survivors come from layer 4.

The achievable parity target is the modern multi-device-IoT
pattern (HarmonyOS / Fuchsia / Genode-Sculpt): service-level
distribution with explicit serialisation contracts, declared
state migration, distributed data with selectable consistency.
This pattern matches what Telix's existing primitives (`proxy_srv`,
`discovery_srv`, capability IPC, VFS) were already designed to
support — clustering is largely a generalisation of local
operation, not a parallel construction.

The four-phase progression (§7) is realistic, each phase building
on the previous, with each individual phase scoped to be
implementable without prerequisites beyond what's already in the
tree plus the immediately-prior phase. The conclusion of phase 1
gets Telix to "remote capability invocation works"; the
conclusion of phase 4 gets Telix to HarmonyOS-class multi-device
operation.

The anti-goals (§8) are explicit so the design surface stays
bounded. Telix will refuse to chase DSM, full process migration,
strong-consistency-by-default, or transparent failover, on the
grounds that each of these has been tried, has well-documented
failure modes, and is not justified by the workloads Telix
actually targets.

---

## Appendix A: Connections to Other Telix Documents

This document is one of several in the cluster / distributed
strategy stack. The cross-references:

- **`docs/telix_distributed_strategy.md`** sets *milestones*
  (what visible deliverables, in what order, with what dependencies).
  This document sets *architecture* (what is and isn't shared
  between nodes, why). They're complementary; the milestones doc
  schedules pieces this doc shapes.
- **`docs/completion_based_syscalls.md`** §2.5.3 (the actor /
  message-passing runtime pattern using destination-3
  port-message delivery) is the local-side primitive on which
  layer-4 cluster operation rests. Cluster operations are
  remote-routed instances of the same primitive; the local
  caller doesn't know or care.
- **`docs/activation_perceus_demotion.md`** §A.6 raises the
  question of how scheduler activations interact with remote
  operations. The activation-locality assumption (one
  activation, one node) is preserved by this doc — there is no
  cross-node activation migration.
- **`docs/related_work_reading_list.md`** §§5, 7 — Akaros,
  Barrelfish, K42 for the kernel-runtime side; Plan 9, Inferno
  for the distributed-namespace side; Erlang/OTP, Akka for the
  actor side. The cluster strategy here draws on all three.

## Appendix B: A Note on the Milojičić Citation

Dejan Milojičić et al., *Process Migration*, ACM Computing
Surveys 32(3), September 2000. The canonical literature survey
of the process-migration / SSI / cluster-OS line through ~2000.
Worth reading even though Telix doesn't follow the path, because
the failure analysis is one of the more honest in systems
literature. See `docs/related_work_reading_list.md` §6 for
adjacent reading.

A specific Milojičić observation that's stayed true: process
migration's benefit was always workload-dependent, and the
workloads that benefited most (long-running idle-tolerant
compute jobs) were better served by virtualisation +
orchestration than by OS-level migration. Telix's phase-3
"service migration" is structurally similar to what the SSI
community wanted but with the explicit-state declaration
discipline that the SSI line lacked. The discipline is what
makes it tractable.
