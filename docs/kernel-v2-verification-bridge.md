# kernel-v2 ↔ Iris ↔ hardware-model bridge (capability transport)

Status: **scaffolding (2026-08-25)**.  Companion to
`docs/kernel-v2-build-plan.md` (layout/build) and Tessera's
`doc/stage3-kernel-strategy.md` (pipeline).  This document itemises the
manual correspondence between the kernel-v2 Rust code, the planned Iris
heap_lang spec, and the Tessera hardware-model theorems each piece
consumes.  It is the audit trail for the seL4-style "read the Iris
program, compare it to the Rust" step — the semantic gap must be
bounded and auditable, not a compiler pipeline.

## The pipeline

```
Telix kernel-v2/src/caps/*.rs          (Rust, spec-first, no unsafe)
        │  ① manual correspondence — this document
        ▼
tessera/hardware/rocq/kernel_specs/
  cap_transport_iris.v                 (Iris heap_lang spec)
        │  ② Iris separation logic
        ▼
K1 machine-interface resources         (Rocq, not yet written)
        │  ③ composition
        ▼
Tessera machine model                  (machine.sail → machine.v, axiom-free)
```

Layer ① is a *documented human audit* (the same decision seL4 made:
manual Isabelle spec, not an automatic translator).  Layers ② and ③ are
machine-checked in Rocq.

---

## Component map

### `caps::cap` — the capability model

| Rust item | Iris spec form | Hardware model link |
|-----------|----------------|---------------------|
| `Rights` (bit flags: read, write, grant, send, recv) | an Iris ghost/abstract type with the same lattice | — (pure) |
| `CapType::{Port, Memory{..}, ..}` | disjoint sum in the spec | `Memory` caps eventually refer to machine memory, governed by K1's memory resources |
| `CapSlot { ty, rights }` (validity = presence in the table's `Option`) | record in the spec; slot validity is the `Option` | — |

**Unforgeability argument**: a capability handle is a `(task_id, slot)`
pair into a table that only the kernel mutates.  In Iris terms, the
kernel holds the *exclusive* ownership of every task's capability table
(K1 resource); a task can only exercise the capabilities the kernel
granted it.  This is the seL4 model and needs no cryptography.

### `caps::table` — the capability table

| Rust item | Iris spec form | Hardware model link |
|-----------|----------------|---------------------|
| `CapTable::alloc_slot(&mut self, ty, rights) -> Option<Slot>` | `wp` triple: `{ table_own γ } alloc_slot … { table_own γ ∗ slot_frag γ s ty rights }` | table memory under K1 `mem`/alloc resources |
| `CapTable::free_slot(&mut self, s)` | inverse: returns the fragment | — |
| `CapTable::grant(&mut self, from, to, s, rights) -> Result<(), GrantError>` | **no rights amplification**: `rights ⊆ from.rights` is a precondition; spec returns `Err` if violated and leaves the table unchanged | — |

**Invariants the host tests encode (and the Iris spec proves):**
unique valid slot per allocation; `free` invalidates and releases the
fragment; `grant` copies with `rights ⊆ source rights` and never
mutates the table on error.

### `caps::port` — bounded message queues

| Rust item | Iris spec form | Hardware model link |
|-----------|----------------|---------------------|
| `Port::send(&mut self, msg: Message) -> Result<(), SendError>` | `{ port_own γ (q, n) } send m { port_own γ (q ++ [m], n) }` for `n < bound`; `{ port_own γ (q, bound) } send m { Err }` — **no partial mutation** | the queue is the abstract representation of the lock-free ring; gpfsl (iRC11) governs the ring's weak-memory behaviour once refined |
| `Port::recv(&mut self) -> Result<Message, RecvError>` | FIFO: takes the head; `Err` on empty, state unchanged | — |
| `Port::bound` | part of the port's ghost state; the Iris proof keeps `length q ≤ bound` as an invariant | boundedness is what the ring refinement must preserve (Tessera's tiling-refinement pattern) |

**Ownership story**: `send` takes `Message` by value — ownership of the
payload moves sender → queue; `recv` returns it — queue → receiver.
The Iris spec states exactly this transfer of ownership via the
`port_own` resource.

### `caps::transport` — the message-passing layer

| Rust item | Iris spec form | Hardware model link |
|-----------|----------------|---------------------|
| `Transport::create_port(&mut self, task, bound) -> PortId` | allocates a fresh port + its `port_own` resource | port table memory under K1 resources |
| `Transport::send(task, port, msg)` | pre: task holds a `Port(port)` cap with `send` right; post: `port_own` extended | — |
| `Transport::recv(task, port)` | pre: task holds a `Port(port)` cap with `recv` right; post: `port_own` shortened | — |

**Cross-partition delivery** (scaffolded in `caps::cluster` +
`caps::doorbell`): when sender and receiver are in different
multikernel domains, `recv` blocks and is woken by an IPI.  The
scaffold mirrors the SSG-3 interrupt-controller theorems:

| Rust item | Iris spec form | Hardware model link |
|-----------|----------------|---------------------|
| `IntcDoorbell` (`caps::doorbell`) | `pending` latch + `mask`; `rings() = pending ∧ ¬masked`; `ack()` clears iff it rang | per-theorem mirror of `intc_send_sets_pending`, `intc_ack_unmasked_clears_pending`, `intc_ack_masked_noop`, `intc_unmask_then_ack_delivers` in `tessera/hardware/rocq/intc_proofs.v` |
| `Cluster::deliver_inbound(part, port, msg)` | enqueue (bound enforced) then ring — delivery precedes the ack that completes the receive | the `bc_machine_ipi_step_via_intc` ghost step (`intc_weak_broadcast.v`) |
| `Cluster::send_remote(from_p, t, to_p, port, msg)` | pre: t holds a `RemotePort(to_p, port)` cap with `SEND`; post: `port_own` extended in `to_p` + doorbell rings | remote-cap grant (`grant_port_remote`) is the cluster-level `cap_unforgeable` |
| `Cluster::recv_blocking(part, t, port)` | pre: t holds a local `Port(port)` cap with `RECV`; empty queue ⇒ `Blocked` with the doorbell armed; the next delivery is the wakeup | the armed-doorbell wait is what the IPI wakeup composes with |
| `Cluster::poll(part, t, port)` | non-blocking recv; explicit mailbox read, allowed while masked | — |

Domain scoping uses the SSG-1 topology model; the `PartitionId`
capability qualifier is the multikernel analogue of the topology's
domain identifier.

---

## What the first Rocq deliverable contains (once K1 lands)

`tessera/hardware/rocq/kernel_specs/cap_transport_iris.v` (new file,
wired into that repo's `build.sh` with `axiom_free` on its headline
theorems):

1. The `cap`, `slot`, `port` ghost-state definitions (matching the Rust
   records above).
2. heap_lang programs for `alloc_slot`, `free_slot`, `grant`,
   `create_port`, `send`, `recv`, stated in Iris `wp` triples with
   pre/post conditions over K1 resources.
3. Headline theorems, each checked axiom-free:
   - `send_never_drops` — `send` on a non-full port enqueues; on a full
     port it errors and the queue is unchanged.
   - `recv_fifo` — `recv` returns the head; sequence of sends/recvs
     preserves order.
   - `grant_no_amplification` — granted rights are a subset of source
     rights; invalid grants error and leave the table unchanged.
   - `cap_unforgeable` — a task can only act on capabilities the kernel
     granted it (exclusive table ownership).
4. The K1 **minimal subset** it consumes (per open question 1 of the
   build plan): memory/alloc resources for the tables, gpfsl for the
   ring, the intc wakeup ghost step, and the SSG-1 scoping.

The host unit tests in `kernel-v2` are the *behavioral* mirror of these
theorems: every invariant the Iris spec proves is asserted in a `#[test]`.
When both exist, the audit is: read the Rust function, read the Iris
program, confirm the correspondence via this document.
