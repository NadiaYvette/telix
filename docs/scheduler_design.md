# Scheduler Design

## Overview

The Telix scheduler manages the allocation of CPU time to threads across multiple processors. It must support the microkernel's IPC-intensive workload pattern (where significant work happens in privileged servers, not just in application threads), the M:N threading model with scheduler activations, priority inheritance across IPC boundaries, coscheduling for virtual machine workloads, and heterogeneous hardware topologies (NUMA, SMT, P-core/E-core).

This document describes the initial scheduler design, the full scheduling class hierarchy, the integration of Telix-specific mechanisms (handoff scheduling, coscheduling, turnstiles), and the upgrade path toward advanced features (EEVDF, full tickless operation, full kernel preemption, energy-aware scheduling, and sophisticated load balancing).

## Design Principles

**Scheduling class abstraction from day one.** The scheduler's core operations — enqueue (a thread becomes runnable), dequeue (a thread is picked to run or blocks), and pick_next (choose which thread to run next) — are behind a function pointer interface provided by the scheduling class. This allows the scheduling policy to be replaced (e.g., MLFQ to EEVDF) without changing the mechanism (context switch, timer programming, IPC handoff). Each scheduling class provides its own run queue data structure and dispatch logic.

**Preemption counter from day one.** A per-thread integer that starts at zero, is incremented when entering a non-preemptible section (holding a spinlock, running in an interrupt handler), and decremented when leaving. A thread is preemptible only when the counter is zero. This gives precise control over preemptibility and is the foundation for later full kernel preemption.

**One-shot timers for quantum enforcement.** When a thread is scheduled, a per-CPU one-shot timer is programmed to fire after the thread's quantum expires. When the thread is descheduled (for any reason), the timer is cancelled. This avoids dependence on a periodic tick for quantum enforcement and enables later tickless operation.

**Time accounting at scheduling events.** Per-thread CPU usage is accumulated at context switch time and at explicit scheduling events (preemption, blocking, unblocking), not at periodic tick time. This provides accurate accounting regardless of tick frequency and is required for tickless operation.

**Abstract scheduling parameters.** Thread priority is expressed through a scheduling parameters structure interpreted by the scheduling class, not through direct array indices or hard-coded priority levels. For MLFQ, this contains the priority level; for a future EEVDF implementation, it contains weight and latency hint. IPC priority inheritance operates on the abstract parameters, so it works correctly regardless of which scheduling class is active.

**Topology hierarchy built at boot.** The machine's CPU topology (SMT siblings, shared cache groups, NUMA nodes, core types) is parsed from firmware data (ACPI/devicetree) at boot and stored in a hierarchical structure accessible to the load balancer. The initial load balancer may use only a subset of this information, but the full structure is available for later sophisticated balancing.

## Scheduling Class Hierarchy

The scheduler supports multiple scheduling classes arranged in a strict priority ordering. A thread in a higher-priority class always preempts a thread in a lower-priority class. Within a class, the class-specific policy determines dispatch order.

### Real-Time FIFO / Round-Robin

**Priority:** Highest. Always preempts all lower classes.

**Policy:** Fixed priority, no dynamic adjustment. SCHED_FIFO threads run until they block, yield, or are preempted by a higher-priority real-time thread. SCHED_RR threads round-robin among equal-priority real-time threads with a fixed quantum.

**Use cases:** Interrupt-handling threads in device drivers, hard deadline tasks, safety-critical paths.

**In Telix:** Some privileged server threads may need real-time scheduling — particularly the interrupt-handling threads in the input server, audio driver, and display server, where a missed deadline means dropped input, audio glitches, or missed display frames.

### Deadline / Isochronous

**Priority:** Below real-time FIFO/RR but above all normal classes.

**Policy:** Each deadline task declares a runtime, period, and deadline: "I need R microseconds of CPU time every P microseconds, and each instance must complete within D microseconds of the start of its period." The scheduler uses an algorithm such as Earliest Deadline First (EDF) with a Constant Bandwidth Server (CBS) to guarantee that each task receives its runtime within each period, while preventing any single deadline task from monopolising the CPU (CBS bounds each task's bandwidth to R/P).

**Use cases:** Audio playback and processing (fill a buffer every 5ms), video decode (decode a frame every 16ms for 60fps), VoIP, software-defined radio, any periodic media processing.

**In Telix:** Audio in a microkernel is an IPC chain (application → audio server → audio driver). The deadline guarantee ideally applies to the entire chain, not just one thread. Initially, the audio driver thread runs with a deadline class and priority inheritance ensures the upstream servers are not delayed. A more sophisticated design could propagate the actual deadline through the IPC path — "this message is part of a deadline task with 2ms remaining in its period" — but this is deferred to future work.

**Admission control:** The scheduler must reject deadline task registrations that would overcommit the CPU. If the sum of R/P ratios across all deadline tasks on a CPU exceeds a threshold (typically around 0.95 to leave headroom for non-deadline work), the registration fails. This prevents deadline tasks from starving all other classes.

### Interactive Tiers

**Priority:** Below deadline, above normal batch and idle. Within the tiers, the first tier is highest.

**Policy:** Three tiers of interactive priority, distinguished by latency sensitivity:

**Tier 1 — Display-critical:** The Wayland compositor, Xwayland, and the display server. Frame-level latency sensitivity (must respond within a few milliseconds of vsync or input events). These threads receive a strong latency bias — shorter effective quantum, preferential wakeup placement, and resistance to being migrated away from their current CPU (to preserve cache warmth).

**Tier 2 — User-facing:** The focused application window (Firefox, text editor, file manager). Keystroke and mouse interaction latency matters (response within tens of milliseconds). These threads receive a moderate latency bias.

**Tier 3 — Indirect interactive:** Unfocused application windows, terminal emulators, shells, child processes of interactive applications. The user expects them to make progress but doesn't need frame-level responsiveness.

**Tier assignment:** Tier assignment is driven by hints from the compositor (which knows which window has focus) and from the session manager. The compositor sets its own threads to tier 1; it marks the focused application's threads as tier 2; unfocused applications default to tier 3. When focus changes, the compositor updates the tier assignments.

**Implementation:** The interactive tiers can be implemented within the MLFQ framework as reserved priority bands — tier 1 occupies the top few priority levels of the normal range, tier 2 the next few, tier 3 the rest. Alternatively, they can be a latency hint attached to the scheduling parameters, interpreted by the scheduling class to provide a latency boost proportional to the tier. The latter approach migrates cleanly to EEVDF, where the latency hint translates to a shorter virtual deadline for higher tiers.

### Normal (SCHED_NORMAL)

**Priority:** The default class. Below interactive tiers.

**Policy:** MLFQ with dynamic priority adjustment. Threads that frequently sleep (I/O-bound pattern) drift toward higher dynamic priority; threads that consume their full quantum (CPU-bound) drift toward lower dynamic priority. This is the standard Unix multilevel feedback queue approach, adapted for the microkernel context where "I/O-bound" often means "waiting for IPC completions."

**Use cases:** Most userspace processes, background application threads, non-time-critical server threads.

### Batch (SCHED_BATCH)

**Priority:** Same base priority as normal, but with the interactivity boost disabled. Batch threads never drift upward in dynamic priority for sleeping — they always run at their base priority. This means they never compete with interactive threads for latency-sensitive scheduling slots.

**Use cases:** Long-running computations, batch processing, background compilation, data processing pipelines. Threads that want throughput and don't care about responsiveness.

**Implementation:** Batch is not a separate scheduling class with its own run queue. It is a flag on the thread's scheduling parameters that tells the MLFQ to skip the interactivity heuristic. Batch threads share the normal class's run queues but are penalised in priority relative to threads that exhibit interactive behavior.

### Idle (SCHED_IDLE)

**Priority:** Lowest. Runs only when no thread in any higher class is runnable on this CPU.

**Policy:** Round-robin among idle-class threads. No priority adjustment.

**Use cases:** Background maintenance — filesystem scrubbing, deduplication, speculative prefetching, garbage collection, background indexing. Anything that should make progress eventually but must never interfere with interactive or batch work.

**Implementation:** Idle-class threads are in a separate run queue that is consulted only when all higher-class queues are empty. An idle-class thread cannot starve higher-class threads by definition.

## Coscheduling

Coscheduling is a **cross-class mechanism**, not a scheduling class. A coscheduling group can contain threads in any class. The coscheduling constraint is: when the scheduler is making a free choice (no higher-priority thread demands a CPU), prefer to schedule all members of a coscheduled group simultaneously across their respective CPUs.

### Implementation

Coscheduling is implemented as a periodic check, not a per-dispatch constraint. At load balancing time (every few hundred milliseconds), the coscheduling balancer examines each active coscheduling group and attempts to align group members' scheduling windows. If group member A is running on CPU 0 and group member B is not running (queued on CPU 1), the balancer promotes B's priority within its class to increase the likelihood that B is dispatched soon.

This is deliberately approximate. Strict gang scheduling (all members run or none run) would waste CPU time when one member is blocked. Approximate coscheduling makes simultaneous execution likely without causing idle CPUs to wait for laggards.

### Interaction with Other Mechanisms

**Handoff scheduling:** When a thread in a coscheduled group performs a directed yield (L4-style handoff) to a server, the kernel counts execution on the group's behalf by the server as satisfying the coscheduling constraint for that CPU. The constraint is "don't schedule unrelated work on this CPU while other group members are running," not "every member must execute its own code."

**Priority inheritance:** If a thread in a coscheduled group inherits priority from a high-priority client, the inherited priority applies within the group's scheduling class. The coscheduling mechanism does not override priority inheritance — a group member handling a real-time request runs at real-time priority regardless of what the other group members are doing.

**Class interaction:** A coscheduling group whose members are in different classes (e.g., one member in real-time, others in normal) is handled by the lowest-class members being pulled up by the coscheduling bias, not the highest-class member being pushed down.

## Telix-Specific Scheduling Mechanisms

### Handoff Scheduling (L4-Style Direct Switch)

When a thread sends a synchronous IPC message and the receiving thread is waiting for a message, the kernel performs a direct context switch from sender to receiver, bypassing the run queue entirely. The sender's remaining quantum is donated to the receiver.

The handoff path is separate from the normal scheduling path. It does not consult the run queue, does not call the scheduling class's pick_next function, and does not update load balancing statistics. It is a direct thread-to-thread transfer of execution.

When the handoff recipient finishes its work and replies, the reply can trigger a reverse handoff (direct switch back to the original sender) if the sender is still the most appropriate thread to run. If the donated quantum expires during the handoff recipient's execution, the recipient is preempted normally (the one-shot quantum timer fires), and the scheduler's regular pick_next path runs.

### Priority Inheritance and Donation

When a client sends a request to a server via IPC, the server thread inherits the client's effective priority if it is higher. Priority inheritance is transitive: if server A handles a high-priority request and sends a message to server B, B inherits the propagated priority.

The scheduler implements this by adjusting the recipient's scheduling parameters at message delivery time. If the recipient is currently running, no action is needed (it's already on a CPU). If the recipient is in a run queue, the scheduling class must re-sort or re-prioritise it to reflect the new effective priority. If the recipient is blocked (waiting for a message on its port set), the priority is recorded and applied when the thread becomes runnable.

The scheduling class abstraction must support a "priority changed" callback that efficiently handles re-sorting a thread in its run queue. For MLFQ, this means moving the thread to a different priority queue. For EEVDF, this means updating the thread's weight and potentially its virtual deadline.

### Kernel-Assisted Turnstiles

When a server thread blocks on a turnstile (a kernel-provided lock primitive), the kernel records the lock dependency and adjusts the lock holder's effective priority to reflect the highest priority of any waiter. This extends the priority inheritance chain seamlessly from IPC-based donation through lock-based turnstile inheritance.

The scheduler sees turnstile priority inheritance as identical to IPC priority inheritance — the thread's effective priority changes, and the scheduling class handles the re-sort. The difference is that turnstile inheritance is triggered by a lock operation rather than a message send, but the scheduler's response is the same.

### Scheduler Activations

When a scheduling-relevant event occurs (a kernel thread blocks, a previously blocked kernel thread becomes runnable, a processor is preempted), the kernel delivers a scheduler activation upcall to the affected task's designated handler at a known entry point, passing event information in registers.

The scheduler must recognise activation upcalls as scheduling events: the upcall handler thread must be dispatched promptly (it is implicitly at the highest priority within its task's scheduling context), and the event that triggered the activation must be recorded before the upcall is delivered (so the handler has consistent state to make decisions with).

## Core Data Structures

### Per-CPU Run Queue

Each CPU maintains its own run queue structure. The run queue contains a pointer to each scheduling class's per-CPU state (the MLFQ priority array, the EEVDF tree, the real-time FIFO/RR queues, the deadline task list, the idle queue). Dispatch consults the classes in priority order: real-time first, then deadline, then interactive tiers, then normal/batch, then idle.

### Scheduling Class Interface

Each scheduling class implements:

- **init:** Initialise per-CPU state for this class.
- **enqueue:** A thread has become runnable; add it to this class's run queue.
- **dequeue:** A thread has been selected to run or has blocked; remove it from the run queue.
- **pick_next:** Return the highest-priority thread in this class's run queue, or NULL if empty.
- **priority_changed:** A thread's effective priority has changed (due to IPC inheritance or turnstile inheritance); re-sort it in the run queue if necessary.
- **yield:** The running thread has voluntarily yielded; handle according to class policy (FIFO: move to back of same priority queue; RR: same; normal: reset quantum).
- **tick:** (For tick-based accounting; becomes optional in tickless mode.) Update the running thread's accounting and check for quantum expiry.
- **update_params:** The thread's scheduling parameters have changed (class transition, weight change, latency hint change); update the run queue accordingly.

### Thread Scheduling State

Each thread carries:

- **Scheduling class:** Which class this thread belongs to.
- **Scheduling parameters:** Class-specific parameters (priority level for MLFQ; weight and latency hint for EEVDF; runtime/period/deadline for deadline class).
- **Effective priority:** The thread's current effective priority after inheritance propagation.
- **Base priority:** The thread's uninherited priority (the external nice value / weight).
- **CPU affinity:** Which CPUs this thread is allowed to run on.
- **Last CPU:** The CPU this thread last ran on (for migration cost heuristics).
- **CPU usage accounting:** Time consumed in the current scheduling window.
- **Coscheduling group:** Pointer to the coscheduling group, if any.
- **Preemption counter:** The non-preemptible nesting depth.

## Time Management

### Quantum Enforcement

When a thread is dispatched, the scheduler programs a per-CPU one-shot timer to fire after the thread's quantum. If the thread is descheduled before the timer fires (blocking, preemption by a higher-priority thread, IPC handoff), the timer is cancelled. If the timer fires, the tick handler marks the thread as needing rescheduling, and the scheduler's pick_next runs at the next preemption point.

Quantum length is class-dependent: real-time RR threads have a fixed short quantum; interactive tier 1 threads have a short quantum for responsiveness; normal threads have a moderate quantum (default ~4ms, tunable); batch threads have a longer quantum for throughput.

### Timekeeping

Wall-clock and monotonic time are maintained by reading the hardware clock (architectural timer on ARM64, TSC on x86-64) on demand, not by accumulating tick counts. This is both more accurate and required for tickless operation.

### Periodic Housekeeping

Some scheduler operations are naturally periodic: load balancing, coscheduling checks, scheduler statistics updates. These are driven by a housekeeping timer that fires at a low frequency (e.g., every 100–250ms) and is independent of the quantum timer. On an idle CPU, the housekeeping timer can be suppressed (tickless idle). On a busy CPU running a single thread with no need for load balancing, the housekeeping timer can also be suppressed (tickless full).

## Load Balancing

### Initial Design

The initial load balancer runs periodically (every few hundred milliseconds) and performs a simple imbalance check: compare the load (weighted run queue length) across all CPUs; if the imbalance exceeds a threshold, migrate one thread from the busiest CPU to the idlest.

Migration respects NUMA boundaries: prefer to balance within a NUMA node before balancing across nodes. When choosing which thread to migrate, prefer threads that have been sleeping (cache is already cold) over threads that are actively running.

The load balancer also handles work stealing: when a CPU goes idle, before entering the idle state, it checks other CPUs for stealable threads. Steal from the busiest CPU within the local NUMA node first; escalate to remote NUMA nodes only if no local work is available.

### Topology Hierarchy

The topology hierarchy is built at boot from ACPI SRAT/SLIT (x86-64) or devicetree (ARM64). It describes:

- **Level 0 (SMT):** Siblings sharing the same physical core. Migrating between SMT siblings is nearly free (shared L1/L2 cache).
- **Level 1 (LLC):** Cores sharing an L3 cache. Migration within this level incurs L1/L2 cache cold start but L3 is still warm.
- **Level 2 (NUMA node):** Cores sharing a memory controller. Migration across this level incurs full cache cold start plus potential NUMA memory penalty.
- **Level 3 (Cross-NUMA):** Separate NUMA nodes. Migration is most expensive.

The initial load balancer uses only the NUMA node level for its boundary check. Later balancers use all levels with level-specific thresholds and frequencies.

### Per-CPU Cost Function

The load balancer accepts a per-CPU cost function that defaults to "all CPUs are equal." This function returns the estimated cost of running a given thread on a given CPU. The initial implementation returns a constant. Later energy-aware scheduling replaces this with actual energy cost data (performance per watt varies by core type and frequency), and the load balancer's decisions automatically incorporate energy cost.

## Idle Management

### Idle Loop

When a CPU has no runnable threads, the idle loop executes:

1. **Work stealing:** Attempt to steal a thread from another CPU (busiest CPU, local NUMA node first).
2. **Idle governor:** Call the idle governor function, which returns a recommended hardware idle state.
3. **Enter idle state:** Enter the recommended state (WFI on ARM64, MWAIT/HLT on x86-64).
4. **Wake:** On interrupt (IPI from another CPU, timer, device interrupt), return to the scheduler.

### Idle Governor

The initial idle governor always returns the shallowest idle state (WFI / HLT). This is correct and power-reasonable.

A later energy-aware idle governor needs:

- **Idle state table:** Available hardware idle states with their power consumption and exit latency (from ACPI C-state tables on x86, from devicetree/PSCI on ARM64).
- **Idle duration prediction:** Estimated time until the next wakeup event, based on the next programmed timer and recent idle history.
- **State selection:** Pick the deepest idle state whose exit latency is acceptable given the predicted idle duration.

The governor function signature accepts the predicted idle duration and returns an idle state index. This signature is stable across the initial and energy-aware implementations.

## Upgrade Path

### Phase 1 (Initial): MLFQ + Basic Load Balancing

**Scheduling classes:** Real-time (FIFO/RR), normal (MLFQ with dynamic priority), idle.

**Load balancing:** Simple periodic imbalance check with NUMA boundary awareness. Work stealing on idle.

**Preemption:** At IPC return and interrupt return. Preemption counter enforced.

**Timers:** One-shot quantum timer. Periodic housekeeping timer. Tickless idle (suppress housekeeping timer when CPU is idle).

**Idle:** Shallowest idle state always.

**Telix-specific:** Handoff scheduling, priority inheritance, scheduler activations.

### Phase 2: Scheduling Classes

**Add deadline class:** EDF/CBS implementation. Admission control. Initially per-thread deadlines; chain-aware deadline propagation through IPC is future work.

**Add batch class:** Flag on MLFQ that disables interactivity boost.

**Add interactive tiers:** Either reserved priority bands in MLFQ or latency hint in scheduling parameters. Compositor-driven tier assignment protocol with the input server and display server.

### Phase 3: EEVDF

**Replace MLFQ with EEVDF** for the normal and interactive classes. The scheduling class abstraction means this is a swap of the enqueue/dequeue/pick_next implementation behind the same interface. Priority inheritance and turnstile inheritance operate on EEVDF's weight/latency parameters through the abstract scheduling parameters structure.

Real-time and deadline classes are unaffected (they have their own dispatch logic). Batch becomes a weight setting in EEVDF (lower weight = less CPU share). Interactive tiers become latency hints that shorten the virtual deadline.

### Phase 4: Full Tickless

**Suppress the periodic housekeeping timer** on CPUs running a single thread that doesn't need load balancing (NO_HZ_FULL). This requires auditing all housekeeping-timer-driven operations and either making them event-driven or deferring them to the next scheduling event.

**Prerequisites:** Time accounting already at scheduling events (done in Phase 1). Quantum enforcement already via one-shot timer (done in Phase 1). Load balancing already on its own timer (done in Phase 1). The main work is ensuring no code path depends on the housekeeping timer firing regularly.

### Phase 5: Full Kernel Preemption

**Audit kernel spinlocks.** Identify which spinlocks protect long critical sections and can be converted to sleeping locks (mutexes). Convert them. The remaining spinlocks (protecting very short critical sections, used in interrupt context) retain preemption disabling.

**Enable preemption checks** at additional kernel points: after any lock release where the preemption counter reaches zero, check if a higher-priority thread is runnable and reschedule if so.

**Prerequisites:** Preemption counter already in place (done in Phase 1). Per-CPU data access already guarded by preemption disable (done in Phase 1, if coding discipline is maintained).

### Phase 6: Energy-Aware Scheduling

**Replace the per-CPU cost function** in the load balancer with actual energy cost data. On heterogeneous systems (P-core/E-core), the cost function returns different values for different core types, steering latency-sensitive threads to P-cores and throughput-oriented threads to E-cores.

**Replace the idle governor** with an energy-aware governor that selects deeper idle states when the predicted idle duration is long enough to justify the exit latency.

**Add frequency scaling integration.** When all threads on a CPU are in low-priority classes (batch, idle), request a lower CPU frequency to save power. When a high-priority or deadline thread arrives, request maximum frequency.

### Phase 7: Sophisticated Load Balancing

**Use all topology levels** in the balancing decision. Balance within SMT siblings first (cheapest migration), then within LLC groups, then within NUMA nodes, then across NUMA nodes.

**Per-level balancing frequency:** Check SMT imbalance frequently (every few milliseconds), LLC imbalance at moderate frequency, NUMA imbalance infrequently (every few hundred milliseconds to seconds).

**Migration cost awareness:** Track cache warmth (time since last run on a CPU) and apply a migration cost threshold that increases with topology distance. Don't migrate a cache-warm thread across a NUMA boundary unless the imbalance is severe.

**Load metrics:** Replace simple run queue length with weighted load that accounts for thread CPU consumption. EEVDF's virtual runtime provides this naturally.

**NUMA balancing:** Detect threads whose memory is on a remote NUMA node (via page fault sampling or hardware-assisted NUMA hints) and migrate them toward their memory, or migrate their memory toward their CPU. This interacts with the VM subsystem's page migration and the extent-based metadata.

## Open Questions

- **Deadline chain propagation:** How to extend deadline guarantees across IPC chains (application → audio server → audio driver) rather than just for individual threads. This requires the scheduler to understand that a message arriving at a server is part of a deadline task's period and should be handled within the remaining deadline budget.
- **Interactive tier protocol:** The exact mechanism by which the compositor communicates tier assignments to the scheduler. Options include a dedicated syscall, a shared-memory hint buffer, or messages to a scheduling policy server.
- **Coscheduling granularity:** How tightly coscheduled threads' execution windows should overlap. Too tight wastes CPU time; too loose doesn't prevent the spinlock pathology. Empirical measurement on VM workloads is needed to tune the coscheduling bias.
- **Autogroup equivalent:** Whether to automatically group all threads within a session (terminal, login) into a scheduling group that receives a single group-level share of CPU time, preventing a build process in one terminal from starving interactive applications.
- **BPF-based scheduling (sched_ext):** Linux 6.12 introduced sched_ext, allowing BPF programs to implement scheduling policy. Whether Telix should support a similar mechanism (a tracing-server-like scheduling policy server that receives scheduling events and returns dispatch decisions) is architecturally interesting but deferred.
