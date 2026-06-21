# Completion ABI — linux_srv "endgame" design

Status: **design for review** (no code yet). Branch `completion-abi-phase0`.
Companion: `docs/completion-abi-design.md` (the ABI), `project_completion_phase1`
(progress), this doc (the linux_srv-specific analysis + options).

## Goal we're testing

The roadmap calls completion-based IPC "canonical; convert until the sync paths
are removable." linux_srv is the hottest IPC path (every Linux syscall), so it's
the natural last big conversion. This doc asks **whether and how** to convert it,
because the investigation found the cost/benefit is very different from the FS
servers — and the answer should be a deliberate decision, not a default.

## How linux_srv does IPC today (the surface to convert)

linux_srv is 15.5k lines and multi-threaded. Its IPC is NOT the reply-cap model
the completion `serve()`/`serve_deferred` helpers are built for.

**Inbound (3 receive points):**
- Main thread: `port_set_recv(port_set)` over {personality port, BACKEND_REPLY_PORT}
  (`linux_srv.rs:14864`). Returns `(src_port, msg)` — source-port identity is how
  it tells a syscall request from a backend async reply.
- 2 syscall workers: `recv_with_cap(SYSCALL_WORKER_PORT)` (`:12799`); main forwards
  worker-safe nrs via `send_nb_4`; workers reply with `personality_reply`.
- 2 reply threads: `recv_with_cap(IRFS_REPLY_PORT)` (`:12853`) for FS read replies.

**The syscall request + reply mechanism (kernel `personality.rs`):**
- Forward: a Linux syscall → `forward_to_server` (`personality.rs:173`) builds
  `Message{ tag = nr | caller_port<<32, data=args }`, `port::send`s it to the
  personality port, then **blocks the caller and spins on `thread.personality_result`**.
- Reply: `personality_reply(caller_port, ret)` (`personality.rs:334`) stores `ret`
  into the caller thread's `personality_result` and `wake_thread`s it. **No port
  recv on the caller side, no reply-cap** — it is a direct thread-field handoff.
  → This is already cheap and is **irreplaceable by OP_REPLY** (the caller isn't
  recv-ing on a port or holding a cap). personality_reply stays, converted or not.

**Outbound (the hand-rolled async machinery — the actual conversion target):**
- 17 async patterns (VFS_OPEN/STAT_ASYNC, FS_READ_ASYNC, PIPE_*, UDS_*, exec,
  wait4/eventfd/timerfd parks): `send_nb_4` the request with a `correlation` id,
  return with `REPLY_DEFERRED` set (suppresses the inline personality_reply),
  later match the reply on BACKEND_REPLY_PORT/IRFS_REPLY_PORT.
- Correlation: a **64-slot `PENDING_ASYNC` table** + `next_correlation_id()` +
  `async_find_by_correlation()` (O(64) scan) + per-kind `finish_*` continuations,
  each ending in `personality_reply(caller_port, …)` (`:1303-1507`, `:12410-12765`).
- Per-process state: `PROC_TABLE` keyed by caller_port, per-process `TicketSpinLock`
  held across a dispatch (Phase B5).

This async+correlation+worker machinery was built deliberately over phases
#183-191 / A1-A5 / B4-B5. It already delivers the two things completion would:
non-blocking dispatch and request/reply correlation.

## The three blockers to a CQ-based linux_srv

1. **Deliver-hook keys on TASK, not port** (`completion.rs:519`, call site
   `port.rs:944`). If linux_srv sets io_depth≠0 (required to issue OP_CALL), the
   hook funnels **every** inbound message on **all** its ports into the one CQ.
2. **The CQE has no source-port field** and forces `user_data=0` for hook-delivered
   inbound. So once in the CQ, linux_srv cannot tell a personality request from a
   BACKEND_REPLY_PORT message from a worker message — it loses the `port_set_recv`
   `src_port` distinction it depends on. (`inline[4]` carries the *sender*, not the
   destination port.)
3. **Dual-wait.** OP_CALL replies arrive in the CQ (via `deliver_reply_cqe`,
   correlated by `user_data`). The main loop blocks in `port_set_recv`, which does
   not observe the CQ. Converting outbound to OP_CALL means the main loop must wait
   on **both** the port set and the CQ — there is no primitive for that today.

None of these is fatal, but each needs kernel work, and together they mean a
"convert linux_srv like a leaf server" framing does not apply.

## Honest cost/benefit

- **Benefit of converting inbound** (port_set→CQ): low. port_set_recv already works
  and is lost-wakeup-safe; personality_reply stays regardless. The demux blockers
  (1)+(2) make it costly for little gain.
- **Benefit of converting outbound** (async machinery→OP_CALL): real but partial —
  it would retire PENDING_ASYNC + handle_async_reply + the correlation scan (~hundreds
  of lines, a recurring source of bugs). But it needs blocker (3) solved (CQ in the
  main wait) and the backends are already on the completion ABI, so the *wire* is
  fine; it's linux_srv's side that's hand-rolled.
- **Risk:** linux_srv is the single most load-bearing server; a botched conversion
  breaks every Linux process. The existing machinery is battle-tested.

## Options

**A — Full inbound+outbound conversion.** Add source-port to the CQE (ABI bump) +
per-port deliver control + a `port_set ∪ CQ` combined wait primitive; move inbound
to the CQ and outbound to OP_CALL. Highest effort, highest "purity," touches the
kernel personality path + the CQE ABI. Multi-session, high risk.

**B — Outbound-only (recommended first slice).** Solve blocker (3) only: give
linux_srv a CQ that the main loop can wait on alongside the port set, then convert
the async backend patterns to OP_CALL, retiring PENDING_ASYNC/handle_async_reply
incrementally (one pattern at a time, each boot-validated). Inbound personality
dispatch + personality_reply stay exactly as they are. Medium effort, medium
value, contained risk. Two ways to do the combined wait:
  - **B1:** add `BACKEND_REPLY_PORT` semantics to the CQ — i.e. make
    `io_reap_wait` also wake on port-set traffic, or add the CQ's wake key to the
    port set. (kernel: unify the two wait sources.)
  - **B2:** keep the main loop on `port_set_recv`; have OP_CALL replies delivered
    as a normal message to BACKEND_REPLY_PORT instead of the CQ (a "reply-to-port"
    variant of deliver_reply_cqe). Then linux_srv keeps ONE wait (port_set), and
    "OP_CALL" is really "kernel-correlated async send" — we keep the correlation
    win without the dual-wait. **Least invasive; likely the right first step.**

**C — Targeted.** Leave the architecture; adopt completion only at a specific
proven hot/contended path if profiling finds one. Low effort.

**D — Declare scope complete.** linux_srv keeps its purpose-built personality IPC;
the completion ABI is "done" for the tier it fits (reply-cap servers: FS, tmpfs,
devfs, procfs, grant_echo, + OP_CALL/OP_SEND for clients). Revisit only if a
concrete linux_srv pain (latency/wedge/bug) points at the async machinery.

## Recommendation

Pursue **B2** as the first concrete step, framed as a measurement-gated pilot:

1. **Profile gate** — confirm the async machinery is actually a cost (correlation
   scan time, BACKEND_REPLY_PORT round-trip latency, PENDING_ASYNC exhaustion
   `FS_ASYNC_SCRATCH_EXHAUST`) on a representative boot. If it isn't, prefer (D).
2. **Kernel enabler** — a "reply to port" form of the OP_CALL reply path
   (`fulfill` → deliver the reply as a message to a nominated port, carrying the
   issuer's correlation in a data word) so linux_srv keeps its single port_set wait.
   Loom-model the new reply rendezvous (same family as the 2b model).
3. **Pilot one pattern** — convert the simplest async backend call (e.g.
   `VFS_STAT_ASYNC`) to issue an OP_CALL whose reply returns on BACKEND_REPLY_PORT
   with kernel correlation, deleting that pattern's PENDING_ASYNC bookkeeping.
   Boot-validate (a focus-surviving Phase 5 smoke + a real Linux stat path).
4. **Roll out** the remaining patterns one at a time, each its own commit + boot,
   retiring PENDING_ASYNC/handle_async_reply incrementally; the table is gone only
   when the last pattern is converted.
5. Inbound personality dispatch (port_set + personality_reply + workers) is **out
   of scope** — it stays.

This captures the real win (retire the hand-rolled correlation machinery) at the
lowest risk and with no CQE ABI break, and it's incremental + per-step validated,
matching how Phase 1/2b/tmpfs landed.

## Open questions for the user

- Is the **profile gate** (step 1) worth doing, or is retiring PENDING_ASYNC
  desirable on maintainability grounds regardless of measured cost?
- B2 (reply-to-port, keep single wait) vs B1 (true CQ dual-wait)? B2 is less
  invasive but keeps a port in the loop; B1 is "more completion" but needs the
  combined-wait primitive.
- Appetite for the CQE ABI bump (source-port field) that Option A/full inbound
  would require — worth it for a future where personality dispatch is on the CQ?
