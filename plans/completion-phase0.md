# Completion ABI — Phase 0 implementation plan (server fix)

Branch: `completion-abi-phase0`. Scope: the **completion transport only** (SQ/CQ + blocking
reap) — NO scheduler-activation upcalls (those are Phase 2, for the M:N PL runtime). Goal: give
system servers a recv path that can't hit the legacy recv_or_park/DirectTransfer/recv_holder
wedge, and prove it on `grant_echo_srv`. Decisions: design doc §9 trio (locked).

## Grounding facts (verified 2026-06-20)
- Syscall hook: `handlers.rs::dispatch()` (:244) → `match nr` (:369). Add new `SYS_IO_*` arms.
- Caps: a handle is a **bare slot index** (`cap::space::CapSpace::lookup(slot) -> &Capability`,
  cnode.rs `get(index)`). **No generation/epoch field.** ⇒ §9.4 generation-tagging is a real
  prerequisite (see step 6).
- Ring substrate: `ipc/port.rs::MpscQueue` (CAS-claimed tail, per-slot EMPTY/WRITING/READY,
  power-of-2) is reusable; our CQ (kernel→server) and SQ (server→kernel) are **SPSC**, so we can
  reuse it as-is (MPSC degenerates to SPSC) or add a leaner SPSC variant later.
- Recv surface to convert later: ~53 `recv_with_cap` sites; introduce one `completion_server_loop`.

## 1. Data structures (kernel/src/ipc/completion.rs, new)
- `Sqe { opcode: u32, flags: u32, target_cap: u64, user_data: u64, inline: [u64; 6] }`
  (inline doubles as grant_desc when flags&GRANT). 64 bytes.
- `Cqe { user_data: u64, result: i64, delivered_cap: u64 (0=none), inline: [u64; 6] }`. 64 bytes.
- `Ring { head: AtomicU32, tail: AtomicU32, capacity: u32, mask: u32 }` header + slot array +
  per-slot state byte (mirror MpscQueue). One SQ + one CQ per server (single CQ per §9.1).
- Opcodes Phase 0: `SEND, CALL, REPLY` (+ `RECV` is implicit = reap). `GRANT/REVOKE/TIMER` later.

## 2. Syscalls (add to dispatch match)
- `SYS_IO_SETUP(sq_cap_out, cq_cap_out, depth) -> 0/err`: kernel allocates the two rings in a
  shared region, maps them into the caller, returns their addresses/caps. depth power-of-2.
- `SYS_IO_SUBMIT() -> n`: kernel drains the caller's SQ, performs each SQE (send/call/reply),
  returns count. (Alternative: kernel lazily drains on demand; start with explicit submit.)
- `SYS_IO_REAP_WAIT(min) -> n`: if CQ non-empty, return available CQEs (count); else block until
  ≥min CQEs, with the §9.1 discipline: set "waiting" flag, **re-check CQ**, sleep only if still
  empty; wake is plain make-runnable, fired only on empty→non-empty.

## 3. Kernel deliver path
When a message targets a port whose receiver is completion-enabled: write a `Cqe` into that
server's CQ (result=incoming, delivered_cap=<reply-cap>, inline=msg) instead of the
send_direct/recv_or_park dance; then make-runnable the server **iff** it's blocked in REAP_WAIT
(transition-only). No parked-frame inject, no recv_holder. Overflow → kernel backlog (§9.3).

## 4. Sync↔completion bridge (migration coexistence)
A legacy sync `sys_call` to a completion-port → kernel posts a CQE to the server's CQ (as above);
the server's `REPLY` SQE → kernel completes the original sync caller (unblock + inject reply via
the existing sync reply path). So sync clients (e.g. the grant_echo client) need NO changes.

## 5. Cap handling (§9.4)
- Day 1: **validate-liveness-at-use** — when SUBMIT performs an SQE, re-lookup `target_cap`;
  if dead/insufficient-rights → `Cqe{result=EREVOKED}`. Safe against revocation.
- Fast-follow (before broad/untrusted use): **generation tags** — add `generation: u32` to the
  cap slot (cnode/space), encode `handle = (slot<<32)|generation`, SQE snapshots it, validate-at-use
  checks the generation → closes the revoke+reuse confused-deputy hole. NOTE: for the grant_echo
  proof (trusted servers, no adversarial reuse) day-1 liveness-check suffices; generation is the
  hardening step. Flag as security-relevant.

## 6. First conversion + helper
- `userlib`: `completion_server_loop(handlers)` — SETUP rings once, then loop `REAP_WAIT` →
  dispatch by opcode/tag → `SUBMIT(REPLY)`. Replaces the hand-rolled recv_or_park loop.
- Convert `grant_echo_srv` to it (smallest server + the one that wedges). Client unchanged (bridge).

## 7. Validation
- Boot grant_echo via the completion server under cgroup isolation (qemu-rt); confirm: client
  call completes, **0 CALL-TIMEOUT, 0 recv livelock**, server reaps+replies. A/B vs legacy in the
  same boot (legacy still default personality).
- loom model: SQ/CQ producer/consumer + the REAP_WAIT transition-wake + lost-wakeup guard
  (bake in from the start, per the user's loom-everything rule).

## 8. Build order (incremental commits on the branch)
1. completion.rs structs + Ring (reuse MpscQueue) + unit/loom test of the ring.
2. SYS_IO_SETUP (alloc+map rings) + a trivial self-test (submit a no-op, reap it).
3. Deliver path + REAP_WAIT wake + bridge.
4. userlib helper + convert grant_echo_srv.
5. Isolated boot validation (no-wedge) + loom.
6. (fast-follow) generation tags.

## Open / verify when coding
- Exact ring-mapping mechanism (reuse the port mpsc shared-region alloc + grant, or a new
  shared-region primitive?). Lean: reuse the existing grant/shared-region path.
- Whether to gate the completion syscalls by personality_id from day 1, or expose them to any
  task that called SYS_IO_SETUP (simpler). Lean: any-task-with-rings for Phase 0; personality
  gating when we formalize the "completion personality" selector.
- generation-tag width + handle encoding (step 5 fast-follow).

## Step ③ design (grounded 2026-06-21 via deliver-path map)

Goal: a completion-enabled server receives via the CQ (blocking REAP_WAIT) and replies via a REPLY SQE, with sync clients unchanged (bridge). **Safety/blast-radius:** every new path is gated on `recv_task.io_depth != 0`, which is only ever true for a task that called SYS_IO_SETUP. Until step ④ converts grant_echo_srv, NO task is completion-enabled, so the legacy IPC path is byte-for-byte unaffected. The hot-path cost added to legacy IPC is one relaxed atomic load (owner task's io_depth).

Hook points (file:line):
- Deliver decision: `ipc/port.rs::send_direct` (:901) — after "no parked receiver", before `q.send(msg)`. Map dest port→owner task via `port.recv_holder` (:264, else `creator_task` :262) / `get_recv_holder` (:594).
- Wake: `sched/scheduler.rs::wake_parked_thread(tid)` (:12125) — PARK_NONE/ENQUEUED/COMMITTED/WOKEN CAS arbiter (transition-safe).
- Park primitive: same one `recv_or_park` (:1053) uses (pre_save_frame → ENQUEUED → recheck → COMMITTED). REAP_WAIT must pre_save_frame + register `io_waiter` BEFORE the final CQ recheck (same ordering recv_or_park uses for its lost-message retry).
- Reply caps: `ipc/call_reply.rs::alloc(caller_tid)->CapHandle` (:233), `fulfill(handle,&reply)->FulfillResult` (:337). Handle = (gen<<32)|slot.
- Frame inject: `handlers.rs::inject_recv_into_frame(tid,&msg)` (:709); `sys_reply` (:1420) already does fulfill→inject→wake — the bridge reuses this exact path.

③b REAP_WAIT blocking (loom-validated — `tests/loom-completion-reap`): add `Task::io_waiter: AtomicU32` (INVALID sentinel; mirrors `sa_waiter`). REAP_WAIT loop: if cq_avail>=need return; else pre_save_frame(ENQUEUED) + `io_waiter.store(tid)` + **recheck** cq (if now>=need: clear io_waiter, unpark, return) + commit park. Deliver wake: after posting CQE, `let w=io_waiter.swap(INVALID); if w!=INVALID { wake_parked_thread(w) }`. The recheck-after-register closes the lost-wakeup window (loom `reap_wait_no_lost_wakeup` PASS; `no_recheck_loses_wakeup` should_panic proves teeth).

③a deliver hook: `deliver_to_completion_cq(owner_task, msg, reply_handle)` in completion.rs — write a Cqe{user_data=<correlation>, result=incoming-tag, delivered_cap=reply_handle, inline=msg payload} into owner's CQ via io_cq_kva (kernel `push`), then the io_waiter wake. Overflow (CQ full) → for Phase 0, fall back to legacy queue OR drop+log (decide at impl; lean: fall back to legacy `q.send` so nothing is lost).

③c REPLY bridge: in `io_submit`/`perform_sqe`, OP_REPLY with target_cap=delivered_cap → `call_reply::fulfill(handle,&reply)` → on WakeCaller(tid): `inject_recv_into_frame(tid,&reply)` + `wake_parked_thread(tid)`. OP_SEND/OP_CALL from a completion task → deliver to the target port (reuse send_direct), CALL mints a reply cap the *completion* server later REPLYs to. For grant_echo (client=legacy sync CALL, server=completion), the kernel mints the reply cap when bridging the sync CALL into the server's CQ (delivered_cap), and the server's OP_REPLY SQE fulfills it.

Build order ③: (1) Task::io_waiter + REAP_WAIT park loop [the wedge-fix core]; (2) deliver hook in send_direct + deliver_to_completion_cq; (3) OP_REPLY bridge in io_submit; (4) compile-check; then step ④ converts grant_echo_srv + end-to-end boot validation. Prefer a quieter boot for ④ (THRASH off) so "no wedge" is unambiguous.
