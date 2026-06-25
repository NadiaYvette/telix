# #274 — Linux signal completeness (EINTR / ERESTARTSYS / SA_SIGINFO) — plan

Status: **Phase 0 IMPLEMENTED flag-gated 2026-06-25 (commit da36502)** — EINTR for
futex/poll parked callers behind `const SIGNAL_INTERRUPT=false` (dormant; build-clean
5-arch). See memory/project_274_signals_phase0.md. Remaining phases below not started.
Multi-phase Linux-personality feature requiring boot-validation. Related: tasks
#187-191 (the async-park sweep that created the gap), [[project_deferred_reply]].

## The gap
The personality has ONE working synchronous signal hook,
`maybe_deliver_signal(pi, caller_port, result)` (userlib/bin/linux_srv.rs:11574),
called from exactly one site — the main dispatch reply path (linux_srv.rs:15911),
right before `personality_reply` (:15927). **Every blocking syscall converted to
async-park / deferred-reply (#187-191) replies on a *separate* `finish_*` /
`poll_*` / `expire_*` path that bypasses this hook**, so a signal posted to a
thread parked there is stranded until the syscall completes normally:
- futex_wait (11447/11540), wait4 (8216/8383), pipe r/w (5042/5058),
  uds_send (5171), eventfd (8258/8308), timerfd (8281/8344),
  poll/select/ppoll/pselect6 (11228/11265). All: **no `sig_pending` check.**
- rt_sigsuspend (11818) returns EINTR but via a 10M-iter spin-poll, not the park path.
Three sub-gaps: (1) no EINTR on interrupted blocking syscalls; (2) no
ERESTARTSYS/SA_RESTART (sa.flags never read); (3) no SA_SIGINFO siginfo_t
(handlers always called 2-arg; kernel stores no si_code/si_pid/si_status).

## Root cause (why signals are stranded)
A forwarded Linux syscall parks the user thread on
`BlockReason::PersonalityWait` (kernel/src/syscall/personality.rs:261, loop
:288-316). `send_signal_to_thread` sets `sig_pending |= bit; wake_thread(tid)`
(scheduler.rs:10271). The wake fires, but the park loop sees
`personality_result == PERSONALITY_PENDING`, treats it as spurious, re-arms and
RE-BLOCKS (personality.rs:303-315). The `abandon_for_interrupt` /
CALL_REPLY_INTERRUPTED path (scheduler.rs:9782) only handles
`BlockReason::CallReply` + `PARK_COMMITTED`, NOT `PersonalityWait`. The fix data
already exists: `personality_peek_signals(port)` (personality.rs:1197) reads the
same `sig_pending` kill set.

## Phased plan
**Phase 0 — EINTR for parked callers (the core).** Add a main-loop sweep
`poll_signal_interrupts()` (register next to `poll_timerfd_pending` ~15157) that
walks FUTEX_TABLE / POLL_TABLE / PENDING_ASYNC, and for each active parked caller
with a *deliverable* signal (`personality_peek_signals(port) & !sig_mask != 0`,
not SIG_IGN) completes the park early: factor the handler-frame-rewrite half of
`maybe_deliver_signal` into `deliver_signal_to_parked(pi, caller_port)`, reply
`linux_err(EINTR)` (no-restart/handler case) or take the SIG_DFL-terminate kill
path; free the slot. **Cadence:** the main loop blocks in `reap_wait(1)` (15200)
/ `port_set_recv` (15290) until a message arrives, so add a **kernel nudge** — in
`send_signal_to_thread`/`wake_thread`, when target is `PersonalityWait` with a
deliverable signal, post a wake msg/CQE to the registered personality server so
its loop polls promptly (preferred over a recv timeout; verify reap_wait timeout
support). Redirect rt_sigsuspend to this park+poll path (drop the spin).
**Phase 1 — SA_SIGINFO.** Branch on `sa.flags & SA_SIGINFO (0x4)`; extend the
sigframe (11606) to reserve 128B siginfo_t + a ucontext_t; set RSI=siginfo,
RDX=ucontext (uc_mcontext from the saved frame); fill si_signo/si_errno=0/
si_code=SI_USER. Field offsets: handle_waitid (8441) is the template.
**Phase 2 — ERESTARTSYS / SA_RESTART.** `restart_parked_syscall` rewinds the
saved frame's user RIP by the syscall-insn width (x86_64: -2) before pushing the
sigframe, for SA_RESTART + restartable syscalls; on rt_sigreturn
(handle_rt_sigreturn_full 11662) control returns to the rewound RIP and the
syscall re-enters linux_srv. Maintain a restartable allowlist (poll/select/
nanosleep stay EINTR per Linux).
**Phase 3 — siginfo provenance (kernel).** Record si_pid/si_uid/si_status in the
signal-post path (scheduler.rs:10241) + SIGCHLD generation; expose via a new
personality query. (Synchronous-fault siginfo si_addr for SIGSEGV/BUS is a
separate path, not via maybe_deliver_signal.)

## First concrete change
Phase 0's `poll_signal_interrupts()` + the factored `deliver_signal_to_parked` +
the kernel nudge. Most libc (glibc/musl, default SA_RESTART + retry loops)
tolerates plain EINTR, so Phase 0 alone unblocks the bulk; SA_SIGINFO/ERESTARTSYS
are correctness refinements. All phases need boot-validation (signal-interrupt is
a runtime behavior), so this waits on a bootable host.
