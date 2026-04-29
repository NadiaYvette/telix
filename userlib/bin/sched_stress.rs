//! sched_stress — tight call/reply round-trip stress test designed to
//! reproduce the deferred-requeue / CallReply scheduler race in seconds.
//!
//! Background: under heavy boot load, threads occasionally end up
//!   state=Ready, blocked_on=CallReply(0), wake=false,
//!   on_cpu=ON_CPU_DEFERRED (4294967294), in_q=true, def=0
//! and the watchdog's drain + reschedule-IPI + rescue path doesn't unstick
//! them (counters double_enq:drain=0 rescue=0 wake=0 other=0).  See
//! `kernel/src/sched/scheduler.rs` around lines 244-340 (deferred-requeue),
//! 2143-2326 (watchdog), 2540-2900 (try_switch deferred-store path).
//!
//! Strategy: many concurrent worker threads do tight call/reply round-trips
//! against a single shared echo server thread.  The kernel scheduler must
//! constantly:
//!   - block workers on CallReply (parking them, on_cpu→MAX),
//!   - wake the server (which was parked in recv_with_cap),
//!   - on the server's reply, wake the client and park the server again,
//!   - re-enter try_switch on the same CPU, which pushes prev into the
//!     deferred slot,
//!   - have the next pickup drain that slot (or have a remote CPU's
//!     work-stealing/heartbeat/rescue do it cross-CPU).
//!
//! The race window is the deferred-store → drain handoff in try_switch.
//! With N workers (N > #CPUs) all hammering one server, every CPU is
//! constantly entering try_switch with a different `prev` and either
//! draining its own slot or losing a CAS when a remote CPU's heartbeat
//! drains it first.  Periodic short sleeps (sleep_ms(0) → yield_now) and
//! occasional yields ensure we don't lock onto one CPU and miss the
//! cross-CPU window.
//!
//! Wiring: spawn'd from init.rs after Phase 5g (so it runs early in boot,
//! before the slow FS / Linux-personality phases).  Track 1's
//! `tools/scheduler-repro-loop.sh` will pick it up automatically once the
//! kernel is rebuilt.
//!
//! Args (a0/a1/a2 unused; tunables are constants below).
//!
//! Self-contained: only uses port_create, thread_create, call,
//! recv_with_cap, reply, exit, yield_now, sleep_ms.  No nameserver, no
//! VFS, no FS — just raw IPC against a sibling thread in the same task.

#![no_std]
#![no_main]

extern crate userlib;

use core::sync::atomic::{AtomicU64, Ordering};

use userlib::syscall;

// --- Tunables -------------------------------------------------------------
// Worker thread count.  Exceed #CPUs (typical boot uses 4) so multiple
// workers race on each CPU's run queue, maximizing time spent in
// try_switch's deferred-store path.
const N_WORKERS: usize = 8;

// Round-trips per worker.  10_000 * 8 = 80_000 round-trips ≈ 160_000
// scheduling decisions on a hot path.  At ~50µs per round-trip that's
// ~4-8 seconds of pressure — well inside the 5s watchdog window so a
// single repro iteration will fire WATCHDOG if the race trips.
const N_ROUNDS: u64 = 10_000;

// How often a worker yields between calls (in rounds).  0 = never; small
// numbers introduce extra context switches that exercise the
// "another thread became Ready while prev is in deferred slot" window.
const YIELD_EVERY: u64 = 7;

// How often a worker sleeps a short time (in rounds).  Sleep parks the
// thread on the SLEEP wheel rather than via CallReply, exercising the
// "wake from sleep dequeue → ON_CPU_PENDING → CAS to cpu" path
// concurrently with deferred-store/drain on other CPUs.
const SLEEP_EVERY: u64 = 53;

// Server tags.
const ECHO_REQ: u64 = 0xE000;
const ECHO_REPLY: u64 = 0xE001;

// --- Shared state --------------------------------------------------------

static SERVER_PORT: AtomicU64 = AtomicU64::new(0);
static SERVER_READY: AtomicU64 = AtomicU64::new(0);
static WORKER_DONE: [AtomicU64; N_WORKERS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; N_WORKERS]
};
// Bumped on every successful round-trip across all workers.  Used to
// detect "no progress for a while" without needing the kernel watchdog
// (workers themselves can print a marker).
static GLOBAL_PROGRESS: AtomicU64 = AtomicU64::new(0);
// Per-worker round counter — exposed in the dump if it stalls.
static WORKER_ROUND: [AtomicU64; N_WORKERS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; N_WORKERS]
};

// --- Helpers -------------------------------------------------------------

fn print_num(mut n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

// --- Server thread -------------------------------------------------------

extern "C" fn server_entry(_arg: u64) -> ! {
    let port = SERVER_PORT.load(Ordering::Acquire);
    SERVER_READY.store(1, Ordering::Release);
    loop {
        let m = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };
        if m.tag == 0xDEAD {
            // Sentinel: workers all done; server exits.
            // Reply so client doesn't get stuck waiting.
            let _ = syscall::reply(0, 0, 0, 0, 0, 0);
            syscall::exit(0);
        }
        // Echo: increment data[0], swap tag.  Tight, no allocation, no
        // syscall except reply — so the server spends almost all of its
        // time parked in recv_with_cap → CallReply / PortRecv block.
        let _ = syscall::reply(
            ECHO_REPLY,
            m.data[0].wrapping_add(1),
            m.data[1],
            m.data[2],
            m.data[3],
            0,
        );
    }
}

// --- Worker thread -------------------------------------------------------

// Pack worker index into the arg register.
extern "C" fn worker_entry(arg: u64) -> ! {
    let idx = arg as usize;
    let port = SERVER_PORT.load(Ordering::Acquire);
    for round in 0..N_ROUNDS {
        WORKER_ROUND[idx].store(round, Ordering::Relaxed);
        // call() blocks the worker on CallReply against the server until
        // the server replies.  Both transitions go through try_switch's
        // deferred-store path on the worker's CPU.
        match syscall::call(port, ECHO_REQ, round, idx as u64, 0, 0) {
            Some(r) => {
                if r.tag != ECHO_REPLY || r.data[0] != round.wrapping_add(1) {
                    syscall::debug_puts(b"[sched_stress] BAD reply tag/data\n");
                    WORKER_DONE[idx].store(2, Ordering::Release);
                    syscall::exit(1);
                }
            }
            None => {
                // call() returns None on transport error (server died,
                // port destroyed).  This only happens if the test wedges
                // — log and bail so the harness sees a worker exit.
                syscall::debug_puts(b"[sched_stress] call() returned None worker=");
                print_num(idx as u64);
                syscall::debug_puts(b" round=");
                print_num(round);
                syscall::debug_puts(b"\n");
                WORKER_DONE[idx].store(3, Ordering::Release);
                syscall::exit(1);
            }
        }
        GLOBAL_PROGRESS.fetch_add(1, Ordering::Relaxed);
        // Inject voluntary scheduling pressure.  yield_now() drops us to
        // the back of our CPU's RQ, which means the next try_switch on
        // this CPU will store us in the deferred slot.  If the next
        // pickup of this CPU is preempted before drain_deferred_requeue
        // runs, and a remote heartbeat fires drain on this CPU,
        // the CAS-recovery path is exercised.
        if YIELD_EVERY != 0 && round % YIELD_EVERY == 0 {
            syscall::yield_now();
        }
        // sleep_ms(0) parks via the timer wheel — different code path
        // than CallReply, but unparks via the same dequeue→ON_CPU_PENDING
        // mechanism that deferred-requeue and rescue all share.  Mixing
        // these wakers exposes ordering hazards.
        if SLEEP_EVERY != 0 && round % SLEEP_EVERY == 0 {
            syscall::sleep_ms(0);
        }
    }
    WORKER_DONE[idx].store(1, Ordering::Release);
    syscall::exit(0);
}

// --- Driver --------------------------------------------------------------

fn alloc_stack() -> u64 {
    // Two pages so the worker has comfortable headroom for its tiny
    // call-stack.  Returns the stack-top address.
    let va = syscall::mmap_anon(0, 2, 1).unwrap_or(0);
    if va == 0 {
        syscall::debug_puts(b"[sched_stress] stack alloc FAIL\n");
        syscall::exit(1);
    }
    (va + 2 * syscall::page_size()) as u64
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[sched_stress] starting workers=");
    print_num(N_WORKERS as u64);
    syscall::debug_puts(b" rounds=");
    print_num(N_ROUNDS);
    syscall::debug_puts(b"\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[sched_stress] port_create FAIL\n");
        syscall::exit(1);
    }
    SERVER_PORT.store(port, Ordering::Release);

    // Spawn server thread first so the port has a receiver before any
    // worker calls into it.
    let stk = alloc_stack();
    let srv_tid = syscall::thread_create(server_entry as u64, stk, 0);
    if srv_tid == u64::MAX {
        syscall::debug_puts(b"[sched_stress] server thread_create FAIL\n");
        syscall::exit(1);
    }
    while SERVER_READY.load(Ordering::Acquire) == 0 {
        syscall::yield_now();
    }

    // Spawn N workers.
    let mut worker_tids = [0u64; N_WORKERS];
    for i in 0..N_WORKERS {
        let stk = alloc_stack();
        let tid = syscall::thread_create(worker_entry as u64, stk, i as u64);
        if tid == u64::MAX {
            syscall::debug_puts(b"[sched_stress] worker thread_create FAIL i=");
            print_num(i as u64);
            syscall::debug_puts(b"\n");
            syscall::exit(1);
        }
        worker_tids[i] = tid;
    }

    // Wait for workers, with a progress-stall heartbeat so the test
    // emits a unique marker into the kernel log if the race wedges
    // someone — making it easy to pinpoint in run-NN.log under
    // /tmp/sched-runs/.
    let mut last_progress = 0u64;
    let mut stall_ticks = 0u32;
    loop {
        let mut all_done = true;
        for i in 0..N_WORKERS {
            if WORKER_DONE[i].load(Ordering::Acquire) == 0 {
                all_done = false;
                break;
            }
        }
        if all_done {
            break;
        }
        // Sleep ~100ms between checks; keeps the driver thread from
        // dominating a CPU.
        syscall::sleep_ms(100);
        let now = GLOBAL_PROGRESS.load(Ordering::Relaxed);
        if now == last_progress {
            stall_ticks += 1;
            // After ~2s of zero progress, dump per-worker rounds so
            // a stuck worker is identifiable in the log.
            if stall_ticks == 20 || stall_ticks == 60 || stall_ticks == 200 {
                syscall::debug_puts(b"[sched_stress] STALL ticks=");
                print_num(stall_ticks as u64);
                syscall::debug_puts(b" progress=");
                print_num(now);
                syscall::debug_puts(b" rounds=[");
                for i in 0..N_WORKERS {
                    if i != 0 {
                        syscall::debug_putchar(b',');
                    }
                    print_num(WORKER_ROUND[i].load(Ordering::Relaxed));
                }
                syscall::debug_puts(b"]\n");
            }
            // After >=20s of zero progress, declare repro and bail
            // so the harness collects the kernel WATCHDOG dump and
            // moves on.  The wedge persists in kernel state — Track 1's
            // log capture will have it.
            if stall_ticks >= 200 {
                syscall::debug_puts(b"[sched_stress] WEDGED - giving up\n");
                syscall::exit(2);
            }
        } else {
            last_progress = now;
            stall_ticks = 0;
        }
    }

    // Tell the server to exit, then we're done.
    let _ = syscall::call(port, 0xDEAD, 0, 0, 0, 0);

    // Verify all workers reported success.
    let mut ok = true;
    for i in 0..N_WORKERS {
        if WORKER_DONE[i].load(Ordering::Acquire) != 1 {
            ok = false;
        }
    }
    if ok {
        syscall::debug_puts(b"[sched_stress] PASSED total=");
        print_num(GLOBAL_PROGRESS.load(Ordering::Relaxed));
        syscall::debug_puts(b"\n");
        syscall::exit(0);
    } else {
        syscall::debug_puts(b"[sched_stress] FAILED (worker error)\n");
        syscall::exit(1);
    }
}
