# SMP-consistent /proc + /sys + affinity view (#275 SMP half, gated on #273)

## Goal
Present N CPUs to Linux processes — `/proc/cpuinfo`, `/proc/stat`, `/sys/devices/
system/cpu/{online,possible,present}`, and `sched_getaffinity(2)` — instead of the
current deliberate uniprocessor (1-CPU) view, so `nproc` / `get_nprocs()` /
thread-pool sizing see the real core count and programs can use real parallelism.

## The hard constraint: this is boot-gated on #273, not friction-free
The four CPU-count surfaces MUST stay mutually consistent (a program that reads
`/proc/cpuinfo` to size a pool and then `sched_getaffinity` to pin threads must see
the SAME N). The current view is consistent at **1**. Widening only some surfaces
is worse than the status quo. And widening the affinity mask makes programs spawn N
threads expecting them scheduled across CPUs — which only works if **NPTL-on-SMP**
(#273: pthread create/join/mutex/cond/TLS/robust-futex under real multi-CPU
scheduling) is validated. So: **implement flag-gated + default OFF; do not enable
until #273 passes under real boots.** (linux_srv.rs:6471-6475 already documents this
coupling.)

## Enabling finding (2026-06-25): the CPU count is already queryable
No new kernel work is needed to LEARN N:
- Kernel: `sched::smp::num_cpus() -> usize` (kernel/src/sched/smp.rs:47) — the live
  online count (MAX_CPUS is only the compile-time bitmap ceiling).
- Userspace: `SYS_CPU_TOPOLOGY` (49) already returns `(package, core, smt, online,
  online_cpu_count)`, wrapped in userlib as `syscall::cpu_topology(cpu_id)`
  (userlib/src/syscall.rs:1500-1502). linux_srv calls `cpu_topology(0)` → 5th field
  = N. (Cache it once at startup into a static, like other linux_srv globals.)

## Implementation (all in userlib/bin/linux_srv.rs), flag-gated
Add a cmdline flag `smp_view` (default OFF), mirroring the `dispatch_window_recheck`
flag pattern (boot/cmdline.rs AtomicU8 + parse). When OFF, every site below keeps
its current 1-CPU output verbatim. When ON, use `n = cpu_topology(0).online_count`:

1. **/proc/cpuinfo** (~6760, currently the per-arch single block): loop `for p in
   0..n` emitting a block per processor with `processor\t: <p>` (+ the arch fields;
   the non-processor fields stay identical per core). Must move from a fixed `&[u8]`
   to dynamic generation (a formatting loop into `buf`, like /proc/self/status).
2. **/proc/stat** (static_proc_content ~6483, currently `cpu ...` + one `cpu0`):
   emit the aggregate `cpu` line + `cpu0..cpu{n-1}` lines. Must move from
   static_proc_content to a dynamic arm in open_proc_file (N varies).
3. **/sys cpu topology** (static_sys_content): `online`/`possible`/`present` →
   `"0-{n-1}\n"` (or `"0\n"` when n==1). Still a static-ish helper but parameterized
   by N — move these three out of static_sys_content into a dynamic arm, or have
   static_sys_content read the cached N.
4. **sched_getaffinity** (handle_sched_getaffinity, 7429, currently CPU-0-only
   mask): return an N-bit mask (bits 0..n set). sched_setaffinity (203) should
   accept any subset of 0..n.

## Validation (post-#273, requires boots — DO NOT enable before)
- Consistency test (extend procfs_selftest): with `smp_view=1`, read cpuinfo
  (count `processor\t:` lines), /proc/stat (count `cpuN` lines), /sys cpu/online,
  and sched_getaffinity popcount — assert all four == N.
- NPTL-on-SMP (#273): spawn N pthreads, verify they run concurrently on distinct
  CPUs (getcpu per thread) and that mutex/cond/join/TLS are correct under load.
  Only after this passes is `smp_view=1` safe as a default.

## Why not done now
The plumbing is implementable + flag-gating makes it safe-by-default, but every
SMP path is untestable on the current memory-saturated host (no reliable boots) and
its correctness is contingent on #273. Shipping dormant unvalidated multi-CPU code
across four surfaces adds lurking-bug surface with no way to confirm it. This plan
captures the ready ncpus source + the exact sites so it can be implemented +
enabled confidently once #273 is validated under boots.

Related: #273 (NPTL/TLS stress), #275 (procfs refine), memory
project_275_procfs_maps + reference_linux_srv_synthetic_fs.
