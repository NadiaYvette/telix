# H14 path-to-compositor — structural performance repertoire

Status: **living candidate list**. These are *structural* (host-independent)
improvements on the path to a live Wayland compositor + Xwayland + X clients,
found by **code audit** (not wall-clock), so they're valid despite the pgcl host
noise that blocks clean A/B. Plan (user, 2026-06-23): build the repertoire, then
quantify with a clean wall-clock A/B once the host frees up.

Already landed this session (the #1 in-kernel sink): serial DIAG spam →
emit-on-change (`af59e86`) + hot-path trace gating (`632eb7f`), 95%→17% of serial.
After that, the remaining sinks are the **workload** (library loading) and host
descheduling (paravirt). This doc covers the workload.

## Prioritized candidates

### 1. [HIGH · verified] Share read-only library pages across processes
**Today:** a file-backed mmap of an initramfs library **copies** the bytes into
each process's private pages — `personality_copy_out` in the fill / cache-hit
paths (`linux_srv.rs:4233/4321/4606`), backing allocated as anon
(`mmap_anon`, ~4517). `LIB_CACHE` is a *server-side staging buffer*, not a shared
mapping. **memfd and DRM already do the right thing** — `personality_map_shared`
(`linux_srv.rs:8544`, `8573`) maps the same physical pages into the process; the
`FdKind::Initramfs` branch (`8629`) does not.
**Cost:** N processes × M shared libs = N×M private copies (memory) + N×M
cross-aspace byte-copy loops (CPU). The compositor + Xwayland + each X client all
load libc / libwayland / libX11 / … → large duplication, paid per process.
**Improvement:** give a `LIB_CACHE` slot a **shared memory object** (keyed by
initramfs handle) and map it into each process via `personality_map_shared` —
i.e. real `MAP_PRIVATE`-file semantics: **RO segments page-cache-shared, RW/RELRO
segments COW** (ld.so relocates GOT/PLT, so the writable segments must COW-break;
.text/.rodata stay shared). Reuse the memfd/DRM map_shared path + the grant / COW
object infra (`mm/object.rs`, `mm/grant.rs`, COW groups).
**Risk:** moderate — sensitive mmap path; must (a) COW-break the writable/relocated
segments correctly, (b) preserve the grant zero-fill fence the sync reader relies
on, (c) refcount the shared object across munmap/exit (the ring-lifecycle pattern
applies). The flagship win; do it carefully + loom the share/COW/teardown race.

### 2. [HIGH · verified · low-risk] Batch the eager-preload's per-chunk reads
**Today:** `lib_cache_eager_populate` (`linux_srv.rs:~5141`) walks each library's
chunks with **synchronous** `irfs_read_bulk` — chunk N+1 waits for chunk N's
reply. A 5–6 MiB lib = ~22 serial round-trips; ×~51 preloaded libs.
**Improvement:** issue up to `FS_ASYNC_SCRATCH_SLOTS` chunk reads asynchronously
and collect replies in a batch (pipeline depth = #slots). ~`#slots`× fewer
serial stalls per library.
**Risk:** low — self-contained to the preload routine, runs at boot before the
dispatch loop; bounded by existing scratch slots. Good first implementation.

### 3. [MED · pending #258] Lift `FS_ASYNC_SCRATCH_SLOTS` (4 → 8/16)
`linux_srv.rs:~3220`. More concurrent in-flight chunk fills (helps #2 and the
lazy mmap-fill path; also reduces the sync-fallback frequency that #258 tracks).
**Risk:** low-moderate — costs scratch VA/memory; validate no grant-region
pressure. Already a tracked task (#258).

### 4. [MED · risk] Defer/background the preload
**Today:** preload runs **before** the dispatch loop (`linux_srv.rs:~15006`),
blocking boot for its whole duration before any process starts.
**Improvement:** start serving immediately; fill `LIB_CACHE` lazily/in-background
so Xwayland launches in parallel and hits cache as it fills.
**Risk:** moderate — first process races the fill (double-fetch a few chunks);
needs careful chunk-state handling. Do after #1/#2.

### 5. [MED · SENSITIVE · UNVERIFIED] init.rs H14 orchestration latency
Candidate (agent-reported, line numbers NOT yet verified): a fixed
`sleep_ms(1000)` before the Xwayland spawn (~11401), a 100 ms-interval X0-listener
probe loop (~11515), a strictly serial compositor→Xwayland→client chain, and a
coarse 10 ms main-loop poll (~12030). Replacing the fixed sleep with event-driven
compositor-readiness + pipelining the spawns could cut ~1–2 s of critical-path
latency.
**Risk:** **HIGH to touch** — this is the H14 demo path the user tuned across many
sessions for #120 / host-pause flakiness; the sleeps may be *defensive* under host
pressure. Verify each line first; change behind care + a no-regression boot;
prefer event-driven readiness signals over merely shrinking sleeps. Steer-gate.

### 6. [LOW] Micro
- `NAME_CACHE` linear O(64) scan (`linux_srv.rs:~4427`) — fine at 64; only matters
  if the table grows. Skip unless it shows up.
- Per-cache-hit 3-way csum verification (`~4624`) — DEBUG-gate it out of the hot
  path if it isn't already.

## Cross-process caching — already good (don't re-solve)
`NAME_CACHE` and `LIB_CACHE` are **linux_srv-global** (shared across all served
processes), so a 2nd process opening a cached lib skips the connect IPC
(NAME_CACHE) and the chunk reads (LIB_CACHE). The remaining cross-process waste is
the **per-process copy** (#1), not re-fetching — the content is cached once; it's
just copied out N times instead of mapped shared.

## Implementation discipline (flying blind)
Each item: build-clean + a no-regression boot (default path) before banking;
prefer correct-by-construction / reversible; loom any new share/COW/teardown race
(#1). Quantify the batch with a clean wall-clock A/B once the pgcl host frees up.
Recommended order: **#2 (safe, quick) → #1 (flagship) → #3 → #4**; #5 only with
explicit steering.
