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

> **FIRST TARGET — IMPLEMENTED 2026-06-23.** Shipped as a new kernel primitive
> `personality_remap_shared` (SYS 0xF017) + a gated branch in
> `handle_mmap(FdKind::Initramfs)`'s cache-hit fast path. Implementation findings
> (the scope shifted twice while reading-to-implement):
> - **Why a new primitive, not `personality_map_shared`:** ld.so maps library
>   segments `MAP_FIXED` into a pre-reserved region (the `personality_mmap_fixed`
>   reserve-then-replace path), so by the cache-hit the target VMA **already
>   exists** — and `personality_map_shared` *always* `map_anon`s a fresh VMA
>   (personality.rs:1355), which would conflict. `personality_remap_shared` is
>   that function **minus the `map_anon`**: it installs the shared PTEs over the
>   already-mapped region. Safe because the region was created moments earlier in
>   the same mmap syscall and the process hasn't resumed → PTEs unfaulted, no
>   stale TLB (the property memfd/DRM `map_shared` also relies on).
> - **RE-only (write-safety):** share only `kern_prot == 2` (read+exec = .text
>   code), which ld.so never writes or mprotects-writable, so the shared cache
>   pages can't be mutated → no COW needed. RW/RELRO/RO-data keep the per-process
>   copy (the RELRO-then-mprotect-RW hazard never touches a shared page).
> - **EOF-coverage gate:** share only when `file_offset + pages*page_size <=
>   file_size` (the whole page-rounded mapping is real file bytes). Linux
>   zero-fills past EOF; sharing a raw backing page in a partial last page would
>   leak backing bytes where zero is required. `.text`/`.rodata` are early in the
>   file (more segments follow) so they still share; only an EOF-crossing tail
>   page falls back to copy.
> - **Teardown:** shared pages are owned by linux_srv's persistent `LIB_CACHE`;
>   aspace teardown frees the target's anon object (owns nothing here) + page
>   tables, not the cache pages — identical to the proven memfd/DRM structure.
> - **Publication:** `lib_cache_lookup` returns `Some` only when ALL chunks are
>   cached (Acquire-load pairing the reply thread's Release store), so shared
>   bytes are fully published — the cross-CPU race **loom-validated** in
>   `tests/loom-libcache-share` (2/2). Observability: `FS_MMAP_RO_SHARED` counter
>   + one-shot `[lsrv] FS_MMAP_RO_SHARED: first RO code page shared` marker.
>
> **Validation (2026-06-23, noisy pgcl host, load 9–11):** all 4 pieces build
> clean (x86_64 kernel + userlib). No-regression boot 91amfsq96 reached **Phase
> 145e** (deep Linux personality, *past* the library mmaps) with **0 crashes / 0
> `remap_shared` failures** — the share path was live in that build and didn't
> break ld.so executing libc. The dedicated marker-fired boot wedged at Phase 5b
> under host load (load 11.3) before reaching the lib loads — a documented
> code-independent Phase-5 host-pressure wedge, NOT this change. **TODO (clean
> host): capture `FS_MMAP_RO_SHARED` firing + the wall-clock A/B** (deferred with
> the rest of the quantification pass).

### 1. [IMPLEMENTED 2026-06-23 · loom-validated · no-regression boot] Share read-only library pages across processes
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

### 3. [IMPLEMENTED 2026-06-23 · #258] Lift `FS_ASYNC_SCRATCH_SLOTS` (4 → 8)
`linux_srv.rs:3220`. Raised 4 → **8** (one constant). More concurrent in-flight
chunk fills → fewer mmap sync-fallbacks (`FS_MMAP_SYNC_FALLBACK`) under the
multi-client load (compositor + Xwayland + N X clients dlopen'ing libs at once,
each holding a scratch slot per in-flight fill).
**Findings:** `FS_ASYNC_SCRATCH_BUSY` is an `AtomicU8` → **8 is the ceiling**
without widening to `AtomicU16` (+ the `1u8 << i` shift literals); the loop only
shifts by `i<8` so it's safe. Region = `FS_ASYNC_SCRATCH_PAGES(64) × SLOTS`
pages, pre-faulted + grant-shared (not duplicated) into each FS task at
`LIN_FS_ASYNC_SCRATCH_REMOTE_BASE=0x5_0010_0000`; at 8 slots it spans 2 MiB
(→ `0x5_0030_0000`), clear of neighbors (`0x5_0000_0000`/`0x5_0001_0000`).
**Validation:** build-clean. Boot 91amfsq100 exercised it past early bringup
with **no exhaustion** and no slot-attributable fault (the one #PF was an ambient
`#208`-family null-write in a native smoke-test process — task=18 "hello"/
"echo_client" — that runs *before* linux_srv's preload, recovered, boot
continued). Exhaustion didn't fire because the single-process bringup doesn't
contend 4 slots; the win is at the multi-client phase, **quantify on a clean host**
(watch `FS_ASYNC_SCRATCH_EXHAUST`/`FS_MMAP_SYNC_FALLBACK` drop vs the 4-slot
baseline). If they still fire at 8, go to 16 (needs the `AtomicU16` widening).

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
Recommended order (revised 2026-06-23): **#1 (flagship) ✅ DONE → #3 → #4 → #2**;
#5 only with explicit steering. (#2 was reassessed *not* quick: the eager preload
is synchronous by necessity — it runs before the dispatch loop, and the reply
threads that would pick up async chunk reads already own `IRFS_REPLY_PORT`, so
inline async-reaping there would race. Revisit after #3 lifts the scratch slots.)
