# Dead-Code Review: `MmapFillResult::Failed` sync fallback in `handle_mmap`

**File reviewed:** `userlib/bin/linux_srv.rs`
**Arm under review:** `MmapFillResult::Failed =>` at line 8058, and the `while total < to_read` loop at lines 8062–8140 (the sync `irfs_read_bulk` fallback)
**Reference commit:** `b4be100` ("chunk-level lib_cache populated as a side effect of mmap-fill (step 5)")
**Prepared:** 2026-05-20

---

## Context refresher

`handle_mmap` in `linux_srv.rs` handles `mmap(2)` calls from Linux personalities for initramfs-backed files (shared libraries, `FdKind::Initramfs`).  The fast path, added some time before the current HEAD, tries to satisfy the mapping asynchronously via `try_irfs_read_mmap` (line 3468), which fires an `IRFS_IO_READ_ASYNC` IPC and defers the reply.  This avoids blocking the service thread during large library loads.

The function returns one of three variants:

| Variant    | Meaning                                            |
|------------|----------------------------------------------------|
| `Deferred` | Async IPC sent; continuation will reply later      |
| `Sync`     | All requested bytes were already cached; reply now |
| `Failed`   | Could not start async path; fall back to sync      |

The `Failed` arm (line 8058) falls through to a synchronous `irfs_read_bulk` loop (lines 8062–8140).  The question raised two weeks ago: does commit `b4be100`—which wires chunk-level population of `LIB_CACHE` as a side effect of every async fill—make `MmapFillResult::Failed` unreachable, rendering the sync fallback dead code?

**Note on commit `b4be100`:** This hash does not appear in the repository's visible history (50 commits are present; none match the prefix).  It was likely squashed or rebased away.  The lib_cache infrastructure it describes *is* present in the current source (see `LIB_CACHE`, `lib_cache_lookup_or_alloc`, `lib_cache_lookup` around line 3998–4092), so the analysis below treats the codebase as reflecting the post-b4be100 state.

---

## Static reachability verdict

`try_irfs_read_mmap` has **nine** `MmapFillResult::Failed` return sites.  Each is classified below.

### Startup-transient — **unreachable in steady state**

| Line | Condition | Why it clears permanently |
|------|-----------|--------------------------|
| `linux_srv.rs:3483` | `!IRFS_ASYNC_REGISTERED` | Set to `true` at line 4338 inside `try_register_irfs_async_reply_port`, called every main-loop iteration (line 13837).  Once set, never reset. |
| `linux_srv.rs:3486` | `!ensure_irfs_async_scratch()` | Returns `true` once `FS_ASYNC_SCRATCH_GRANTED` is set (line 2850).  The granted flag is permanent. |
| `linux_srv.rs:3519` | `get_initramfs_port() == 0` | Returns 0 only while `ns_lookup("initramfs")` fails.  After initramfs_srv publishes, `INITRAMFS_PORT` is cached as non-zero forever (line 4301). |

All three clear within seconds of boot and stay clear.

### Defensive — **impossible in the calling context**

| Line | Condition | Why the caller prevents it |
|------|-----------|---------------------------|
| `linux_srv.rs:3489` | `total_target == 0` | The call site has `if to_read > 0 { … try_irfs_read_mmap(…, to_read, …) }` at line 8021.  `to_read` is the argument mapped to `total_target`. |
| `linux_srv.rs:3492` | `total_target > u32::MAX \|\| aligned_len > u32::MAX` | `aligned_len` is page-aligned `len` from a `mmap(2)` syscall.  A 4 GiB+ mmap request would have been rejected by `personality_mmap_anon` long before this point. |

These are defensive guards that are correct to keep but can never fire from the `handle_mmap` call site.

### **Reachable in steady state — the fallback is live**

| Line | Condition | When it fires |
|------|-----------|---------------|
| `linux_srv.rs:3523` | `alloc_async_scratch_slot()` returns `None` | `FS_ASYNC_SCRATCH_SLOTS = 4` (line 2843).  Four scratch slots exist.  If four concurrent mmap fills are already in-flight when a fifth arrives, every slot has its bit set in `FS_ASYNC_SCRATCH_BUSY` and this returns `None`.  **Fires routinely during parallel library loading** (Xwayland pulls in 40+ libs; the eager-preload list at line 13683 runs sequentially, but concurrent process spawns overlap). |
| `linux_srv.rs:3529` | `async_alloc_slot()` returns `None` | `MAX_PENDING_ASYNC = 64` (line 865).  All 64 pending-async slots exhausted.  Less likely, but possible when pipe-async, UDS-async, FS-async, wait4-async, timerfd-async, and mmap-async operations all pile up simultaneously. |
| `linux_srv.rs:3585` | `send_nb_4(irfs, …) != 0` | Non-blocking send to initramfs_srv fails if its receive port queue is full (server busy / backpressure).  `send_nb` never blocks; it returns an error code instead.  **Fires under sustained IO load.** |

**Verdict: `MmapFillResult::Failed` is reachable in steady state via at least three independent paths.**  The `while total < to_read` sync fallback loop at lines 8062–8140 is **live code**.

### What b4be100 actually changed

The chunk-level cache-population commit ensures that every successfully completed async fill writes its fetched chunk into `LIB_CACHE[cache_slot].backing_va` and sets the corresponding bit in `chunks_cached`.  Once a file's entire content is cached, `lib_cache_lookup` at line 7996 short-circuits `handle_mmap` before `try_irfs_read_mmap` is ever called.

That eliminates `MmapFillResult::Failed` for **repeat mmaps of fully-cached files**.  It does **not** help:

- The *first* mmap of a file (cache is empty; async is attempted, and may fail under contention).
- Partial fills interrupted mid-way (not all chunks cached yet).
- The resource-exhaustion sites (lines 3523, 3529, 3585), which are independent of cache state.

---

## Local-data check Nadia must run

The `SHORT-READ mmap initramfs` debug_puts marker (line 8082) fires **only** inside the `while total < to_read` loop — i.e., only when the sync fallback is exercised and `irfs_read_bulk` returns zero or None.  There is no other occurrence of this exact string in the codebase:

```
grep -rn "SHORT-READ mmap initramfs" /home/user/telix/
# → userlib/bin/linux_srv.rs:8082   (only hit)
```

To check whether the fallback has fired recently on your machine, search your boot logs:

```bash
grep -c "SHORT-READ mmap initramfs" /path/to/your/boot_logs/*.txt 2>/dev/null
```

Substitute your actual log directory (e.g. `~/src/telix/boot_logs/` or wherever `debug_puts` output is captured).  A non-zero count means the sync fallback ran at least once.  Because `DEBUG_SHORT_READ` is `true` at line 3170, the marker is live in the current build — no rebuild needed to collect this data.

Note: the fallback can fire even when no `SHORT-READ mmap initramfs` line appears — that marker is only emitted when `irfs_read_bulk` returns `None` or `Some(0)` (the short-read sub-case within the loop).  A successful sync fallback (all bytes read via `irfs_read_bulk`) leaves no trace in the log.

---

## Cleanup diff

Because the fallback is reachable, the correct cleanup is **not deletion** but clarifying the comment to explain why the code survives b4be100:

```diff
--- a/userlib/bin/linux_srv.rs
+++ b/userlib/bin/linux_srv.rs
@@ -8058,7 +8058,10 @@ match try_irfs_read_mmap(
                             MmapFillResult::Failed => {
-                                // fall through to sync irfs_read_bulk loop
+                                // fall through to sync irfs_read_bulk loop.
+                                // Reaches here when scratch slots are exhausted
+                                // (FS_ASYNC_SCRATCH_SLOTS=4), pending-async slots
+                                // are full (MAX_PENDING_ASYNC=64), or send_nb to
+                                // initramfs_srv fails under backpressure.  The
+                                // lib_cache fast-path at line 7996 eliminates this
+                                // arm for files already fully cached, but the first
+                                // mmap and contention-time arrivals still land here.
                             }
```

This is a comment-only change; no functional difference.

If you want to also annotate the two defensive guards that can never fire from this call site (as documentation for future readers):

```diff
--- a/userlib/bin/linux_srv.rs
+++ b/userlib/bin/linux_srv.rs
@@ -3488,6 +3488,7 @@ fn try_irfs_read_mmap(
         if total_target == 0 {
+            // Unreachable from handle_mmap (caller guards with `if to_read > 0`).
             return MmapFillResult::Failed;
         }
         if total_target > u32::MAX as usize || aligned_len > u32::MAX as usize {
+            // Unreachable in practice: mmap_anon would reject a >4 GiB request first.
             return MmapFillResult::Failed;
         }
```

---

## Recommendation

**Do not remove the `while total < to_read` sync fallback loop.**  Commit `b4be100` made the `Failed` arm less common (repeat accesses to fully-cached files now short-circuit before reaching `try_irfs_read_mmap`), but it did not close the resource-exhaustion paths.  The three live sites — scratch-slot saturation (line 3523), pending-slot saturation (line 3529), and `send_nb` backpressure (line 3585) — all fire under realistic load: the scratch pool is only 4 slots deep, so any burst of more than four concurrent mmap faults that miss the lib_cache full-hit check will push the fifth into the sync path.  The fallback is load-shedding safety, not dead code.  Apply the comment-only diff above to document why the arm survives the cache refactor, and note in the commit message that b4be100 reduced the frequency but not the reachability.
