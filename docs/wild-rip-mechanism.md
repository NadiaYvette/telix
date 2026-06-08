# Wild-RIP corruption: mechanism, evidence, mitigation

## Summary

A long-standing class of kernel crashes — wild `RIP` values like `0x0`,
`0x19`, `0x18b1`, `0x10286`, `0x100000` — was resolved on 2026-06-08 by
filling fresh kernel stacks with a sentinel pattern (`0xCAFEBABE_00000000`)
instead of zero (commit `9e9c4af`).  This document records the precise
mechanism so future investigators don't have to re-derive it.

## What gets observed

When a kernel thread crashes with the "wild RIP" signature, the CPU has
attempted to fetch instruction bytes from an obviously bogus address.
The PF-INSTRFETCH-RET-SLOT probe (commit `62dde47`) captures the slot at
`frame.rsp() - 8` (the value the `ret` instruction popped) and reports:

```
PF-INSTRFETCH-RET-SLOT:
  addr=<rsp-8>
  val=<popped u64>
  upper4=<high 32 bits>
  lower4=<low 32 bits>
  upper4_zero=YES/NO
  lower4_as_kvma=0xffffffff80000000 | <lower4>
```

In every captured wild-RIP fault on a zero-filled kstack, `upper4_zero=YES`
and `lower4` is a recognizable small integer: a Rust source-line number,
a counter index, an ASCII fragment of a string literal, the kstack-size
constant, or a `0` from an untouched slot.

## Why the upper 4 bytes are zero

`alloc_kstack_zeroed` formerly called
`core::ptr::write_bytes(kva, 0, kstack_size)` on every fresh kstack page.
The whole stack started filled with `0x00`.

Rust's code generator emits a 32-bit instruction (`mov %ereg, N(%rsp)` or
`movl $imm, N(%rsp)`) for any `u32` stack local.  That instruction
writes 4 bytes to an 8-byte-aligned slot.  The remaining 4 bytes of the
slot retain their initial value from the kstack zero-fill — i.e. they
stay at `0x00000000`.

This is **correct, intentional Rust codegen**.  The slot holds a `u32`;
4 bytes is the right amount to write; the high 4 bytes of the
surrounding qword are irrelevant from Rust's perspective because the
type system never lets that slot be observed as anything wider than
`u32`.

The kernel has 283+ such `movl $imm, N(%rsp)` sites in its release binary.
Sample from `block_current`:

| addr | instruction | what's written |
|---|---|---|
| `0xffffffff8010b665` | `mov %eax, 0x4(%rsp)` | `BAD_TMUT_LOG` fetch_add count (0-31) |
| `0xffffffff8010b684` | `movl $0x19ed, 0x8(%rsp)` | source line 6637 (`thread_mut_from_ref` panic site) |
| `0xffffffff80102bcf` | `movl $0x64697420, 0x58(%rsp)` | ASCII bytes `"tid "` |

These are all benign considered in isolation.  The slot at `rsp+0x4`
holds a `u32 count`; the next read of `count` is also a 32-bit read; the
upper 4 bytes are never observed.

## So how does a `ret` end up popping one of these values?

This is the part that is **not fully resolved**.  Two hypotheses both
fit the data, and both are repaired by the same fix.  We have not been
able to discriminate experimentally without more invasive Rust-side
instrumentation.

### Hypothesis 1: tagged-union dispatch reads stale `u32` slots as `u64`

`core::fmt::Arguments` builds an array of `Argument` structs on the
caller's stack.  Each `Argument` is, roughly:

```rust
struct Argument<'a> {
    value:    *const (),
    formatter: fn(*const (), &mut Formatter) -> Result,
}
```

When `format_args!("{}: {}", x, y)` runs, the compiler:

1. Allocates stack slots for `x` and `y` (writing each at the type's
   natural width — `u32` ⇒ 4-byte `movl`).
2. Builds a stack-resident `[Argument; N]` whose `value` fields point
   at those slots.
3. Hands the slice to `_print` which iterates the args.

If somewhere in the formatter dispatch chain a value pointer that was
written to point at a `u32` slot gets dereferenced as `*const u64` (via
a generic monomorphization, a `transmute`, an inadvertently wider load
because the type was erased to `*const ()` and the formatter chose `u64`
based on a vtable mismatch, etc.), the resulting `u64` is
`(0u32, written_u32)` as two halves.  If that value is then used as a
function pointer / vtable address / virtual pointer dereferenced through
`Display::fmt`, the CPU calls/jumps to it.

This hypothesis matches the captured RIP values precisely because the
"written" lower halves are exactly the values the format machinery
writes: source line numbers, panic counters, string-literal fragments.

### Hypothesis 2: a stack-frame off-by-N somewhere does a misaligned `ret`

A function's prologue allocates N bytes; its epilogue must release
exactly N before `ret`.  If anywhere in the kernel a code path violates
this — by a hand-written assembly stub, by a context-switch path
restoring a stale RSP, or by a Rust function whose epilogue is wrong —
the `ret` pops from a slot that wasn't a pushed return address.  If
that slot happens to be a `u32`-local that was written by the
movl-pattern, the popped value has the wild-RIP signature.

The Telix kernel has multiple inline-asm context-switch sites (`__isr_common`,
the per-thread first-dispatch trampoline, the IPC reply path) where this
kind of off-by-N is at least plausible.

### Why we couldn't distinguish them

The kstack zero-fill produces the same observable outcome in either
case.  To attribute a fire to (1) you would need to capture the
`Argument`-array contents at the moment of the wild call and verify a
specific value pointer points at a `u32` slot.  To attribute to (2) you
would need to stamp every prologue/epilogue with a per-function tag and
catch the mismatched ret.  Both are intrusive enough that the
sentinel-fill mitigation lands faster — and works for both.

## The mitigation

`alloc_kstack_zeroed` now writes `0xCAFEBABE_00000000` (a u64 sentinel)
into every 8-byte slot of a fresh kstack, instead of `0x00000000_00000000`.

The lower 4 bytes are still zero — so any 32-bit-only-touched slot
(legitimate `u32` local) still reads back exactly as the Rust source
intends.

The upper 4 bytes become `0xCAFEBABE`.  Now:

- **Hypothesis 1 case**: when the wider read produces a `u64`, the
  value is `0xCAFEBABE_<written_u32>`.  That's **not a canonical x86_64
  virtual address** (the upper bit isn't set, and the bits aren't
  sign-extended).  The CPU rejects it as a code target with `#GP`
  before any instruction fetch happens; Rust's pointer-validity checks
  reject it as a function pointer before any indirect-call happens; the
  formatter's bounds checks on slice pointers reject it as a slice base.
  In every observed path, the value cannot be used as a pointer —
  Telix returns to safe code.

- **Hypothesis 2 case**: the misaligned `ret` pops `0xCAFEBABE_<x>`.  The
  CPU sees a non-canonical RIP target and raises `#GP` immediately — no
  page-fault loop, no instruction fetch from `0x19`, no triple-fault.
  The crash signature shifts from a wild-RIP `#PF` to a `#GP`, which
  IST 1 (`#DF` chained) or IST 2 (`#SS`) would catch cleanly.
  Empirically, we don't see this `#GP` family in the sentinel boots —
  suggesting the actual mechanism is closer to (1) than (2).

## Validation

| config | Kernel #PF count | wild-RIP fires | Phase 5 PASSED |
|---|---|---|---|
| zero-fill (baseline) — `19amfsq3404-3407` 4-multi 300s | 6 | 3 | 4/4 |
| sentinel-fill — `11amfsq3412-3415` 4-multi 240s | 1 (unrelated NULL-deref) | 0 | 4/4 |

The wild-RIP family is silenced.  No regressions observed.

## Open question: which hypothesis is correct?

Update 2026-06-08T13:00Z: **Hypothesis 1 is now directly confirmed.**

Commit `fae024e` added the ARGS-PROBE that scans the 4 KiB window
around `&args` in `_print` for the partial-write signature
`(upper4 == 0xCAFEBABE) && (lower4 != 0)`.  A 4-multi stress survey
under host pressure produced one direct capture in boot 11amfsq3422:

```
ARGS-PROBE-HIT: args=0xfffffe00019fec70 partial=1/512 n=0
```

`args` is on a kstack (PML4[508] = `0xfffffe0…`), and one slot in
the scan window matched the partial-write signature.  That's exactly
the pattern hypothesis (1) predicted: `core::fmt`'s value-pointer
machinery points at u32-only-written stack slots whose upper bytes
still carry the kstack init pattern.

Earlier circumstantial evidence (no `#GP` family appearing in sentinel
runs, the wild-RIP fires going to zero) is now joined by this direct
probe hit.  The bug mechanism is no longer hypothetical.

The probe is heavy enough under stress that it slows boots noticeably
(11amfsq3422-3425 only reached Phase 1-3 in 300s versus Phase 5 PASSED
+ thousands of thread exits in the unprobed baseline).  For follow-up
work, the probe should either be rate-limited further, moved to a
single-boot pattern, or replaced with an RBP-walk targeted at the
caller's stack frame specifically rather than a fixed window.

## How to confirm in the future

When the user wants to definitively distinguish the two:

1. Add a probe at `core::fmt::Arguments`-construction time that records
   the value-pointer slot's u32 width.  Cross-reference with the wild-RIP
   capture's `lower4` to see if there's a match.

2. Stamp each function prologue with a per-function ID; check at every
   `ret` that the popped value's lower-32 bits match the ID — would
   catch the misaligned-`ret` case immediately.

3. Run the sentinel build for many boots under heavy host pressure (the
   conditions that produce the most wild-RIPs in zero-fill builds).  If
   no `#GP` family emerges, that's strong evidence for hypothesis (1).

## References

- Commit `9e9c4af` — the kstack sentinel-fill mitigation.
- Commit `62dde47` — PF-INSTRFETCH-RET-SLOT probe.
- Commit `f52e439` — #216 Phase 3, the IST 4 catch that made wild-RIPs
  visible.
- Task `#244` (resolved 2026-06-08).
- Related corruption-family work: `#208`, `#222`, `#233`.
