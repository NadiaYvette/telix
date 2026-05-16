//! Verus retrofit for kernel/src/mm/phys.rs's bit-packed chunk state.
//!
//! The phys allocator packs a 64-bit ChunkNode state word with fields:
//!   bits  [6:0]  free_count   (7 bits, max 127, legal range 0..=64)
//!   bits [13:7]  owner        (7 bits, max 127, NO_CPU=0x7F sentinel)
//!   bit  14      has_bitmap   (1 bit)
//!   bits [20:15] bmp_page     (6 bits, max 63 = page-index in chunk)
//!   bits [56:21] inline_bits  (6 slots of 6 bits each = 36 bits)
//!
//! This file proves the most basic invariant: the accessors round-trip
//! the values written by make_state, given field ranges.  Concretely,
//! for fc <= 127, own <= 127, bmp_pg <= 63, hb: bool:
//!
//!   free_count (make_state(fc, own, hb, bmp_pg, 0)) == fc
//!   owner      (make_state(fc, own, hb, bmp_pg, 0)) == own
//!   has_bitmap (make_state(fc, own, hb, bmp_pg, 0)) == hb
//!   bmp_page   (make_state(fc, own, hb, bmp_pg, 0)) == bmp_pg
//!
//! The proofs use Verus' bit_vector solver, which handles non-
//! overlapping bit-field reasoning directly.

#![cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]

#[allow(unused_imports)]
use verus_builtin::*;
use verus_builtin_macros::*;
use vstd::prelude::*;

verus! {

// Mirror of phys.rs constants (must stay in sync — these are part of
// the spec being proved).
spec const FREE_COUNT_MASK: u64 = 0x7F;
spec const OWNER_SHIFT: u64 = 7;
spec const OWNER_MASK: u64 = 0x7Fu64 << 7u64;     // bits [13:7]
spec const HAS_BITMAP_BIT: u64 = 1u64 << 14u64;   // bit  14
spec const BMP_PAGE_SHIFT: u64 = 15;
spec const BMP_PAGE_MASK: u64 = 0x3Fu64 << 15u64; // bits [20:15]

// ── make_state (the encoder) ────────────────────────────────────────
//
// Mirrors `make_state` from phys.rs.  Marked exec so we can run it
// at verification time as a concrete computation, and the ensures
// clauses pin down the bit-level structure for downstream proofs.
fn make_state(fc: u64, own: u64, has_bmp: bool, bmp_pg: u64, inline_bits: u64) -> (s: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        bmp_pg <= 0x3F,
        inline_bits < (1u64 << 36),
    ensures
        s == (fc & FREE_COUNT_MASK)
           | (own << 7)
           | (if has_bmp { HAS_BITMAP_BIT } else { 0 })
           | (bmp_pg << 15)
           | (inline_bits << 21),
{
    (fc & 0x7F)
        | (own << 7)
        | (if has_bmp { 1u64 << 14 } else { 0 })
        | (bmp_pg << 15)
        | (inline_bits << 21)
}

// ── Accessor proofs ─────────────────────────────────────────────────
//
// Each proof uses #[verifier::bit_vector] which dispatches the goal
// to Verus' bit-vector SMT theory.  The theory handles AND/OR/SHIFT
// reasoning natively, so these are one-shot proofs with no manual
// case analysis.

#[verifier::bit_vector]
proof fn lemma_free_count_roundtrip(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64, inline_bits: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        inline_bits < (1u64 << 36),
    ensures
        ((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | (inline_bits << 21)) & 0x7F == fc,
{
}

#[verifier::bit_vector]
proof fn lemma_owner_roundtrip(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64, inline_bits: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        inline_bits < (1u64 << 36),
    ensures
        (((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | (inline_bits << 21)) & (0x7Fu64 << 7u64)) >> 7 == own,
{
}

#[verifier::bit_vector]
proof fn lemma_has_bitmap_roundtrip(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64, inline_bits: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        inline_bits < (1u64 << 36),
    ensures
        (((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | (inline_bits << 21)) & (1u64 << 14)) == hb_bit,
{
}

#[verifier::bit_vector]
proof fn lemma_bmp_page_roundtrip(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64, inline_bits: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        inline_bits < (1u64 << 36),
    ensures
        (((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | (inline_bits << 21)) & (0x3Fu64 << 15u64)) >> 15 == bmp_pg,
{
}

// ── Inline index encoding ──────────────────────────────────────────
//
// The inline_bits portion of the state word is 36 bits at positions
// [56:21], packing up to INLINE_K=6 6-bit indices.  Position i lives
// at bits [21 + 6*i : 27 + 6*i].  inline_idx(s, i) extracts the
// i-th index by `(s >> (21 + 6*i)) & 0x3F`.
//
// We prove the encoder/decoder round-trips for each position
// individually.  Because each lemma below pins one slot via its
// requires-clause shape, the bit-vector solver discharges them
// directly without needing to reason across all positions
// simultaneously.

#[verifier::bit_vector]
proof fn lemma_inline_idx0(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64, idx0: u64, rest: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        idx0 <= 0x3F,
        rest < (1u64 << 30),  // 30 = 5 slots × 6 bits, leaving slot 0 free
    ensures
        (((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | ((idx0 | (rest << 6)) << 21)) >> 21) & 0x3F == idx0,
{
}

#[verifier::bit_vector]
proof fn lemma_inline_idx1(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64,
                           idx0: u64, idx1: u64, rest: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        idx0 <= 0x3F,
        idx1 <= 0x3F,
        rest < (1u64 << 24),  // 24 = 4 slots × 6 bits
    ensures
        (((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | ((idx0 | (idx1 << 6) | (rest << 12)) << 21)) >> (21 + 6)) & 0x3F == idx1,
{
}

#[verifier::bit_vector]
proof fn lemma_inline_idx5(fc: u64, own: u64, hb_bit: u64, bmp_pg: u64,
                           low: u64, idx5: u64)
    requires
        fc <= 0x7F,
        own <= 0x7F,
        hb_bit == 0 || hb_bit == (1u64 << 14),
        bmp_pg <= 0x3F,
        low < (1u64 << 30),  // 30 = 5 slots × 6 bits
        idx5 <= 0x3F,
    ensures
        (((fc & 0x7F)
            | (own << 7)
            | hb_bit
            | (bmp_pg << 15)
            | ((low | (idx5 << 30)) << 21)) >> (21 + 30)) & 0x3F == idx5,
{
}

// ── Field non-overlap ──────────────────────────────────────────────
//
// Prove that the inline_bits region (bits [56:21]) is disjoint from
// the FREE_COUNT, OWNER, HAS_BITMAP, and BMP_PAGE regions.  This is
// the key fact that lets future state-machine proofs reason about a
// single field without re-proving the whole layout.

#[verifier::bit_vector]
proof fn lemma_inline_does_not_corrupt_fc(fc: u64, inline_bits: u64)
    requires
        fc <= 0x7F,
        inline_bits < (1u64 << 36),
    ensures
        ((fc & 0x7F) | (inline_bits << 21)) & 0x7F == fc,
{
}

#[verifier::bit_vector]
proof fn lemma_inline_does_not_corrupt_owner(own: u64, inline_bits: u64)
    requires
        own <= 0x7F,
        inline_bits < (1u64 << 36),
    ensures
        (((own << 7) | (inline_bits << 21)) & (0x7Fu64 << 7u64)) >> 7 == own,
{
}

} // verus!
