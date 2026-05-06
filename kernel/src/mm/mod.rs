pub mod aspace;
pub mod cowgroup;
pub mod extent;
pub mod fault;
pub mod frame;
pub mod hat;
pub mod radix_pt;

/// Byte used to fill freshly-allocated user-facing anonymous pages.
///
/// Diagnostic: programs aren't supposed to read freshly-allocated
/// anon pages without writing first.  The "garbage" appearing in a
/// register loaded from such memory used to be 0x00 (indistinguishable
/// from "uninitialized happens to be zero" or "deliberately zeroed by
/// loader").  Setting this to 0xCD makes the source unmistakable:
/// any 64-bit dereference of a register holding 0xCDCDCDCDCDCDCDCD
/// is a non-canonical-address #GP and tells us the value came from
/// a fresh anon page.
///
/// Set to 0x00 to disable poisoning and restore baseline behaviour.
pub const ANON_POISON_BYTE: u8 = 0xCD;

pub mod grant;
pub mod kswapd;
pub mod object;
pub mod page;
pub mod paged_array;
pub mod pager;
pub mod pagevec;
pub mod phys;
pub mod ptshare;
pub mod slab;
pub mod stats;
pub mod swap;
pub mod vma;
pub mod vmatree;
pub mod wsclock;
pub mod zeropool;
