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
/// loader").  Setting this to a non-zero pattern makes the source
/// unmistakable: a 64-bit dereference of a register holding the
/// repeated pattern is a non-canonical #GP and tells us the value
/// came from a fresh anon page.
///
/// **Default 0x00** — POSIX guarantees mmap(MAP_ANONYMOUS) returns
/// zero, and Linux programs (including glibc) rely on it.  Flip to
/// 0xCD only for kernel-side diagnostic boots.  For the more common
/// case of catching uninitialised-malloc bugs, prefer the userspace
/// path: glibc honours `MALLOC_PERTURB_=N` to fill malloc()'d memory
/// with `~N` and freed memory with `N` — same diagnostic value
/// without violating mmap semantics.
pub const ANON_POISON_BYTE: u8 = 0x00;

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
