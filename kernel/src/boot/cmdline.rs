//! Kernel command line parser.
//!
//! Parses `key=value` pairs from the kernel command line, which can come from:
//! - QEMU `-append "..."` (via Multiboot1 on x86_64, DTB on aarch64/riscv64)
//! - Device tree `/chosen/bootargs` property
//! - YAMON environment (MIPS64 Malta)
//!
//! Must be called before the physical allocator is initialized, since
//! `page_mmushift` affects allocation granularity.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// Maximum command line length we support.
const MAX_CMDLINE: usize = 1024;

/// Maximum number of unknown key=value pairs to store.
const MAX_EXTRA_PARAMS: usize = 16;

/// Maximum key or value length for extra params.
const MAX_PARAM_LEN: usize = 64;

/// Raw command line bytes (copied from firmware data before it's overwritten).
static mut CMDLINE_BUF: [u8; MAX_CMDLINE] = [0; MAX_CMDLINE];
static CMDLINE_LEN: AtomicUsize = AtomicUsize::new(0);

/// Boot configuration populated from the command line.
///
/// All fields are atomic so they can be read from any context after boot.
/// Written once during early boot by the BSP.
pub struct BootConfig {
    /// PAGE_MMUSHIFT value (0 = use compile-time default).
    /// Valid range: 0 (4K), 2 (16K), 4 (64K), 5 (128K), 6 (256K).
    pub page_mmushift: AtomicU8,

    /// Console device name index (0 = default serial).
    pub console: AtomicU8,

    /// Log level (0 = quiet, 7 = debug). Default: 5 (notice+).
    pub loglevel: AtomicU8,

    /// Whether command line was successfully parsed.
    pub parsed: AtomicU8,
}

pub static BOOT_CONFIG: BootConfig = BootConfig {
    page_mmushift: AtomicU8::new(0),
    console: AtomicU8::new(0),
    loglevel: AtomicU8::new(5),
    parsed: AtomicU8::new(0),
};

/// Extra key=value pairs not recognized by the built-in parser.
/// Personality layers or servers can query these.
struct ExtraParam {
    key: [u8; MAX_PARAM_LEN],
    key_len: u8,
    val: [u8; MAX_PARAM_LEN],
    val_len: u8,
}

static mut EXTRA_PARAMS: [ExtraParam; MAX_EXTRA_PARAMS] = {
    const EMPTY: ExtraParam = ExtraParam {
        key: [0; MAX_PARAM_LEN],
        key_len: 0,
        val: [0; MAX_PARAM_LEN],
        val_len: 0,
    };
    [EMPTY; MAX_EXTRA_PARAMS]
};
static EXTRA_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Save the raw command line from firmware data into our buffer.
/// Must be called before the physical allocator overwrites firmware memory.
pub fn save_cmdline(cmdline: &[u8]) {
    let len = cmdline.len().min(MAX_CMDLINE);
    unsafe {
        CMDLINE_BUF[..len].copy_from_slice(&cmdline[..len]);
    }
    CMDLINE_LEN.store(len, Ordering::Release);
}

/// Parse the saved command line, populating BOOT_CONFIG.
/// Call after save_cmdline(), before phys::init().
pub fn parse() {
    let len = CMDLINE_LEN.load(Ordering::Acquire);
    if len == 0 {
        BOOT_CONFIG.parsed.store(1, Ordering::Release);
        return;
    }

    let cmdline = unsafe { &CMDLINE_BUF[..len] };

    // Tokenize on whitespace, parse each key=value pair.
    for token in CmdlineTokenizer::new(cmdline) {
        if let Some(eq_pos) = token.iter().position(|&b| b == b'=') {
            let key = &token[..eq_pos];
            let val = &token[eq_pos + 1..];
            handle_param(key, val);
        } else {
            // Boolean flag (no '='), treat as key with empty value.
            handle_param(token, &[]);
        }
    }

    BOOT_CONFIG.parsed.store(1, Ordering::Release);
}

fn handle_param(key: &[u8], val: &[u8]) {
    match key {
        b"page_mmushift" => {
            if let Some(n) = parse_u64(val) {
                let shift = n as u8;
                // Validate: shift must produce a power-of-two page count.
                // 0→4K (1 MMU page), 2→16K, 4→64K, 5→128K, 6→256K
                if shift <= 6 {
                    BOOT_CONFIG.page_mmushift.store(shift, Ordering::Relaxed);
                }
            }
        }
        b"loglevel" => {
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.loglevel.store((n as u8).min(7), Ordering::Relaxed);
            }
        }
        b"console" => {
            // Future: map console name to index.
            let _ = val;
        }
        _ => {
            // Store as extra param for personality layers.
            store_extra(key, val);
        }
    }
}

fn store_extra(key: &[u8], val: &[u8]) {
    let idx = EXTRA_COUNT.load(Ordering::Relaxed);
    if idx >= MAX_EXTRA_PARAMS {
        return;
    }
    let kl = key.len().min(MAX_PARAM_LEN);
    let vl = val.len().min(MAX_PARAM_LEN);
    unsafe {
        EXTRA_PARAMS[idx].key[..kl].copy_from_slice(&key[..kl]);
        EXTRA_PARAMS[idx].key_len = kl as u8;
        EXTRA_PARAMS[idx].val[..vl].copy_from_slice(&val[..vl]);
        EXTRA_PARAMS[idx].val_len = vl as u8;
    }
    EXTRA_COUNT.store(idx + 1, Ordering::Release);
}

/// Look up an extra parameter by key. Returns None if not found.
#[allow(dead_code)]
pub fn get_extra(key: &[u8]) -> Option<&'static [u8]> {
    let count = EXTRA_COUNT.load(Ordering::Acquire);
    for i in 0..count {
        let p = unsafe { &EXTRA_PARAMS[i] };
        let k = &p.key[..p.key_len as usize];
        if k == key {
            return Some(unsafe {
                core::slice::from_raw_parts(p.val.as_ptr(), p.val_len as usize)
            });
        }
    }
    None
}

/// Get the configured PAGE_MMUSHIFT, or the compile-time default if not set.
pub fn page_mmushift() -> u8 {
    let val = BOOT_CONFIG.page_mmushift.load(Ordering::Relaxed);
    if val == 0 {
        // Use compile-time default.
        crate::mm::page::PAGE_MMUSHIFT as u8
    } else {
        val
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a decimal integer from ASCII bytes.
fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(result)
}

/// Iterator over whitespace-delimited tokens in a byte slice.
struct CmdlineTokenizer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CmdlineTokenizer<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for CmdlineTokenizer<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Skip whitespace.
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        // Find end of token.
        while self.pos < self.data.len() && !self.data[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
        Some(&self.data[start..self.pos])
    }
}
