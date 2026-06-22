//! Kernel command line parser.
//!
//! Parses `key=value` pairs from the kernel command line, which can come from:
//! - QEMU `-append "..."` (via Multiboot1 on x86_64, DTB on aarch64/riscv64)
//! - Device tree `/chosen/bootargs` property
//! - YAMON environment (MIPS64 Malta)
//!
//! Must be called before the physical allocator is initialized, since
//! `page_mmushift` affects allocation granularity.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

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

    /// Cap on the number of CPUs to bring online (0 = no cap, use firmware
    /// detected count). Mirrors Linux `nr_cpus=N`.
    pub nr_cpus: AtomicU32,

    /// #173 Phase 5 A/B knob.  0 = leave the legacy default
    /// (`DISPATCH_USE_CLAIM_HELPER` keeps its compile-time value);
    /// 1 = force ON; 2 = force OFF.  Lets the multi-boot harness compare
    /// matched gate states without rebuilding the kernel.
    pub dispatch_claim_helper: AtomicU8,

    /// #228 alloc/free hammer kthread count.  0 = disabled (default);
    /// N = spawn N hammer kthreads that loop alloc_page → write
    /// sentinel → read-back → free.  See mm/hammer.rs.
    pub alloc_hammer: AtomicU8,

    /// #228 PERSISTENT hammer kthread count.  0 = disabled (default);
    /// N = spawn N kthreads that allocate PERSISTENT_CHUNKS order=4
    /// chunks each, fill with sentinel, never free, verify in a loop.
    /// Mimics kstack lifecycle to surface path-specific corruption.
    pub alloc_hammer_persist: AtomicU8,

    /// #228 rv64 hardware watchpoint on tid=4 saved_sp.  1 = enable.
    /// Requires QEMU with `Sdtrig` extension (default `-cpu rv64` does
    /// NOT support it — `csrrw tselect` raises Illegal Instruction).
    /// On real hardware or `-cpu max` setups, arms a S-mode store
    /// watchpoint on tid=4's Thread.saved_sp slot the first time
    /// `write_saved_sp` touches it; the next non-write_saved_sp store
    /// to that slot traps Breakpoint and logs the offending PC.
    pub wp_savedsp: AtomicU8,

    /// #228 NR_CPUS watchpoint enable.  Like `wp_savedsp` but arms the WP on
    /// the `NR_CPUS` static (`smp::nr_cpus_addr()`) on every hart instead of a
    /// thread `saved_sp` slot — to catch the wild-write that scribbles
    /// `num_cpus` (the `scheduler.rs:7157` OOB).  Requires Sdtrig QEMU.
    pub wp_nrcpus: AtomicU8,

    /// #228 kstack-free liveness guard toggle: 1 = PREVENTIVE (skip freeing a
    /// kstack a live thread still owns — the fix); 0 = detect+count but free
    /// anyway (control, reproduces the bug).  Default 1.  One binary A/Bs the fix.
    pub kstack_free_guard: AtomicU8,

    /// Whether command line was successfully parsed.
    pub parsed: AtomicU8,
}

pub static BOOT_CONFIG: BootConfig = BootConfig {
    page_mmushift: AtomicU8::new(0),
    console: AtomicU8::new(0),
    loglevel: AtomicU8::new(5),
    nr_cpus: AtomicU32::new(0),
    dispatch_claim_helper: AtomicU8::new(0),
    alloc_hammer: AtomicU8::new(0),
    alloc_hammer_persist: AtomicU8::new(0),
    wp_savedsp: AtomicU8::new(0),
    wp_nrcpus: AtomicU8::new(0),
    kstack_free_guard: AtomicU8::new(1),
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
        b"nr_cpus" => {
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.nr_cpus.store(n as u32, Ordering::Relaxed);
            }
        }
        b"console" => {
            // Future: map console name to index.
            let _ = val;
        }
        b"dispatch_claim_helper" => {
            // #173 Phase 5 A/B knob.  Accepts 0|1|2 (see BootConfig docs).
            if let Some(n) = parse_u64(val) {
                if n <= 2 {
                    BOOT_CONFIG.dispatch_claim_helper.store(n as u8, Ordering::Relaxed);
                }
            }
        }
        b"alloc_hammer" => {
            // #228 alloc/free hammer thread count.  Caps at 255.
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.alloc_hammer.store(n.min(255) as u8, Ordering::Relaxed);
            }
        }
        b"alloc_hammer_persist" => {
            // #228 persistent-allocation hammer thread count.  Caps at 255.
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.alloc_hammer_persist.store(n.min(255) as u8, Ordering::Relaxed);
            }
        }
        b"wp_savedsp" => {
            // #228 rv64 hardware watchpoint enable.  Requires QEMU
            // with Sdtrig extension; default rv64 cpu does not.
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.wp_savedsp.store(n.min(255) as u8, Ordering::Relaxed);
            }
        }
        b"wp_nrcpus" => {
            // #228 NR_CPUS wild-write watchpoint.  Same Sdtrig requirement.
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.wp_nrcpus.store(n.min(255) as u8, Ordering::Relaxed);
            }
        }
        b"kstack_free_guard" => {
            // #228 fix toggle: 1=preventive (fix, default), 0=detect-only (control).
            if let Some(n) = parse_u64(val) {
                BOOT_CONFIG.kstack_free_guard.store(n.min(255) as u8, Ordering::Relaxed);
            }
        }
        b"real_park" => {
            // #228 CLASS-2 A/B: runtime override of BLOCK_REAL_PARK (real-park
            // path).  1=ON, 0=OFF.  Parsed before scheduler threads block, so the
            // first block_current sees the override.  Lets one binary A/B whether
            // the residual wild-PC (sepc=0x200000020) is real-park-specific.
            if let Some(n) = parse_u64(val) {
                crate::sched::scheduler::BLOCK_REAL_PARK
                    .store(n != 0, core::sync::atomic::Ordering::Relaxed);
            }
        }
        b"sched_trace" => {
            // #H14-perf: re-enable the hot-path scheduler debug traces (TS-IN,
            // IDLE-SP-WRITE, KSTACK-ALLOC, KUSER-SPAWN, EXIT-THREAD-ENTRY), which
            // default OFF to keep the polled-UART out of the boot's hot path.
            // 1=ON, 0=OFF.  Parsed at boot, before those sites first fire.
            if let Some(n) = parse_u64(val) {
                crate::sched::scheduler::SCHED_TRACE_VERBOSE
                    .store(n != 0, core::sync::atomic::Ordering::Relaxed);
            }
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

/// Optional cap on the number of CPUs from `nr_cpus=N` on the command line.
/// `None` means no cap (use firmware-detected count as-is).
pub fn nr_cpus_cap() -> Option<usize> {
    let v = BOOT_CONFIG.nr_cpus.load(Ordering::Relaxed);
    if v == 0 { None } else { Some(v as usize) }
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
