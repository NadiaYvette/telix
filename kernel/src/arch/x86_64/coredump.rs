//! Userspace fault core-dump emitter (x86_64).
//!
//! Tier-3 strategy: emit machine-readable lines into the debug log
//! containing all the state needed to reconstruct an ELF64 core file
//! on the host.  The kernel only handles raw extraction; the host
//! script (`tools/extract-core.py`) parses the markers, decodes the
//! base64'd memory blobs, and assembles a `*.core` file that gdb can
//! load directly (with debuginfod resolving symbols).
//!
//! Wire format (one fault → one block bracketed by markers):
//!
//!   [CORE-START tid=N task=N vector=N error=N rip=H rsp=H rbp=H]
//!   [CORE-REGS r15=H r14=H ... rax=H rip=H cs=H rflags=H rsp=H ss=H]
//!   [CORE-MEM va=H len=N b64=...]    (one or more — stack pages)
//!   [CORE-LIB-REF tid=N]              (cue host to scrape preceding [lib-load] lines for this task)
//!   [CORE-END tid=N]
//!
//! Memory is base64-encoded in 64-byte chunks per line (88 chars
//! base64) so the serial port doesn't choke on a single huge line and
//! the host parser can consume incrementally.
//!
//! Best-effort throughout: re-faulting during dump is acceptable since
//! the thread is being killed anyway; we just lose later lines.

use super::exception::ExceptionFrame;

/// How many stack pages to dump around RSP.  4 KiB × 2 = 8 KiB:
/// captures the entire frame chain we'd reasonably want plus saved
/// caller state.  Trade-off: serial port is slow, so each extra page
/// costs ~64 log lines.
const STACK_PAGES: usize = 2;
const PAGE_SIZE: usize = 4096;

/// Base64 alphabet (RFC 4648 §4 — standard, with `+/` not `-_`).
const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` (≤ 64 bytes) into `out` using standard base64.
/// Returns the number of base64 chars written.
fn b64_encode(input: &[u8], out: &mut [u8]) -> usize {
    let mut i = 0;
    let mut o = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out[o] = B64[((b0 >> 2) & 0x3F) as usize];
        out[o + 1] = B64[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize];
        out[o + 2] = B64[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize];
        out[o + 3] = B64[(b2 & 0x3F) as usize];
        i += 3;
        o += 4;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i];
        out[o] = B64[((b0 >> 2) & 0x3F) as usize];
        out[o + 1] = B64[((b0 << 4) & 0x3F) as usize];
        out[o + 2] = b'=';
        out[o + 3] = b'=';
        o += 4;
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out[o] = B64[((b0 >> 2) & 0x3F) as usize];
        out[o + 1] = B64[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize];
        out[o + 2] = B64[((b1 << 2) & 0x3F) as usize];
        out[o + 3] = b'=';
        o += 4;
    }
    o
}

/// Read CR3 to get the active address space's PML4 root.
#[inline]
fn current_pml4() -> usize {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }
    (cr3 & !0xfff) as usize
}

/// Page-mapped check.  Walks the active PML4 — does NOT itself fault on
/// missing user mapping.  Boot 448 hit a kernel #PF inside the dump path
/// when the stack walk crossed below RSP into an unmapped guard page;
/// gating reads on this check stops that.
#[inline]
fn user_va_mapped(va: u64) -> bool {
    crate::arch::x86_64::mm::translate_va(current_pml4(), va as usize).is_some()
}

/// Read a u64 from userspace, returning None if the page is unmapped.
/// Exposed for the RBP-chain walker and STACK[0..8] dump in
/// exception.rs — those code paths used raw read_volatile and crashed
/// the kernel on unmapped pages (boot 448).
pub(crate) fn safe_read_user_u64(va: u64) -> Option<u64> {
    if va < 0x1000 || va.checked_add(8).is_none() {
        return None;
    }
    if !user_va_mapped(va) {
        return None;
    }
    // 8-byte read could straddle a page boundary; if the second byte's
    // page differs from the first, verify it too.
    if (va & !0xfff) != ((va + 7) & !0xfff) && !user_va_mapped(va + 7) {
        return None;
    }
    Some(unsafe { core::ptr::read_volatile(va as *const u64) })
}

/// Try to read up to `len` bytes starting at `va` into `out`.  Stops at
/// the first unmapped page.  Performs a page-table walk only at page
/// boundaries (4 KiB granularity) — once a page is verified mapped,
/// subsequent bytes within it are read directly.
fn user_read_block(va: u64, out: &mut [u8]) -> usize {
    let mut got = 0;
    let mut current_page: u64 = u64::MAX; // sentinel — never matches a real page
    let mut current_page_mapped = false;
    for i in 0..out.len() {
        let cur_va = va + i as u64;
        if cur_va < 0x1000 {
            return got;
        }
        let page = cur_va & !0xfff;
        if page != current_page {
            current_page = page;
            current_page_mapped = user_va_mapped(page);
        }
        if !current_page_mapped {
            return got;
        }
        out[i] = unsafe { core::ptr::read_volatile(cur_va as *const u8) };
        got += 1;
    }
    got
}

/// Map a 4-bit AMD64 register number (REX.R/B-extended) to a name.
fn reg64_name(num: u8) -> &'static str {
    match num & 0xf {
        0 => "rax", 1 => "rcx", 2 => "rdx", 3 => "rbx",
        4 => "rsp", 5 => "rbp", 6 => "rsi", 7 => "rdi",
        8 => "r8",  9 => "r9", 10 => "r10", 11 => "r11",
        12 => "r12", 13 => "r13", 14 => "r14", 15 => "r15",
        _ => "?",
    }
}

/// Tiny opcode classifier — enough to name the dereferenced register
/// for the common faulting instruction classes.  Not a real disassembler.
/// We only really need to answer "did this instruction fault because
/// it dereferenced register X" for #GP non-canonical / #PF unmapped
/// faults.  When in doubt, return a hex tag.
fn decode_insn_mnem(bytes: &[u8], _frame: &ExceptionFrame) -> &'static str {
    if bytes.is_empty() {
        return "(no bytes)";
    }
    // Skip a single legacy prefix group if present (most common: 0xf2/0xf3 rep,
    // 0x66 operand-size, 0x67 address-size, 0x2e/0x36/0x3e/0x26/0x64/0x65 segment).
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i],
        0xf0 | 0xf2 | 0xf3 | 0x66 | 0x67 |
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65)
    {
        i += 1;
    }
    // Skip REX prefix if present.
    let rex_b = if i < bytes.len() && (bytes[i] & 0xf0) == 0x40 {
        let r = bytes[i] & 0x01;
        i += 1;
        r
    } else { 0 };
    if i >= bytes.len() { return "(prefixes only)"; }
    let op = bytes[i];
    let modrm = bytes.get(i + 1).copied();
    match op {
        0xc3 | 0xc2 => return "RET (deref [rsp])",
        0xcb | 0xca => return "RET FAR (deref [rsp])",
        0xcf      => return "IRET (deref [rsp])",
        0x50..=0x57 => return "PUSH r (no memop)",
        0x58..=0x5f => return "POP r (deref [rsp])",
        0xe8 => return "CALL rel32 (deref [rsp] on push)",
        0xe9 => return "JMP rel32 (no memop)",
        _ => {}
    }
    if op == 0xff {
        if let Some(m) = modrm {
            let reg_field = (m >> 3) & 0x7;
            let rm = m & 0x7;
            let base = reg64_name(rm | (rex_b << 3));
            // Synthesize static strings via a 6×16 cell of common
            // (op, base) combos.  Keeping the return type &'static
            // means we can't format on the fly, so we hand-pick the
            // ones we care about most: CALL/JMP through any of the
            // 16 GPRs (the most common faulting indirect opcodes).
            return match (reg_field, base) {
                (2, "rax") => "CALL [rax]", (2, "rcx") => "CALL [rcx]",
                (2, "rdx") => "CALL [rdx]", (2, "rbx") => "CALL [rbx]",
                (2, "rsp") => "CALL [rsp]", (2, "rbp") => "CALL [rbp]",
                (2, "rsi") => "CALL [rsi]", (2, "rdi") => "CALL [rdi]",
                (2, "r8")  => "CALL [r8]",  (2, "r9")  => "CALL [r9]",
                (2, "r10") => "CALL [r10]", (2, "r11") => "CALL [r11]",
                (2, "r12") => "CALL [r12]", (2, "r13") => "CALL [r13]",
                (2, "r14") => "CALL [r14]", (2, "r15") => "CALL [r15]",
                (4, "rax") => "JMP [rax]",  (4, "rcx") => "JMP [rcx]",
                (4, "rdx") => "JMP [rdx]",  (4, "rbx") => "JMP [rbx]",
                (4, "rsp") => "JMP [rsp]",  (4, "rbp") => "JMP [rbp]",
                (4, "rsi") => "JMP [rsi]",  (4, "rdi") => "JMP [rdi]",
                (4, "r8")  => "JMP [r8]",   (4, "r9")  => "JMP [r9]",
                (4, "r10") => "JMP [r10]",  (4, "r11") => "JMP [r11]",
                (4, "r12") => "JMP [r12]",  (4, "r13") => "JMP [r13]",
                (4, "r14") => "JMP [r14]",  (4, "r15") => "JMP [r15]",
                (6, _)     => "PUSH [r/m]",
                _ => "FF /? (CALL/JMP/PUSH r/m — see modrm)",
            };
        }
        return "FF (truncated)";
    }
    if op == 0x8b || op == 0x89 {
        if let Some(m) = modrm {
            let mode = (m >> 6) & 0x3;
            let rm = m & 0x7;
            if mode != 0x3 {
                // memop with base register `rm` (+ REX.B)
                let base = reg64_name(rm | (rex_b << 3));
                return match (op, base) {
                    (0x8b, "rax") => "MOV r, [rax]", (0x8b, "rcx") => "MOV r, [rcx]",
                    (0x8b, "rdx") => "MOV r, [rdx]", (0x8b, "rbx") => "MOV r, [rbx]",
                    (0x8b, "rsp") => "MOV r, [rsp+sib]", (0x8b, "rbp") => "MOV r, [rbp+disp]",
                    (0x8b, "rsi") => "MOV r, [rsi]", (0x8b, "rdi") => "MOV r, [rdi]",
                    (0x8b, "r8")  => "MOV r, [r8]",  (0x8b, "r9")  => "MOV r, [r9]",
                    (0x8b, "r10") => "MOV r, [r10]", (0x8b, "r11") => "MOV r, [r11]",
                    (0x8b, "r12") => "MOV r, [r12+sib]", (0x8b, "r13") => "MOV r, [r13+disp]",
                    (0x8b, "r14") => "MOV r, [r14]", (0x8b, "r15") => "MOV r, [r15]",
                    (0x89, "rax") => "MOV [rax], r", (0x89, "rcx") => "MOV [rcx], r",
                    (0x89, "rdx") => "MOV [rdx], r", (0x89, "rbx") => "MOV [rbx], r",
                    (0x89, "rsp") => "MOV [rsp+sib], r", (0x89, "rbp") => "MOV [rbp+disp], r",
                    (0x89, "rsi") => "MOV [rsi], r", (0x89, "rdi") => "MOV [rdi], r",
                    (0x89, "r8")  => "MOV [r8], r",  (0x89, "r9")  => "MOV [r9], r",
                    (0x89, "r10") => "MOV [r10], r", (0x89, "r11") => "MOV [r11], r",
                    (0x89, "r12") => "MOV [r12+sib], r", (0x89, "r13") => "MOV [r13+disp], r",
                    (0x89, "r14") => "MOV [r14], r", (0x89, "r15") => "MOV [r15], r",
                    _ => "MOV (unrecognized)",
                };
            }
            return "MOV reg, reg";
        }
    }
    "(other — see bytes)"
}

/// Emit the per-fault core dump block to the debug log.  Caller is
/// expected to be in user-fault context (RSP is a userspace stack).
pub fn dump_user_fault(frame: &ExceptionFrame, vector: u64) {
    let tid = crate::sched::scheduler::current_thread_id();
    let task = crate::sched::scheduler::thread_ref(tid).task_id;
    let rip = frame.rip();
    let rsp = frame.rsp();
    let rbp = frame.rbp();
    let error = frame.error_code();

    crate::println!(
        "[CORE-START tid={} task={} vector={} error={:#x} rip={:#x} rsp={:#x} rbp={:#x}]",
        tid, task, vector, error, rip, rsp, rbp
    );

    // Full register block — values match the user_regs_struct order
    // so the host script can build NT_PRSTATUS without re-mapping.
    crate::println!(
        "[CORE-REGS r15={:#x} r14={:#x} r13={:#x} r12={:#x} r11={:#x} r10={:#x} r9={:#x} r8={:#x} \
         rbp={:#x} rbx={:#x} rax={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} \
         rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}]",
        frame.r15(), frame.r14(), frame.r13(), frame.r12(), frame.r11(),
        frame.r10(), frame.r9(),  frame.r8(),
        frame.rbp(), frame.rbx(), frame.rax(), frame.rcx(),
        frame.rdx(), frame.rsi(), frame.rdi(),
        frame.rip(), frame.cs(),  frame.rflags(),
        frame.rsp(), frame.ss()
    );

    // Faulting-instruction hint: read 16 bytes at RIP and decode just
    // enough to identify the instruction class and (if it dereferences
    // a register) name the base register.  Lets a human grep the dump
    // for "what was 0x20000da45 *doing* with rdi=non-canonical" without
    // disassembling on the host.
    {
        let mut bytes = [0u8; 16];
        let got = user_read_block(rip, &mut bytes);
        let mnem = decode_insn_mnem(&bytes[..got], frame);
        let mut hex = [0u8; 16 * 3];
        let mut hi = 0usize;
        for i in 0..got {
            hex[hi]     = b"0123456789abcdef"[(bytes[i] >> 4) as usize];
            hex[hi + 1] = b"0123456789abcdef"[(bytes[i] & 0xf) as usize];
            hex[hi + 2] = b' ';
            hi += 3;
        }
        let hex_str = unsafe { core::str::from_utf8_unchecked(&hex[..hi.saturating_sub(1)]) };
        crate::println!("[CORE-INSN-HINT rip={:#x} bytes={} mnem=\"{}\"]", rip, hex_str, mnem);
    }

    // Code-page snapshot: dump the page containing RIP.  Critical for
    // diagnosing "bytes don't match on-disk binary" bugs — host-side
    // can compare these bytes to the file at the resolved offset and
    // tell whether the file load was corrupted (bytes wrong) vs.
    // control-flow corruption (bytes correct but wild jump).
    {
        let rip_page = rip & !(PAGE_SIZE as u64 - 1);
        let chunk_size = 256;
        let mut off = 0usize;
        while off < PAGE_SIZE {
            let mut buf = [0u8; 256];
            let got = user_read_block(rip_page + off as u64, &mut buf);
            if got == 0 {
                crate::println!(
                    "[CORE-MEM-GAP va={:#x} len={}]",
                    rip_page + off as u64,
                    chunk_size
                );
                break;
            }
            let mut b64 = [0u8; 352];
            let n = b64_encode(&buf[..got], &mut b64);
            let s = unsafe { core::str::from_utf8_unchecked(&b64[..n]) };
            crate::println!(
                "[CORE-MEM va={:#x} len={} b64={}]",
                rip_page + off as u64,
                got,
                s
            );
            off += chunk_size;
            if got < chunk_size {
                break;
            }
        }
    }

    // Stack memory dump.  Anchor at the page containing RSP and
    // include STACK_PAGES pages downward toward higher addresses
    // (stack grows down, so memory above RSP holds the saved frames).
    //
    // Emit in 256-byte chunks: 16 lines per page (32 lines for the
    // default 2-page dump).  4× fewer println calls than the original
    // 64-byte chunking; meaningful under serial-port-bandwidth
    // constraints.  Each line carries ~344 base64 chars + framing —
    // well under any reasonable serial / line-buffer limit.
    let stack_base = rsp & !(PAGE_SIZE as u64 - 1);
    const CHUNK_SIZE: usize = 256;
    for page in 0..STACK_PAGES {
        let page_va = stack_base + (page * PAGE_SIZE) as u64;
        let mut off = 0;
        while off < PAGE_SIZE {
            let mut buf = [0u8; CHUNK_SIZE];
            let got = user_read_block(page_va + off as u64, &mut buf);
            if got == 0 {
                // Hit an unmapped page; emit a marker and stop this
                // page so the host knows there's a gap.
                crate::println!(
                    "[CORE-MEM-GAP va={:#x} len={}]",
                    page_va + off as u64,
                    CHUNK_SIZE
                );
                break;
            }
            // base64 expansion: ⌈n/3⌉ × 4.  256 → 344 chars.
            let mut b64 = [0u8; 352];
            let n = b64_encode(&buf[..got], &mut b64);
            let s = unsafe { core::str::from_utf8_unchecked(&b64[..n]) };
            crate::println!(
                "[CORE-MEM va={:#x} len={} b64={}]",
                page_va + off as u64,
                got,
                s
            );
            off += CHUNK_SIZE;
            if got < CHUNK_SIZE {
                break;
            }
        }
    }

    // The list of loaded libraries for this task is already in the
    // boot log via linux_srv's [lib-load] lines (tagged by pid).
    // The host script greps those out on its own; just emit a
    // pointer for clarity.
    crate::println!("[CORE-LIB-REF tid={}]", tid);

    crate::println!("[CORE-END tid={}]", tid);
}
