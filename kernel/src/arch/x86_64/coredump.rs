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

/// Read a single byte from a userspace address in the current address
/// space.  Returns None on read fault.  (We assume the page-fault path
/// is set up to recover; in practice, dumping a faulting thread has
/// the caller already in fault context, and re-faulting just kills
/// later lines — acceptable.)
fn user_read_byte(va: u64) -> Option<u8> {
    if va < 0x1000 {
        return None;
    }
    Some(unsafe { core::ptr::read_volatile(va as *const u8) })
}

/// Try to read up to `len` bytes starting at `va` into `out`.  Stops
/// at the first read fault.  Returns the number of bytes successfully
/// read.
fn user_read_block(va: u64, out: &mut [u8]) -> usize {
    let mut got = 0;
    for i in 0..out.len() {
        match user_read_byte(va + i as u64) {
            Some(b) => out[i] = b,
            None => return got,
        }
        got += 1;
    }
    got
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
