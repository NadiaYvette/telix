#!/usr/bin/env python3
"""
Reconstruct an ELF64 core file from the [CORE-*] markers a Telix kernel
emits via tools/coredump.rs when a userspace thread faults.  The kernel
side dumps registers + stack pages as base64; this script assembles a
proper Linux ELF64 ET_CORE file that gdb (with debuginfod resolving
symbols) loads natively.

Usage:
    tools/extract-core.py BOOT_LOG [--task TID] [--out FILE.core]

If --task is omitted and the log has multiple [CORE-START] blocks, the
script writes one .core file per task.

Companion to:
    kernel/src/arch/x86_64/coredump.rs
    userlib/bin/linux_srv.rs    (lib-load lines)

Workflow:
    $ tools/extract-core.py /tmp/h14/aa9mfsq426.log --out fault.core
    $ gdb -e initramfs/Xwayland -c fault.core
    (gdb) bt
    ... full symbolic backtrace via debuginfod ...
"""
import argparse
import base64
import re
import struct
import sys
from pathlib import Path

# ELF constants
ELFMAG = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_CORE = 4
EM_X86_64 = 62
PT_NOTE = 4
PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4

# Note types (from elf.h / linux/elfcore.h)
NT_PRSTATUS = 1
NT_PRPSINFO = 3

# Markers we look for
RX_START = re.compile(r"\[CORE-START tid=(\d+) task=(\d+) vector=(\d+) error=(0x[0-9a-fA-F]+) rip=(0x[0-9a-fA-F]+) rsp=(0x[0-9a-fA-F]+) rbp=(0x[0-9a-fA-F]+)\]")
RX_REGS = re.compile(r"\[CORE-REGS ([^\]]+)\]")
RX_MEM = re.compile(r"\[CORE-MEM va=(0x[0-9a-fA-F]+) len=(\d+) b64=([A-Za-z0-9+/=]+)\]")
RX_GAP = re.compile(r"\[CORE-MEM-GAP va=(0x[0-9a-fA-F]+) len=(\d+)\]")
RX_END = re.compile(r"\[CORE-END tid=(\d+)\]")

REG_NAMES = [
    "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8",
    "rbp", "rbx", "rax", "rcx", "rdx", "rsi", "rdi",
    "rip", "cs", "rflags", "rsp", "ss",
]


def parse_regs(s: str) -> dict:
    out = {}
    for tok in s.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        out[k] = int(v, 16)
    return out


def build_user_regs_struct(regs: dict) -> bytes:
    """elf_gregset_t for x86_64: matches Linux struct user_regs_struct.

    Layout (27 u64s, in this exact order):
    r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8,
    rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags,
    rsp, ss, fs_base, gs_base, ds, es, fs, gs.
    """
    r = lambda k: regs.get(k, 0)
    return struct.pack(
        "<27Q",
        r("r15"), r("r14"), r("r13"), r("r12"),
        r("rbp"), r("rbx"),
        r("r11"), r("r10"), r("r9"), r("r8"),
        r("rax"), r("rcx"), r("rdx"), r("rsi"), r("rdi"),
        0,           # orig_rax
        r("rip"),
        r("cs"),
        r("rflags"),
        r("rsp"),
        r("ss"),
        0, 0, 0, 0, 0, 0,  # fs_base, gs_base, ds, es, fs, gs
    )


def build_prstatus_note(regs: dict, signo: int = 11) -> bytes:
    """elf_prstatus minus pad. Layout per linux/elfcore-compat.h.

    Total size = 12 + 2 + 6 + 32 + 32 + 16 + 216 + 4 + (pad) = ~336 bytes
    on x86_64.  Build it field-by-field; padding goes at the end.
    """
    # struct elf_siginfo: si_signo, si_code, si_errno (3 × i32).
    elf_siginfo = struct.pack("<iii", signo, 0, 0)
    # pr_cursig (i16), pad (i16), pr_sigpend (u64), pr_sighold (u64).
    sig_block = struct.pack("<hH QQ", signo, 0, 0, 0)
    # pids: pr_pid, pr_ppid, pr_pgrp, pr_sid (4 × i32).
    pids = struct.pack("<iiii", 1, 0, 0, 0)
    # times: pr_utime, pr_stime, pr_cutime, pr_cstime (4 × {u64 sec, u64 usec}).
    times = struct.pack("<QQ QQ QQ QQ", 0, 0, 0, 0, 0, 0, 0, 0)
    # pr_reg: 27 × u64 = 216 bytes
    pr_reg = build_user_regs_struct(regs)
    # pr_fpvalid (i32) + pad to 8.
    fpvalid = struct.pack("<ii", 0, 0)
    return elf_siginfo + sig_block + pids + times + pr_reg + fpvalid


def make_note(name: bytes, ntype: int, desc: bytes) -> bytes:
    """ELF note: 4-byte aligned name and desc; header = 3 × u32."""
    name_padded = name + b"\x00"
    while len(name_padded) % 4 != 0:
        name_padded += b"\x00"
    desc_padded = desc
    while len(desc_padded) % 4 != 0:
        desc_padded += b"\x00"
    hdr = struct.pack("<III", len(name) + 1, len(desc), ntype)
    return hdr + name_padded + desc_padded


def assemble_core(regs: dict, mem_pages: list, out_path: Path):
    """mem_pages = list of (va_start, bytes) where bytes is the page contents."""
    # Coalesce contiguous memory chunks into PT_LOAD segments.
    mem_pages.sort(key=lambda x: x[0])
    segments = []  # list of (va, data)
    if mem_pages:
        cur_va, cur_buf = mem_pages[0]
        cur_buf = bytearray(cur_buf)
        for va, data in mem_pages[1:]:
            if va == cur_va + len(cur_buf):
                cur_buf.extend(data)
            else:
                segments.append((cur_va, bytes(cur_buf)))
                cur_va, cur_buf = va, bytearray(data)
        segments.append((cur_va, bytes(cur_buf)))

    # Build the NOTE segment.
    prstatus = make_note(b"CORE", NT_PRSTATUS, build_prstatus_note(regs))
    note_seg = prstatus

    # ELF64 header sizes.
    EHDR_SIZE = 64
    PHDR_SIZE = 56

    n_phdrs = 1 + len(segments)  # 1 NOTE + N LOAD
    phdr_off = EHDR_SIZE
    note_off = phdr_off + n_phdrs * PHDR_SIZE
    note_size = len(note_seg)
    seg_data_off = note_off + note_size
    # Round seg_data_off up to page boundary for PT_LOAD alignment.
    PAGE = 4096
    seg_data_off = (seg_data_off + PAGE - 1) & ~(PAGE - 1)

    # ELF header
    e_ident = ELFMAG + bytes([
        ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0, 0,
    ]) + b"\x00" * 7
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_CORE, EM_X86_64, EV_CURRENT,
        0,             # e_entry
        phdr_off,      # e_phoff
        0,             # e_shoff
        0,             # e_flags
        EHDR_SIZE, PHDR_SIZE, n_phdrs,
        0, 0, 0,       # shentsize, shnum, shstrndx
    )

    # Program headers
    phdrs = bytearray()
    # NOTE phdr
    phdrs += struct.pack(
        "<IIQQQQQQ",
        PT_NOTE, PF_R,
        note_off, 0, 0,
        note_size, note_size,
        4,  # align
    )
    # LOAD phdrs
    cur_off = seg_data_off
    for va, data in segments:
        phdrs += struct.pack(
            "<IIQQQQQQ",
            PT_LOAD, PF_R | PF_W,
            cur_off, va, 0,
            len(data), len(data),
            PAGE,
        )
        cur_off += len(data)

    # Assemble file
    buf = bytearray(ehdr)
    buf.extend(phdrs)
    buf.extend(note_seg)
    # pad to seg_data_off
    if len(buf) < seg_data_off:
        buf.extend(b"\x00" * (seg_data_off - len(buf)))
    for _, data in segments:
        buf.extend(data)

    out_path.write_bytes(buf)
    print(f"wrote {out_path} ({len(buf)} bytes, {len(segments)} LOAD segments)", file=sys.stderr)


def parse_log(path: Path, want_tid: int | None):
    blocks = []  # list of dicts with tid/regs/mem
    cur = None
    for line in path.read_text(errors="replace").splitlines():
        # Strip CR and any leading boot-log noise before the [CORE-...] marker.
        line = line.rstrip("\r")
        m = RX_START.search(line)
        if m:
            tid, task, vector, error, rip, rsp, rbp = m.groups()
            cur = {
                "tid": int(tid),
                "task": int(task),
                "vector": int(vector),
                "error": int(error, 16),
                "regs": {"rip": int(rip, 16), "rsp": int(rsp, 16), "rbp": int(rbp, 16)},
                "mem": [],
            }
            continue
        if cur is None:
            continue
        m = RX_REGS.search(line)
        if m:
            cur["regs"].update(parse_regs(m.group(1)))
            continue
        m = RX_MEM.search(line)
        if m:
            va, length, b64 = m.groups()
            data = base64.b64decode(b64)[:int(length)]
            cur["mem"].append((int(va, 16), data))
            continue
        m = RX_END.search(line)
        if m:
            blocks.append(cur)
            cur = None

    if want_tid is not None:
        blocks = [b for b in blocks if b["tid"] == want_tid]
    return blocks


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("log")
    p.add_argument("--task", type=int, default=None, help="filter by tid")
    p.add_argument("--out", type=Path, default=None, help="output core file (default: <log>.tid<TID>.core)")
    args = p.parse_args()

    log = Path(args.log)
    blocks = parse_log(log, args.task)
    if not blocks:
        print(f"no [CORE-START..CORE-END] blocks found in {log}", file=sys.stderr)
        sys.exit(1)

    for b in blocks:
        out = args.out or log.with_suffix(f".tid{b['tid']}.core")
        assemble_core(b["regs"], b["mem"], Path(out))
        # Also dump a one-liner summary of where to find the lib-load lines for this tid.
        print(
            f"tid={b['tid']} task={b['task']} vector={b['vector']} rip={b['regs']['rip']:#x} "
            f"-> {out}",
            file=sys.stderr,
        )
        print(
            f"  for symbol resolution, scrape '[lib-load] pid=...' lines from {log} for the matching task",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
