#![no_std]
#![no_main]

extern crate userlib;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use userlib::syscall;

// I/O protocol tags (must match kernel/src/io/protocol.rs).
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
/// Async variant of IO_CONNECT: same name packing as IO_CONNECT except
/// the d2 word now holds a 32-bit correlation in bits 16..48 (where
/// the sync path packs name bytes 24-27).  This limits async names to
/// 24 bytes — longer names fall back to the sync IO_CONNECT path.
/// Reply lands as IO_CONNECT_REPLY on the port linux_srv registered
/// via IO_SET_ASYNC_REPLY_PORT.
///
/// data[0] = name bytes 0-7
/// data[1] = name bytes 8-15
/// data[2] = name_len (low 16) | correlation (bits 16..48) | reserved (48..64)
/// data[3] = name bytes 16-23
///
/// No reply is sent on the original caller's reply slot — the request
/// is fire-and-forget.
const IO_CONNECT_ASYNC: u64 = 0x102;
/// Companion of IO_CONNECT_ASYNC.  Sent via send_nb_4 to the
/// async reply port.
///
/// data[0] = correlation (echoes the request word)
/// data[1] = handle    (0 if not-found)
/// data[2] = size      (0 if not-found)
/// data[3] = server_aspace_id (0 if not-found)
///
/// "not-found" is signalled by handle == 0 && size == 0; linux_srv
/// distinguishes this from a real handle 0 by reserving handle 0 as
/// "no file" in its async path.  (initramfs_srv's normal handles are
/// indices into fs.files, which is 0-based but the 0th slot is the
/// CPIO trailer entry — never a real file.)
const IO_CONNECT_REPLY: u64 = 0x103;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
/// Async grant-based read.  Caller `send`s instead of `call`s, so its
/// thread isn't parked waiting for the reply.  Args: d0=handle (low 32)
/// | length (high 32), d1=offset, d2=grant_dst_va, d3=correlation.
/// initramfs_srv processes the read normally and posts an
/// `IO_READ_REPLY` to the previously-registered async reply port with
/// `(correlation, bytes_read)`.  No implicit `reply` — this is a pure
/// notification path.
const IO_READ_ASYNC: u64 = 0x202;
const IO_READ_REPLY: u64 = 0x203;
/// One-time registration: caller (linux_srv) tells us where to post
/// IO_READ_REPLY notifications.  d0=async_reply_port.  Synchronous
/// (caller uses `call`); we ack with IO_READ_OK so the registration
/// is observably complete before any IO_READ_ASYNC is sent.
const IO_SET_ASYNC_REPLY_PORT: u64 = 0x204;
/// One-time registration: caller (linux_srv) tells us where to post
/// IO_CONNECT_REPLY notifications.  Separate from IO_SET_ASYNC_REPLY_PORT
/// because IO_CONNECT_REPLY needs to be handled on linux_srv's main
/// dispatch thread (it writes PROC_TABLE.fds when populating the new fd),
/// whereas IO_READ_REPLY can be processed by a dedicated reply thread
/// (it writes only LIB_CACHE backing pages and per-process mmap state
/// that the main thread isn't concurrently touching).
/// d0=connect_reply_port.  Synchronous; we ack with IO_READ_OK.
const IO_SET_CONNECT_REPLY_PORT: u64 = 0x205;
const IO_STAT: u64 = 0x400;
const IO_STAT_OK: u64 = 0x401;
const IO_CLOSE: u64 = 0x500;
const IO_ERROR: u64 = 0xF00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_INVALID: u64 = 3;

const MAX_INLINE_READ: usize = 40;
const MAX_FILES: usize = 512;
const MAX_NAME: usize = 64;

/// Diagnostic flag: log a per-IO_READ summary (handle, offset, len, csum,
/// first 8 bytes) for reads >= 4 KiB.  Pair with the matching log on
/// linux_srv's irfs_read_bulk side; csum mismatch between the two means
/// the grant_pages mapping resolved to different phys pages on the two
/// aspaces — the file-too-short / Verdef-version-0 / cannot-read-file-data
/// flake.  Boot b9mfsq310-r13 ran with this on and confirmed every single
/// observed read matched server↔client; flip back to true if the flake
/// resurfaces and a fresh corruption-check is wanted.
const DEBUG_IO_READ_CSUM: bool = false;

/// Diagnostic flag: log every IO_CONNECT_OK with handle, size, name.
/// Pair with linux_srv's record of the same handle's later read offsets:
/// if linux_srv stops reading at offset N but the file's actual size is
/// > N, we'd see fstat report N (correct) yet ld.so still expects more.
const DEBUG_IO_CONNECT_LOG: bool = true;

/// Cheap Fletcher-style 32-bit running sum.  Not cryptographic, just
/// enough to detect single-byte changes or wholesale zeroing.
fn csum32(data: &[u8]) -> u32 {
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = s1.wrapping_add(b as u32);
        s2 = s2.wrapping_add(s1);
    }
    (s2 << 16) | (s1 & 0xFFFF)
}

fn print_hex32(n: u32) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 8];
    for i in 0..8 {
        buf[7 - i] = hex[((n >> (i * 4)) & 0xF) as usize];
    }
    syscall::debug_puts(&buf);
}

struct FileEntry {
    name: [u8; MAX_NAME],
    name_len: usize,
    data_offset: usize,
    data_len: usize,
    active: bool,
}

impl FileEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            data_offset: 0,
            data_len: 0,
            active: false,
        }
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

struct Initramfs {
    files: [FileEntry; MAX_FILES],
    count: usize,
}

impl Initramfs {
    const fn new() -> Self {
        Self {
            files: [const { FileEntry::empty() }; MAX_FILES],
            count: 0,
        }
    }

    fn parse(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos + 110 <= data.len() && self.count < MAX_FILES {
            if &data[pos..pos + 6] != b"070701" {
                break;
            }
            let filesize = parse_hex8(&data[pos + 54..pos + 62]);
            let namesize = parse_hex8(&data[pos + 94..pos + 102]);
            let name_start = pos + 110;
            let name_end = name_start + namesize - 1;
            let data_start = align4(name_start + namesize);
            let data_end = data_start + filesize;
            let next = align4(data_end);
            if name_end > data.len() || data_end > data.len() {
                break;
            }
            let name = &data[name_start..name_end];
            if name == b"TRAILER!!!" {
                break;
            }
            if !(filesize == 0 || name == b".") {
                let entry = &mut self.files[self.count];
                let copy_len = name.len().min(MAX_NAME);
                entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
                entry.name_len = copy_len;
                entry.data_offset = data_start;
                entry.data_len = filesize;
                entry.active = true;
                self.count += 1;
            }
            pos = next;
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.count {
            if self.files[i].active && self.files[i].name_bytes() == name {
                return Some(i);
            }
        }
        None
    }
}

fn parse_hex8(bytes: &[u8]) -> usize {
    let mut val = 0usize;
    for &b in bytes.iter().take(8) {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => 0,
        };
        val = (val << 4) | digit;
    }
    val
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Unpack a path name from 4 packed u64 words.  d0 / d1 / d3 hold
/// 24 bytes (3 × 8); the upper 32 bits of d2 (whose low 16 bits
/// carry name_len) hold 4 more — total 28 chars.  That fits paths
/// like "lib64/libwayland-client.so.0" (28 chars exactly) without
/// needing a long-path IPC variant.
fn unpack_name(w0: u64, w1: u64, w2_extra: u32, w3: u64, len: usize) -> [u8; 28] {
    let mut buf = [0u8; 28];
    // bytes 0-7 from w0
    for i in 0..len.min(8) {
        buf[i] = (w0 >> (i * 8)) as u8;
    }
    // bytes 8-15 from w1
    for i in 8..len.min(16) {
        buf[i] = (w1 >> ((i - 8) * 8)) as u8;
    }
    // bytes 16-23 from w3
    for i in 16..len.min(24) {
        buf[i] = (w3 >> ((i - 16) * 8)) as u8;
    }
    // bytes 24-27 from upper 32 bits of d2
    for i in 24..len.min(28) {
        buf[i] = (w2_extra >> ((i - 24) * 8)) as u8;
    }
    buf
}

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE_READ) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

/// Caller-supplied port for IO_READ_REPLY notifications.  Set once via
/// IO_SET_ASYNC_REPLY_PORT (currently only linux_srv uses async reads;
/// extending to multiple async clients would require a per-src-port
/// table here).  Zero means async reads have not been wired up — fall
/// back to refusing IO_READ_ASYNC with IO_ERROR rather than silently
/// dropping notifications.
///
/// Atomic because under the worker-pool design (N threads recv'ing
/// from the shared port) one worker may handle the IO_SET while
/// another concurrently handles an IO_READ_ASYNC; Acquire-load
/// pairs with the Release-store on update.
static ASYNC_REPLY_PORT: AtomicU64 = AtomicU64::new(0);
/// Companion of ASYNC_REPLY_PORT: where IO_CONNECT_REPLY notifications
/// are sent.  Separate so linux_srv can route connect-completions to
/// its main dispatch thread (PROC_TABLE-writing) while read-completions
/// go to a dedicated reply thread.  Set via IO_SET_CONNECT_REPLY_PORT.
static CONNECT_REPLY_PORT: AtomicU64 = AtomicU64::new(0);

/// Worker-pool globals.  initramfs_srv is single-task but multi-thread:
/// after `main` parses the cpio archive into `FS`, it spawns
/// (N_WORKERS - 1) sibling threads and itself enters the same server
/// loop, so all N threads park on the same shared port and the kernel
/// dispatches one parked recv per arriving message.  Post-parse state
/// (`FS`, the cpio data slice, port id, aspace id) is read-only,
/// hence safe to share without locking.
const N_WORKERS: usize = 4;
static mut CPIO_DATA_VA: u64 = 0;
static mut CPIO_DATA_LEN: u64 = 0;
static mut FS: Initramfs = Initramfs::new();
static mut PORT_ID: u64 = 0;
static mut MY_ASPACE: u64 = 0;
/// Release-store after main has populated FS, CPIO_DATA_VA/LEN, PORT_ID,
/// MY_ASPACE.  Workers spin on Acquire-load so all those plain writes
/// are guaranteed visible before any worker reads them.  Without this
/// gate we'd be relying on thread_create's implicit fence — works in
/// practice but unspecified.
static WORKERS_READY: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Diagnostic counters — surface where time goes when callers see CALL-TIMEOUT
// blocks of 30+ s on this server (boots 408/411/413 confirmed this server's
// port is the timeout target during Xwayland startup).  Two-axis breakdown:
//
//   REQS_TOTAL              — count of request handlers entered
//   REQS_TIME_NS            — cumulative time inside handlers
//   REQS_MAX_NS             — longest single handler duration
//
// If REQS_TIME_NS / REQS_TOTAL is small (< 1 ms avg) but CALL-TIMEOUTs are
// still firing, the bottleneck is IPC dispatch / port-queue / scheduler, not
// this server's work.  If the avg is large, this server is the bottleneck.
// Periodic log line every PROGRESS_INTERVAL requests lets us read the live
// rate from the boot log without external instrumentation.
// ---------------------------------------------------------------------------
static REQS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQS_TIME_NS: AtomicU64 = AtomicU64::new(0);
static REQS_MAX_NS: AtomicU64 = AtomicU64::new(0);
/// Cumulative time spent inside the reply syscall itself (across all
/// workers).  If REPLY_TIME_NS dominates REQS_TIME_NS the bottleneck is
/// the reply path (kernel scheduler / cap-slot / wakeup), not handler work.
static REPLY_TIME_NS: AtomicU64 = AtomicU64::new(0);
static REPLY_MAX_NS: AtomicU64 = AtomicU64::new(0);
const PROGRESS_INTERVAL: u64 = 32;

/// Time a `syscall::reply` call and accumulate into REPLY_TIME_NS /
/// REPLY_MAX_NS.  Returning the syscall result keeps callers happy.
#[inline(always)]
fn reply_timed(tag: u64, d0: u64, d1: u64, d2: u64, d3: u64, d4: u64) -> u64 {
    let s = syscall::clock_gettime();
    let r = syscall::reply(tag, d0, d1, d2, d3, d4);
    let e = syscall::clock_gettime().wrapping_sub(s);
    REPLY_TIME_NS.fetch_add(e, Ordering::Relaxed);
    let mut cur = REPLY_MAX_NS.load(Ordering::Relaxed);
    while e > cur {
        match REPLY_MAX_NS.compare_exchange_weak(
            cur, e, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
    r
}

fn cpio_slice() -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(CPIO_DATA_VA as *const u8, CPIO_DATA_LEN as usize) }
}

fn fs_ref() -> &'static Initramfs {
    unsafe { &*core::ptr::addr_of!(FS) }
}

fn alloc_stack() -> u64 {
    let va = match syscall::mmap_anon(0, 2, 1) {
        Some(v) => v,
        None => return 0,
    };
    (va + 2 * syscall::page_size()) as u64
}

extern "C" fn worker_entry(_arg: u64) -> ! {
    while !WORKERS_READY.load(Ordering::Acquire) {
        syscall::yield_now();
    }
    let port = unsafe { PORT_ID };
    let my_aspace = unsafe { MY_ASPACE };
    server_loop(port, my_aspace, cpio_slice(), fs_ref());
    syscall::exit(0)
}

/// Entry: arg0 = port ID, arg1 = CPIO data VA, arg2 = CPIO data length.
#[unsafe(no_mangle)]
fn main(port_id: u64, data_va: u64, data_len: u64) {
    let cpio_data = unsafe { core::slice::from_raw_parts(data_va as *const u8, data_len as usize) };

    unsafe {
        CPIO_DATA_VA = data_va;
        CPIO_DATA_LEN = data_len;
        (*core::ptr::addr_of_mut!(FS)).parse(cpio_data);
        PORT_ID = port_id;
        MY_ASPACE = syscall::aspace_id();
    }
    let count = unsafe { (*core::ptr::addr_of!(FS)).count };
    let my_aspace = unsafe { MY_ASPACE };

    syscall::debug_puts(b"  [initramfs_srv] parsed ");
    print_num(count as u64);
    syscall::debug_puts(b" files, serving on port ");
    print_num(port_id);
    syscall::debug_puts(b"\n");

    // Register with name server.
    syscall::ns_register(b"initramfs", port_id);
    // Also register our aspace under `initramfs_task` so linux_srv (and
    // others) can grant pages to us — same convention as ext_srv /
    // ext2_srv / rootfs_srv.
    syscall::ns_register(b"initramfs_task", my_aspace);

    // Spawn N_WORKERS - 1 sibling worker threads; main becomes the Nth.
    // All threads park on the same port; the kernel's KEY_PORT_RECV_PARK
    // turnstile dequeues one parked recv per arriving message, so up
    // to N grant-page IO_READ_ASYNC copies can run in parallel on
    // different CPUs.
    let mut spawned = 0usize;
    for _ in 1..N_WORKERS {
        let stk = alloc_stack();
        if stk == 0 {
            syscall::debug_puts(b"  [initramfs_srv] worker stack alloc FAIL\n");
            break;
        }
        let tid = syscall::thread_create(worker_entry as u64, stk, 0);
        if tid == u64::MAX {
            syscall::debug_puts(b"  [initramfs_srv] worker thread_create FAIL\n");
            break;
        }
        spawned += 1;
    }
    // Release-store the gate AFTER all global writes (FS/CPIO/PORT_ID/
    // MY_ASPACE) above and after thread_create — workers spinning on
    // Acquire-load will then see those writes consistently.
    WORKERS_READY.store(true, Ordering::Release);
    syscall::debug_puts(b"  [initramfs_srv] worker pool up: ");
    print_num((spawned + 1) as u64);
    syscall::debug_puts(b" threads\n");

    server_loop(port_id, my_aspace, cpio_slice(), fs_ref());

    loop {
        core::hint::spin_loop();
    }
}

fn server_loop(port: u64, my_aspace: u64, cpio_data: &[u8], fs: &Initramfs) {
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };
        // Per-request timing.  We treat the time between recv-return and
        // reply-send as the in-handler service time.  Note: any time the
        // request waits in the kernel port queue *before* recv_with_cap
        // returns is NOT counted here — that's the IPC-dispatch time and
        // is the most likely contributor to caller-side CALL-TIMEOUT
        // when this server is otherwise idle.
        let req_start_ns = syscall::clock_gettime();

        match msg.tag {
            IO_CONNECT => {
                // Userspace protocol (4 data words used):
                //   data[0] = name bytes 0-7
                //   data[1] = name bytes 8-15
                //   data[2] = name_len (low 16) | name_bytes_24_27 (upper 32)
                //   data[3] = name bytes 16-23
                // Total 28-char inline name (covers
                // "lib64/libwayland-client.so.0" = 28 exactly).  We pack
                // 4 extra bytes into d2's upper 32 bits because the
                // syscall ABI gives us only 4 data words on the wire.
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let w2_extra = ((msg.data[2] >> 32) & 0xFFFF_FFFF) as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], w2_extra, msg.data[3], name_len);
                let name = &name_buf[..name_len.min(28)];

                match fs.find(name) {
                    Some(idx) => {
                        // d0=handle, d1=size, d2=server_aspace_id
                        if DEBUG_IO_CONNECT_LOG {
                            // Log handle and size so we can verify ld.so's fstat
                            // matches the actual cpio entry size.  If a file is
                            // reported with the wrong size, ld.so would either
                            // read past EOF (zeros, "file too short") or stop
                            // short of real content.
                            syscall::debug_puts(b"[irfs] IO_CONNECT_OK h=");
                            print_num(idx as u64);
                            syscall::debug_puts(b" size=");
                            print_num(fs.files[idx].data_len as u64);
                            syscall::debug_puts(b" name=");
                            // Print first 24 bytes of name (covers most lib paths).
                            for i in 0..fs.files[idx].name_len.min(28) {
                                syscall::debug_putchar(fs.files[idx].name[i]);
                            }
                            syscall::debug_puts(b"\n");
                        }
                        let _ = reply_timed(
                            IO_CONNECT_OK,
                            idx as u64,
                            fs.files[idx].data_len as u64,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                    None => {
                        let _ = reply_timed(IO_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                    }
                }
            }

            IO_CONNECT_ASYNC => {
                // Name packing differs from IO_CONNECT: d2 holds a
                // 32-bit correlation in bits 16..48 instead of name
                // bytes 24-27.  Names are therefore capped at 24
                // bytes in this path (linux_srv falls back to sync
                // IO_CONNECT for longer names).
                //
                // Fire-and-forget: no reply on this request's slot;
                // instead, send IO_CONNECT_REPLY via send_nb_4 to the
                // ASYNC_REPLY_PORT.  Worst case if the reply port is
                // full: linux_srv times out its pending slot via the
                // normal CALL-TIMEOUT path (cost is the same as a
                // single sync timeout, far better than blocking the
                // server thread).
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                // No bytes 24-27 in async path — w2_extra forced to 0.
                let name_buf = unpack_name(msg.data[0], msg.data[1], 0u32, msg.data[3], name_len);
                let name = &name_buf[..name_len.min(24)];
                let correlation = (msg.data[2] >> 16) & 0xFFFF_FFFF;
                let reply_port = CONNECT_REPLY_PORT.load(Ordering::Acquire);
                if reply_port == 0 {
                    // No reply port registered.  Reply via the normal
                    // path so the caller doesn't hang.  (Should only
                    // happen if linux_srv sent IO_CONNECT_ASYNC before
                    // its own IO_SET_ASYNC_REPLY_PORT landed.)
                    let _ = reply_timed(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }
                let (handle, size, srv_aspace) = match fs.find(name) {
                    Some(idx) => (
                        idx as u64,
                        fs.files[idx].data_len as u64,
                        my_aspace as u64,
                    ),
                    None => (0u64, 0u64, 0u64),
                };
                let _ = syscall::send_nb_4(
                    reply_port,
                    IO_CONNECT_REPLY,
                    correlation,
                    handle,
                    size,
                    srv_aspace,
                );
                // No reply to the original IO_CONNECT_ASYNC slot — we
                // just consumed the message.  Skip reply_timed.
                continue;
            }

            IO_READ => {
                // data[0] = handle, data[1] = offset
                // data[2] = length (low 32)
                // data[3] = grant_dst_va (if grant)
                let file_handle = msg.data[0] as usize;
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let grant_va = msg.data[3] as usize;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    let _ = reply_timed(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let f = &fs.files[file_handle];
                let start = f.data_offset + offset.min(f.data_len);
                let end = f.data_offset + (offset + length).min(f.data_len);
                let data = &cpio_data[start..end];

                if grant_va != 0 {
                    if DEBUG_IO_READ_CSUM && data.len() >= 4096 {
                        let cs = csum32(data);
                        syscall::debug_puts(b"[irfs] IO_READ srv h=");
                        print_num(file_handle as u64);
                        syscall::debug_puts(b" off=");
                        print_num(offset as u64);
                        syscall::debug_puts(b" len=");
                        print_num(data.len() as u64);
                        syscall::debug_puts(b" csum=");
                        print_hex32(cs);
                        syscall::debug_puts(b" first8=");
                        for k in 0..8.min(data.len()) {
                            let hex = b"0123456789abcdef";
                            syscall::debug_putchar(hex[(data[k] >> 4) as usize]);
                            syscall::debug_putchar(hex[(data[k] & 0xF) as usize]);
                        }
                        syscall::debug_puts(b"\n");
                    }
                    // Grant-based read with cache_srv-style fence pattern:
                    // volatile u64 stride + Release fence + mfence.  Without
                    // this, ld.so on the receiving CPU sees zero-filled
                    // grant pages under boot concurrency (same shape of bug
                    // cache_srv and ext_srv had — surfaces in Step H as
                    // "Verdef version 0" / "Verneed version 0" on libc).
                    let bytes_read = data.len();
                    unsafe {
                        let src = data.as_ptr();
                        let dst = grant_va as *mut u8;
                        let words = bytes_read / 8;
                        let tail_start = words * 8;
                        let src_u64 = src as *const u64;
                        let dst_u64 = dst as *mut u64;
                        for i in 0..words {
                            let v = core::ptr::read_volatile(src_u64.add(i));
                            core::ptr::write_volatile(dst_u64.add(i), v);
                        }
                        for i in tail_start..bytes_read {
                            let b = core::ptr::read_volatile(src.add(i));
                            core::ptr::write_volatile(dst.add(i), b);
                        }
                    }
                    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                    #[cfg(target_arch = "x86_64")]
                    unsafe { core::arch::asm!("mfence"); }
                    let _ = reply_timed(IO_READ_OK, bytes_read as u64, 0, 0, 0, 0);
                } else {
                    // Inline read: pack into message words.
                    let bytes_read = data.len().min(MAX_INLINE_READ);
                    let packed = pack_inline_data(&data[..bytes_read]);
                    let _ = reply_timed(
                        IO_READ_OK,
                        bytes_read as u64,
                        packed[0],
                        packed[1],
                        packed[2],
                        0,
                    );
                }
            }

            IO_SET_ASYNC_REPLY_PORT => {
                // d0 = caller's reply port (where IO_READ_REPLY notifications
                // should be delivered).  Synchronous to make the registration
                // observably ordered before any subsequent IO_READ_ASYNC.
                // Release-store pairs with Acquire-load in any sibling
                // worker that subsequently handles an IO_READ_ASYNC.
                ASYNC_REPLY_PORT.store(msg.data[0], Ordering::Release);
                let _ = reply_timed(IO_READ_OK, 0, 0, 0, 0, 0);
            }

            IO_SET_CONNECT_REPLY_PORT => {
                // d0 = caller's reply port for IO_CONNECT_REPLY.  Separate
                // from ASYNC_REPLY_PORT so linux_srv can route connect
                // completions to its main dispatch thread (PROC_TABLE-
                // touching).  Same observability/ordering rationale as
                // IO_SET_ASYNC_REPLY_PORT above.  Reusing IO_READ_OK as
                // the ack tag — there's no need for a dedicated ACK type.
                CONNECT_REPLY_PORT.store(msg.data[0], Ordering::Release);
                let _ = reply_timed(IO_READ_OK, 0, 0, 0, 0, 0);
            }

            IO_READ_ASYNC => {
                // d0 = handle (low 32) | length (high 32)
                // d1 = offset
                // d2 = grant_dst_va
                // d3 = correlation
                // No `reply` — caller used `send`, not `call`.  We process
                // the read inline (cpio is in-memory, fast) and post
                // IO_READ_REPLY(correlation, bytes_read) to ASYNC_REPLY_PORT.
                let file_handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let length = ((msg.data[0] >> 32) & 0xFFFF_FFFF) as usize;
                let offset = msg.data[1] as usize;
                let grant_va = msg.data[2] as usize;
                let correlation = msg.data[3];
                let async_port = ASYNC_REPLY_PORT.load(Ordering::Acquire);

                if async_port == 0 {
                    // Caller forgot to register — drop silently; the sync
                    // path is still available.  Logging here is cheap and
                    // catches the misconfiguration during bringup.
                    syscall::debug_puts(b"[irfs] IO_READ_ASYNC dropped: no reply port registered\n");
                    continue;
                }

                let bytes_read: u64 = if file_handle >= fs.count
                    || !fs.files[file_handle].active
                    || grant_va == 0
                {
                    0
                } else {
                    let f = &fs.files[file_handle];
                    let start = f.data_offset + offset.min(f.data_len);
                    let end = f.data_offset + (offset + length).min(f.data_len);
                    let data = &cpio_data[start..end];
                    let n = data.len();
                    unsafe {
                        let src = data.as_ptr();
                        let dst = grant_va as *mut u8;
                        let words = n / 8;
                        let tail_start = words * 8;
                        let src_u64 = src as *const u64;
                        let dst_u64 = dst as *mut u64;
                        for i in 0..words {
                            let v = core::ptr::read_volatile(src_u64.add(i));
                            core::ptr::write_volatile(dst_u64.add(i), v);
                        }
                        for i in tail_start..n {
                            let b = core::ptr::read_volatile(src.add(i));
                            core::ptr::write_volatile(dst.add(i), b);
                        }
                    }
                    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                    #[cfg(target_arch = "x86_64")]
                    unsafe { core::arch::asm!("mfence"); }
                    n as u64
                };

                // Compute csum of the source bytes (cpio side) so the
                // reply carries it; linux_srv computes the same csum from
                // its scratch view after the fence and compares.  A
                // mismatch means initramfs_srv's grant_va writes didn't
                // reach linux_srv's scratch — the grant_pages phys-page
                // mismatch shape from project_grant_pages_phys_mismatch.md.
                // Source-side csum is taken from cpio_data (the bytes we
                // wrote, not what we wrote them to) — a self-consistency
                // check between source and destination.
                let csum: u64 = if bytes_read > 0 && file_handle < fs.count {
                    let f = &fs.files[file_handle];
                    let start = f.data_offset + offset.min(f.data_len);
                    let end = f.data_offset + (offset + length).min(f.data_len);
                    csum32(&cpio_data[start..end]) as u64
                } else {
                    0
                };

                let _ = syscall::send_nb_4(
                    async_port,
                    IO_READ_REPLY,
                    correlation,
                    bytes_read,
                    csum,
                    0,
                );
            }

            IO_STAT => {
                // data[0] = handle (low 32)
                let file_handle = (msg.data[0] & 0xFFFF_FFFF) as usize;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    let _ = reply_timed(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let _ = reply_timed(
                    IO_STAT_OK,
                    fs.files[file_handle].data_len as u64,
                    0,
                    0,
                    0,
                    0,
                );
            }

            IO_CLOSE => {
                let _ = reply_timed(IO_CONNECT_OK, 0, 0, 0, 0, 0);
            }
            _ => {
                let _ = reply_timed(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }

        // Per-request accounting.  All four workers share these atomics —
        // the cumulative + max number reflect the whole pool.
        let elapsed_ns = syscall::clock_gettime().wrapping_sub(req_start_ns);
        REQS_TIME_NS.fetch_add(elapsed_ns, Ordering::Relaxed);
        let prev_max = REQS_MAX_NS.load(Ordering::Relaxed);
        if elapsed_ns > prev_max {
            // CAS loop so the recorded max is monotonic across workers.
            let mut cur = prev_max;
            while elapsed_ns > cur {
                match REQS_MAX_NS.compare_exchange_weak(
                    cur, elapsed_ns, Ordering::Relaxed, Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => cur = actual,
                }
            }
        }
        // Outlier log: if a single handler runs >1s, dump its tag and
        // latency immediately so we can correlate with the request kind
        // (IO_CONNECT / IO_READ / IO_READ_ASYNC / IO_STAT / etc).  This
        // is the key piece for root-causing the 30s CALL-TIMEOUTs:
        // once we see "tag=0x200 took 18s" we know it's IO_READ
        // memcpy that's slow, not the dispatch.
        if elapsed_ns > 1_000_000_000 {
            syscall::debug_puts(b"  [initramfs_srv] SLOW tag=");
            print_hex32(msg.tag as u32);
            syscall::debug_puts(b" took=");
            print_num(elapsed_ns / 1_000_000);
            syscall::debug_puts(b"ms\n");
        }
        let n = REQS_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if n % PROGRESS_INTERVAL == 0 {
            let total_time = REQS_TIME_NS.load(Ordering::Relaxed);
            let max_ns = REQS_MAX_NS.load(Ordering::Relaxed);
            let reply_total = REPLY_TIME_NS.load(Ordering::Relaxed);
            let reply_max_ns = REPLY_MAX_NS.load(Ordering::Relaxed);
            let avg_us = (total_time / n) / 1_000;
            let max_us = max_ns / 1_000;
            let reply_avg_us = (reply_total / n) / 1_000;
            let reply_max_us = reply_max_ns / 1_000;
            // Format: total_avg / total_max | reply_avg / reply_max
            // total - reply ≈ work (memcpy + decode + dispatch).
            syscall::debug_puts(b"  [initramfs_srv] reqs=");
            print_num(n);
            syscall::debug_puts(b" total avg=");
            print_num(avg_us);
            syscall::debug_puts(b"us max=");
            print_num(max_us);
            syscall::debug_puts(b"us  reply avg=");
            print_num(reply_avg_us);
            syscall::debug_puts(b"us max=");
            print_num(reply_max_us);
            syscall::debug_puts(b"us\n");
        }
    }
}
