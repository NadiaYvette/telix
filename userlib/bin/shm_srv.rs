#![no_std]
#![no_main]

//! Shared memory server — manages named shared memory segments.
//!
//! Clients send IPC requests to create, open, map, and unlink named segments.
//! The server allocates anonymous pages in its own address space and grants
//! them to requesting address spaces.

extern crate userlib;

use userlib::syscall;

// Protocol tags.
const SHM_CREATE: u64 = 0x5000;
const SHM_OPEN: u64 = 0x5001;
const SHM_MAP: u64 = 0x5002;
const SHM_UNMAP: u64 = 0x5003;
const SHM_UNLINK: u64 = 0x5004;

const SHM_OK: u64 = 0x5100;
const SHM_MAP_OK: u64 = 0x5102;
const SHM_ERROR: u64 = 0x5F00;

const MAX_SEGMENTS: usize = 16;
const MAX_NAME_LEN: usize = 16;

struct Segment {
    active: bool,
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    page_count: usize,
    va: usize,
}

impl Segment {
    const fn empty() -> Self {
        Self {
            active: false,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            page_count: 0,
            va: 0,
        }
    }

    fn name_matches(&self, name: &[u8]) -> bool {
        if self.name_len != name.len() {
            return false;
        }
        let mut i = 0;
        while i < self.name_len {
            if self.name[i] != name[i] {
                return false;
            }
            i += 1;
        }
        true
    }
}

static mut SEGMENTS: [Segment; MAX_SEGMENTS] = {
    const EMPTY: Segment = Segment::empty();
    [EMPTY; MAX_SEGMENTS]
};

fn unpack_name(d0: u64, d1: u64, len: usize) -> [u8; MAX_NAME_LEN] {
    let mut buf = [0u8; MAX_NAME_LEN];
    let b0 = d0.to_le_bytes();
    let b1 = d1.to_le_bytes();
    let mut i = 0;
    while i < len && i < 8 {
        buf[i] = b0[i];
        i += 1;
    }
    while i < len && i < 16 {
        buf[i] = b1[i - 8];
        i += 1;
    }
    buf
}

fn find_segment(name: &[u8]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_SEGMENTS {
            if SEGMENTS[i].active && SEGMENTS[i].name_matches(name) {
                return Some(i);
            }
        }
    }
    None
}

fn alloc_segment_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_SEGMENTS {
            if !SEGMENTS[i].active {
                return Some(i);
            }
        }
    }
    None
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let svc_port = if arg0 > 0 && arg0 != u64::MAX {
        arg0
    } else {
        let p = syscall::port_create();
        syscall::ns_register(b"shm", p);
        p
    };

    let my_aspace = syscall::aspace_id();

    // Call/reply server: recv_with_cap installs the reply-cap onto this
    // thread; every request path must consume the cap by calling sys_reply
    // exactly once (including error paths), or the kernel's server-death
    // teardown will eventually deliver CALL_REPLY_SERVER_DIED to the caller.
    loop {
        let msg = match syscall::recv_with_cap(svc_port) {
            Some(m) => m,
            None => continue,
        };

        // data[4] holds the sender task port stamped by sys_call; that's our
        // client_aspace for SHM_MAP/SHM_UNMAP. No more per-request reply_port.
        let client_aspace = msg.data[4];

        match msg.tag {
            SHM_CREATE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let page_count = msg.data[3] as usize;

                if name_len == 0 || name_len > MAX_NAME_LEN || page_count == 0 || page_count > 256 {
                    let _ = syscall::reply(SHM_ERROR, 1, 0, 0, 0, 0);
                    continue;
                }

                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len];

                // Check if already exists — return existing handle.
                if let Some(idx) = find_segment(name) {
                    let pc = unsafe { SEGMENTS[idx].page_count };
                    let _ = syscall::reply(
                        SHM_OK,
                        idx as u64,
                        pc as u64,
                        my_aspace as u64,
                        0,
                        0,
                    );
                    continue;
                }

                let slot = match alloc_segment_slot() {
                    Some(s) => s,
                    None => {
                        let _ = syscall::reply(SHM_ERROR, 2, 0, 0, 0, 0);
                        continue;
                    }
                };

                // page_count from the protocol is in alloc pages (historical
                // semantics — predates the grant_pages mmu-count fix in
                // dec88a7).  Convert to mmu pages for both mmap_anon and the
                // subsequent grant_pages calls in SHM_MAP.
                let ps = syscall::page_size();
                let mmu_per_alloc = ps / 4096;
                let mmu_pages = page_count * mmu_per_alloc;

                let va = match syscall::mmap_anon(0, mmu_pages, 1) {
                    Some(v) => v,
                    None => {
                        let _ = syscall::reply(SHM_ERROR, 3, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Touch pages to ensure physical backing (grants require it).
                let ptr = va as *mut u8;
                for p in 0..page_count {
                    unsafe {
                        core::ptr::write_volatile(ptr.add(p * ps), 0);
                    }
                }

                unsafe {
                    SEGMENTS[slot].active = true;
                    SEGMENTS[slot].name = name_buf;
                    SEGMENTS[slot].name_len = name_len;
                    SEGMENTS[slot].page_count = page_count;
                    SEGMENTS[slot].va = va;
                }

                let _ = syscall::reply(
                    SHM_OK,
                    slot as u64,
                    page_count as u64,
                    my_aspace as u64,
                    0,
                    0,
                );
            }

            SHM_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;

                if name_len == 0 || name_len > MAX_NAME_LEN {
                    let _ = syscall::reply(SHM_ERROR, 1, 0, 0, 0, 0);
                    continue;
                }

                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len];

                match find_segment(name) {
                    Some(idx) => {
                        let pc = unsafe { SEGMENTS[idx].page_count };
                        let _ = syscall::reply(
                            SHM_OK,
                            idx as u64,
                            pc as u64,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                    None => {
                        let _ = syscall::reply(SHM_ERROR, 4, 0, 0, 0, 0);
                    }
                }
            }

            SHM_MAP => {
                // d0=handle, d2=(readonly flag), d3=dst_va. Sender aspace is
                // in data[4] (auto-stamped by sys_call). The SHM mapping is a
                // long-lived grant that outlives this call — deliberately
                // NOT using GrantLease, which would be revoked on reply.
                let handle = msg.data[0] as usize;
                let dst_va = msg.data[3] as usize;
                let readonly = (msg.data[2] & 1) != 0;

                if handle >= MAX_SEGMENTS {
                    let _ = syscall::reply(SHM_ERROR, 5, 0, 0, 0, 0);
                    continue;
                }

                let (active, src_va, page_count) = unsafe {
                    (
                        SEGMENTS[handle].active,
                        SEGMENTS[handle].va,
                        SEGMENTS[handle].page_count,
                    )
                };

                if !active {
                    let _ = syscall::reply(SHM_ERROR, 6, 0, 0, 0, 0);
                    continue;
                }

                // page_count is alloc pages; grant_pages takes mmu pages.
                let ps = syscall::page_size();
                let mmu_per_alloc = ps / 4096;
                let mmu_pages = page_count * mmu_per_alloc;
                if syscall::grant_pages(client_aspace, src_va, dst_va, mmu_pages, readonly) {
                    let _ = syscall::reply(
                        SHM_MAP_OK,
                        handle as u64,
                        page_count as u64,
                        0,
                        0,
                        0,
                    );
                } else {
                    let _ = syscall::reply(SHM_ERROR, 7, 0, 0, 0, 0);
                }
            }

            SHM_UNMAP => {
                let handle = msg.data[0] as usize;
                let dst_va = msg.data[3] as usize;

                if handle < MAX_SEGMENTS {
                    let active = unsafe { SEGMENTS[handle].active };
                    if active {
                        syscall::revoke(client_aspace, dst_va);
                    }
                }

                let _ = syscall::reply(SHM_OK, 0, 0, 0, 0, 0);
            }

            SHM_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;

                if name_len == 0 || name_len > MAX_NAME_LEN {
                    let _ = syscall::reply(SHM_ERROR, 1, 0, 0, 0, 0);
                    continue;
                }

                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len];

                match find_segment(name) {
                    Some(idx) => {
                        let va = unsafe { SEGMENTS[idx].va };
                        syscall::munmap(va);
                        unsafe {
                            SEGMENTS[idx].active = false;
                        }
                        let _ = syscall::reply(SHM_OK, 0, 0, 0, 0, 0);
                    }
                    None => {
                        let _ = syscall::reply(SHM_ERROR, 4, 0, 0, 0, 0);
                    }
                }
            }

            _ => {
                let _ = syscall::reply(SHM_ERROR, 0xFF, 0, 0, 0, 0);
            }
        }
    }
}
