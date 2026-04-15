//! grant_echo_srv — call/reply server that echoes a client-leased buffer
//! with ASCII uppercasing applied in-place.
//!
//! Pilot Step-4 migration to the new IPC primitives (sys_call, sys_reply,
//! grant_pages_lease). The client stages a grant lease against us, calls,
//! we see the client's page mapped at a known dst_va, transform in place,
//! reply with the byte count. The kernel auto-revokes the lease when the
//! cap is freed by sys_reply — no explicit revoke on either side.
//!
//! Protocol:
//!   request: tag = GRANT_ECHO_REQ
//!            data[0] = granted_va (where the lease was mapped in our aspace)
//!            data[1] = length in bytes
//!   reply:   tag = GRANT_ECHO_OK  | data[0] = bytes processed
//!            tag = GRANT_ECHO_ERR | data[0] = error code
//!
//! Registers under the nameserver as b"grant_echo_srv". Clients do:
//!   let p = ns_lookup_wait(b"grant_echo_srv")?;
//!   grant_pages_lease(p, src_va, DST_VA, 1, false);
//!   let r = call(p, GRANT_ECHO_REQ, DST_VA, len, 0, 0);

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

pub const GRANT_ECHO_REQ: u64 = 0x6E01;
pub const GRANT_ECHO_OK: u64 = 0x6E02;
pub const GRANT_ECHO_ERR: u64 = 0x6E03;

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[grant_echo_srv] starting\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[grant_echo_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    if !syscall::ns_register(b"grant_echo_srv", port) {
        syscall::debug_puts(b"[grant_echo_srv] ns_register FAIL\n");
        syscall::exit(1);
    }

    syscall::debug_puts(b"[grant_echo_srv] listening\n");

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };

        if msg.tag != GRANT_ECHO_REQ {
            // Unknown request: reply with error. recv_with_cap already
            // installed the cap on this thread, so sys_reply consumes it.
            let _ = syscall::reply(GRANT_ECHO_ERR, 1, 0, 0, 0, 0);
            continue;
        }

        let va = msg.data[0] as usize;
        let len = msg.data[1] as usize;

        // The leased page is mapped at `va` in our address space by the
        // kernel (sys_grant_pages_lease → mm::grant::grant_pages). Access
        // it in place, uppercase ASCII letters, leave others untouched.
        if va == 0 || len == 0 || len > 4096 {
            let _ = syscall::reply(GRANT_ECHO_ERR, 2, 0, 0, 0, 0);
            continue;
        }

        unsafe {
            let p = va as *mut u8;
            for i in 0..len {
                let b = core::ptr::read_volatile(p.add(i));
                let u = if (b'a'..=b'z').contains(&b) {
                    b - 32
                } else {
                    b
                };
                core::ptr::write_volatile(p.add(i), u);
            }
        }

        let _ = syscall::reply(GRANT_ECHO_OK, len as u64, 0, 0, 0, 0);
        // After sys_reply returns, the kernel has already revoked the
        // client's lease — our mapping at `va` is gone. Do not touch it.
    }
}
