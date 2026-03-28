#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// Protocol tags (must match kernel/src/io/protocol.rs).
const SEC_LOGIN: u64 = 0x700;
const SEC_LOGIN_OK: u64 = 0x701;
const SEC_LOGIN_FAIL: u64 = 0x702;
const SEC_VERIFY: u64 = 0x703;
const SEC_VERIFY_OK: u64 = 0x704;
const SEC_VERIFY_FAIL: u64 = 0x705;
const SEC_REVOKE: u64 = 0x706;
const SEC_REVOKE_OK: u64 = 0x707;

// Hardcoded user database: (username_hash, password_hash, roles).
const USERS: [(u64, u64, u64); 3] = [
    (0x0001_0001, 0x0001_0002, 0x03), // root: ADMIN|USER
    (0x0002_0001, 0x0002_0002, 0x02), // alice: USER
    (0x0003_0001, 0x0003_0002, 0x04), // guest: GUEST
];

const MAX_CREDENTIALS: usize = 16;

struct Credential {
    port_id: u64,
    username_hash: u64,
    roles: u64,
}

static mut CREDENTIALS: [Option<Credential>; MAX_CREDENTIALS] = {
    const NONE: Option<Credential> = None;
    [NONE; MAX_CREDENTIALS]
};

fn find_user(username_hash: u64, password_hash: u64) -> Option<u64> {
    for &(u, p, roles) in &USERS {
        if u == username_hash && p == password_hash {
            return Some(roles);
        }
    }
    None
}

fn find_credential(port_id: u64) -> Option<usize> {
    for i in 0..MAX_CREDENTIALS {
        let slot = unsafe { &raw const CREDENTIALS };
        let entry = unsafe { &(*slot)[i] };
        if let Some(cred) = entry {
            if cred.port_id == port_id {
                return Some(i);
            }
        }
    }
    None
}

fn alloc_credential(port_id: u64, username_hash: u64, roles: u64) -> bool {
    for i in 0..MAX_CREDENTIALS {
        let slot = unsafe { &raw mut CREDENTIALS };
        let entry = unsafe { &mut (*slot)[i] };
        if entry.is_none() {
            *entry = Some(Credential {
                port_id,
                username_hash,
                roles,
            });
            return true;
        }
    }
    false
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"[security_srv] starting\n");

    // If arg0 is a valid port, use it as our service port (passed from parent).
    // Otherwise, create our own and register with the name server.
    let svc_port = if arg0 > 0 && arg0 != u64::MAX {
        arg0
    } else {
        let p = syscall::port_create();
        if !syscall::ns_register(b"security", p) {
            syscall::debug_puts(b"[security_srv] ns_register failed\n");
            syscall::exit(1);
        }
        p
    };

    syscall::debug_puts(b"[security_srv] listening\n");

    loop {
        let msg = match syscall::recv_msg(svc_port) {
            Some(m) => m,
            None => continue,
        };

        match msg.tag {
            SEC_LOGIN => {
                let username_hash = msg.data[0];
                let password_hash = msg.data[1];
                let reply_port = msg.data[2];

                if let Some(roles) = find_user(username_hash, password_hash) {
                    // Create credential port as token.
                    let cred_port = syscall::port_create();
                    if cred_port != u64::MAX && alloc_credential(cred_port, username_hash, roles) {
                        // Reply with credential port in data[0] — auto-grant
                        // gives client SEND cap to the credential port.
                        syscall::send(reply_port, SEC_LOGIN_OK, cred_port as u64, roles, 0, 0);
                    } else {
                        syscall::send(reply_port, SEC_LOGIN_FAIL, 1, 0, 0, 0);
                    }
                } else {
                    syscall::send(reply_port, SEC_LOGIN_FAIL, 2, 0, 0, 0);
                }
            }
            SEC_VERIFY => {
                let cred_port = msg.data[0];
                let reply_port = msg.data[2];

                if let Some(idx) = find_credential(cred_port) {
                    let slot = unsafe { &raw const CREDENTIALS };
                    let cred = unsafe { (*slot)[idx].as_ref().unwrap() };
                    syscall::send(
                        reply_port,
                        SEC_VERIFY_OK,
                        cred_port as u64,
                        cred.roles,
                        cred.username_hash,
                        0,
                    );
                } else {
                    syscall::send(reply_port, SEC_VERIFY_FAIL, 1, 0, 0, 0);
                }
            }
            SEC_REVOKE => {
                let cred_port = msg.data[0];
                let reply_port = msg.data[2];

                if let Some(idx) = find_credential(cred_port) {
                    syscall::port_destroy(cred_port);
                    let slot = unsafe { &raw mut CREDENTIALS };
                    unsafe {
                        (*slot)[idx] = None;
                    }
                }
                // Idempotent: always reply OK.
                syscall::send(reply_port, SEC_REVOKE_OK, 0, 0, 0, 0);
            }
            _ => {}
        }
    }
}
