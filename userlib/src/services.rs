//! Content-addressed service registry — userlib client (Piece (b)).
//!
//! Wraps the `servicereg_srv` IPC protocol so callers can address
//! services by 16-byte UUID + method index instead of the kernel
//! name-server's string-keyed binding.  Today this resolves locally
//! only; once distributed bonding lands, lookup will transparently
//! consult remote peers' servicereg instances and return the best
//! match per the caller's constraints.
//!
//! Service-UUID convention: each service kind picks a stable v4 random
//! UUID and publishes it.  Implementations register that UUID; clients
//! look it up by the same UUID.  No string negotiation, no version
//! drift across name spellings, and the wire format is the same shape
//! cross-architecture.

use crate::syscall;

// IPC protocol tags (must match servicereg_srv).
const SVCREG_REGISTER: u64 = 0x7E01;
const SVCREG_REGISTER_OK: u64 = 0x7E02;
const SVCREG_UNREGISTER: u64 = 0x7E03;
const SVCREG_UNREGISTER_OK: u64 = 0x7E04;
const SVCREG_LOOKUP: u64 = 0x7E10;
const SVCREG_LOOKUP_OK: u64 = 0x7E11;

/// 16-byte service UUID.  Authors of services pick + publish the
/// UUID for their service kind; all implementations use the same UUID.
pub type ServiceUuid = [u8; 16];

/// Successful lookup result: a port to send to, plus a capability
/// hint (placeholder u64 today; piece (c) will carry the attenuated
/// capability bundle authorising the calling session).
#[derive(Copy, Clone, Debug)]
pub struct ServiceEndpoint {
    pub port: u64,
    pub capability_hint: u64,
}

fn pack_uuid(uuid: &ServiceUuid) -> (u64, u64) {
    let mut w0 = [0u8; 8];
    let mut w1 = [0u8; 8];
    w0.copy_from_slice(&uuid[0..8]);
    w1.copy_from_slice(&uuid[8..16]);
    (u64::from_le_bytes(w0), u64::from_le_bytes(w1))
}

fn registry_port() -> Option<u64> {
    syscall::ns_lookup(b"servicereg")
}

/// Register `service_port` as the local provider of service `uuid`,
/// supporting the methods specified by `method_mask` (bit `i` set =
/// method index `i` is supported).  Returns true on success.
///
/// Re-registering with the same UUID updates the port + mask.  Use
/// `unregister` to remove a registration.
pub fn register(uuid: &ServiceUuid, method_mask: u64, service_port: u64) -> bool {
    let reg = match registry_port() {
        Some(p) => p,
        None => return false,
    };
    let (w0, w1) = pack_uuid(uuid);
    match syscall::call(reg, SVCREG_REGISTER, w0, w1, method_mask, service_port) {
        Some(m) => m.tag == SVCREG_REGISTER_OK,
        None => false,
    }
}

/// Unregister a previously-registered service.  Caller must supply the
/// same `service_port` it registered with — the registry only honors
/// requests from the original registrant.
pub fn unregister(uuid: &ServiceUuid, service_port: u64) -> bool {
    let reg = match registry_port() {
        Some(p) => p,
        None => return false,
    };
    let (w0, w1) = pack_uuid(uuid);
    match syscall::call(reg, SVCREG_UNREGISTER, w0, w1, service_port, 0) {
        Some(m) => m.tag == SVCREG_UNREGISTER_OK,
        None => false,
    }
}

/// Look up an endpoint providing `uuid` + `method`.  Returns
/// None if no provider is registered (locally — once distributed
/// bonding lands, this also consults remote peers).
///
/// Method 0..=63 selects a specific method; out-of-range values
/// match any provider of the UUID regardless of method support.
pub fn lookup(uuid: &ServiceUuid, method: u32) -> Option<ServiceEndpoint> {
    let reg = registry_port()?;
    let (w0, w1) = pack_uuid(uuid);
    let resp = syscall::call(reg, SVCREG_LOOKUP, w0, w1, method as u64, 0)?;
    if resp.tag != SVCREG_LOOKUP_OK {
        return None;
    }
    Some(ServiceEndpoint {
        port: resp.data[0],
        capability_hint: resp.data[1],
    })
}
