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

/// Capability-bundle bitmask (Piece c).  A u64 of rights bits carried
/// alongside every (register, lookup) pair.  Producers (registrants)
/// declare what they grant; consumers (lookup callers) receive the
/// bundle and decide whether the granted rights match what they need.
/// Attenuation along a forwarding chain is bitwise AND with a mask —
/// a NAT rewrite might drop CAP_LOCAL_ADDRESSING; an encryption proxy
/// might add CAP_CONFIDENTIAL.  Each transformer narrows or augments
/// the bundle; the receiver at egress sees the final attenuated set.
pub type CapabilityBundle = u64;

/// Holder may issue read-style requests to the service.
pub const CAP_READ: CapabilityBundle = 1 << 0;
/// Holder may issue write-style requests.
pub const CAP_WRITE: CapabilityBundle = 1 << 1;
/// Holder may issue call/reply invocations (most common).
pub const CAP_INVOKE: CapabilityBundle = 1 << 2;
/// Holder may forward the capability to a third party (delegation).
pub const CAP_FORWARD: CapabilityBundle = 1 << 3;
/// Holder may produce strictly-attenuated derivatives.
pub const CAP_ATTENUATE: CapabilityBundle = 1 << 4;
/// Holder may revoke the capability.
pub const CAP_REVOKE: CapabilityBundle = 1 << 5;
/// Service guarantees confidentiality on the wire (e.g., encrypted
/// proxy hop).  Set by transformers, not by the original registrant.
pub const CAP_CONFIDENTIAL: CapabilityBundle = 1 << 6;
/// Service guarantees integrity (signed messages, MAC, etc.).
pub const CAP_INTEGRITY: CapabilityBundle = 1 << 7;
/// Service is reachable only on the local node (not crossed any
/// network boundary).  Inverse-attenuation: a remote-bonded session
/// drops this bit.
pub const CAP_LOCAL_ONLY: CapabilityBundle = 1 << 8;

/// Default bundle for "ordinary" callable services: invoke + read +
/// write + local-only.  Suitable for a registrant that doesn't have
/// specific rights it wants to advertise.
pub const CAP_DEFAULT: CapabilityBundle =
    CAP_INVOKE | CAP_READ | CAP_WRITE | CAP_LOCAL_ONLY;

/// Successful lookup result: a port to send to, plus the capability
/// bundle the caller's session is authorised under.  The bundle is
/// the (possibly attenuated) rights set propagated through the
/// forwarding chain — the caller can inspect it to decide whether
/// the granted rights match what they need.
#[derive(Copy, Clone, Debug)]
pub struct ServiceEndpoint {
    pub port: u64,
    pub capability_hint: CapabilityBundle,
}

/// Attenuate a bundle: produce a strictly-narrower derivative by
/// AND'ing with a mask.  Pure function, no IPC.  Transformers along
/// the forwarding chain call this to narrow the rights they propagate.
/// Cannot add rights — a transformer that wants to *augment* (e.g.,
/// an encryption proxy adding CAP_CONFIDENTIAL) needs separate
/// machinery and a signed assertion of the new guarantee.
pub fn attenuate(bundle: CapabilityBundle, mask: CapabilityBundle) -> CapabilityBundle {
    bundle & mask
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
/// method index `i` is supported), declaring the rights bundle
/// `bundle` to callers.  The bundle is packed into the upper 32 bits
/// of `method_mask` over the wire — the kernel name server's IPC
/// shape only carries 4 u64 data words and we need both the UUID
/// pair, the mask, the port, and the bundle.  Method count is
/// effectively limited to 32 by this packing; a future revision can
/// lift the limit by adding a multi-word register variant.
///
/// Returns true on success.  Re-registering with the same UUID
/// updates the port + mask + bundle.
pub fn register(
    uuid: &ServiceUuid,
    method_mask: u64,
    bundle: CapabilityBundle,
    service_port: u64,
) -> bool {
    let reg = match registry_port() {
        Some(p) => p,
        None => return false,
    };
    let (w0, w1) = pack_uuid(uuid);
    // Pack: low 32 bits = method_mask, high 32 bits = bundle (low 32
    // bits of the full u64 bundle).  Bundles wider than 32 bits will
    // be silently truncated for now; the rights set we ship is a
    // small u32 in practice.
    let mask_and_bundle =
        (method_mask & 0xFFFF_FFFF) | ((bundle & 0xFFFF_FFFF) << 32);
    match syscall::call(reg, SVCREG_REGISTER, w0, w1, mask_and_bundle, service_port) {
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
