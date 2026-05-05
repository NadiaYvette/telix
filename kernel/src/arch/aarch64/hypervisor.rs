//! aarch64 hypervisor detection via SMCCC.
//!
//! SMCCC (Secure Monitor Calling Convention) provides standardized
//! HVC entry points.  KVM-ARM publishes its presence at function ID
//! `ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID` (0x86000000) — a
//! 16-byte UUID returned in W0..W3.  KVM's UUID is
//! `b66fb428-9728-4b7e-bc6d-e2e3aa42dad4`.  Other UUIDs identify
//! Hyper-V on ARM, etc.
//!
//! Calling HVC at EL1 when no hypervisor is present produces an
//! UNDEFINED INSTRUCTION exception.  A safe probe needs to either
//! check device-tree / ACPI for a "psci" / hypervisor node first,
//! or temporarily install an undefined-instruction handler that
//! reports the HVC as missing.  Telix doesn't yet have either piece
//! wired up for aarch64, so this file remains a stub to avoid
//! crashing bare-metal aarch64 boots.  When the device-tree probe
//! exists, we'd:
//!
//!   1. Check DT for `psci` node with method = "hvc".  If absent,
//!      return HypervisorKind::None.
//!   2. Call HVC with ARM_SMCCC_VERSION (0x80000000); on success
//!      we're under a hypervisor at EL2.
//!   3. Call HVC with the vendor-hyp UID FID (0x86000000); compare
//!      the returned 16-byte value to known UUIDs to identify KVM
//!      vs. Hyper-V vs. other.

use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, NO_OP, set_ops};

pub fn detect_and_install() {
    let ops: &'static dyn HypervisorOps = &NO_OP;
    unsafe { set_ops(HypervisorKind::None, ops); }
}
