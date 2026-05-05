//! riscv64 hypervisor detection — stub.
//!
//! Real detection on riscv64 goes through SBI: `sbi_get_spec_version`
//! plus `sbi_probe_extension` queries identify OpenSBI vs. KVM-as-SBI
//! vs. M-mode firmware.  Hypercall mechanism is ECALL, delegated to
//! M-mode via SBI.
//!
//! Until the real plumbing lands, leave detection as None so the
//! kernel uses native paths.

use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, NO_OP, set_ops};

pub fn detect_and_install() {
    let ops: &'static dyn HypervisorOps = &NO_OP;
    unsafe { set_ops(HypervisorKind::None, ops); }
}
