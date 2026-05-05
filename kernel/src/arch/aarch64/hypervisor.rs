//! aarch64 hypervisor detection — stub.
//!
//! Real detection on aarch64 goes through SMCCC: issue
//! `ARM_SMCCC_VERSION` HVC and inspect the response, plus device-tree
//! `psci` properties to distinguish hypervisor implementations.  KVM
//! on ARM publishes hyp services through SMCCC.  Hypercall mechanism
//! is HVC #imm with the SMCCC convention.
//!
//! Until the real plumbing lands, leave detection as None so the
//! kernel uses native paths.

use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, NO_OP, set_ops};

pub fn detect_and_install() {
    let ops: &'static dyn HypervisorOps = &NO_OP;
    unsafe { set_ops(HypervisorKind::None, ops); }
}
