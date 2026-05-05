//! mips64 hypervisor detection — stub.

use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, NO_OP, set_ops};

pub fn detect_and_install() {
    let ops: &'static dyn HypervisorOps = &NO_OP;
    unsafe { set_ops(HypervisorKind::None, ops); }
}
