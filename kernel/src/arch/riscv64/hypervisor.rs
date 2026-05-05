//! riscv64 hypervisor detection via SBI (Supervisor Binary Interface).
//!
//! On riscv64, SBI is the standard interface between the supervisor
//! (us) and M-mode firmware (OpenSBI, etc.) or a hypervisor presenting
//! itself as SBI (KVM-RISCV).  Detection uses two SBI base-extension
//! calls:
//!
//!   sbi_get_spec_version  (EID=0x10, FID=0)
//!   sbi_get_impl_id       (EID=0x10, FID=1)  -> 4 = KVM
//!                                             3 = OpenSBI (bare metal)
//!                                             others per the SBI spec
//!
//! When KVM is detected we publish HypervisorKind::Kvm but no concrete
//! ops yet — KVM-RISCV's PV extensions (currently just SBI sta/STA for
//! steal-time and IPI accelerators) are smaller than x86's set and
//! follow the SBI extension probe pattern.  Wired in once we have a
//! riscv64 boot to verify against.

use core::arch::asm;
use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, NO_OP, set_ops};

const SBI_EID_BASE: u64 = 0x10;
const SBI_FID_GET_IMPL_ID: u64 = 1;
#[allow(dead_code)]
const SBI_FID_GET_SPEC_VERSION: u64 = 0;
#[allow(dead_code)]
const SBI_IMPL_BBL: u64 = 0;
#[allow(dead_code)]
const SBI_IMPL_OPENSBI: u64 = 1;
const SBI_IMPL_KVM: u64 = 4;

#[repr(C)]
struct SbiRet {
    error: i64,
    value: i64,
}

#[inline]
unsafe fn sbi_call(eid: u64, fid: u64) -> SbiRet {
    let error: i64;
    let value: i64;
    unsafe {
        asm!(
            "ecall",
            in("a7") eid,
            in("a6") fid,
            lateout("a0") error,
            lateout("a1") value,
            options(nostack, preserves_flags),
        );
    }
    SbiRet { error, value }
}

pub fn detect_and_install() {
    let ret = unsafe { sbi_call(SBI_EID_BASE, SBI_FID_GET_IMPL_ID) };
    let kind = if ret.error == 0 && (ret.value as u64) == SBI_IMPL_KVM {
        HypervisorKind::Kvm
    } else if ret.error == 0 {
        // SBI present but not KVM — bare metal under OpenSBI etc.
        HypervisorKind::None
    } else {
        HypervisorKind::None
    };
    let ops: &'static dyn HypervisorOps = &NO_OP;
    unsafe { set_ops(kind, ops); }
}
