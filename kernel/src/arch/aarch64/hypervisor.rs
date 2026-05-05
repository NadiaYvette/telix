//! aarch64 hypervisor detection via DT + SMCCC.
//!
//! At EL1, Telix calls HVC #0 to issue Standardized SMCCC functions.
//! At bare metal HVC traps as UNDEFINED INSTRUCTION (no hypervisor at
//! EL2 to handle it), so we MUST gate the probe behind a device-tree
//! check for a `/psci` node with `method = "hvc"`.  The PSCI node
//! presence (with hvc method) confirms a hypervisor or secure monitor
//! at EL2 willing to handle our HVC.
//!
//! Detection flow:
//!   1. Find FDT via the boot-stashed DTB_ADDR (already populated by
//!      arch::aarch64::boot::_rust_entry, with find_fdt_in_ram() as
//!      fallback when QEMU's ELF-kernel path doesn't pass x0).
//!   2. Locate `/psci` node and inspect its `method` property.  If it
//!      isn't `"hvc"`, return HypervisorKind::None — HVC is unsafe.
//!   3. Issue HVC with x0 = ARM_SMCCC_VENDOR_HYP_CALL_UID (0x8600_0000).
//!      Return values in w0..w3 form a 16-byte UUID identifying the
//!      hypervisor implementation.
//!   4. Map known UUIDs:
//!      - KVM:    b66fb428-9728-4b7e-bc6d-e2e3aa42dad4
//!      - Hyper-V on ARM, Xen on ARM, etc. each have their own.

use core::arch::asm;
use core::sync::atomic::Ordering;
use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, NO_OP, set_ops};
use crate::arch::aarch64::boot::DTB_ADDR;
use crate::firmware::dtb::Fdt;

/// SMCCC function ID for the Vendor-specific Hypervisor Service UID
/// query.  Returns the hypervisor's identifying UUID in w0..w3.
const SMCCC_VENDOR_HYP_CALL_UID: u64 = 0x8600_0000;

/// KVM-ARM's published UUID, register-encoded.  These are the four
/// 32-bit values returned in w0..w3 from the vendor-hyp UID HVC when
/// running under KVM.  Source: Linux kernel's
/// `include/linux/arm-smccc.h` ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_*.
/// Verify on first aarch64 boot under KVM by printing the returned
/// values; this constant set is the canonical Linux export.
const KVM_UID_W0: u32 = 0xb66f_b428;
const KVM_UID_W1: u32 = 0xe911_c52e;
const KVM_UID_W2: u32 = 0x564b_caa9;
const KVM_UID_W3: u32 = 0x743a_004d;

/// Issue an HVC call with the SMCCC convention: function ID in x0,
/// up to four results returned in x0..x3.  Caller must have already
/// confirmed HVC is safe to issue (i.e., a hypervisor exists at EL2).
#[inline]
unsafe fn smccc_hvc_uid(fid: u64) -> (u32, u32, u32, u32) {
    let r0: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    unsafe {
        asm!(
            "hvc #0",
            inout("x0") fid => r0,
            lateout("x1") r1,
            lateout("x2") r2,
            lateout("x3") r3,
            options(nostack, preserves_flags),
        );
    }
    (r0 as u32, r1 as u32, r2 as u32, r3 as u32)
}

pub fn detect_and_install() {
    let dtb = DTB_ADDR.load(Ordering::Relaxed);
    if dtb == 0 {
        let ops: &'static dyn HypervisorOps = &NO_OP;
        unsafe { set_ops(HypervisorKind::None, ops); }
        return;
    }
    // SAFETY: the FDT was placed in RAM by the bootloader (QEMU virt)
    // and verified by fdt_magic_ok in arch::aarch64::boot.  The slice
    // length is bounded by the FDT's own totalsize header which Fdt::new
    // re-validates; we hand it a generous 16 MiB upper bound which the
    // FDT parser narrows to its actual size.
    let raw = unsafe { core::slice::from_raw_parts(dtb as *const u8, 16 * 1024 * 1024) };
    let fdt = match Fdt::new(raw) {
        Ok(f) => f,
        Err(_) => {
            let ops: &'static dyn HypervisorOps = &NO_OP;
            unsafe { set_ops(HypervisorKind::None, ops); }
            return;
        }
    };
    let psci = match fdt.find_node(b"/psci") {
        Some(n) => n,
        None => {
            // No /psci node — typically means no hypervisor and
            // no secure-monitor power-management.  HVC is unsafe.
            let ops: &'static dyn HypervisorOps = &NO_OP;
            unsafe { set_ops(HypervisorKind::None, ops); }
            return;
        }
    };
    let method = match psci.property(b"method") {
        Some(p) => p.data,
        None => {
            let ops: &'static dyn HypervisorOps = &NO_OP;
            unsafe { set_ops(HypervisorKind::None, ops); }
            return;
        }
    };
    // FDT strings are NUL-terminated; "hvc\0" or just "hvc".
    let is_hvc = method.starts_with(b"hvc");
    if !is_hvc {
        // method = "smc" → secure-monitor only, no hypervisor at EL2.
        let ops: &'static dyn HypervisorOps = &NO_OP;
        unsafe { set_ops(HypervisorKind::None, ops); }
        return;
    }

    // HVC is safe to issue — we're at EL1 with a hypervisor at EL2.
    let (w0, w1, w2, w3) = unsafe { smccc_hvc_uid(SMCCC_VENDOR_HYP_CALL_UID) };
    crate::println!(
        "[hypervisor] aarch64 SMCCC vendor-hyp UID = {:08x}-{:08x}-{:08x}-{:08x}",
        w0, w1, w2, w3
    );
    let kind = if w0 == KVM_UID_W0 && w1 == KVM_UID_W1
        && w2 == KVM_UID_W2 && w3 == KVM_UID_W3
    {
        HypervisorKind::Kvm
    } else if w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0 {
        // SMCCC convention: all-zero return means "function not
        // implemented" — hypervisor at EL2 doesn't expose a vendor
        // UID.  Treat as unknown rather than KVM.
        HypervisorKind::UnknownHypervisor
    } else {
        // Some hypervisor responded but it's not one we recognize.
        // Add Hyper-V/Xen/etc. UIDs here as needed.
        HypervisorKind::UnknownHypervisor
    };

    // No concrete HypervisorOps yet — KVM-ARM's PV ops (PV_LOCK_FEATURES,
    // PTP_KVM via SMCCC, etc.) are smaller than x86's set and follow the
    // SMCCC service-discovery pattern.  When wired in, define a struct
    // KvmHypervisorArm with HypervisorOps method overrides and select
    // it here based on `kind == HypervisorKind::Kvm`.
    let ops: &'static dyn HypervisorOps = &NO_OP;
    unsafe { set_ops(kind, ops); }
}
