//! Architecture-independent hypervisor abstraction.
//!
//! Detects the hypervisor (if any) at boot via the architecture-specific
//! probe, and exposes a `HypervisorOps` trait for paravirt operations
//! (PV IPI, stolen-time accounting, vcpu yield, ...).  Concrete
//! implementations live under `arch::<arch>::hypervisor` and register
//! themselves at boot via `set_ops`.
//!
//! Phases:
//!  1. (this file)   Detection enum + trait skeleton + global slot,
//!                   default no-op impl so the rest of the kernel can
//!                   call into `ops()` unconditionally.
//!  2. (later)       PV IPI fast path: when KVM detected and feature
//!                   advertised, send_ipi() routes through hypercall
//!                   instead of memory-mapped LAPIC ICR write.
//!  3. (later)       Stolen-time accounting: scheduler subtracts
//!                   host-descheduled time from quantum counters.
//!  4. (later)       Per-arch hypercall plumbing (x86 VMCALL, aarch64
//!                   HVC, riscv ECALL/SBI).

use core::sync::atomic::{AtomicU8, Ordering};

/// Identification of the hypervisor we're running under.  Detected
/// once at boot.  `None` covers both bare metal and unrecognized
/// hypervisors — in either case we fall through to the no-op
/// implementation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum HypervisorKind {
    /// Bare metal or unidentified hypervisor.
    None = 0,
    /// QEMU/KVM (signature "KVMKVMKVM\0\0\0" on x86 CPUID 0x40000000).
    Kvm = 1,
    /// QEMU TCG (faithful CPU emulator, signature "TCGTCGTCGTCG").
    /// No paravirt hypercalls — included for awareness so the kernel
    /// can adjust expectations (slower simulation, no PV IPI).
    Tcg = 2,
    /// Microsoft Hyper-V ("Microsoft Hv").
    HyperV = 3,
    /// VMware ("VMwareVMware").
    Vmware = 4,
    /// Xen ("XenVMMXenVMM").
    Xen = 5,
    /// Detected hypervisor signature but no specific match.
    UnknownHypervisor = 6,
}

/// Cross-arch trait for paravirt operations.  Default no-op
/// implementations keep callers ergonomic — `ops().send_ipi(cpu)`
/// works whether we're on bare metal or under a recognized
/// hypervisor; only the latter overrides the default.
pub trait HypervisorOps: Sync {
    /// Best-effort fast-path IPI through the hypervisor.  Returns
    /// true if the hypercall was used, false if the caller should
    /// fall back to the architecture-native IPI path
    /// (LAPIC ICR / GIC SGI / SBI IPI).
    fn send_reschedule_ipi(&self, _target_cpu: u32) -> bool {
        false
    }

    /// Stolen time in nanoseconds since boot for the calling vCPU
    /// (host-descheduled time excluded from guest accounting).
    /// Returns `None` if the hypervisor doesn't expose this.
    fn steal_time_ns(&self) -> Option<u64> {
        None
    }

    /// Hint the hypervisor that the calling vCPU is waiting for
    /// `target_cpu` (which holds a contended lock or is the
    /// recipient of a pending IPI).  Returns true if the hint was
    /// delivered.  Useful for spinlock contention.
    fn yield_to(&self, _target_cpu: u32) -> bool {
        false
    }
}

/// Default no-op implementation.  Used when no hypervisor is
/// detected, when the detected hypervisor doesn't override a
/// particular op, or before `set_ops` runs at boot.
pub struct NoOpHypervisor;
impl HypervisorOps for NoOpHypervisor {}

pub static NO_OP: NoOpHypervisor = NoOpHypervisor;

/// The active hypervisor's ops vtable.  Populated at boot by
/// `set_ops`.  Until then (and when no hypervisor is detected),
/// resolves to `NoOpHypervisor`.
static mut OPS: &'static dyn HypervisorOps = &NO_OP;

/// AtomicU8 of the detected `HypervisorKind`.  Read freely from
/// any context after boot.
static KIND: AtomicU8 = AtomicU8::new(0);

/// Called once at boot from `arch::platform::init` (or equivalent)
/// to publish the detection result and any concrete ops vtable.
///
/// Safety: must be called exactly once, before any other CPU is
/// brought up, so the plain `static mut OPS` write is uncontested.
pub unsafe fn set_ops(kind: HypervisorKind, ops: &'static dyn HypervisorOps) {
    unsafe {
        OPS = ops;
    }
    KIND.store(kind as u8, Ordering::Release);
}

/// Currently detected hypervisor kind.  `None` until `set_ops` runs.
pub fn kind() -> HypervisorKind {
    match KIND.load(Ordering::Acquire) {
        1 => HypervisorKind::Kvm,
        2 => HypervisorKind::Tcg,
        3 => HypervisorKind::HyperV,
        4 => HypervisorKind::Vmware,
        5 => HypervisorKind::Xen,
        6 => HypervisorKind::UnknownHypervisor,
        _ => HypervisorKind::None,
    }
}

/// Active hypervisor ops vtable.  Always returns a valid reference
/// — the no-op implementation before `set_ops`, or the detected
/// implementation after.
pub fn ops() -> &'static dyn HypervisorOps {
    unsafe { OPS }
}

/// Per-arch detection.  Each architecture defines its own
/// `arch::<arch>::hypervisor::detect_and_install` that probes the
/// platform's hypervisor signature mechanism (CPUID on x86, SMCCC
/// on aarch64, SBI on riscv) and calls `set_ops` with the
/// appropriate kind + ops impl.  Called once at boot.
pub fn detect_and_install() {
    crate::arch::platform::hypervisor::detect_and_install();
}
