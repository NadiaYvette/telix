//! x86_64 hypervisor detection and KVM-specific paravirt ops.
//!
//! Detection: CPUID leaf 0x40000000 returns the hypervisor's
//! 12-byte signature in EBX/ECX/EDX (when running under any of the
//! recognized hypervisors).  A separate "HV present" hint sits at
//! CPUID leaf 1 ECX bit 31.
//!
//! The KVM-specific ops (PV_SEND_IPI, STEAL_TIME, ...) live here
//! and are wired up only when the KVM signature is found AND the
//! corresponding feature bit is advertised in CPUID 0x40000001 EAX.
//!
//! Hypercall mechanism: VMCALL on Intel, VMMCALL on AMD.  Until we
//! plumb the actual hypercall (next phase), the impl returns false
//! from each op so the kernel falls back to the native path.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use crate::arch::hypervisor::{HypervisorKind, HypervisorOps, set_ops};

// KVM CPUID feature bits (from CPUID 0x40000001 EAX).
const KVM_FEATURE_PV_SEND_IPI: u32 = 1 << 11;
#[allow(dead_code)]
const KVM_FEATURE_STEAL_TIME: u32 = 1 << 5;
const KVM_FEATURE_PV_UNHALT: u32 = 1 << 7;
#[allow(dead_code)]
const KVM_FEATURE_PV_SCHED_YIELD: u32 = 1 << 13;
/// MSR_KVM_SYSTEM_TIME_NEW pvclock support advertised at bit 3 of
/// CPUID 0x40000001 EAX.  Telix scheduler residual #135 / paravirt
/// Layer 2: replaces TSC-based monotonic_ns with vCPU-monotonic
/// time that excludes host-pause durations.
const KVM_FEATURE_CLOCKSOURCE2: u32 = 1 << 3;

// KVM hypercall numbers (matches arch/x86/include/uapi/asm/kvm_para.h).
const KVM_HC_SEND_IPI: u64 = 12;
/// Wake target vCPU from HLT.  Paired with KVM_FEATURE_PV_UNHALT.
/// Args: a0 = flags (0), a1 = target apicid.
const KVM_HC_KICK_CPU: u64 = 5;

// KVM model-specific registers (kvm_para.h).
/// MSR for per-vCPU steal-time page address.  Write phys_addr | 1 to
/// enable; the host accumulates stolen-time updates into the page.
const MSR_KVM_STEAL_TIME: u32 = 0x4b56_4d03;

/// MSR for per-vCPU pvclock (CLOCKSOURCE2) page address.  Write
/// phys_addr | 1 to enable; the host updates a `pvclock_vcpu_time_info`
/// at that address with a seqlock-style version field.
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;

/// Layout matches Linux's `struct kvm_steal_time` (arch/x86/include/uapi/
/// asm/kvm_para.h).  64 bytes total.  Host writes; guest reads volatile.
/// `steal` is accumulated host-descheduled time in nanoseconds for the
/// vCPU this page is bound to.
#[repr(C, align(64))]
struct KvmStealTime {
    steal: core::sync::atomic::AtomicU64,
    version: core::sync::atomic::AtomicU32,
    flags: u32,
    preempted: u8,
    _pad0: [u8; 3],
    _pad1: [u32; 11],
}

/// Per-CPU steal-time pages.  Each vCPU gets its own page, with the
/// MSR pointing at it written from that CPU at bring-up.  The host
/// updates the steal field while the vCPU is host-descheduled.
const KVM_ST_NEW: KvmStealTime = KvmStealTime {
    steal: core::sync::atomic::AtomicU64::new(0),
    version: core::sync::atomic::AtomicU32::new(0),
    flags: 0,
    preempted: 0,
    _pad0: [0; 3],
    _pad1: [0; 11],
};
static STEAL_TIME: [KvmStealTime; crate::sched::smp::MAX_CPUS] =
    [KVM_ST_NEW; crate::sched::smp::MAX_CPUS];
static KVM_STEAL_TIME_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable STEAL_TIME for the calling CPU.  Reads the flag set by
/// `detect_and_install` (BSP-side) — APs check it and bind their
/// own page if the feature is advertised.  Idempotent.
pub fn enable_steal_time_self() {
    if !KVM_STEAL_TIME_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let cpu = crate::sched::smp::cpu_id() as usize;
    if cpu >= crate::sched::smp::MAX_CPUS {
        return;
    }
    let pa = &STEAL_TIME[cpu] as *const _ as u64;
    unsafe { wrmsr(MSR_KVM_STEAL_TIME, pa | 1); }
}

/// Per-vCPU pvclock page.  Host writes a `pvclock_vcpu_time_info` here
/// (32 bytes packed in Linux), guest reads seqlock-style.  We hold one
/// 64-byte-aligned slot per CPU; the MSR is written from each CPU at
/// bringup, pointing to its own slot.  All fields are atomic for cross-
/// CPU read safety; the seqlock pattern on `version` guarantees a
/// consistent snapshot of the rest.
#[repr(C, align(64))]
struct PvclockVcpuTimeInfo {
    version: core::sync::atomic::AtomicU32,
    pad0: u32,
    tsc_timestamp: core::sync::atomic::AtomicU64,
    system_time: core::sync::atomic::AtomicU64,
    tsc_to_system_mul: core::sync::atomic::AtomicU32,
    tsc_shift: core::sync::atomic::AtomicI8,
    flags: core::sync::atomic::AtomicU8,
    _pad: [u8; 2],
}

const PVCLOCK_NEW: PvclockVcpuTimeInfo = PvclockVcpuTimeInfo {
    version: core::sync::atomic::AtomicU32::new(0),
    pad0: 0,
    tsc_timestamp: core::sync::atomic::AtomicU64::new(0),
    system_time: core::sync::atomic::AtomicU64::new(0),
    tsc_to_system_mul: core::sync::atomic::AtomicU32::new(0),
    tsc_shift: core::sync::atomic::AtomicI8::new(0),
    flags: core::sync::atomic::AtomicU8::new(0),
    _pad: [0u8; 2],
};

static PVCLOCK: [PvclockVcpuTimeInfo; crate::sched::smp::MAX_CPUS] =
    [PVCLOCK_NEW; crate::sched::smp::MAX_CPUS];
static KVM_PVCLOCK_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable pvclock for the calling CPU.  Each vCPU writes its own
/// per-CPU page address into MSR_KVM_SYSTEM_TIME_NEW.  Idempotent.
pub fn enable_pvclock_self() {
    if !KVM_PVCLOCK_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let cpu = crate::sched::smp::cpu_id() as usize;
    if cpu >= crate::sched::smp::MAX_CPUS {
        return;
    }
    let pa = &PVCLOCK[cpu] as *const _ as u64;
    unsafe {
        wrmsr(MSR_KVM_SYSTEM_TIME_NEW, pa | 1);
    }
}

/// Read pvclock-based monotonic ns for this CPU, or None if pvclock
/// isn't enabled / mapped / valid.  Implements the standard seqlock
/// reader pattern from Linux's `pvclock_clocksource_read`: read
/// version (odd = in-progress, retry), read fields, re-read version,
/// retry on mismatch.  Time arithmetic: `system_time + scaled_delta`
/// where `scaled_delta = (((tsc - tsc_timestamp) << shift) * mul) >> 32`
/// for shift >= 0; right-shift by `-shift` otherwise.
#[inline]
pub fn pvclock_now_ns() -> Option<u64> {
    if !KVM_PVCLOCK_ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let cpu = crate::sched::smp::cpu_id() as usize;
    if cpu >= crate::sched::smp::MAX_CPUS {
        return None;
    }
    let p = &PVCLOCK[cpu];
    for _ in 0..16 {
        let v0 = p.version.load(Ordering::Acquire);
        if v0 == 0 || v0 & 1 != 0 {
            // 0 = host hasn't initialised yet; odd = update in progress.
            continue;
        }
        let ts = p.tsc_timestamp.load(Ordering::Relaxed);
        let st = p.system_time.load(Ordering::Relaxed);
        let mul = p.tsc_to_system_mul.load(Ordering::Relaxed);
        let shift = p.tsc_shift.load(Ordering::Relaxed);
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        let v1 = p.version.load(Ordering::Acquire);
        if v0 != v1 {
            continue;
        }
        let mut delta = tsc.wrapping_sub(ts) as u128;
        if shift >= 0 {
            delta <<= shift as u32;
        } else {
            delta >>= (-shift) as u32;
        }
        let scaled = (delta * (mul as u128)) >> 32;
        return Some(st.wrapping_add(scaled as u64));
    }
    None
}

#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

// Vendor enum used to pick VMCALL vs VMMCALL.
const VENDOR_UNKNOWN: u8 = 0;
const VENDOR_INTEL: u8 = 1;
const VENDOR_AMD: u8 = 2;

static CPU_VENDOR: AtomicU8 = AtomicU8::new(VENDOR_UNKNOWN);
static KVM_PV_SEND_IPI_ENABLED: AtomicBool = AtomicBool::new(false);
/// PV wake-from-HLT (KVM_HC_KICK_CPU) available.  Used by `kick_cpu`
/// to wake a vCPU whose physical CPU is host-descheduled, pairing
/// with the reschedule IPI so cross-CPU wakes don't stall waiting
/// for the host scheduler to bring the target vCPU back in.
static KVM_PV_UNHALT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Run CPUID leaf `leaf` with `subleaf` 0; returns (eax, ebx, ecx, edx).
/// LLVM reserves rbx so we can't bind it directly — capture EBX into a
/// temporary register and copy it out as a u64.
#[inline]
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx_tmp: u64;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = lateout(reg) ebx_tmp,
            inout("eax") leaf => eax,
            inout("ecx") 0u32 => ecx,
            lateout("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    (eax, ebx_tmp as u32, ecx, edx)
}

/// Pack three u32s into the 12-byte signature buffer.
fn signature_from_regs(ebx: u32, ecx: u32, edx: u32) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&ebx.to_le_bytes());
    buf[4..8].copy_from_slice(&ecx.to_le_bytes());
    buf[8..12].copy_from_slice(&edx.to_le_bytes());
    buf
}

/// KVM hypercall: VMCALL on Intel, VMMCALL on AMD.  KVM patches
/// the instruction at runtime in Linux; we branch on the cached
/// vendor.  All KVM hypercalls follow the same convention:
///   RAX = nr,  RBX = a0, RCX = a1, RDX = a2, RSI = a3
/// returning a u64 in RAX.
#[inline]
unsafe fn kvm_hypercall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    // LLVM reserves rbx for its own use, so we can't pass it as an
    // operand directly.  Save → load → restore around the hypercall.
    let vendor = CPU_VENDOR.load(Ordering::Relaxed);
    if vendor == VENDOR_AMD {
        unsafe {
            asm!(
                "mov {tmp:r}, rbx",
                "mov rbx, {a0:r}",
                "vmmcall",
                "mov rbx, {tmp:r}",
                tmp = lateout(reg) _,
                a0 = in(reg) a0,
                inout("rax") nr => ret,
                in("rcx") a1,
                in("rdx") a2,
                in("rsi") a3,
                options(nostack, preserves_flags),
            );
        }
    } else {
        // VMCALL is the Intel encoding; we also use it as the
        // fallback for VENDOR_UNKNOWN.  KVM treats both opcodes
        // as equivalent on its side.
        unsafe {
            asm!(
                "mov {tmp:r}, rbx",
                "mov rbx, {a0:r}",
                "vmcall",
                "mov rbx, {tmp:r}",
                tmp = lateout(reg) _,
                a0 = in(reg) a0,
                inout("rax") nr => ret,
                in("rcx") a1,
                in("rdx") a2,
                in("rsi") a3,
                options(nostack, preserves_flags),
            );
        }
    }
    ret
}

struct KvmHypervisor;
impl HypervisorOps for KvmHypervisor {
    fn steal_time_ns(&self) -> Option<u64> {
        if !KVM_STEAL_TIME_ENABLED.load(Ordering::Relaxed) {
            return None;
        }
        // Read with a version-pair check (Linux pattern): odd version
        // means the host is mid-update.  Retry until version is even
        // and stable across the read.  In practice it converges in 1
        // iteration, but the loop is a safety net.  Returns the
        // calling CPU's stolen time.
        let cpu = crate::sched::smp::cpu_id() as usize;
        if cpu >= crate::sched::smp::MAX_CPUS {
            return None;
        }
        let p = &STEAL_TIME[cpu];
        for _ in 0..8 {
            let v0 = p.version.load(Ordering::Acquire);
            if v0 & 1 != 0 { continue; }
            let s = p.steal.load(Ordering::Relaxed);
            let v1 = p.version.load(Ordering::Acquire);
            if v0 == v1 { return Some(s); }
        }
        None
    }

    fn send_reschedule_ipi(&self, target_cpu: u32) -> bool {
        if !KVM_PV_SEND_IPI_ENABLED.load(Ordering::Relaxed) {
            return false;
        }
        // Telix model: target_cpu is the LAPIC/APIC id of the target.
        // KVM_HC_SEND_IPI takes a bitmap of vCPUs starting at `min`,
        // plus an ICR-formatted delivery descriptor.  For a single
        // target we set one bit and use min = target rounded down to
        // 64-bit boundary.
        let min = (target_cpu as u64) & !63;
        let bit = (target_cpu as u64) - min;
        let bitmap_low: u64;
        let bitmap_high: u64;
        if bit < 64 {
            bitmap_low = 1u64 << bit;
            bitmap_high = 0;
        } else {
            bitmap_low = 0;
            bitmap_high = 1u64 << (bit - 64);
        }
        // ICR encoding: vector in bits 0..7, fixed delivery mode
        // (0b000 in bits 8..10), physical dest mode (bit 11 = 0),
        // assert (bit 14 = 1), edge trigger (bit 15 = 0).  Vector
        // 0xFD is the reschedule IPI used by Linux on KVM; Telix's
        // own IRQ wiring uses crate::arch::irq::RESCHEDULE_VECTOR.
        // Reschedule IPI vector is 0xFD (matches lapic::send_reschedule).
        // ICR encoding for KVM_HC_SEND_IPI: just vector | delivery
        // mode (Fixed=0) | dest mode (Physical=0).  Linux's
        // __prepare_ICR does NOT set the assert bit (1<<14) here —
        // that's a bit for the in-guest LAPIC ICR write path, not
        // for the PV hypercall.  Setting it caused boot 91amfsq390
        // to regress at Phase 145e because the hypercall succeeded
        // but the host's IPI delivery had the wrong shape.
        const RESCHEDULE_VECTOR: u64 = 0xFD;
        let icr = RESCHEDULE_VECTOR;
        let r = unsafe {
            kvm_hypercall(KVM_HC_SEND_IPI, bitmap_low, bitmap_high, min, icr)
        };
        // r is the number of IPIs delivered (positive) or a negative
        // errno-like value cast to u64.  Treat u64::MAX..top as
        // failure and return false so the caller falls back.
        r < 256
    }

    fn kick_cpu(&self, target_cpu: u32) -> bool {
        if !KVM_PV_UNHALT_ENABLED.load(Ordering::Relaxed) {
            return false;
        }
        // Pure hint to the host: schedule `target_cpu`'s vCPU back if
        // it's currently HALTed.  flags=0 (a0), apicid=target_cpu (a1).
        // The hypercall returns 0 on success and is documented to be
        // safe to issue against any apicid — the host validates.
        unsafe {
            kvm_hypercall(KVM_HC_KICK_CPU, 0, target_cpu as u64, 0, 0);
        }
        true
    }
}

static KVM: KvmHypervisor = KvmHypervisor;

/// Read CPU vendor string from CPUID leaf 0 to choose VMCALL vs
/// VMMCALL.  AMD vendor string = "AuthenticAMD"; Intel = "GenuineIntel".
fn detect_cpu_vendor() {
    let (_, ebx, ecx, edx) = cpuid(0);
    let mut sig = [0u8; 12];
    sig[0..4].copy_from_slice(&ebx.to_le_bytes());
    sig[4..8].copy_from_slice(&edx.to_le_bytes()); // CPUID quirk: EDX before ECX
    sig[8..12].copy_from_slice(&ecx.to_le_bytes());
    let v = if &sig == b"AuthenticAMD" {
        VENDOR_AMD
    } else if &sig == b"GenuineIntel" {
        VENDOR_INTEL
    } else {
        VENDOR_UNKNOWN
    };
    CPU_VENDOR.store(v, Ordering::Relaxed);
}

pub fn detect_and_install() {
    // CPUID leaf 1 ECX bit 31: "hypervisor present" hint.  If clear,
    // we're on bare metal — fast exit with HypervisorKind::None.
    let (_, _, ecx_1, _) = cpuid(1);
    let hv_present = (ecx_1 & (1 << 31)) != 0;
    if !hv_present {
        // No hypervisor — leave KIND at None and OPS at the no-op
        // default.  set_ops still publishes the kind explicitly so
        // queries are deterministic.
        let ops: &'static dyn HypervisorOps = &crate::arch::hypervisor::NO_OP;
        unsafe { set_ops(HypervisorKind::None, ops); }
        return;
    }

    // CPUID leaf 0x40000000 returns the signature.
    let (_, ebx, ecx, edx) = cpuid(0x40000000);
    let sig = signature_from_regs(ebx, ecx, edx);

    let kind = match &sig {
        b"KVMKVMKVM\0\0\0" => HypervisorKind::Kvm,
        b"TCGTCGTCGTCG" => HypervisorKind::Tcg,
        b"Microsoft Hv" => HypervisorKind::HyperV,
        b"VMwareVMware" => HypervisorKind::Vmware,
        b"XenVMMXenVMM" => HypervisorKind::Xen,
        _ => HypervisorKind::UnknownHypervisor,
    };

    crate::println!(
        "[hypervisor] x86_64 detected kind={:?} sig={:?}",
        kind,
        core::str::from_utf8(&sig).unwrap_or("<non-utf8>")
    );

    if kind == HypervisorKind::Kvm {
        // Cache CPU vendor so kvm_hypercall picks VMCALL vs VMMCALL.
        detect_cpu_vendor();
        // KVM feature flags advertised at CPUID 0x40000001 EAX.
        let (eax_kvm, _, _, _) = cpuid(0x40000001);
        if eax_kvm & KVM_FEATURE_PV_SEND_IPI != 0 {
            KVM_PV_SEND_IPI_ENABLED.store(true, Ordering::Relaxed);
            crate::println!("[hypervisor] KVM PV_SEND_IPI enabled");
        } else {
            crate::println!("[hypervisor] KVM PV_SEND_IPI not advertised");
        }
        if eax_kvm & KVM_FEATURE_STEAL_TIME != 0 {
            KVM_STEAL_TIME_ENABLED.store(true, Ordering::Relaxed);
            // Bind the BSP's per-CPU steal-time page.  APs do their
            // own equivalent at AP-rust-entry by calling
            // enable_steal_time_self.
            enable_steal_time_self();
            crate::println!("[hypervisor] KVM STEAL_TIME enabled");
        } else {
            crate::println!("[hypervisor] KVM STEAL_TIME not advertised");
        }
        if eax_kvm & KVM_FEATURE_PV_UNHALT != 0 {
            KVM_PV_UNHALT_ENABLED.store(true, Ordering::Relaxed);
            crate::println!("[hypervisor] KVM PV_UNHALT (KICK_CPU) enabled");
        } else {
            crate::println!("[hypervisor] KVM PV_UNHALT not advertised");
        }
        if eax_kvm & KVM_FEATURE_CLOCKSOURCE2 != 0 {
            KVM_PVCLOCK_ENABLED.store(true, Ordering::Relaxed);
            // Bind BSP's pvclock page; APs do the same in their bringup
            // path next to enable_steal_time_self.
            enable_pvclock_self();
            crate::println!("[hypervisor] KVM PVCLOCK (CLOCKSOURCE2) enabled");
        } else {
            crate::println!("[hypervisor] KVM PVCLOCK not advertised");
        }
    }

    let ops: &'static dyn HypervisorOps = match kind {
        HypervisorKind::Kvm => &KVM,
        // TCG and other recognized hypervisors fall through to no-op
        // until they get a concrete impl.
        _ => &crate::arch::hypervisor::NO_OP,
    };
    unsafe { set_ops(kind, ops); }
}
