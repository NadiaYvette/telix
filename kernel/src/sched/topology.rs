//! CPU topology discovery.
//!
//! Discovers the package/core/SMT structure of each CPU at boot.
//! x86_64: Uses CPUID leaf 0x0B (Extended Topology Enumeration).
//! riscv64/aarch64: Flat topology (each CPU = separate core, 1 package).

use super::smp::MAX_CPUS;

/// Topology entry for a single CPU.
#[derive(Clone, Copy)]
pub struct CpuTopoEntry {
    pub package_id: u8,
    pub core_id: u8,
    pub smt_id: u8,
    pub online: bool,
}

impl CpuTopoEntry {
    const fn empty() -> Self {
        Self { package_id: 0, core_id: 0, smt_id: 0, online: false }
    }
}

static mut CPU_TOPO: [CpuTopoEntry; MAX_CPUS] = [CpuTopoEntry::empty(); MAX_CPUS];

// --- CPUID helper (x86_64 only) ---

#[cfg(target_arch = "x86_64")]
fn cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d);
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {b:e}, ebx",
            "pop rbx",
            b = lateout(reg) b,
            inlateout("eax") eax => a,
            inlateout("ecx") ecx => c,
            lateout("edx") d,
        );
    }
    (a, b, c, d)
}

/// Initialize topology for the BSP (CPU 0).
pub fn init() {
    let entry = discover_local();
    unsafe {
        CPU_TOPO[0] = CpuTopoEntry { online: true, ..entry };
    }
}

/// Initialize topology for a secondary CPU.
pub fn init_ap(cpu: u32) {
    if (cpu as usize) < MAX_CPUS {
        let entry = discover_local();
        unsafe {
            CPU_TOPO[cpu as usize] = CpuTopoEntry { online: true, ..entry };
        }
    }
}

/// Get topology entry for a CPU.
pub fn get(cpu: usize) -> CpuTopoEntry {
    if cpu < MAX_CPUS {
        unsafe { CPU_TOPO[cpu] }
    } else {
        CpuTopoEntry::empty()
    }
}

/// Set the online state for a CPU (used by hotplug).
///
/// # Safety
/// Caller must ensure `cpu < MAX_CPUS`.
pub unsafe fn set_online(cpu: usize, online: bool) {
    if cpu < MAX_CPUS {
        unsafe { CPU_TOPO[cpu].online = online; }
    }
}

/// Print topology at boot.
pub fn print() {
    crate::println!("  CPU topology:");
    for i in 0..MAX_CPUS {
        let e = unsafe { CPU_TOPO[i] };
        if e.online {
            crate::println!(
                "    CPU {}: package={} core={} smt={}",
                i, e.package_id, e.core_id, e.smt_id
            );
        }
    }
}

/// Discover topology for the currently executing CPU.
#[cfg(target_arch = "x86_64")]
fn discover_local() -> CpuTopoEntry {
    // Try CPUID leaf 0x0B (Extended Topology Enumeration).
    // ECX=0: SMT level, ECX=1: core level.
    let (_a0, b0, _c0, d0) = cpuid(0x0B, 0);
    let smt_count = b0 & 0xFFFF;

    if smt_count == 0 {
        // Leaf 0x0B not supported. Fallback: use LAPIC ID as core_id.
        let lapic_id = crate::arch::x86_64::lapic::id() as u8;
        return CpuTopoEntry {
            package_id: 0,
            core_id: lapic_id,
            smt_id: 0,
            online: false,
        };
    }

    let x2apic_id = d0;
    let smt_shift = cpuid(0x0B, 0).0 & 0x1F;
    let core_shift = cpuid(0x0B, 1).0 & 0x1F;

    let smt_id = x2apic_id & ((1 << smt_shift) - 1);
    let core_id = if core_shift > smt_shift {
        (x2apic_id >> smt_shift) & ((1 << (core_shift - smt_shift)) - 1)
    } else {
        0
    };
    let package_id = x2apic_id >> core_shift;

    CpuTopoEntry {
        package_id: package_id as u8,
        core_id: core_id as u8,
        smt_id: smt_id as u8,
        online: false,
    }
}

/// Discover topology for the currently executing CPU (flat topology).
#[cfg(not(target_arch = "x86_64"))]
fn discover_local() -> CpuTopoEntry {
    let cpu = super::smp::cpu_id();
    CpuTopoEntry {
        package_id: 0,
        core_id: cpu as u8,
        smt_id: 0,
        online: false,
    }
}
