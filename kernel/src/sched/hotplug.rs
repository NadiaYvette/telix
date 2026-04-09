//! CPU hotplug and energy-aware scheduling.
//!
//! Provides mechanisms to dynamically offline/online CPUs at runtime.
//! When a CPU is offlined, all threads with affinity for that CPU have
//! their affinity masks adjusted so they migrate to remaining online CPUs.
//! When re-onlined, the CPU rejoins the scheduling domain.
//!
//! Energy-aware load tracking: each CPU's tick handler updates a per-CPU
//! load counter. Spawn placement uses this to pack threads onto fewer
//! CPUs, leaving idle CPUs in low-power states.

use super::cpumask::{AtomicCpuMask, CpuMask};
use super::smp;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

// Per-CPU load tracking lives in dynamic slices installed by
// `init_dynamic_percpu` from `smp::init_dynamic_percpu`. See the
// runtime-nr_cpus plan.

/// Per-CPU load: number of ticks in the last window where this CPU was
/// NOT idle. Updated every tick. Range 0..LOAD_WINDOW.
static CPU_LOAD_PTR: AtomicPtr<AtomicU32> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn cpu_load_slice() -> &'static [AtomicU32] {
    let ptr = CPU_LOAD_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "CPU_LOAD not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU tick counter within the current load window.
static CPU_BUSY_TICKS_PTR: AtomicPtr<AtomicU32> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn cpu_busy_ticks() -> &'static [AtomicU32] {
    let ptr = CPU_BUSY_TICKS_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "CPU_BUSY_TICKS not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU window tick counter.
static CPU_WINDOW_TICKS_PTR: AtomicPtr<AtomicU32> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn cpu_window_ticks() -> &'static [AtomicU32] {
    let ptr = CPU_WINDOW_TICKS_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "CPU_WINDOW_TICKS not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Allocate and install this module's dynamic per-CPU slices.
/// Called by `smp::init_dynamic_percpu` after `phys::init`.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    unsafe {
        let s = crate::mm::phys::alloc_static_slice::<AtomicU32>(n);
        CPU_LOAD_PTR.store(s.as_mut_ptr(), Ordering::Release);
        let s = crate::mm::phys::alloc_static_slice::<AtomicU32>(n);
        CPU_BUSY_TICKS_PTR.store(s.as_mut_ptr(), Ordering::Release);
        let s = crate::mm::phys::alloc_static_slice::<AtomicU32>(n);
        CPU_WINDOW_TICKS_PTR.store(s.as_mut_ptr(), Ordering::Release);
    }
}

/// Load measurement window size in ticks (1 second at 100 Hz).
const LOAD_WINDOW: u32 = 100;

/// Total hotplug events (online + offline).
pub static HOTPLUG_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Bitmask of CPUs that are currently online for scheduling.
/// Bit i = CPU i is online. Initialized with all CPUs offline;
/// set by init_bsp / init_ap via `mark_online`.
static ONLINE_MASK: AtomicCpuMask = AtomicCpuMask::new();

/// Mark a CPU as online (called during boot).
pub fn mark_online(cpu: u32) {
    ONLINE_MASK.set_with(cpu, Ordering::Release);
}

/// Get the current online CPU bitmask.
pub fn online_mask() -> CpuMask {
    ONLINE_MASK.load_mask(Ordering::Acquire)
}

/// Update per-CPU load counter. Called from tick() on each CPU.
pub fn tick_load(cpu: u32, is_idle: bool) {
    let c = cpu as usize;
    let busy = cpu_busy_ticks();
    let win = cpu_window_ticks();
    let load = cpu_load_slice();
    if !is_idle {
        busy[c].fetch_add(1, Ordering::Relaxed);
    }
    let window = win[c].fetch_add(1, Ordering::Relaxed) + 1;
    if window >= LOAD_WINDOW {
        // End of window: publish load and reset counters.
        let b = busy[c].swap(0, Ordering::Relaxed);
        load[c].store(b, Ordering::Relaxed);
        win[c].store(0, Ordering::Relaxed);
    }
}

/// Get current load for a CPU (0..LOAD_WINDOW, higher = busier).
pub fn cpu_load(cpu: u32) -> u32 {
    if (cpu as usize) >= smp::num_cpus() {
        return 0;
    }
    cpu_load_slice()[cpu as usize].load(Ordering::Relaxed)
}

/// Get the load window size (for interpreting load values).
pub fn load_window() -> u32 {
    LOAD_WINDOW
}

/// Offline a CPU: clear it from the online mask, update topology,
/// and migrate all threads away from it.
///
/// Returns 0 on success, 1 on error (e.g., trying to offline the last CPU,
/// or invalid CPU ID).
pub fn cpu_offline(cpu: u32) -> u64 {
    if (cpu as usize) >= smp::num_cpus() {
        return 1;
    }

    let mask = ONLINE_MASK.load_mask(Ordering::Acquire);

    // Can't offline a CPU that's already offline.
    if !mask.test(cpu) {
        return 1;
    }

    // Must keep at least one CPU online.
    let mut remaining = mask;
    remaining.clear(cpu);
    if remaining.is_empty() {
        return 1;
    }

    // Mark offline in all tracking structures.
    ONLINE_MASK.clear_with(cpu, Ordering::Release);
    smp::get(cpu).online.store(false, Ordering::Release);
    unsafe {
        super::topology::set_online(cpu as usize, false);
    }

    // Migrate all threads: clear the offlined CPU's bit from their
    // affinity masks. Threads currently on the run queue with affinity
    // only for this CPU get expanded to all remaining online CPUs.
    // Collect thread IDs under the scheduler lock, then update locklessly.
    let mut tids = [0u32; 64];
    let mut count = 0usize;
    // Lock-free: SCHED_THREAD_ART is safe for concurrent reads.
    super::scheduler::SCHED_THREAD_ART.for_each(|key, _val| {
        if count < tids.len() {
            tids[count] = key as u32;
            count += 1;
        }
    });
    for i in 0..count {
        let tid = tids[i];
        let tptr = super::scheduler::THREAD_TABLE.get(tid) as *const super::thread::Thread;
        if tptr.is_null() {
            continue;
        }
        let thread = unsafe { &*tptr };
        let old = thread.affinity_mask.load_mask(Ordering::Relaxed);
        if old.is_empty() {
            continue;
        }
        let mut new = old;
        new.clear(cpu);
        if new.is_empty() {
            // Thread was pinned to only this CPU — expand to all online CPUs.
            thread
                .affinity_mask
                .store_mask(&remaining, Ordering::Relaxed);
        } else if new.as_u64() != old.as_u64() || CPUMASK_WORDS > 1 {
            thread.affinity_mask.store_mask(&new, Ordering::Relaxed);
        }
    }

    // Drain slab magazines for this CPU back to global caches.
    crate::mm::slab::drain_cpu(cpu);

    HOTPLUG_EVENTS.fetch_add(1, Ordering::Relaxed);
    0
}

/// Online a CPU: add it back to the online mask and update topology.
///
/// Returns 0 on success, 1 on error.
pub fn cpu_online(cpu: u32) -> u64 {
    if (cpu as usize) >= smp::num_cpus() {
        return 1;
    }

    let mask = ONLINE_MASK.load_mask(Ordering::Acquire);

    // Already online.
    if mask.test(cpu) {
        return 1;
    }

    // Check that this CPU was initialized (has an idle thread).
    let idle = smp::get(cpu).idle_thread_id.load(Ordering::Relaxed);
    if idle == 0 && cpu != 0 {
        return 1; // CPU was never booted
    }

    // Mark online.
    ONLINE_MASK.set_with(cpu, Ordering::Release);
    smp::get(cpu).online.store(true, Ordering::Release);
    unsafe {
        super::topology::set_online(cpu as usize, true);
    }

    // Reset load counters for this CPU.
    cpu_load_slice()[cpu as usize].store(0, Ordering::Relaxed);
    cpu_busy_ticks()[cpu as usize].store(0, Ordering::Relaxed);
    cpu_window_ticks()[cpu as usize].store(0, Ordering::Relaxed);

    HOTPLUG_EVENTS.fetch_add(1, Ordering::Relaxed);
    0
}

/// Number of CpuMask words (re-exported for conditional compilation).
use super::cpumask::CPUMASK_WORDS;

/// Energy-aware CPU selection for new thread placement.
/// Returns the online CPU with the highest current load (bin-packing),
/// so that idle CPUs can enter low-power states.
///
/// If all CPUs have equal load, returns the CPU with the lowest ID.
#[allow(dead_code)]
pub fn pick_packed_cpu() -> u32 {
    let mask = ONLINE_MASK.load_mask(Ordering::Acquire);
    let mut best_cpu: u32 = 0;
    let mut best_load: u32 = 0;
    let mut found = false;

    let load_slice = cpu_load_slice();
    mask.for_each(|cpu| {
        let load = load_slice[cpu as usize].load(Ordering::Relaxed);
        if !found || load > best_load {
            best_cpu = cpu;
            best_load = load;
            found = true;
        }
    });

    best_cpu
}

/// Build an affinity mask containing only online CPUs.
#[allow(dead_code)]
pub fn online_affinity_mask() -> CpuMask {
    ONLINE_MASK.load_mask(Ordering::Acquire)
}
