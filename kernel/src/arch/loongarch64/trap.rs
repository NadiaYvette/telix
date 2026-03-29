//! LoongArch64 trap/exception handling.

/// Trap frame saved/restored by vectors.S.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers r0-r31.
    pub regs: [u64; 32],
    /// Exception return address (CSR.ERA).
    pub era: u64,
    /// Pre-exception mode (CSR.PRMD).
    pub prmd: u64,
    /// Exception status (CSR.ESTAT).
    pub estat: u64,
}

/// Initialize trap handling.
pub fn init() {
    // TODO: set CSR.EENTRY, configure exception vectors
}

/// Enable interrupts (set CRMD.IE).
pub fn enable_interrupts() {
    // TODO: csrxchg to set IE bit in CRMD
}
