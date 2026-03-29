//! MIPS64 trap/exception handling.

/// Trap frame saved/restored by vectors.S.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers $0-$31 (k0/k1 slots unused but reserved).
    pub regs: [u64; 32],
    /// Exception return address (CP0 EPC).
    pub epc: u64,
    /// CP0 Status saved at entry.
    pub status: u64,
    /// CP0 Cause.
    pub cause: u64,
    /// CP0 BadVAddr.
    pub badvaddr: u64,
}

/// Initialize trap handling.
pub fn init() {
    // TODO: set EBase, configure Status register, install exception vectors
}

/// Enable interrupts (set Status.IE).
pub fn enable_interrupts() {
    // TODO: set IE bit in CP0 Status
}
