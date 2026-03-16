//! Message format for IPC.
//!
//! Messages are fixed-size: a tag word plus 6 register-sized data words.
//! This fits in registers for fast L4-style transfer.

/// A message: tag + 6 data words.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Message {
    /// Message tag: identifies the message type/operation.
    pub tag: u64,
    /// Data words (arguments/return values).
    pub data: [u64; 6],
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            data: [0; 6],
        }
    }

    pub const fn new(tag: u64, data: [u64; 6]) -> Self {
        Self { tag, data }
    }
}
