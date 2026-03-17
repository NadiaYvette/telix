//! I/O message protocol — tag constants and data word layouts.
//!
//! All I/O uses the kernel's fixed-size IPC messages (tag + 6 data words).
//! Tags identify the operation; data words carry arguments/results.


// --- Message tags ---

/// Client → server: open a channel to a named resource.
///   data[0] = name bytes 0-7 (packed)
///   data[1] = name bytes 8-15
///   data[2] = name bytes 16-23
///   data[3] = name length
///   data[4] = client reply port ID
///   data[5] = flags
pub const IO_CONNECT: u64 = 0x100;

/// Server → client: connection accepted.
///   data[0] = channel/file handle
///   data[1] = file size (bytes), or 0 if unknown
pub const IO_CONNECT_OK: u64 = 0x101;

/// Client → server: read request.
///   data[0] = channel/file handle
///   data[1] = offset (bytes)
///   data[2] = length (bytes)
///   data[3] = client reply port ID
///   data[4] = client aspace ID (for grants)
///   data[5] = flags (0 = inline, 1 = grant)
pub const IO_READ: u64 = 0x200;

/// Server → client: read completed.
///   data[0] = bytes read
///   data[1] = inline data bytes 0-7 (if inline)
///   data[2] = inline data bytes 8-15 (if inline)
///   data[3] = inline data bytes 16-23 (if inline)
///   data[4] = inline data bytes 24-31 (if inline)
///   data[5] = inline data bytes 32-39 (if inline)
/// For grant reads, data[1] = grant VA, data[2] = grant page count.
pub const IO_READ_OK: u64 = 0x201;

/// Client → server: write request.
///   data[0] = channel/file handle
///   data[1] = offset (bytes)
///   data[2] = length (bytes)
///   data[3] = client reply port ID
///   data[4] = inline data or grant VA
///   data[5] = flags
#[allow(dead_code)]
pub const IO_WRITE: u64 = 0x300;

/// Server → client: write completed.
///   data[0] = bytes written
#[allow(dead_code)]
pub const IO_WRITE_OK: u64 = 0x301;

/// Client → server: stat request (query metadata).
///   data[0] = channel/file handle
///   data[1] = client reply port ID
pub const IO_STAT: u64 = 0x400;

/// Server → client: stat result.
///   data[0] = file size (bytes)
///   data[1] = file type (0 = regular, 1 = directory)
pub const IO_STAT_OK: u64 = 0x401;

/// Client → server: close channel.
///   data[0] = channel/file handle
pub const IO_CLOSE: u64 = 0x500;

/// Server → client: error response.
///   data[0] = error code
pub const IO_ERROR: u64 = 0xF00;

// --- I/O flags ---

/// Grant-based I/O (as opposed to inline).
#[allow(dead_code)]
pub const FLAG_GRANT: u64 = 1;

// --- Name server tags ---

/// Register a service: data[0..2] = packed name, data[3] = name_len | (reply_port << 32), data[4] = service_port
pub const NS_REGISTER: u64 = 0x1000;
pub const NS_REGISTER_OK: u64 = 0x1001;

/// Lookup a service: data[0..2] = packed name, data[3] = name_len | (reply_port << 32)
pub const NS_LOOKUP: u64 = 0x1100;
/// Lookup result: data[0] = service_port (or u32::MAX if not found)
pub const NS_LOOKUP_OK: u64 = 0x1101;

// --- Error codes ---
pub const ERR_NOT_FOUND: u64 = 1;
#[allow(dead_code)]
pub const ERR_IO: u64 = 2;
pub const ERR_INVALID: u64 = 3;
#[allow(dead_code)]
pub const ERR_FULL: u64 = 4;

// --- Helpers ---

/// Maximum bytes that can be returned inline in a read reply (5 data words × 8 bytes).
pub const MAX_INLINE_READ: usize = 40;

/// Pack a filename (up to 24 bytes) into three u64 data words.
pub fn pack_name(name: &[u8]) -> (u64, u64, u64) {
    let mut words = [0u64; 3];
    for (i, &b) in name.iter().enumerate().take(24) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    (words[0], words[1], words[2])
}

/// Unpack a filename from three u64 data words + length.
pub fn unpack_name(w0: u64, w1: u64, w2: u64, len: usize) -> [u8; 24] {
    let mut buf = [0u8; 24];
    let words = [w0, w1, w2];
    for i in 0..len.min(24) {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    buf
}

/// Pack up to 40 bytes of inline data into 5 data words.
pub fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE_READ) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}
