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
///   data[0] = request_id (echoed in completion; 0 for legacy sync)
///   data[1] = offset (bytes)
///   data[2] = length (low 32) | reply_port (high 32)
///   data[3] = grant_va (0 for inline)
pub const IO_READ: u64 = 0x200;

/// Server → client: read completed.
///   data[0] = bytes read
///   data[1] = request_id (echoed from request)
/// For inline reads, data[2..5] = inline data bytes.
pub const IO_READ_OK: u64 = 0x201;

/// Client → server: write request.
///   data[0] = request_id (echoed in completion; 0 for legacy sync)
///   data[1] = offset (bytes)
///   data[2] = length (low 32) | reply_port (high 32)
///   data[3] = grant_va (0 for inline)
#[allow(dead_code)]
pub const IO_WRITE: u64 = 0x300;

/// Server → client: write completed.
///   data[0] = bytes written
///   data[1] = request_id (echoed from request)
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

/// Client → server: I/O barrier (fence).
///   data[2] = (reply_port << 32)
/// Server guarantees all prior requests are complete before replying.
#[allow(dead_code)]
pub const IO_BARRIER: u64 = 0x600;

/// Server → client: barrier complete.
#[allow(dead_code)]
pub const IO_BARRIER_OK: u64 = 0x601;

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

// --- Security protocol tags ---

/// Client → security_srv: authenticate.
///   data[0] = username_hash, data[1] = password_hash, data[2] = reply_port
#[allow(dead_code)]
pub const SEC_LOGIN: u64 = 0x700;

/// security_srv → client: login succeeded.
///   data[0] = credential_port, data[1] = role_bits
#[allow(dead_code)]
pub const SEC_LOGIN_OK: u64 = 0x701;

/// security_srv → client: login failed.
///   data[0] = error_code
#[allow(dead_code)]
pub const SEC_LOGIN_FAIL: u64 = 0x702;

/// Server → security_srv: verify a credential.
///   data[0] = credential_port, data[2] = reply_port
#[allow(dead_code)]
pub const SEC_VERIFY: u64 = 0x703;

/// security_srv → server: credential valid.
///   data[0] = credential_port, data[1] = role_bits, data[2] = username_hash
#[allow(dead_code)]
pub const SEC_VERIFY_OK: u64 = 0x704;

/// security_srv → server: credential invalid.
///   data[0] = error_code
#[allow(dead_code)]
pub const SEC_VERIFY_FAIL: u64 = 0x705;

/// Client → security_srv: revoke a credential.
///   data[0] = credential_port, data[2] = reply_port
#[allow(dead_code)]
pub const SEC_REVOKE: u64 = 0x706;

/// security_srv → client: credential revoked.
#[allow(dead_code)]
pub const SEC_REVOKE_OK: u64 = 0x707;

// Role constants for security policy.
#[allow(dead_code)]
pub const ROLE_ADMIN: u64 = 0x01;
#[allow(dead_code)]
pub const ROLE_USER: u64 = 0x02;
#[allow(dead_code)]
pub const ROLE_GUEST: u64 = 0x04;

// --- Filesystem protocol tags (served by userspace FS servers, 0x2xxx) ---
// Core: FS_OPEN (0x2000), FS_READ (0x2100), FS_READDIR (0x2200),
//   FS_STAT (0x2300), FS_CLOSE (0x2400), FS_CREATE (0x2500),
//   FS_WRITE (0x2600), FS_DELETE (0x2700), FS_FLOCK (0x2800),
//   FS_UTIMENS (0x2900), FS_MKDIR (0x2A00), FS_UNLINK (0x2A20),
//   FS_FSYNC (0x2B00), FS_CHMOD (0x2E00), FS_ERROR (0x2F00).
// Extended (Phase 177+):
//   FS_SYMLINK (0x2C00), FS_READLINK (0x2C10), FS_LINK (0x2C20),
//   FS_RENAME (0x2C30), FS_CHOWN (0x2C40), FS_TRUNCATE (0x2C50),
//   FS_STATFS (0x2C60).
//   FS_XATTR_GET (0x2D00), FS_XATTR_SET (0x2D10), FS_XATTR_LIST (0x2D20),
//   FS_XATTR_REMOVE (0x2D30), FS_MKNOD (0x2D40), FS_FALLOCATE (0x2D50),
//   FS_STREAM_OPEN (0x2D60), FS_STREAM_LIST (0x2D70), FS_IOCTL (0x2D80).

// --- VFS protocol tags (served by vfs_srv, 0x6xxx) ---
// Core: VFS_MOUNT (0x6000), VFS_UNMOUNT (0x6001), VFS_OPEN (0x6010),
//   VFS_STAT (0x6020), VFS_READDIR (0x6030), VFS_MKDIR (0x6040),
//   VFS_UNLINK (0x6050), VFS_CHMOD (0x6080), VFS_UTIMENS (0x6090).
// Extended (Phase 177+):
//   VFS_SYMLINK (0x60A0), VFS_READLINK (0x60A1), VFS_LINK (0x60B0),
//   VFS_RENAME (0x60C0), VFS_CHOWN (0x60D0), VFS_TRUNCATE (0x60E0),
//   VFS_STATFS (0x60F0), VFS_ACCESS (0x60F1).
//   VFS_XATTR_GET (0x6200), VFS_XATTR_SET (0x6201), VFS_XATTR_LIST (0x6202),
//   VFS_XATTR_REMOVE (0x6203), VFS_MKNOD (0x6220), VFS_FALLOCATE (0x6240),
//   VFS_STREAM_OPEN (0x6300), VFS_STREAM_LIST (0x6301), VFS_IOCTL (0x6400).

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
