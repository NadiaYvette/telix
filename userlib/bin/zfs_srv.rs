//! zfs_srv — ZFS filesystem scaffold.
//!
//! Reserves the spot for ZFS support.  The pool / dataset model and
//! copy-on-write block layout are far enough from the existing FS
//! servers (ext, fat, xfs, btrfs, etc.) that retrofitting one of them
//! into ZFS would distort it; ZFS deserves its own starting point.
//!
//! Coverage the eventual implementation needs:
//!   - **vdev tree.** ZFS organises storage into a tree of vdevs:
//!     mirror / raidz1 / raidz2 / raidz3 / single-disk leaves.  The
//!     pool's top-level vdevs are striped.  The vdev geometry is
//!     stored in the labels at fixed offsets at the start and end of
//!     each member device.
//!   - **uberblock + label parsing.**  Each vdev has four label
//!     copies (two at start, two at end of the device).  Labels
//!     contain the nvlist-encoded pool config + a ring of uberblocks.
//!     Pool import = find the labels, parse the config, find the
//!     newest uberblock, walk down to the meta-objset.
//!   - **DMU (Data Management Unit).**  Object layer above the SPA.
//!     The DSL (Dataset/Snapshot Layer) sits on top of DMU.
//!   - **ZIO pipeline.**  All I/O passes through a layered pipeline:
//!     compression → checksum → encryption → dedup → vdev allocation
//!     → physical I/O.  The pipeline is async / staged, which fits
//!     Telix's message-passing architecture naturally.
//!   - **Block pointer + checksum verification.**  Every block has a
//!     checksum (fletcher4 or sha256 typically); verification is
//!     mandatory.  Self-healing pulls from a redundant copy on
//!     mismatch.
//!   - **Copy-on-write semantics.**  Writes always allocate new
//!     blocks; the uberblock atomic-replace (with an even/odd
//!     transaction-group ring) is what makes the on-disk format
//!     crash-consistent.
//!   - **Snapshot and clone.**  Cheap because of CoW — a snapshot
//!     just bumps a reference on the existing block tree and starts
//!     a new transaction group.
//!   - **ZIL (intent log)** for synchronous write semantics.
//!   - **ARC / L2ARC** for in-memory caching.  L2ARC lives on a
//!     dedicated SSD vdev; ARC is RAM.
//!
//! Initial scope worth aiming for: read-only import of a ZFS pool
//! created externally (zpool create + write data on Linux, then
//! point Telix at the same disk image and read).  This requires
//! label parsing + uberblock + DMU read + DSL traversal.
//! Read-write needs the full ZIO pipeline + transaction-group
//! commit machinery — substantially more work.
//!
//! Service name: registered as b"zfs"; mounts a pool on demand
//! and exposes datasets through the standard VFS_* protocol so
//! linux_srv can route open/read/write through to it identically
//! to the other filesystem servers.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Message protocol (placeholder).  ZFS-specific operations beyond what the
// generic VFS protocol exposes — pool import, dataset enumeration, snapshot
// creation, etc. — go here.  Pure file I/O happens through standard VFS
// messages once a dataset is mounted.
// ---------------------------------------------------------------------------

/// Import a pool from a set of vdev block-device port-ids.
/// data[0] = pool-name address, data[1] = pool-name length,
/// data[2] = vdev list grant_va (array of u64 port-ids),
/// data[3] = vdev count.
pub const ZFS_POOL_IMPORT: u64 = 0x7D01;
pub const ZFS_POOL_IMPORT_OK: u64 = 0x7D02;
pub const ZFS_POOL_EXPORT: u64 = 0x7D03;
pub const ZFS_POOL_EXPORT_OK: u64 = 0x7D04;

/// Mount a dataset.  data[0] = pool/dataset name VA, data[1] = length.
/// reply data[0] = mount-id used for subsequent unmount.
pub const ZFS_DATASET_MOUNT: u64 = 0x7D10;
pub const ZFS_DATASET_MOUNT_OK: u64 = 0x7D11;
pub const ZFS_DATASET_UNMOUNT: u64 = 0x7D12;
pub const ZFS_DATASET_UNMOUNT_OK: u64 = 0x7D13;

/// Create / destroy snapshots.  CoW makes these cheap.
pub const ZFS_SNAPSHOT_CREATE: u64 = 0x7D20;
pub const ZFS_SNAPSHOT_CREATE_OK: u64 = 0x7D21;
pub const ZFS_SNAPSHOT_DESTROY: u64 = 0x7D22;
pub const ZFS_SNAPSHOT_DESTROY_OK: u64 = 0x7D23;

/// Pool / dataset stats — capacity, used, dedup ratio, ARC hit rate, ...
pub const ZFS_STATS: u64 = 0x7D30;
pub const ZFS_STATS_OK: u64 = 0x7D31;

/// Scrub: walk the entire pool, verify every checksum, repair from
/// redundant copy on mismatch.  Long-running; reply when done.
pub const ZFS_SCRUB_START: u64 = 0x7D40;
pub const ZFS_SCRUB_START_OK: u64 = 0x7D41;
pub const ZFS_SCRUB_STATUS: u64 = 0x7D42;
pub const ZFS_SCRUB_STATUS_OK: u64 = 0x7D43;

/// Generic error (out-of-scope, not implemented, no such pool, ...).
pub const ZFS_ERR: u64 = 0x7DFF;
pub const ERR_NOT_IMPLEMENTED: u64 = 1;

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[zfs_srv] starting (scaffold - no pool support yet)\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[zfs_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    if !syscall::ns_register(b"zfs", port) {
        syscall::debug_puts(b"[zfs_srv] ns_register FAIL\n");
        syscall::exit(1);
    }
    syscall::debug_puts(b"[zfs_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };
        // Scaffold: every protocol op acks with NOT_IMPLEMENTED.
        // Real label / uberblock / DMU code drops in the match arms.
        let (rep_tag, rep_d0) = match msg.tag {
            ZFS_POOL_IMPORT => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_POOL_EXPORT => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_DATASET_MOUNT => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_DATASET_UNMOUNT => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_SNAPSHOT_CREATE => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_SNAPSHOT_DESTROY => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_STATS => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_SCRUB_START => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            ZFS_SCRUB_STATUS => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
            _ => (ZFS_ERR, ERR_NOT_IMPLEMENTED),
        };
        let _ = syscall::reply(rep_tag, rep_d0, 0, 0, 0, 0);
    }
}

fn print_num(n: u64) {
    if n == 0 { syscall::debug_putchar(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}
