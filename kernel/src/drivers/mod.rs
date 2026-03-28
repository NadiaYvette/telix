#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
pub mod virtio_blk;
#[allow(dead_code)]
pub mod virtio_mmio;
