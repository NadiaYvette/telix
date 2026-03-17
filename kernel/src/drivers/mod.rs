#[cfg(not(target_arch = "x86_64"))]
pub mod virtio_mmio;
#[cfg(not(target_arch = "x86_64"))]
pub mod virtio_blk;
