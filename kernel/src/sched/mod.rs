pub mod thread;
pub mod task;
pub mod scheduler;
pub mod smp;

pub use scheduler::{init, spawn, tick, current_thread_id, current_aspace_id};
