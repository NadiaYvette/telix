//! Frame refcount module — removed.
//!
//! Per-page refcounts have been replaced by epoch-based COW tracking in
//! cowgroup.rs. This module is retained as an empty stub; `pub mod frame`
//! in mod.rs can be removed once all external references are confirmed gone.
