//! telix-kernel-v2 — the second-round verified Telix kernel.
//!
//! This crate grows incrementally, component by component, beside the
//! frozen first-round prototype (`kernel/`).  See
//! `docs/kernel-v2-build-plan.md` for the build-up order and
//! `docs/kernel-v2-verification-bridge.md` for how each component maps
//! to its Iris heap_lang spec and the Tessera hardware models.
//!
//! Build posture (the "necessarily decoupled" toolchain rule):
//! - kernel builds: `#![no_std]` (this crate is a dependency of a
//!   bare-metal kernel, built with the root nightly toolchain);
//! - host tests: `cargo test` compiles with `std`, so every component
//!   is testable on the development machine with no QEMU required.
//!
//! Every module follows the spec-first shape: total functions over
//! explicit state, `Result` returns, no partial mutation on error, no
//! globals, no interior mutability, no `unsafe`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod caps;
