# License

Telix is dual-licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

at your option. This is the same dual-license arrangement used throughout the
Rust ecosystem; downstream users may pick either license depending on their
own constraints.

The dual-license declaration appears in `kernel/Cargo.toml` and
`userlib/Cargo.toml` as `license = "MIT OR Apache-2.0"`.

## Contributions

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.

## Third-Party Components

Telix is currently entirely original code authored under the dual
MIT-or-Apache-2.0 declaration above. As the codebase grows to include
vendored or imported third-party components — for example, future ports of
external filesystems, network stacks, or device drivers — those components
will be tracked in a top-level `NOTICE` file and a `LICENSES/` directory
following the SPDX standard, with each file carrying an
`SPDX-License-Identifier` header for machine-readable attribution.

When adding such a component:

1. Drop its license file into `LICENSES/<spdx-id>.txt`.
2. Add an entry to `NOTICE` describing the component, its origin, and its
   SPDX license identifier.
3. Add `// SPDX-License-Identifier: <id>` to each imported source file.

This keeps Telix compliant with the obligations of any imported licenses
without diluting the project's own dual-license arrangement.
