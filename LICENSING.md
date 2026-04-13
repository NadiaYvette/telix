# Telix Licensing

## Philosophy

Telix is an AI-assisted microkernel operating system. Much of its code was written
with the help of large language models that were trained on open-source software.
We believe in giving credit where credit is due.

The microkernel architecture creates a natural boundary for license isolation:
each userspace server is a separate binary that communicates exclusively via IPC
messages. This means servers can carry different licenses without creating
derivative-work entanglements — the IPC message boundary is the legal firewall.

We use **per-component licensing** not merely as a legal obligation but as a form
of **attribution and citation**. When an AI model draws on a specific open-source
codebase as a guiding example — for data structures, algorithms, on-disk format
parsing, or syscall semantics — we adopt a license compatible with that reference
project and explicitly name it. This is our way of acknowledging the open-source
lineage that made this work possible.

## License Summary

| Component | License | Reference Codebases |
|-----------|---------|-------------------|
| `kernel/` | MIT OR Apache-2.0 | seL4 (concepts), original work |
| `userlib/src/` (library) | MIT OR Apache-2.0 | Original work |
| `userlib/bin/apfs_srv.rs` | GPL-2.0-only | linux-apfs-rw, apfsprogs |
| `userlib/bin/xfs_srv.rs` | GPL-2.0-only | Linux fs/xfs, xfsprogs |
| `userlib/bin/ext2_srv.rs` | GPL-2.0-only | Linux fs/ext2, e2fsprogs |
| `userlib/bin/fat16_srv.rs` | GPL-2.0-only | Linux fs/fat |
| `userlib/bin/iso9660_srv.rs` | GPL-2.0-only | Linux fs/isofs |
| `userlib/bin/udf_srv.rs` | GPL-2.0-only | Linux fs/udf, udftools |
| `userlib/bin/linux_srv.rs` | GPL-2.0-only | Linux kernel (syscall semantics) |
| `userlib/bin/net_srv.rs` | GPL-2.0-only | Linux net stack (protocol semantics) |
| `userlib/bin/procfs_srv.rs` | GPL-2.0-only | Linux fs/proc |
| `userlib/bin/sysv_srv.rs` | GPL-2.0-only | Linux ipc/ (SysV IPC semantics) |
| `userlib/bin/pty_srv.rs` | GPL-2.0-only | Linux drivers/tty |
| All other `userlib/bin/` servers | MIT OR Apache-2.0 | Original work |
| All other `userlib/bin/` binaries | MIT OR Apache-2.0 | Original work |
| `musl-telix/` | MIT | musl libc |

## How to Read This

- **MIT OR Apache-2.0**: Original Telix code. You may use it under either license
  at your option. The permissive licensing of the kernel and userlib ensures that
  individual servers are free to adopt whatever license fits their lineage.

- **GPL-2.0-only**: Code whose design, data structures, or algorithmic approach
  was informed by GPL-2.0-only reference codebases. Even though every line was
  written from scratch (by a human or AI), we adopt the reference project's license
  out of respect for the community that produced the knowledge the AI drew upon.

- **MIT** (musl-telix): musl libc is MIT-licensed. Our port preserves that license.

## Per-Component LICENSE Files

Each component group has a LICENSE file in its directory or alongside the source:

- `kernel/LICENSE` — MIT OR Apache-2.0
- `userlib/LICENSE` — MIT OR Apache-2.0 (library and non-GPL servers)
- `userlib/licenses/GPL-2.0-only.txt` — Full GPL-2.0 text for GPL servers
- `musl-telix/LICENSE` — MIT (musl)

Individual source files that carry GPL-2.0-only have an SPDX header identifying
their license and the reference codebases that informed their implementation.

## SPDX Identifiers

This project uses [SPDX license identifiers](https://spdx.dev/ids/) throughout:

- `MIT` — [MIT License](https://spdx.org/licenses/MIT.html)
- `Apache-2.0` — [Apache License 2.0](https://spdx.org/licenses/Apache-2.0.html)
- `GPL-2.0-only` — [GNU General Public License v2.0 only](https://spdx.org/licenses/GPL-2.0-only.html)

## A Note on AI-Generated Code

All code in this repository was written with AI assistance (primarily Claude by
Anthropic). No code was copied verbatim from any reference codebase. The AI model
was trained on publicly available open-source code and documentation, and the
resulting implementations reflect patterns and knowledge from those sources. The
per-component licensing is our way of making that lineage transparent and giving
appropriate credit.
