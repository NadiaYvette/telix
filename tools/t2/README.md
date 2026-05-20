# T2 SDE userspace as a Telix additional initramfs option

This directory wires a [T2 SDE](https://t2sde.org/) build target
(`tlx-min`) into Telix's initramfs flow.  T2 produces a complete
Linux userspace (busybox + glibc) without a kernel — Telix supplies
the kernel via its Linux personality.  The resulting binaries land
in `initramfs/` alongside Telix's own server binaries, becoming an
additional bootable userspace for testing the personality against
real-world distro-shaped tools.

## Files

- `targets/tlx-min/{build.sh,config.in,pkgsel}` — the custom T2 target.
  (Plural to avoid Telix's top-level `.gitignore` excluding `target/`.
  `sync-target.sh` copies these into the upstream `target/` dir layout.)
- `sync-target.sh` — copies the target into a t2sde checkout.
- `install-into-initramfs.sh` — merges a built T2 rootfs into Telix's `initramfs/`.

## One-time setup

```sh
git clone https://github.com/rxrbln/t2sde ~/src/t2sde
export TELIX_T2_HOME=~/src/t2sde
tools/t2/sync-target.sh
```

## Per-build workflow

```sh
# Inside the t2sde checkout, run the interactive config menu
# and select Target → tlx-min, then build.
cd "$TELIX_T2_HOME"
./t2 config --cfg telix-min
./t2 build telix-min                 # ~30min-2hr first time

# Back in the Telix tree
cd /path/to/telix
tools/t2/install-into-initramfs.sh   # merges T2's rootfs into initramfs/
tools/make-initramfs.sh              # rebuild the cpio
tools/build-kernel.sh x86_64 --release
tools/boot-h14.sh                    # boot Telix with the T2 userspace included
```

## Design choices baked into `targets/tlx-min/`

| Decision | Value | Rationale |
|----------|-------|-----------|
| libc | glibc | Telix's Linux personality has the best coverage here (per `project_phase171_gap_a` memory note). |
| init | busybox | Default; provides ash, ls, cat, vi, etc. |
| kernel | dropped | Telix supplies its own; we only want userspace. |
| toolchain in rootfs | no | Built to bootstrap T2's package compilation, NOT shipped to Telix. |
| size opt | yes | `SDECFGSET_OPT=size` keeps payload small. |
| cross-build | no | Same-arch native build (x86_64 → x86_64) is faster. |
| NLS | disabled | One less library to debug under personality. |

## Tuning knobs

- **Switch libc**: edit `targets/tlx-min/config.in`, set
  `SDECFGSET_LIBC="musl"` if glibc's `__intl_freemem` exit-path keeps
  biting (per `project_ld_debug_libc_pf` memory note).
- **Add SSH**: append `[O] payload = dropbear` to
  `targets/tlx-min/pkgsel` once Telix's network stack maturity story
  for the personality lands.
- **Cross-build for aarch64**: set `SDECFGSET_CROSSBUILD=1` in
  `config.in` and select the right target arch in `./t2 config`.

## Why opt-in

Telix's existing initramfs is purpose-built for testing specific
Telix scenarios (compositor, X servers, test binaries).  A T2
userspace ADDS standard Linux tools as a separate stress and
coverage source.  Use it when you want to exercise the personality
against busybox + ash + real binaries running from `/bin`, not
replace the current test harness.

## Status

Scaffolding committed; the actual T2 build is a multi-hour offline
step that we run when convenient, not automatically.  Coordinate
with René (T2 maintainer) on tuning if first-build results are
surprising.

See also: `reference_t2linux_for_personality_tests.md` memory note.
