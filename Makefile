# Telix development entry points.
#
# The kernel-v2 (second-round verified kernel) is its own cargo workspace,
# host-testable: every component runs under plain `cargo test` on the
# development machine.  It is built via tools/build-kernel-v2.sh, which
# runs from a neutral CWD so the repo-root .cargo/config.toml (bare-metal
# target + `-Z build-std`, needed by the prototype kernel) does not
# contaminate host builds.  The Rocq/Iris specs live in the Tessera tree
# (tessera/hardware/rocq), not here — see docs/kernel-v2-build-plan.md §2.3.

TESSERA ?= $(HOME)/src/tessera

.PHONY: test-kernel-v2 fmt verify verify-rocq

## Host unit tests for the second-round kernel.
test-kernel-v2:
	tools/build-kernel-v2.sh --test

## Format check for kernel-v2 (no edits).
fmt:
	tools/build-kernel-v2.sh --fmt

## Telix-side verification: unit tests + hygiene.
verify: test-kernel-v2 fmt
	@echo "Telix-side checks passed."

## Rocq/Iris kernel-spec build (Tessera).  No-op until the K1
## machine-interface layer and kernel_specs/*.v exist in Tessera.
verify-rocq:
	@if [ -d "$(TESSERA)/hardware/rocq" ]; then \
		echo "Rocq kernel specs are pending K1 (machine-interface) in tessera/hardware/rocq."; \
		echo "Once kernel_specs/*.v exist, this runs: bash $(TESSERA)/hardware/rocq/build.sh"; \
	else \
		echo "Tessera not found at $(TESSERA); set TESSERA to your tessera checkout."; \
	fi
