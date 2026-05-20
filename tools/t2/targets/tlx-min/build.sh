#!/bin/bash
# --- T2-COPYRIGHT-BEGIN ---
# t2/target/tlx-min/build.sh
# Copyright (C) 2026 The Telix Project
# SPDX-License-Identifier: GPL-2.0
# --- T2-COPYRIGHT-END ---

# T2 invokes this script during the target's per-stage build hook.
# For tlx-min we don't have any target-specific customisation beyond
# what's in pkgsel + config.in, so this is a no-op shim.  Kept as a
# file so T2's target machinery recognises this directory as a
# valid target (T2 requires build.sh + config.in + pkgsel triple).

# If we later need to post-process the rootfs (e.g. inject Telix-
# specific init scripts, strip binaries, regenerate /etc), hook it
# here.

exit 0
