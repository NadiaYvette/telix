#!/bin/bash
# tools/t2/sync-target.sh — copy this repo's `tlx-min` target into
# a t2sde checkout so the user can run `./t2 config` + `./t2 build`
# against it.  Re-runnable: a second invocation refreshes the target
# in-place.
#
# Usage:
#   TELIX_T2_HOME=/path/to/t2sde tools/t2/sync-target.sh
#
# If TELIX_T2_HOME isn't set, the script explains how to get a t2sde
# checkout and exits.

set -e

if [ -z "${TELIX_T2_HOME:-}" ]; then
    cat <<'EOF'
TELIX_T2_HOME is not set.  Set it to the path of a t2sde checkout:

    git clone https://github.com/rxrbln/t2sde "$HOME/src/t2sde"
    export TELIX_T2_HOME="$HOME/src/t2sde"

Then re-run this script.  T2 SDE is the build system; we layer a
custom `tlx-min` target on top of it without modifying upstream.
EOF
    exit 1
fi

if [ ! -d "$TELIX_T2_HOME/target" ]; then
    echo "TELIX_T2_HOME=$TELIX_T2_HOME has no target/ dir — not a t2sde checkout?"
    exit 1
fi

SRC="$(cd "$(dirname "$0")" && pwd)/targets/tlx-min"
DST="$TELIX_T2_HOME/target/tlx-min"

mkdir -p "$DST"
cp -v "$SRC"/{build.sh,config.in,pkgsel} "$DST/"
echo
echo "Target tlx-min synced to $DST"
echo
echo "Next:"
echo "  cd \"$TELIX_T2_HOME\""
echo "  ./t2 config --cfg telix-min   # in the menu: Target → tlx-min, save+exit"
echo "  ./t2 build telix-min          # ~30min-2hr depending on host"
echo
echo "Result lands under \$TELIX_T2_HOME/build/telix-min-*/"
echo "Use tools/t2/install-into-initramfs.sh to merge it into Telix's initramfs/."
