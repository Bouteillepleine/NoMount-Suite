#!/bin/sh
# Compile and run tests/ovl-layout-check.c against the engine's own nm_ovl_layout_ok().
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
awk '/^static bool nm_ovl_layout_ok\(/{p=1} p{print} p&&/^}/{exit}' "$HERE/hookless/src/nomount.c" > "$W/fn.inc"
[ -s "$W/fn.inc" ] || { echo "nm_ovl_layout_ok() not found in hookless/src/nomount.c"; exit 1; }
${CC:-cc} -O2 -Wall -Werror -I"$W" -DNM_OVL_FN='"fn.inc"' -o "$W/t" "$HERE/tests/ovl-layout-check.c"
"$W/t"
