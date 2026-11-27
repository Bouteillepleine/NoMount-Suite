#!/bin/sh
# Compile and run tests/tail-gap-check.c against the engine's own nm_emit_tail() and nm_tail_gap().
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
for f in nm_tail_gap nm_emit_tail; do
	awk -v f="$f" '$0 ~ "^static (inline )?(bool|loff_t) " f "\\(" {p=1} p{print} p&&/^}/{exit}' \
		"$HERE/hookless/src/nomount.c" > "$W/$f.inc"
	[ -s "$W/$f.inc" ] || { echo "$f() not found in hookless/src/nomount.c"; exit 1; }
done
cat "$W/nm_tail_gap.inc" "$W/nm_emit_tail.inc" > "$W/fn.inc"
${CC:-cc} -O2 -Wall -Werror -Wno-unused-function -I"$W" -DNM_TAIL_FN='"fn.inc"' -o "$W/t" "$HERE/tests/tail-gap-check.c"
"$W/t"
