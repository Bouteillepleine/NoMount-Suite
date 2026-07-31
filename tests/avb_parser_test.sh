#!/usr/bin/env bash
# Host-side unit tests for the AVB byte-parser primitives in module/spoof.sh.
# Sources spoof.sh with NM_SPOOF_SOURCE=1 (skips the main pass) and drives the
# parser functions against synthetic fixtures. Run:  bash tests/avb_parser_test.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SPOOF="$HERE/../module/spoof.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# stubs so any top-level getprop/resetprop in spoof.sh load cleanly off-device
getprop()   { echo ""; }
resetprop() { :; }

# shellcheck disable=SC1090
NM_SPOOF_SOURCE=1 . "$SPOOF"

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "  ok   $1"; pass=$((pass+1));
       else echo "  FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }

# --- be_u32: big-endian 4-byte reader ---
printf '\x12\x34\x56\x78' > "$TMP/a"
ck "be_u32 0x12345678"        305419896 "$(be_u32 "$TMP/a" 0)"
printf '\xff\x00\x00\x01\x00' > "$TMP/b"          # value at offset 1 = 0x00000100
ck "be_u32 @offset1 = 256"    256       "$(be_u32 "$TMP/b" 1)"

# --- be_u64: big-endian 8-byte reader ---
printf '\x00\x00\x00\x00\x00\x00\x00\x64' > "$TMP/c"
ck "be_u64 = 100"             100       "$(be_u64 "$TMP/c" 0)"

# --- vbmeta_base: a pure vbmeta partition starts with 'AVB0' at offset 0 ---
{ printf 'AVB0'; head -c 60 /dev/zero; } > "$TMP/hdr"
ck "vbmeta_base AVB0@0 -> 0"  0         "$(vbmeta_base "$TMP/hdr")"

# --- vbmeta_base: a chained image partition ends in a 64-byte AvbFooter whose
#     vbmeta_offset (u64 @ footer+20) points at the struct. Here = 100. ---
{ head -c 200 /dev/zero; \
  printf 'AVBf'; head -c 16 /dev/zero; \
  printf '\x00\x00\x00\x00\x00\x00\x00\x64'; head -c 36 /dev/zero; } > "$TMP/foot"
ck "vbmeta_base AVBf off=100" 100       "$(vbmeta_base "$TMP/foot")"

# --- vbmeta_base: no AVB0 and no AVBf footer -> failure (non-zero) ---
head -c 128 /dev/zero > "$TMP/junk"
vbmeta_base "$TMP/junk" >/dev/null 2>&1; ck "vbmeta_base junk -> fail" 1 "$?"

echo "AVB parser: $pass passed, $fail failed"
[ "$fail" = 0 ]
