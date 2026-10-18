#!/usr/bin/env bash
# The matrix step runs under `bash -e` with `set -o pipefail`, so this script does
# too: every grep below may legitimately match nothing, and without `|| true` a
# clean engine fails the leg before it compiles anything. That is not theoretical -
# it is what shipping this without the flags did.
set -euo pipefail

extract_positive() {
    local cond ie all neg
    cond=$(grep -ohE '^[[:space:]]*#[[:space:]]*(if|ifdef|ifndef|elif)([^A-Za-z0-9_].*)?$' "$@" || true)
    ie=$(grep -ohE 'IS_ENABLED\([[:space:]]*CONFIG_[A-Z0-9_]+' "$@" || true)
    all=$(printf '%s\n%s\n' "$cond" "$ie" | grep -oE 'CONFIG_[A-Z0-9_]+' | sort -u || true)
    neg=$(printf '%s\n' "$cond" | grep -E '(ifndef|![[:space:]]*defined)' \
          | grep -oE 'CONFIG_[A-Z0-9_]+' | sort -u || true)
    [ -n "$all" ] || return 0
    if [ -n "$neg" ]; then
        comm -23 <(printf '%s\n' "$all") <(printf '%s\n' "$neg")
    else
        printf '%s\n' "$all"
    fi
}

extract_negative() {
    grep -ohE '^[[:space:]]*#[[:space:]]*(if|ifdef|ifndef|elif)([^A-Za-z0-9_].*)?$' "$@" 2>/dev/null \
        | { grep -E '(ifndef|![[:space:]]*defined)' || true; } \
        | { grep -oE 'CONFIG_[A-Z0-9_]+' || true; } | sort -u
}

fail=0
check() {
    local label=$1 got=$2 want=$3
    if [ "$got" = "$want" ]; then
        printf 'ok    %s\n' "$label"
    else
        printf 'FAIL  %s\n        got  %s\n        want %s\n' "$label" "$got" "$want"
        fail=1
    fi
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cat > "$T/a.c" <<'EOF'
#ifdef CONFIG_A
#ifndef CONFIG_B
#if defined(CONFIG_C)
#elif defined(CONFIG_D)
#if !defined(CONFIG_E)
#if IS_ENABLED(CONFIG_F)
  x = IS_ENABLED(CONFIG_G);
#if defined(CONFIG_H) && defined(CONFIG_I)
#elif IS_ENABLED(CONFIG_J)
int nothing = CONFIG_NOT_A_GATE;
EOF
: > "$T/a.h"

check "every positive gating form is seen" \
      "$(extract_positive "$T/a.c" "$T/a.h" | tr '\n' ' ')" \
      "CONFIG_A CONFIG_C CONFIG_D CONFIG_F CONFIG_G CONFIG_H CONFIG_I CONFIG_J "
check "negative gating forms are reported, not asserted" \
      "$(extract_negative "$T/a.c" "$T/a.h" | tr '\n' ' ')" \
      "CONFIG_B CONFIG_E "

cat > "$T/b.c" <<'EOF'
#ifndef EROFS_SUPER_MAGIC_V1
int plain = 1;
EOF
: > "$T/b.h"
check "a file with no CONFIG_ gate yields none" \
      "$(extract_positive "$T/b.c" "$T/b.h" | tr '\n' ' ')" ""
check "a file with no negative gate yields none" \
      "$(extract_negative "$T/b.c" "$T/b.h" | tr '\n' ' ')" ""

# The matrix step is `bash -e` + `set -o pipefail`. A grep that matches nothing
# exits 1, so an extraction without `|| true` kills the leg before it compiles.
# Run both extractors under those exact flags against a source with no gate at
# all - the case the real engine hits today.
if bash -euo pipefail -c "
    $(declare -f extract_positive)
    $(declare -f extract_negative)
    extract_positive '$T/b.c' '$T/b.h' >/dev/null
    extract_negative '$T/b.c' '$T/b.h' >/dev/null
"; then
    printf 'ok    extraction survives bash -e -o pipefail with zero matches\n'
else
    printf 'FAIL  extraction dies under bash -e -o pipefail when nothing matches\n'
    printf '        this is exactly what turned all ten matrix legs red on 2026-09-22\n'
    fail=1
fi

SRC_C=${1:-hookless/src/nomount.c}
SRC_H=${2:-hookless/src/nomount.h}
if [ ! -f "$SRC_C" ] || [ ! -f "$SRC_H" ]; then
    printf 'FAIL  engine source not found (%s, %s)
' "$SRC_C" "$SRC_H"
    printf '        without it this script would assert only its own fixtures and exit 0,
'
    printf '        which is the vacuous gate it exists to prevent
'
    exit 1
fi

pos=$(extract_positive "$SRC_C" "$SRC_H" | tr '
' ' ')
neg=$(extract_negative "$SRC_C" "$SRC_H" | tr '
' ' ')
printf '
engine positive gates: %s
engine negative gates: %s
' "${pos:-none}" "${neg:-none}"
if [ -z "$pos" ]; then
    printf 'FAIL  the engine reports no positive gate at all - the matrix assertion would be vacuous
'
    fail=1
fi

exit $fail
