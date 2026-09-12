#!/bin/sh
set -eu

kpm="${1:?usage: gate.sh <nomount.kpm> <kp checkout> [label]}"
kpdir="${2:?usage: gate.sh <nomount.kpm> <kp checkout> [label]}"
label="${3:-$(basename "$kpm")}"
NM="${NM:-aarch64-linux-gnu-nm}"

summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ ! -f "$kpm" ]; then
    printf '#### %s - no .kpm built\n' "$label" >> "$summary"
    echo "::error::no .kpm was produced for $label"
    exit 1
fi

undef=$(mktemp)
provided=$(mktemp)
left=$(mktemp)
trap 'rm -f "$undef" "$provided" "$left"' EXIT

"$NM" -u "$kpm" | awk '{print $2}' | sort -u > "$undef"

grep -rhoE 'KP_EXPORT_SYMBOL[(][a-zA-Z_0-9]+[)]' "$kpdir/kernel" \
    | sed 's/.*(//; s/)//' | sort -u > "$provided"
echo "KernelPatch exports $(wc -l < "$provided") symbols to modules"
if [ ! -s "$provided" ]; then
    echo "::error::found no KP_EXPORT_SYMBOL in $kpdir; cannot judge the gate"
    exit 1
fi

comm -23 "$undef" "$provided" > "$left" || true

{
    printf '#### %s - %s bytes\n' "$label" "$(stat -c%s "$kpm")"
    echo '```'
    if [ -s "$undef" ]; then cat "$undef"; else echo '(nothing undefined)'; fi
    echo '```'
} >> "$summary"

if [ -s "$left" ]; then
    {
        echo
        printf '**%s of these are not provided by KernelPatch.**\n' "$(wc -l < "$left")"
        echo "The loader rejects the whole module on the first one, so this"
        echo ".kpm would not load:"
        echo '```'
        cat "$left"
        echo '```'
    } >> "$summary"
    echo "$label: unresolvable at load:"
    cat "$left"
    echo "::error::$(wc -l < "$left") symbols cannot be resolved at load ($label)"
    exit 1
fi

echo "All undefined symbols are ones KernelPatch provides." >> "$summary"
echo "$label: gate clean"
