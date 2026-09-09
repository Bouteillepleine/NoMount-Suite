#!/system/bin/sh
[ "$3" = "packages.list" ] || exit 0

[ -n "$(printf %s "$1" | tr -d "ar0xo")" ] || exit 0

MODDIR=/data/adb/modules/meta-nomount
NMDIR=/data/adb/nomount
[ -f "$NMDIR/disabled" ] && exit 0
[ -s "$NMDIR/uidhide" ] || [ -s "$NMDIR/absorbed.list" ] || exit 0

ABI=$(getprop ro.product.cpu.abi)
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
[ -x "$BIN" ] || exit 0
export NM_BIN="$MODDIR/bin/$ABI/nm"

BOOTLOG="$NMDIR/boot.log"
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [uidwatch] $*" >> "$BOOTLOG" 2>/dev/null
}

LOCK=$NMDIR/.uidwatch.lock
if [ -f "$LOCK" ]; then
    _now=$(date +%s)
    _age=$(( _now - $(stat -c %Y "$LOCK" 2>/dev/null || echo "$_now") ))
    [ "$_age" -ge 180 ] && rm -f "$LOCK"
fi
( set -o noclobber; : > "$LOCK" ) 2>/dev/null || exit 0
trap 'rm -f "$LOCK"' EXIT INT TERM

sleep 3
if [ -s "$NMDIR/uidhide" ]; then
    _out=$(timeout 60 "$BIN" uid apply 2>&1)
    _urc=$?
    if [ "$_urc" -eq 124 ]; then
        nmlog "⚠ hide list apply after package change timed out after 60s - apps you expect to be hidden are not"
    elif [ "$_urc" -ne 0 ]; then
        nmlog "⚠ hide list apply after package change FAILED (exit $_urc) - apps you expect to be hidden are not ($_out)"
    else
        nmlog "hide list re-applied after package change ($_out)"
    fi
fi

if [ -s "$NMDIR/absorbed.list" ]; then
    _abs_all=$(timeout 60 "$BIN" absorb 2>&1)
    _abs_rc=$?
    if [ "$_abs_rc" -eq 124 ]; then
        nmlog "absorb after package change timed out after 60s"
    else
        nmlog "absorb after package change ($(printf '%s\n' "$_abs_all" | tail -1))"
    fi
fi
exit 0
