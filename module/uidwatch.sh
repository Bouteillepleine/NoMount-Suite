#!/system/bin/sh
[ "$3" = "packages.list" ] || exit 0

[ -n "$(printf %s "$1" | tr -d "ar0xo")" ] || exit 0

MODDIR=/data/adb/modules/meta-nomount
NMLOG_TAG=uidwatch
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - the package watcher cannot run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
[ -e "$NMDIR/disabled" ] && exit 0

_has_entries "$NMDIR/uidhide" || _has_entries "$NMDIR/absorbed.list" || exit 0

nm_set_bin
[ -x "$BIN" ] || exit 0

LOCK=$NMDIR/.uidwatch.lock
if [ -f "$LOCK" ]; then
    _lp=$(cat "$LOCK" 2>/dev/null)
    case "$_lp" in ''|*[!0-9]*) _lp=0 ;; esac
    if [ "$_lp" = 0 ] || ! kill -0 "$_lp" 2>/dev/null; then
        _now=$(date +%s 2>/dev/null || echo 0)
        case "$_now" in ''|*[!0-9]*) _now=0 ;; esac
        _mt=$(stat -c %Y "$LOCK" 2>/dev/null || echo "$_now")
        case "$_mt" in ''|*[!0-9]*) _mt=$_now ;; esac
        _age=$(( _now - _mt ))
        [ "$_age" -ge 180 ] && rm -f "$LOCK"
    fi
fi
( set -o noclobber; echo $$ > "$LOCK" ) 2>/dev/null || exit 0
trap 'rm -f "$LOCK"' EXIT INT TERM

sleep 3
if _has_entries "$NMDIR/uidhide"; then
    _out=$(nmto 60 "$BIN" uid apply 2>&1)
    _urc=$?
    if [ "$_urc" -eq 124 ]; then
        nmlog "⚠ hide list apply after package change timed out after 60s - apps you expect to be hidden are not"
    elif [ "$_urc" -ne 0 ]; then
        nmlog "⚠ hide list apply after package change FAILED (exit $_urc) - apps you expect to be hidden are not ($_out)"
    else
        nmlog "hide list re-applied after package change ($_out)"
    fi
fi

if _has_entries "$NMDIR/absorbed.list"; then
    _abs_all=$(nmto 60 "$BIN" absorb 2>&1)
    _abs_rc=$?
    nmlog_absorb_notes "$_abs_all"
    if [ "$_abs_rc" -eq 124 ]; then
        nmlog "absorb after package change timed out after 60s"
    elif [ "$_abs_rc" -ne 0 ]; then
        nmlog "⚠ absorb after package change FAILED (exit $_abs_rc) - foreign mounts may still be visible: $(printf '%s\n' "$_abs_all" | tail -1)"
    else
        nmlog "absorb after package change ($(printf '%s\n' "$_abs_all" | tail -1))"
    fi
fi
exit 0
