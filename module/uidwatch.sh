#!/system/bin/sh
case "$3" in
    packages.list|.allowlist) ;;
    *) exit 0 ;;
esac

[ -n "$(printf %s "$1" | tr -d x)" ] || exit 0

MODDIR=/data/adb/modules/meta-nomount
NMLOG_TAG=uidwatch
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - the package watcher cannot run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
[ -e "$NMDIR/disabled" ] && exit 0

if [ "$3" = ".allowlist" ]; then
    _follow_ksu || exit 0
else
    _has_entries "$NMDIR/uidhide" || _follow_ksu || _has_entries "$NMDIR/absorbed.list" || exit 0
fi

nm_set_bin
[ -x "$BIN" ] || exit 0

LOCK=$NMDIR/.uidwatch.lock
if [ -f "$LOCK" ]; then
    _lp=$(cat "$LOCK" 2>/dev/null)
    case "$_lp" in ''|*[!0-9]*) _lp=0 ;; esac
    _now=$(date +%s 2>/dev/null || echo 0)
    case "$_now" in ''|*[!0-9]*) _now=0 ;; esac
    _mt=$(stat -c %Y "$LOCK" 2>/dev/null || echo "$_now")
    case "$_mt" in ''|*[!0-9]*) _mt=$_now ;; esac
    _age=$(( _now - _mt ))
    # Age ANDed with liveness, not ORed. A pass can legitimately run three rounds of
    # two 60s timeouts, so 180s of age proves nothing on its own - and stealing a live
    # holder's lock let two `uid apply` runs write the engine's uid table at once, then
    # the first holder's EXIT trap deleted the second one's lock.
    if [ "$_lp" = 0 ] || ! kill -0 "$_lp" 2>/dev/null; then
        rm -f "$LOCK"
    elif [ "$_age" -ge 900 ]; then
        nmlog "uidwatch: pid $_lp has held the lock ${_age}s and is still alive - breaking it"
        rm -f "$LOCK"
    fi
fi
DIRTY=$NMDIR/.uidwatch.dirty
DIGEST=$NMDIR/.uidwatch.digest
_SUM=$(command -v sha256sum 2>/dev/null || command -v md5sum 2>/dev/null)
# packages.list is rewritten byte-identically on every PMS commit; gate on the real inputs.
_uw_digest() {
    [ -n "$_SUM" ] || return 0
    for _f in "$NMDIR/uidhide" "$NMDIR/uidhide.conf" "$NMDIR/absorbed.list" \
              /data/system/packages.list /data/adb/ksu/.allowlist; do
        [ -f "$_f" ] && "$_SUM" "$_f" 2>/dev/null
    done
}
( set -o noclobber; echo $$ > "$LOCK" ) 2>/dev/null || {
    : > "$DIRTY" 2>/dev/null
    exit 0
}
trap 'rm -f "$LOCK"' EXIT INT TERM

sleep 3
_rounds=0
while :; do
# Keep the lock's mtime current so its age measures how long this round has run,
# not how long ago the pass started.
touch "$LOCK" 2>/dev/null
rm -f "$DIRTY" 2>/dev/null
_cur=$(_uw_digest)
if [ -z "$_cur" ] || [ "$_cur" != "$(cat "$DIGEST" 2>/dev/null)" ]; then
_ok=1
if _has_entries "$NMDIR/uidhide" || _follow_ksu; then
    _out=$(export NM_REDACT_HIDE_LIST=1; nmto 60 "$BIN" uid apply 2>&1)
    _urc=$?
    if [ "$_urc" -eq 124 ]; then
        nmlog "⚠ hide list apply after package change timed out after 60s - apps you expect to be hidden are not"
        _ok=0
    elif [ "$_urc" -ne 0 ]; then
        nmlog "⚠ hide list apply after package change FAILED (exit $_urc) - apps you expect to be hidden are not ($_out)"
        _ok=0
    else
        nmlog "hide list re-applied after $3 change ($_out)"
    fi
fi

if _has_entries "$NMDIR/absorbed.list"; then
    _abs_all=$(nmto 60 "$BIN" absorb 2>&1)
    _abs_rc=$?
    nmlog_absorb_notes "$_abs_all"
    if [ "$_abs_rc" -eq 124 ]; then
        nmlog "absorb after package change timed out after 60s"
        _ok=0
    elif [ "$_abs_rc" -ne 0 ]; then
        nmlog "⚠ absorb after package change FAILED (exit $_abs_rc) - foreign mounts may still be visible: $(printf '%s\n' "$_abs_all" | tail -1)"
        _ok=0
    else
        nmlog "absorb after package change ($(printf '%s\n' "$_abs_all" | tail -1))"
    fi
fi
[ "$_ok" = 1 ] && [ -n "$_cur" ] && printf '%s\n' "$_cur" > "$DIGEST" 2>/dev/null
fi
_rounds=$((_rounds + 1))
[ -e "$DIRTY" ] || break
if [ "$_rounds" -ge 3 ]; then
    nmlog "package changes kept arriving while the hide list was being re-applied; stopping after $_rounds passes - the next package event or boot picks up the rest"
    break
fi
done
exit 0
