#!/system/bin/sh
# inotifyd handler: run `nomount check --write` HERE, on behalf of a caller that cannot.
#
# service.sh starts this watcher at boot_completed, so it is reparented to init and
# carries no seccomp filter. The manager's WebUI, by contrast, execs from a root shell
# spawned by an app and inherits that app's filter - which denies setgroups, so the four
# checks that have to take on an app's uid cannot run there at all. A tap used to replace
# a clean report with "not fully measured (4 checks)", one SIGSYS tombstone per probe.
# The WebUI now asks here instead, and reads the report this writes.
case "$3" in
    check) ;;
    *) exit 0 ;;
esac
# 'x' alone means the watch itself went away, not that anything was written.
[ -n "$(printf %s "$1" | tr -d x)" ] || exit 0

MODDIR=/data/adb/modules/meta-nomount
NMLOG_TAG=checkwatch
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || exit 1

REQ="$NMDIR/request/check"
[ -e "$REQ" ] || exit 0
# $NMDIR is 0700 root:root so only root can have put it there, but a request is a command
# to run the engine binary: verify rather than assume.
_own=$(stat -c '%u:%g' "$REQ" 2>/dev/null)
rm -f "$REQ"
if [ "$_own" != "0:0" ]; then
    nmlog "⚠ check request was owned by $_own, not root - ignored"
    exit 0
fi

[ -e "$NMDIR/disabled" ] && exit 0
nm_set_bin
[ -x "$BIN" ] || exit 0

LOCK=$NMDIR/.checkwatch.lock
if [ -f "$LOCK" ]; then
    _lp=$(cat "$LOCK" 2>/dev/null)
    case "$_lp" in ''|*[!0-9]*) _lp=0 ;; esac
    { [ "$_lp" = 0 ] || ! kill -0 "$_lp" 2>/dev/null; } && rm -f "$LOCK"
fi
# One check at a time. A second tap while one is running needs no second run: the one in
# flight writes a newer report, which is what the caller is waiting for.
( set -o noclobber; echo $$ > "$LOCK" ) 2>/dev/null || exit 0
trap '[ "$(cat "$LOCK" 2>/dev/null)" = "$$" ] && rm -f "$LOCK"' EXIT INT TERM

# `check` takes the pass lock itself, so this cannot sample a half-applied mount pass.
nmto 90 "$BIN" check --write >/dev/null 2>&1
_rc=$?
if [ "$_rc" -eq 124 ]; then
    nmlog "⚠ requested check timed out after 90s - the cached report was left as it was"
else
    nmlog "check on request: verdict=$(sed -n 's/^verdict=//p' "$NMDIR/health.txt" 2>/dev/null)"
fi
exit 0
