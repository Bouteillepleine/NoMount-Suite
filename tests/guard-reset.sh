#!/bin/sh
# The bootloop guard across simulated boots: module/lib.sh's real nm_guard_* functions,
# a fake boot_id per boot, nothing else stubbed but the paths.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
check() {
	if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf '  ok   %s\n' "$1"
	else fail=$((fail + 1)); printf '  FAIL %s\n       want=%s got=%s\n' "$1" "$3" "$2"; fi
}
. "$HERE/module/lib.sh"
NMDIR="$WORK/nm"; BOOTLOG="$NMDIR/boot.log"; MODDIR="$WORK/mod"; NM_BIN=/bin/false
NM_BOOT_ID="$WORK/boot_id"; NM_GUARD_FG_WAIT=0
mkdir -p "$MODDIR"; echo 'version=vtest' > "$MODDIR/module.prop"
n=0
fresh() { rm -rf "$NMDIR"; mkdir -p "$NMDIR"; n=0; }
# One boot up to the given point. The guard is bumped once at post-fs-data, as on a device.
boot() {
	n=$((n + 1)); echo "boot-$n-$$" > "$NM_BOOT_ID"
	nm_guard_bump "test"; rc=$?
	[ "$rc" = 0 ] || return "$rc"
	count=$(cat "$NMDIR/bootcount" 2>/dev/null)
	case "$1" in
	foreground) return 0 ;;                                   # dies before the foreground returns
	fg-done) nm_guard_fg_done; return 0 ;;                    # user reboots in the gap
	late) nm_guard_fg_done; nm_guard_late_hold "$count"; return 0 ;;  # dies in the late pass
	clean) nm_guard_fg_done; nm_guard_late_hold "$count"; nm_guard_late_release; return 0 ;;
	esac
}
tripped() { [ -e "$NMDIR/disabled" ] && echo tripped || echo armed; }

echo "bootloop guard"
fresh; boot fg-done; boot fg-done; boot fg-done
check "three reboots after the foreground passes do not park the Suite" "$(tripped)" "armed"
fresh; boot late; boot late; boot late
check "a panic in the late pass every boot parks it on the third" "$(tripped)" "tripped"
fresh; boot foreground; boot foreground; boot foreground
check "a panic before the foreground returns parks it on the third" "$(tripped)" "tripped"
fresh; boot clean; boot clean; boot clean
check "clean boots leave no count behind" "$([ -e "$NMDIR/bootcount" ] && cat "$NMDIR/bootcount" || echo none)" "none"
check "  and never park" "$(tripped)" "armed"
fresh; boot late; boot clean
check "a clean boot after a late-pass panic clears the count" "$([ -e "$NMDIR/bootcount" ] && cat "$NMDIR/bootcount" || echo none)" "none"
fresh; echo "boot-1-$$" > "$NM_BOOT_ID"; nm_guard_bump test; c=$(cat "$NMDIR/bootcount")
rm -f "$NMDIR/.guard_fg"; nm_guard_late_hold "$c"
check "the late hold re-arms the count even when the foreground never signalled" "$(cat "$NMDIR/bootcount")" "1"
fresh; nm_guard_late_hold ""
check "an unread count holds nothing" "$([ -e "$NMDIR/bootcount" ] && echo held || echo none)" "none"
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
