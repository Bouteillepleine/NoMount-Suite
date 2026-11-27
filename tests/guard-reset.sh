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
echo "system_server crash loop inside one boot"
soft() { nm_guard_soft_loop "$1" >/dev/null 2>&1 && echo parked || echo running; }
incident() { [ -e "$NMDIR/incident.log" ] && echo written || echo none; }
fresh; boot foreground
check "a healthy start parks nothing" "$(soft 1)" "running"
check "one restart parks nothing" "$(soft 2)" "running"
check "two restarts park nothing" "$(soft 3)" "running"
check "  nor leave an incident" "$(incident)" "none"
check "a third restart before boot completed parks it" "$(soft 4)" "parked"
check "  with the guard's own marker" "$(tripped)" "tripped"
check "  and an incident naming the crash loop" \
	"$(grep -c '^reason=system_server restarted 3 times before boot completed' "$NMDIR/incident.log")" "1"
check "  once: a parked Suite is not parked again" "$(soft 9)" "running"
fresh; boot foreground; rm -f "$NMDIR/guard.ts"
check "a boot the guard did not arm never parks on it" "$(soft 9)" "running"
fresh; boot foreground
check "an unreadable start count parks nothing" "$(soft "")$(soft x)" "runningrunning"
fresh; boot foreground; : > "$NMDIR/incident.log"; touch "$NMDIR/disabled"
soft 9 >/dev/null
check "a Suite parked before keeps its incident" "$([ -s "$NMDIR/incident.log" ] && echo rewritten || echo kept)" "kept"
fresh; boot foreground; NM_SOFT_LOOP_MAX=6
check "the threshold is a knob" "$(soft 5)$(soft 6)" "runningparked"
unset NM_SOFT_LOOP_MAX

echo
echo "a boot with no mount pass does not bury a guard record"
fresh; boot foreground; boot foreground; boot foreground
nm_incident_no_entry
check "a guard trip's incident survives" "$(grep -c '^bootcount=3' "$NMDIR/incident.log")" "1"
fresh; boot foreground; soft 4 >/dev/null
nm_incident_no_entry
check "  and so does a crash loop's" "$(grep -c '^reason=system_server' "$NMDIR/incident.log")" "1"
fresh; nm_incident_no_entry
check "with no record, it writes its own" "$(grep -c '^reason=no boot entry point' "$NMDIR/incident.log")" "1"
echo "reason=engine did not run: x" > "$NMDIR/incident.log"; nm_incident_no_entry
check "  and replaces one that is not a guard record" "$(grep -c '^reason=no boot entry point' "$NMDIR/incident.log")" "1"

echo
echo "the guard's card on Magisk"
if command -v ksud >/dev/null 2>&1 || command -v apd >/dev/null 2>&1; then
	echo "  skip: a root manager's CLI is on this host's PATH"
else
	printf 'id=meta-nomount\ndescription=old\n' > "$MODDIR/module.prop"
	BIN=/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount
	( APATCH=""; nm_card "⛔ disabled - bootloop guard tripped, see the WebUI" )
	check "names a command Magisk's root shell can run" \
		"$(sed -n 's/^description=//p' "$MODDIR/module.prop")" \
		"⛔ disabled - bootloop guard tripped, run $BIN check"
	echo 'version=vtest' > "$MODDIR/module.prop"
fi
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
