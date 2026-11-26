#!/system/bin/sh
# Drives statmount-probe twice: once as root, once as a hide-listed app uid.
#
# Root is the baseline - no guard acts for it, so what root sees is what is
# really mounted. The hide-listed run is the measurement: the mount filter blanks
# the bind out of /proc/<pid>/mountinfo for that uid, and the question is whether
# listmount/statmount still hand it over.
#
#   adb push tests/statmount-check.sh /data/local/tmp/
#   adb push statmount-probe /data/local/tmp/
#   adb shell su -c 'sh /data/local/tmp/statmount-check.sh'
#
# Exits 0 PASS, 1 FAIL, 2 UNMEASURED. The three are deliberately distinct: this
# script used to print its three measurements and compare none of them, and its
# status was whatever `grep -c` last returned -- which is 1 when the count is 0,
# so it exited non-zero on the CLEAN result and zero on a leak. It could not go
# red for the thing it is named after.

PROBE=${1:-/data/local/tmp/statmount-probe}
BIN=${2:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount}

[ "$(id -u)" = 0 ] || { echo "fatal: needs root"; exit 1; }
[ -x "$PROBE" ] || { echo "fatal: no probe at $PROBE"; exit 1; }

fail=0
unmeasured=0

echo "== kernel =="
uname -r

echo
echo "== what is really there (root, no guard acts) =="
root_out=$("$PROBE" 2>&1)
printf '%s\n' "$root_out"
root_n=$(printf '%s\n' "$root_out" | sed -n 's|^statmount/listmount: \([0-9]*\) module-rooted.*|\1|p')
echo "-- mountinfo, for comparison --"
root_mi=$(grep -c '/adb/modules/' /proc/self/mountinfo 2>/dev/null)
echo "$root_mi"
# With nothing module-rooted mounted at all, "the uid sees none" holds whether or not the
# filter works, so the comparison below would pass without measuring anything.
if [ "$root_n" = 0 ] && [ "${root_mi:-0}" = 0 ]; then
	echo
	echo "UNMEASURED: root sees no module-rooted mount either, so there is nothing for the"
	echo "            filter to hide. Run this where a module bind is mounted."
	echo "RESULT: UNMEASURED (not a pass)"
	exit 2
fi

echo
echo "== as a hide-listed app uid (the guard's only caller) =="
# A LIVE row only. `uid list` prints a "uid NNNNN" field for saved-but-not-applied
# and engine-unreadable rows too, and taking the first row with any uid drove the
# whole measurement against a uid no guard is installed for -- which then reports
# clean because nothing was being hidden from it in the first place.
HID=$("$BIN" uid list 2>/dev/null \
	| grep -E 'uid [0-9]{4,}' \
	| grep -v 'not applied' \
	| grep -v 'unreadable' \
	| grep -E 'live' \
	| sed -n 's/.*uid \([0-9]\{4,\}\).*/\1/p' | head -1)
if [ -z "$HID" ]; then
	echo "UNMEASURED: no LIVE hide-list uid, so the guard has no caller to measure."
	echo "            Add one with: $BIN uid block <package>, then re-run."
	exit 2
fi
echo "uid: $HID"
chmod 755 "$PROBE"
hid_out=$(su "$HID" -c "$PROBE" 2>&1)
hid_rc=$?
printf '%s\n' "$hid_out"
echo "-- that uid's mountinfo --"
hid_mi=$(su "$HID" -c "grep -c /adb/modules/ /proc/self/mountinfo" 2>/dev/null)
echo "$hid_mi"

echo
echo "== verdict =="
# The probe exits 1 on a leak and prints one verdict line; 0 covers clean, and also
# the two "could not measure" cases, which are NOT passes.
case "$hid_out" in
*"verdict: clean"*)
	echo "ok    statmount/listmount hand that uid no module-rooted mount"
	;;
*"verdict: not applicable"*)
	echo "UNMEASURED: this kernel predates listmount, so there is nothing to hide"
	unmeasured=1
	;;
*"verdict: unmeasured"*)
	echo "UNMEASURED: the probe could not read the mount list for that uid"
	unmeasured=1
	;;
*"contradiction(s): listmount offered"*)
	echo "FAIL  listmount offered that uid ids statmount then refused: the refusal is the tell"
	fail=1
	;;
*"verdict:"*)
	echo "FAIL  the probe reported a leak for a hide-listed uid"
	fail=1
	;;
*)
	echo "FAIL  the probe printed no verdict at all (did it run?)"
	fail=1
	;;
esac
if [ "$hid_rc" -gt 1 ]; then
	echo "FAIL  the probe exited $hid_rc for uid $HID"
	fail=1
fi

# The cross-check this script's own header describes. mountinfo is the surface the
# filter already blanks; statmount agreeing with it only means something when the
# filter is in fact hiding something from this uid.
case "$hid_mi" in
'' | *[!0-9]*)
	echo "UNMEASURED: could not count that uid's mountinfo rows"
	unmeasured=1
	;;
0) ;;
*)
	echo "UNMEASURED: that uid still sees $hid_mi module row(s) in its own mountinfo,"
	echo "            so statmount hiding them would not be the property under test"
	unmeasured=1
	;;
esac

echo
if [ "$fail" != 0 ]; then
	echo "RESULT: FAIL"
	exit 1
fi
if [ "$unmeasured" != 0 ]; then
	echo "RESULT: UNMEASURED (not a pass)"
	exit 2
fi
echo "RESULT: PASS"
exit 0
