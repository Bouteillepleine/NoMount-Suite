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

PROBE=${1:-/data/local/tmp/statmount-probe}
BIN=${2:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount}

[ "$(id -u)" = 0 ] || { echo "fatal: needs root"; exit 1; }
[ -x "$PROBE" ] || { echo "fatal: no probe at $PROBE"; exit 1; }

echo "== kernel =="
uname -r

echo
echo "== what is really there (root, no guard acts) =="
"$PROBE"
echo "-- mountinfo, for comparison --"
grep -c '/adb/modules/' /proc/self/mountinfo 2>/dev/null

echo
echo "== as a hide-listed app uid (the guard's only caller) =="
HID=$("$BIN" uid list 2>/dev/null | sed -n 's/.*uid \([0-9]\{4,\}\).*/\1/p' | head -1)
if [ -z "$HID" ]; then
	echo "SKIP: no uid on the hide list, so nothing can be measured here."
	echo "      Add one with: $BIN uid add <uid>"
	exit 0
fi
echo "uid: $HID"
chmod 755 "$PROBE"
su "$HID" -c "$PROBE"
echo "-- that uid's mountinfo --"
su "$HID" -c "grep -c /adb/modules/ /proc/self/mountinfo"
