#!/system/bin/sh
# inotifyd handler: re-apply the per-app hide list when the package map changes.
#
# Per-UID hiding is kernel-runtime state keyed on an appid, and an appid only
# exists once the app is installed. An entry saved for an app that wasn't
# installed yet used to sit inert until the next reboot — install the detector you
# meant to hide from and it saw everything until you rebooted. PackageManager
# rewrites /data/system/packages.list on every install, uninstall and update
# (write, then create+rename of the temp file), so a watch on the directory is the
# cheapest true trigger available without a system service.
#
# inotifyd calls us as: <handler> <event> <dir> <filename>
[ "$3" = "packages.list" ] || exit 0

MODDIR=/data/adb/modules/meta-nomount
NMDIR=/data/adb/nomount
[ -f "$NMDIR/disabled" ] && exit 0
[ -s "$NMDIR/uidhide" ] || exit 0

ABI=$(getprop ro.product.cpu.abi)
BIN="$MODDIR/bin/$ABI/nomount"
[ -x "$BIN" ] || exit 0
export NM_BIN="$MODDIR/bin/$ABI/nm"

# PackageManager writes the file in a couple of steps; let it settle so we resolve
# the finished map rather than a half-written one. Serialised with a lock so a
# burst of events (an install touches the file several times) collapses into one
# pass instead of a pile-up.
LOCK=/dev/nomount_uidwatch.lock
( set -o noclobber; : > "$LOCK" ) 2>/dev/null || exit 0
sleep 3
_out=$("$BIN" uid apply 2>&1)
echo "nomount: hide list re-applied after package change ($_out)" > /dev/kmsg 2>/dev/null
rm -f "$LOCK"
exit 0
