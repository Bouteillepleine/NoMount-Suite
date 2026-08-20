#!/system/bin/sh
# inotifyd handler: re-apply the per-app hide list when the package map changes.
#
# Per-UID hiding is kernel-runtime state keyed on an appid, and an appid only
# exists once the app is installed. An entry saved for an app that wasn't
# installed yet used to sit inert until the next reboot — install the detector you
# meant to hide from and it saw everything until you rebooted. PackageManager
# rewrites /data/system/packages.list on every install, uninstall and update, so a
# watch on that directory is the cheapest true trigger available without a system
# service.
#
# service.sh registers the watch with NO event mask, deliberately: the mask
# letters differ between the busybox and toybox inotifyd implementations, and a
# letter this toybox does not know makes inotifyd exit at startup — the watcher
# would then simply never run, silently, which is the failure mode this whole
# script exists to remove. Watching everything and filtering here costs one
# short-lived shell per change to a direct child of /data/system, which is rare.
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

# Serialised so a burst of events (an install touches the file several times)
# collapses into one pass instead of a pile-up. The trap matters: without it a
# killed handler leaves the lock behind and every later change is ignored for the
# rest of the boot — the watcher would look alive and do nothing.
LOCK=/dev/nomount_uidwatch.lock
( set -o noclobber; : > "$LOCK" ) 2>/dev/null || exit 0
trap 'rm -f "$LOCK"' EXIT INT TERM

# PackageManager writes the file in a couple of steps (temp file, then rename);
# let it settle so we resolve the finished map rather than a half-written one.
sleep 3
_out=$("$BIN" uid apply 2>&1)
echo "nomount: hide list re-applied after package change ($_out)" > /dev/kmsg 2>/dev/null
exit 0
