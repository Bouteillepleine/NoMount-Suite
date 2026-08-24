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

# Ignore read-only events. `uid apply` below READS packages.list, and with the
# no-mask registration above inotifyd reports that read straight back as an
# ACCESS/OPEN on the same file -- so the handler re-triggered itself and one real
# package change armed a permanent loop at the `sleep 3` cadence below. Measured
# on OP15: 121 passes in the first 413s of uptime, still climbing, 24 UIDs
# re-applied every 3.07s until reboot.
#
# Filtering here rather than in the registration mask keeps the property the mask
# comment describes: an unknown letter can still never stop inotifyd from
# starting. Deny-list, not allow-list, for the same reason -- a letter that
# differs between busybox and toybox should over-trigger, not go silent. These
# five mean the same thing in both: a=ACCESS r=OPEN 0=CLOSE_NOWRITE x=IGNORED
# o=OVERFLOW. A rename (how PackageManager actually publishes the file) arrives
# as y=MOVED_TO and is kept.
[ -n "$(printf %s "$1" | tr -d "ar0xo")" ] || exit 0

MODDIR=/data/adb/modules/meta-nomount
NMDIR=/data/adb/nomount
[ -f "$NMDIR/disabled" ] && exit 0
# Two jobs ride this one watch, because PackageManager rewriting packages.list is
# the trigger for both and a second inotifyd would cost another blocked process:
#   * re-apply the per-app hide list (an appid only exists once installed);
#   * re-point absorbed app-APK rules (an update regenerates the /data/app path,
#     leaving the rule aimed at a file that no longer exists — issue #14).
# Proceed when EITHER has something to do.
[ -s "$NMDIR/uidhide" ] || [ -s "$NMDIR/absorbed.list" ] || exit 0

ABI=$(getprop ro.product.cpu.abi)
BIN="$MODDIR/bin/$ABI/nomount"
[ -x "$BIN" ] || exit 0
export NM_BIN="$MODDIR/bin/$ABI/nm"

# Serialised so a burst of events (an install touches the file several times)
# collapses into one pass instead of a pile-up. The trap matters: without it a
# killed handler leaves the lock behind and every later change is ignored for the
# rest of the boot — the watcher would look alive and do nothing.
LOCK=/dev/nomount_uidwatch.lock
# The trap covers INT/TERM but not SIGKILL, which is exactly what Android's
# low-memory killer sends to a background shell. Treat an abandoned lock as stale
# instead of going deaf for the rest of the boot -- the failure the trap comment
# below describes, reached by the one signal a trap cannot catch.
#
# 180, not 60: a handler runs `uid apply`, which now takes the engine-wide pass
# lock and can legitimately WAIT there (bounded at 25s) behind a mount/reload/
# absorb pass. At 60s a merely-waiting handler was indistinguishable from a dead
# one, so B would reap A's lock, A's EXIT trap would then delete B's, and mutual
# exclusion was gone for the rest of the session -- handlers piling up, each
# waiting on the same pass lock. The threshold has to exceed the worst case of
# (pass-lock wait + the apply itself), not the apply alone.
if [ -f "$LOCK" ]; then
    _now=$(date +%s)
    _age=$(( _now - $(stat -c %Y "$LOCK" 2>/dev/null || echo "$_now") ))
    [ "$_age" -ge 180 ] && rm -f "$LOCK"
fi
( set -o noclobber; : > "$LOCK" ) 2>/dev/null || exit 0
trap 'rm -f "$LOCK"' EXIT INT TERM

# PackageManager writes the file in a couple of steps (temp file, then rename);
# let it settle so we resolve the finished map rather than a half-written one.
sleep 3
if [ -s "$NMDIR/uidhide" ]; then
    _out=$("$BIN" uid apply 2>&1)
    echo "nomount: hide list re-applied after package change ($_out)" > /dev/kmsg 2>/dev/null
fi

# An absorbed APK rule survives the app it serves being updated only if it is
# re-pointed at the new path; absorb refreshes those before it surveys, and is a
# no-op when nothing moved.
if [ -s "$NMDIR/absorbed.list" ]; then
    _abs=$("$BIN" absorb 2>&1 | tail -1)
    echo "nomount: absorb after package change ($_abs)" > /dev/kmsg 2>/dev/null
fi
exit 0
