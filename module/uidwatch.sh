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
# Same fallback the boot entry points carry: an empty ABI builds
# "$MODDIR/bin//nomount", which can never be executable, so the handler exits 0
# and the hide list silently stops following installs.
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
[ -x "$BIN" ] || exit 0
export NM_BIN="$MODDIR/bin/$ABI/nm"

# Tee to the durable boot log as well as kmsg (see metamount.sh): this handler
# fires on package changes, long after boot, by which point the kernel ring on
# this device has already been flushed by roam-stats spam. No rotation here --
# the boot entry point does that once per boot, and this can run many times.
BOOTLOG="$NMDIR/boot.log"
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [uidwatch] $*" >> "$BOOTLOG" 2>/dev/null
}

# Serialised so a burst of events (an install touches the file several times)
# collapses into one pass instead of a pile-up. The trap matters: without it a
# killed handler leaves the lock behind and every later change is ignored for the
# rest of the boot — the watcher would look alive and do nothing.
# NOT /dev. This was `/dev/nomount_uidwatch.lock`, which is the same design
# metamount.sh removed from its own single-run guard and documented as wrong:
# "world-writable (boot umask), named after the project, and 'held' by mere
# existence -- so anything able to create that path pre-empted the whole mount
# pass." Both objections apply here unchanged, and there is a third: `nomount
# check`'s kernel-surface probe walks /sys/kernel, /sys/module and /proc looking
# for an entry named after the engine, so the one such name the Suite created
# for itself was in the only directory that probe does not read. The 0700 state
# directory is writable by root alone, and nothing there is named in a listing
# an app can take.
#
# /dev is a tmpfs, so the old path could never outlive a boot. This one can, so
# both boot entry points delete it before anything can take it -- see the
# `rm -f` beside the boot.log rotation in metamount.sh and post-fs-data.sh. The
# 180s mtime reaper below is unchanged and still covers a handler killed
# mid-run within a boot.
LOCK=$NMDIR/.uidwatch.lock
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
# Both jobs below are BOUNDED, so the 180s stale-lock threshold above is provably
# unreachable rather than merely generous. They were unbounded, and each can
# additionally wait up to 25s on the engine-wide pass lock -- which meant a
# waiting handler was still indistinguishable from a dead one, just further out,
# and the reaper's whole premise (age implies death) was still unsound.
# 60s: comfortably past (25s pass-lock wait + the apply itself), comfortably
# under 180.
if [ -s "$NMDIR/uidhide" ]; then
    _out=$(timeout 60 "$BIN" uid apply 2>&1)
    _urc=$?
    # 124 is not the only failure. A plain non-zero exit means the apply itself
    # failed -- apps the user believes are hidden are not -- and the else arm
    # logged that outcome as "hide list re-applied". service.sh says of the very
    # same call that "a failed apply is the one thing here that must not pass
    # quietly"; this path, which runs on EVERY install and update, did not.
    if [ "$_urc" -eq 124 ]; then
        nmlog "⚠ hide list apply after package change TIMED OUT after 60s — apps you expect to be hidden are NOT"
    elif [ "$_urc" -ne 0 ]; then
        nmlog "⚠ hide list apply after package change FAILED (exit $_urc) — apps you expect to be hidden are NOT ($_out)"
    else
        nmlog "hide list re-applied after package change ($_out)"
    fi
fi

# An absorbed APK rule survives the app it serves being updated only if it is
# re-pointed at the new path; absorb refreshes those before it surveys, and is a
# no-op when nothing moved.
if [ -s "$NMDIR/absorbed.list" ]; then
    # Capture the status BEFORE the pipe: `$?` after a command substitution that
    # contains a pipeline is `tail`'s, which always succeeds, so a timeout branch
    # written the obvious way is dead code (the same trap service.sh documents).
    _abs_all=$(timeout 60 "$BIN" absorb 2>&1)
    _abs_rc=$?
    if [ "$_abs_rc" -eq 124 ]; then
        nmlog "absorb after package change TIMED OUT after 60s"
    else
        nmlog "absorb after package change ($(printf '%s\n' "$_abs_all" | tail -1))"
    fi
fi
exit 0
