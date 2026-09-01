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
NMLOG_TAG=uidwatch
# nmlog / nmto / nm_set_bin, and the umask -- the same helpers every other entry
# point uses. THIS SCRIPT WAS THE ONE WITHOUT THEM, and it is the one that runs on
# every install, update and uninstall: it called `timeout` bare, which on a device
# with no toybox `timeout` does not run the command unbounded but does not run it
# AT ALL, so the hide list silently stopped following installs. Nobody decided
# that; it was a copy that was never made. GUARDED, like the others.
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR — the package watcher cannot run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
[ -f "$NMDIR/disabled" ] && exit 0

# Does this list hold an actual ENTRY, or only its header?
#
# `[ -s FILE ]` is the wrong question for both files below, and for
# absorbed.list it is wrong on every device: absorb::set_absorbed_pairs writes a
# three-line comment header before it writes any pairs, so the file is 184 bytes
# and non-empty the moment the mount pass has run once, whether or not anything
# has ever been absorbed. Measured on an OP11: 184 bytes, 0 non-comment lines,
# and boot.log showing `absorb` fired four times in the first 60s after boot,
# each reporting "nothing to absorb" -- a full mountinfo survey, an `nm list`, a
# /proc walk over ~1000 pids and the engine-wide pass lock, on the root-exec path
# OOS's kevent heuristic watches, once per package change, forever. Floor cost
# measured at 133 ms per run (`absorb --dry-run`; the real pass adds more).
#
# Same predicate the readers use (blocklist::parse_blocklist,
# absorb::parse_absorbed_pairs): a line counts when its first non-blank
# character is not `#`. Blank lines and comments do not.
_has_entries() { [ -s "$1" ] && grep -qE '^[[:space:]]*[^[:space:]#]' "$1" 2>/dev/null; }

# Two jobs ride this one watch, because PackageManager rewriting packages.list is
# the trigger for both and a second inotifyd would cost another blocked process:
#   * re-apply the per-app hide list (an appid only exists once installed);
#   * re-point absorbed app-APK rules (an update regenerates the /data/app path,
#     leaving the rule aimed at a file that no longer exists — issue #14).
# Proceed when EITHER has something to do.
_has_entries "$NMDIR/uidhide" || _has_entries "$NMDIR/absorbed.list" || exit 0

# ABI / BIN / NM_BIN, with the empty-getprop fallback -- see nm_set_bin in lib.sh.
nm_set_bin
[ -x "$BIN" ] || exit 0

# nmlog() and $BOOTLOG are lib.sh's. No rotation here -- the boot entry point does
# that once per boot, and this handler can run many times.

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
# EACH value guarded separately, and BEFORE the arithmetic -- the same discipline
# service.sh applies to `_now`/`_up` and metamount.sh to `bootcount`. This was
# `_now=$(date +%s)` with no fallback and no digit test, feeding
# `$(( _now - $(stat ... || echo "$_now") ))`: an empty `_now` makes the fallback
# echo nothing too, so the expression became `$(( _now - ))` -- an arithmetic
# SYNTAX error, which in both mksh and ash kills a non-interactive shell on the
# spot. This script would then die HERE, before it takes the lock, so the whole
# handler (`uid apply` for the package that just changed) silently would not run
# and a newly installed app would stay unhidden with nothing logged.
#
# The stat arm is the reachable half: the lock can legitimately vanish between the
# `[ -f ]` above and the `stat` below, when another handler's EXIT trap unlinks it.
# `date` failing is what makes that fatal rather than harmless, so guard both.
#
# Falling back to 0 for BOTH on an unreadable clock yields _age=0, i.e. "not
# stale" -- the conservative answer. Reaping a lock we cannot age would break the
# mutual exclusion the reaper exists to protect.
if [ -f "$LOCK" ]; then
    _now=$(date +%s 2>/dev/null || echo 0)
    case "$_now" in ''|*[!0-9]*) _now=0 ;; esac
    _mt=$(stat -c %Y "$LOCK" 2>/dev/null || echo "$_now")
    case "$_mt" in ''|*[!0-9]*) _mt=$_now ;; esac
    _age=$(( _now - _mt ))
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
if _has_entries "$NMDIR/uidhide"; then
    _out=$(nmto 60 "$BIN" uid apply 2>&1)
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
if _has_entries "$NMDIR/absorbed.list"; then
    # Capture the status BEFORE the pipe: `$?` after a command substitution that
    # contains a pipeline is `tail`'s, which always succeeds, so a timeout branch
    # written the obvious way is dead code (the same trap service.sh documents).
    _abs_all=$(nmto 60 "$BIN" absorb 2>&1)
    _abs_rc=$?
    # THREE outcomes, not two. A non-zero, non-124 exit is a FAILED absorb --
    # every mount it could not take over stays in every app's mountinfo -- and it
    # used to be logged in the voice of a success by the `else` arm. The same
    # asymmetry was fixed for `uid apply` twenty lines up ("124 is not the only
    # failure"), and service.sh states it for this very command: "a plain failure
    # was logged with its own summary line ... in exactly the voice of a
    # successful pass".
    if [ "$_abs_rc" -eq 124 ]; then
        nmlog "absorb after package change TIMED OUT after 60s"
    elif [ "$_abs_rc" -ne 0 ]; then
        nmlog "⚠ absorb after package change FAILED (exit $_abs_rc) — foreign mounts may still be visible: $(printf '%s\n' "$_abs_all" | tail -1)"
    else
        nmlog "absorb after package change ($(printf '%s\n' "$_abs_all" | tail -1))"
    fi
fi
exit 0
