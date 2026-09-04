#!/system/bin/sh
# Bootloop-guard reset: once the system finishes booting, the last boot was
# healthy, so clear the boot counter (re-arms the guard for next time).
MODDIR="${0%/*}"
NMLOG_TAG=service
# nmlog / nmto / nm_set_bin / nm_fix_shell_tmp / nm_delink_ksud, and the umask.
# GUARDED for the reason post-fs-data.sh spells out: a partial extraction must
# stop loudly rather than run with every helper undefined.
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR — the post-boot pass did not run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
# Binary paths, hoisted to the top because the ghost block below needs `nm`.
# ABI / BIN / NM_BIN, with the empty-getprop fallback -- see nm_set_bin in lib.sh.
# EVERY block below is gated on [ -x "$BIN" ], so an unresolved ABI made absorb,
# the whiteout re-apply, the authoritative `uid apply`, the package watcher, the
# check canary and the card refresh all silently do nothing.
nm_set_bin

# nmto() is lib.sh's -- see the note there on what a missing `timeout` costs.

# nmlog() and $BOOTLOG are lib.sh's. No rotation here: the boot entry point
# (metamount.sh / post-fs-data.sh) already rotated once this boot.

# --- health.txt freshness -----------------------------------------------------
# health.txt carries a `ts=` field (written by src/health.rs) that NOTHING read.
# So a check run that failed to write -- or an engine that hung and never
# returned -- silently left LAST BOOT's file in place, and every consumer below
# sed'd yesterday's verdict out of it as if it were current. Worse, the empty
# case mapped to _consbad=0 and the card printed "healthy" off a file that did
# not exist at all.
#
# Boot epoch = now minus uptime. A record stamped before that is not this boot's.
_now=$(date +%s 2>/dev/null || echo 0)
_up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
# FAIL CLOSED when the boot epoch is unknowable. Zeroing both left
# _bootepoch=0, which makes the >= test below true for EVERY timestamp -- so the
# one input that defeats the freshness check (an unreadable date or
# /proc/uptime) made a stale record from last boot read as this boot's, which is
# precisely the false green the check exists to stop. "Cannot tell" has to mean
# "not fresh", the same way an unparsable ts= already does.
_epoch_known=1
# EACH value separately. This was `case "$_now$_up"`, which tests the two
# CONCATENATED -- so an empty `$_up` beside a valid `$_now` yields a string that is
# all digits, passes, and reaches `$((_now - ))`. That is an arithmetic SYNTAX
# error, and in both mksh and ash it kills a non-interactive shell on the spot:
# the rest of the post-boot pass (absorb, the whiteout re-apply, the authoritative
# `uid apply`, the package watcher, the status card) simply would not run, with
# nothing logged. It is the same class metamount.sh sanitizes `bootcount` against
# before `$((COUNT + 1))`, and the guard there is per-value for this reason.
#
# Unreachable in practice -- /proc/uptime always has content, and both assignments
# have an `|| echo 0` -- but the concatenated form only LOOKED like it covered the
# empty case, and that is the property worth keeping true.
case "$_now" in ''|*[!0-9]*) _now=0; _epoch_known=0 ;; esac
case "$_up"  in ''|*[!0-9]*) _up=0;  _epoch_known=0 ;; esac
_bootepoch=$((_now - _up))
# ...and refuse an IMPLAUSIBLE epoch too, not just an unreadable one. On a device
# that lost its RTC (or had the clock set backward across the reboot) _bootepoch
# comes out small or negative, and LAST boot's ts -- a real, large epoch -- then
# satisfies ">= -60" and reads as fresh. That is the precise scenario the
# freshness check was added for, so the check must not be the thing that misses
# it. 1000000000 = 2001-09-09; anything below it is not a real wall clock.
[ "$_bootepoch" -ge 1000000000 ] 2>/dev/null || _epoch_known=0
# 0 unless health.txt exists AND was stamped at or after this boot began.
_health_fresh() {
    [ "$_epoch_known" = 1 ] || return 1
    _hts=$(sed -n 's/^ts=//p' "$NMDIR/health.txt" 2>/dev/null)
    case "$_hts" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_hts" -ge "$_bootepoch" ]
}
# Read a key only from a fresh record; prints nothing at all otherwise, so a
# stale file behaves exactly like a missing one instead of like a verdict.
_health_get() {
    _health_fresh || return 0
    sed -n "s/^$1=//p" "$NMDIR/health.txt" 2>/dev/null
}

i=0
booted=0
while [ "$i" -lt 120 ]; do
    if [ "$(getprop sys.boot_completed)" = "1" ]; then booted=1; break; fi
    sleep 2
    i=$((i + 1))
done

# NB: unlike the old build we do NOT re-assert kernel_umount here — forcing that
# feature on breaks root for other modules on OP15. Hiding of the Suite's real
# mounts is handled by the manager's per-app-profile default-umount instead.

sleep 10
# Only re-arm when the boot really finished. Clearing the counter after the wait
# merely TIMED OUT disarms the bootloop guard on exactly the hanging boots it
# exists to catch, so it could never reach GUARD_MAX.
if [ "$booted" = "1" ]; then
    rm -f "$NMDIR/bootcount"
    nmlog "boot completed, guard counter reset"
else
    nmlog "boot_completed never set - leaving guard counter armed"
fi

# --- did ANY boot entry point run this boot? ----------------------------------
# metamount.sh (KSU/APatch metamodule hook) and post-fs-data.sh (Magisk) each
# stamp $NMDIR/mountpass.ts at the top of their run. Neither stamp means neither
# ran, and the case that produces is the one this check exists for: a KernelSU
# build WITHOUT metamodule support never invokes metamount.sh, and post-fs-data.sh
# hands over to it because $KSU is set. The module then does nothing at all, with
# no kmsg line, no boot.log entry, no incident.log and no card -- a failure the
# user cannot even report, because there is nothing to paste.
#
# Matched on the KERNEL BOOT ID, not on an epoch. Both entry points stamp before
# the RTC is applied, so their `date +%s` was a 1970 value and the old
# "stamp >= boot epoch" test failed on EVERY boot -- reporting "the mount pass
# never ran" on a device that had just injected 258 rules. Fail closed the same
# way: if boot_id is unreadable we say nothing rather than accuse a working manager.
_hookran=1
_bootid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if [ -n "$_bootid" ]; then
    [ "$(cat "$NMDIR/mountpass.ts" 2>/dev/null)" = "$_bootid" ] || _hookran=0
fi
if [ "$_hookran" = 0 ]; then
    nmlog "⛔ the mount pass NEVER RAN this boot — nothing was injected. On KernelSU this means the manager has no metamodule support (metamount.sh is never invoked); on Magisk it means post-fs-data.sh did not run."
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "reason=no boot entry point ran: $NMDIR/mountpass.ts is absent or stale"
        echo "ksu_env_seen_by_post_fs_data=see boot.log [post-fs-data] lines"
        echo "manager=$(ksud -V 2>/dev/null | head -1)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "note=NoMount is a METAMODULE. It needs a KernelSU/SukiSU/APatch build that supports metamodules, or Magisk. Update the manager."
    } > "$NMDIR/incident.log" 2>/dev/null
fi

# --- Ghost: populate the existence cloak's two tables ------------------------
# _ghost closes the syscalls that resolve a path and then act without consulting
# a hijacked filesystem op -- O_PATH handing back the path, getxattr handing back
# the SELinux label, the whole LOOKUP_DIRECTORY/ENOTDIR family, link() answering
# EXDEV, truncate/utimensat/chmod/chown answering EROFS, mkdirat answering
# EEXIST, and access(W_OK)/open(O_WRONLY|O_CREAT) answering EROFS where an absent
# path answers ENOENT. Its guards are DEAD CODE until both of its tables are
# populated: measured on OP15, a kernel built WITH the _ghost patches but with
# nothing feeding it leaked every one of them exactly as an unpatched kernel does.
#
# FORTY LINES OF SHELL USED TO LIVE HERE. They are now `nomount ghost sync` --
# see src/ghost.rs for the three things the move fixed (ENOENT told apart from
# EACCES, targets taken from the one rule parser instead of a sed that truncated
# any path containing " (", and one fork instead of one exec per path) and for
# the residual it does not fix.
#
# The important half is not the rewrite, it is WHO ELSE calls it: `nomount mount`
# and `nomount reload` now re-sync at the end of every pass. This block ran once
# per boot and nothing re-ran it, so tapping the WebUI's Reload button -- whose
# own help text is "Install/remove a module, tap Reload, no reboot" -- left the
# tables describing the PREVIOUS rule set. A path that went from injected-only to
# shadowing then answered stat=OK and chmod/listxattr=ENOENT at the same time,
# which is the self-contradiction this block always warned about producing.
#
# It still runs HERE, once, because this is the first point at which the hide
# list has been applied and uidhide.cache is warm -- the boot mount pass runs
# before either. It is inert and silent on a kernel without _ghost.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _gh=$(nmto 60 "$BIN" ghost sync 2>&1)
    _gh_rc=$?
    if [ "$_gh_rc" -eq 124 ]; then
        nmlog "⚠ ghost sync TIMED OUT after 60s — the existence oracles stay OPEN this boot"
    elif [ "$_gh_rc" -ne 0 ]; then
        nmlog "⚠ ghost sync FAILED (rc=$_gh_rc): $(printf '%s
' "$_gh" | tail -1)"
    elif [ -n "$_gh" ]; then
        nmlog "$(printf '%s
' "$_gh" | tail -1)"
    fi
    unset _gh _gh_rc
fi

# Re-assert /data/local/tmp's AOSP owner/mode/context -- see nm_fix_shell_tmp in
# lib.sh. The post-fs-data entry point runs the same pass earlier; this one
# repeats it because ksud and adbd keep staging files there for the whole of
# boot and can put the mode/owner back.
nm_fix_shell_tmp

# Re-assert the ksud multicall de-link after boot -- see nm_delink_ksud in lib.sh.
# metamount.sh does it at mount time; this is the belt to that brace, against a
# timing race where ksud finishes its install stage after the mount pass and
# re-creates the hardlink. (A clobbered ksud cannot be healed from a module
# service -- if ksud were broken this service would not run -- so only the split
# is re-asserted here.)
nm_delink_ksud service

# --- refresh the manager card with the settled state ---
# metamount.sh tags the card in post-fs-data, when the mount table is not final and
# health cannot be judged yet. Now that boot is complete both are knowable, so restate
# the card with the real mount count and the health-check verdict — that turns the
# module list into a status readout you can trust without opening the WebUI.
# (MODDIR/ABI/BIN/NM_BIN are set at the top of this script.)

# --- let bindhosts take the mountless path it already has ---
#
# bindhosts probes its environment and picks one of eleven operating modes. One
# of them, mode 0, exists precisely for a metamodule like this one -- its own
# comment reads "for nomount metamodule, just use mode 0. it performs injection
# rather than mounts". Mode 0's handler does nothing at all: it ships
# system/etc/hosts as an ordinary module file and lets the metamodule serve it.
#
# That detection never fires here. It needs BOTH of:
#
#     [ -L /data/adb/metamodule ]          <- present, points at meta-nomount
#     [ -d /data/adb/modules/nomount ]     <- absent, we install as meta-nomount
#
# so it fails on a hardcoded directory name while the symlink it already checks
# points straight at the real one. The result is not breakage -- bindhosts falls
# through to a bind mount and absorb takes that over -- but it is a mount created
# and then removed on every boot for no reason.
#
# mode_override.sh is bindhosts' own documented extension point, so this is not
# a patch to another module; it is answering the question bindhosts asked with
# the answer it was looking for.
#
# The override is written CONDITIONAL rather than as a bare `mode=0`. If NoMount
# is later removed or disabled, a hardcoded mode 0 would leave bindhosts serving
# its hosts file through a metamodule that is no longer there -- adblocking would
# stop silently, which is exactly the failure class the rest of this work exists
# to remove. Evaluating the condition at bindhosts' runtime means the override
# no-ops the moment we are gone and it picks its own mode again.
#
# Takes effect from the NEXT boot: bindhosts sorts before meta-nomount, so its
# post-fs-data has already run by the time this does.
_bh_dir=/data/adb/bindhosts
_bh_ovr="$_bh_dir/mode_override.sh"
# `-L /data/adb/metamodule` also gates out Magisk, where that symlink does not
# exist at all (see post-fs-data.sh): the override could only ever be inert
# there, and writing one anyway would promise a mode 0 that never arrives.
if [ -d "$_bh_dir" ] && [ -d /data/adb/modules/bindhosts ] &&
   [ ! -f /data/adb/modules/bindhosts/remove ] && [ -L /data/adb/metamodule ]; then
    # Absent, or already ours. `grep -q` alone answers the same for "no file"
    # and "somebody else's file", and this is bindhosts' documented user-facing
    # extension point -- truncating a hand-written override would be silent data
    # loss, and unrecoverable, since our marker would then be present and this
    # block would never look at it again.
    if [ ! -e "$_bh_ovr" ] || grep -q 'NoMount Suite' "$_bh_ovr" 2>/dev/null; then
        # Temp file then rename, the same discipline as the ksud de-link above.
        # Writing straight onto the target means a short write (ENOSPC, killed
        # shell) leaves a truncated file whose first line already carries the
        # marker -- permanently unrepairable, and a syntax error in whatever
        # sources it.
        cat > "$_bh_ovr.nm_new" <<'BHEOF'
# Written by the NoMount Suite. Safe to delete.
#
# bindhosts mode 0 = ship system/etc/hosts as a normal module file and let the
# metamodule serve it, with no mount of its own. bindhosts already prefers this
# when it detects a nomount metamodule; its check looks for
# /data/adb/modules/nomount and this Suite installs as meta-nomount, so it does
# not match. Resolve the metamodule symlink instead.
#
# Conditional on OUR metamodule being live, not merely on one existing: the
# sha256sums manifest is ours. Without that test a leftover copy of this file
# would force mode 0 under a different metamodule after NoMount was removed.
_nm=$(readlink -f /data/adb/metamodule 2>/dev/null)
if [ -n "$_nm" ] && [ -d "$_nm" ] && [ -f "$_nm/nomount.sha256sums" ] &&
   [ ! -f "$_nm/disable" ] && [ ! -f "$_nm/remove" ] &&
   [ ! -f /data/adb/nomount/disabled ]; then
    mode=0
fi
unset _nm
BHEOF
        _bh_rc=$?
        if [ "$_bh_rc" -eq 0 ] && mv -f "$_bh_ovr.nm_new" "$_bh_ovr" 2>/dev/null; then
            chmod 0644 "$_bh_ovr" 2>/dev/null
            nmlog "bindhosts: wrote mode_override.sh — it will use its mountless mode 0 from the next boot"
        else
            rm -f "$_bh_ovr.nm_new"
            nmlog "⚠ bindhosts: could not write mode_override.sh (rc=$_bh_rc) — it keeps its own mount mode"
        fi
    fi
fi
unset _bh_dir _bh_ovr _bh_rc

# --- pick up content modules wrote after the mount pass ---
# The mount pass runs at post-fs-data. Measured across 576 module payloads, 56%
# build their payload tree at RUNTIME rather than shipping it in the zip -- and
# a module's own service.sh runs at late_start, after that pass has already
# walked it. Anything written there was invisible for the whole session: the
# file existed in the module directory and no rule named it.
#
# Verified on an OP15 with a module writing one file per lifecycle stage: the
# post-fs-data file was served on the same boot, the service.sh and
# boot-completed.sh files were not, and a single `reload` served all three with
# nothing else disturbed. That is this call.
#
# reload is a gap-free delta (it applies only what changed, never a clear), so
# on the common case of nothing new it is a cheap no-op. It runs BEFORE absorb
# so absorb sees the finished rule set.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _rl_all=$(nmto 60 "$BIN" reload 2>&1)
    _rl_rc=$?
    _rl=$(printf '%s\n' "$_rl_all" | tail -1)
    if [ "$_rl_rc" -eq 124 ]; then
        nmlog "post-boot reload TIMED OUT after 60s - late module content may be unserved"
    elif [ "$_rl_rc" -ne 0 ]; then
        nmlog "⚠ post-boot reload FAILED (exit $_rl_rc) — content written by module service.sh is NOT served: $_rl"
    else
        nmlog "post-boot reload: $_rl"
    fi
fi

# --- absorb any bind mounts other modules made ---
# Module boot scripts have all run by now. Anything that bind-mounted its own
# content is visible in every app's mountinfo, which defeats the zero-mount
# posture no matter how mountless the Suite itself is. Re-serve each as an
# injection and drop the mount. No-op when nothing mounted anything.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    # Bounded. This is FOREGROUND and everything below it -- the whiteout
    # re-apply, the authoritative `uid apply`, the package watcher, the
    # check canary -- only runs once it returns. absorb now takes the
    # process-wide pass lock, so a concurrent WebUI reload can make it wait;
    # without a timeout here that wait would silently cost per-UID hiding for
    # the rest of the boot. 90s is well past a worst-case absorb (measured in
    # seconds) and still far short of stalling boot.
    # Capture the status BEFORE any pipe. `$?` after a command substitution that
    # contains a pipeline is the status of the LAST element -- `tail`, which
    # always succeeds -- so `_ab=$(timeout 90 ... | tail -1); [ $? -eq 124 ]`
    # could never be true and the timeout branch was dead code. Verified:
    # `x=$(sh -c "exit 124" | tail -1)` leaves $? at 0; without the pipe, 124.
    _ab_all=$(nmto 90 "$BIN" absorb 2>&1)
    _ab_rc=$?
    _ab=$(printf '%s\n' "$_ab_all" | tail -1)
    if [ "$_ab_rc" -eq 124 ]; then
        nmlog "absorb TIMED OUT after 90s - continuing boot"
    elif [ "$_ab_rc" -ne 0 ]; then
        # A non-zero, non-124 exit is a FAILED absorb: every mount it could not
        # take over stays in every app's mountinfo. The status was captured but
        # only 124 was acted on, so a plain failure was logged with its own
        # summary line -- written before absorb knew it would fail -- in exactly
        # the voice of a successful pass.
        nmlog "⚠ absorb FAILED (exit $_ab_rc) — foreign mounts may still be visible: $_ab"
    else
        nmlog "$_ab"
    fi
    # Second pass, later. Not every module binds by the time this runs: a
    # patched-APK module (ReVanced and friends, issue #14) waits for
    # sys.boot_completed, then for /sdcard, then polls `pm path` until
    # PackageManager answers, then sleeps before mounting its APK over the
    # installed one. That lands after the pass above on a slow boot, and a bind
    # that arrives after the only absorb pass stays mounted for the whole
    # session. Backgrounded so it cannot delay anything else here, and a plain
    # no-op when nothing new turned up.
    (
        sleep 45
        # Same reason as the late absorb pass below it: boot-completed.sh runs
        # after this script, and a module that writes its payload there lands
        # after the foreground reload. One more delta pass catches it.
        _rl2_all=$(nmto 60 "$BIN" reload 2>&1)
        _rl2_rc=$?
        if [ "$_rl2_rc" -eq 124 ]; then
            nmlog "late reload pass TIMED OUT after 60s"
        elif [ "$_rl2_rc" -ne 0 ]; then
            nmlog "⚠ late reload pass FAILED (exit $_rl2_rc): $(printf '%s\n' "$_rl2_all" | tail -1)"
        else
            nmlog "late reload pass: $(printf '%s\n' "$_rl2_all" | tail -1)"
        fi
        # Bounded and status-checked like the foreground pass. Backgrounded, so a
        # hang cannot delay boot -- but it CAN sit forever on the engine-wide pass
        # lock and hold it against uidwatch.sh, and a failed late pass reported by
        # its last line alone reads as a success. Status captured BEFORE any pipe.
        _ab2_all=$(nmto 90 "$BIN" absorb 2>&1)
        _ab2_rc=$?
        _ab2=$(printf '%s
' "$_ab2_all" | tail -1)
        if [ "$_ab2_rc" -eq 124 ]; then
            nmlog "late absorb pass TIMED OUT after 90s"
        elif [ "$_ab2_rc" -ne 0 ]; then
            nmlog "⚠ late absorb pass FAILED (exit $_ab2_rc): $_ab2"
        else
            nmlog "late absorb pass: $_ab2"
        fi
    ) &
fi

# --- re-apply persistent whiteouts ---
# Whiteouts live in kernel memory and are empty after every reboot; the list on
# disk is the durable record.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/whiteouts.txt" ]; then
    # Status BEFORE the pipe. `$(cmd | tail -1)` leaves $? as tail's, which always
    # succeeds -- the same trap documented for absorb above, still live here. A
    # failed whiteout apply means the stock paths the user asked to hide are
    # VISIBLE for the whole session, which is the one result that must not be
    # logged in the same voice as a success.
    _wo_all=$(nmto 30 "$BIN" whiteout apply 2>&1)
    _wo_rc=$?
    _wo=$(printf '%s
' "$_wo_all" | tail -1)
    if [ "$_wo_rc" -ne 0 ]; then
        nmlog "⚠ whiteout apply FAILED (exit $_wo_rc) — hidden paths are still VISIBLE: $_wo"
    else
        nmlog "$_wo"
    fi
fi

# --- re-apply the persistent per-app hide list (authoritative pass) ---
# Per-UID hiding lives in kernel memory and is empty after every reboot; the hide
# list on disk (package names / UIDs) is the durable record. The mount pass has
# already applied it from the cached appid mirror at post-fs-data, so apps are
# hidden from the moment the injections exist rather than from here — this later
# pass is the authoritative one: packages.list is now populated and app UIDs are
# stable, so it re-resolves, refreshes the mirror, and retires any appid an entry
# no longer maps to (appids get reused after an uninstall). Guard-gated.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/uidhide" ]; then
    _bl=$(nmto 60 "$BIN" uid apply 2>&1)
    if [ $? -eq 0 ]; then
        nmlog "hide list re-applied ($_bl)"
    else
        # A failed apply is the one thing here that must not pass quietly: it means
        # apps the user believes are hidden are not.
        nmlog "⚠ hide list apply FAILED ($_bl)"
    fi
fi

# --- watch the package map, so the hide list follows installs ---
# An entry saved for an app that wasn't installed yet used to sit inert until the
# next reboot — install the detector you meant to hide from and it saw everything
# until you rebooted. PackageManager rewrites packages.list on every install,
# uninstall and update, so watch its directory and re-apply.
#
# Deliberately NOT gated on the list being non-empty: hide your first app from the
# WebUI after boot and a list-gated watcher would not be running, leaving the gap
# open for the rest of the boot — the exact hole this closes. uidwatch.sh exits
# immediately when there is nothing to apply, so the idle cost is one blocked
# process. No event mask either: the mask letters differ between the busybox and
# toybox inotifyd, and an unknown letter makes inotifyd exit at startup, which
# would disable the watcher silently.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] \
   && command -v inotifyd >/dev/null 2>&1 && [ -f "$MODDIR/uidwatch.sh" ]; then
    inotifyd "$MODDIR/uidwatch.sh" /data/system >/dev/null 2>&1 &
    nmlog "hide-list package watcher started"
fi

# The missing `else`. Every block above is gated on [ -x "$BIN" ] and NONE of them
# had one, so a binary that is absent, not executable, or under an ABI directory
# this device does not have made absorb, the whiteout re-apply, the authoritative
# `uid apply`, the package watcher and the health canary ALL no-ops -- in silence,
# on a boot that otherwise completed. The card block below is gated the same way,
# so it would not even restate the post-fs-data text; the user simply sees their
# modules stop working. Say it once, where the WebUI already looks.
if [ ! -x "$BIN" ]; then
    nmlog "⛔ engine binary is missing or not executable ($BIN) — absorb, whiteouts, per-app hiding and the health canary were ALL skipped this boot"
fi

# --- one check pass: plan + device, cached for the WebUI and the card ----------
# `check` replaced `selfcheck` and `audit` (and `doctor`, `posture`, `plan`): one
# run, one report, both artifacts. It writes audit.json for the WebUI AND the
# health.txt fingerprint the card reads, so the two calls this block used to make
# would now measure the same device twice and cache the second answer over the
# first.
#
# The device half runs the per-UID self-consistency probe that the d_drop
# regression would have failed on the first boot: does a normal app see the same
# injected files as root? That probe can transiently disagree right after boot,
# before every app UID has launched and materialised its per-UID injection, so
# retry across a settle window and keep the *settled* answer — a boot-time blip
# must not stamp a scary "inconsistency" on the card. Only a disagreement that
# PERSISTS through the whole window is a real d_drop-style regression.
#
# `consistency` doubles as the settle signal for the detection oracles too, which
# is why the audit no longer needs a pass of its own AFTER the window: the run
# that reports a settled hide pass measured the oracles at that same settled
# moment. Non-fatal in every arm; surfaced on the card / WebUI.
#
# Cost note: one try here is heavier than the old `selfcheck` alone — the canary's
# su spawns plus a /proc walk for the oracles. The common case is now ONE run
# instead of two, and the retry path only engages when the probe actually
# disagrees. Bounded per call, like every other engine call on this path: a hung
# engine must not hold the rest of the boot pass (card refresh included) hostage,
# nor leave a stale health.txt to be read as if it were this boot's.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _try=0
    _arc=0
    while [ "$_try" -lt 6 ]; do
        nmto 60 "$BIN" check --write >/dev/null 2>&1
        _arc=$?
        # A run that timed out will time out again. Re-asking costs another 60s of
        # boot for the same non-answer, and the settle window exists to smooth a
        # transient DISAGREEMENT, not to re-ask a question that produced nothing.
        [ "$_arc" -eq 124 ] && break
        _cons=$(_health_get consistency)
        if ! _health_fresh; then
            # No record from THIS boot: the write failed, or the probe never
            # finished. Stop rather than spend 6 x 15s of boot on it, and let the
            # "unknown" state below carry the result.
            break
        fi
        # "unchecked" and its qualified forms (unchecked:probe-uid-hidden, when
        # shell itself is on the hide list) are not-a-verdict, not a failure.
        case "$_cons" in
            ok|unchecked*|"") break ;;
        esac
        _try=$((_try + 1))
        [ "$_try" -lt 6 ] || break
        sleep 15
    done
    if _health_fresh; then
        _hv=$(_health_get verdict)
        nmlog "check verdict=${_hv:-unknown} consistency=${_cons:-unknown} (settle tries=$_try)"
    else
        nmlog "⚠ check wrote no health record this boot — health is UNKNOWN, not healthy"
    fi
    # The cache ladder, unchanged in meaning. `check --write` writes audit.json
    # itself (0600, in the state dir) so nothing here has to know the format, and
    # exits 1 whenever a finding is open — the normal case for some setups, which
    # must not read as an error here.
    if [ "$_arc" -eq 0 ]; then
        nmlog "check cached — nothing open"
    elif [ "$_arc" -eq 124 ]; then
        # A TIMEOUT is not a verdict. `check --write` exits 1 when a finding is
        # open and 124 when timeout killed it, and the old test could not tell
        # them apart: it saw a non-empty audit.json -- LAST boot's -- and logged
        # it as this boot's result. The WebUI then painted a cached verdict, with
        # an age, for a run that never finished.
        rm -f "$NMDIR/audit.json"
        nmlog "⚠ check TIMED OUT after 60s — dropped the stale cache; the WebUI will show no verdict"
    elif [ -s "$NMDIR/audit.json" ]; then
        # Exit 1 with a cache present: it ran and found something. Normal and
        # actionable, unlike the two above.
        nmlog "check cached — one or more findings are open (see the Detection audit card)"
    else
        rm -f "$NMDIR/audit.json"
        nmlog "⚠ check did not complete — the WebUI will show no cached verdict"
    fi
    unset _arc
fi

if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    # One dump, both counts (see metamount.sh): two `nm list` runs returning the
    # same answer is two full netlink dumps of the whole rule table.
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    # EXCLUDE the (virtual dir) rows. `grep -c .` counts every line of the dump,
    # which on this device is 260 while `nomount check` and health.txt both
    # say 257 -- the difference being 3 directories the engine materialises, which
    # are not rules. The card is the surface most users read, so having it
    # disagree with every other number the Suite prints made a real discrepancy
    # indistinguishable from a bug. Measured on OP15: 260 lines, 3 virtual dirs.
    _rules=$(_nmcount -vc '(virtual dir)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    # Match on mountinfo FIELD 4, the mount's root within its own filesystem. A bind
    # out of a module reads "/adb/modules/<id>/..." there, because /data is its own
    # filesystem -- so the old `grep -c '/data/adb/modules'` matched nothing on any
    # device and the card reported "0 mounts" however many there really were.
    # (It also used `|| echo 0` after a grep that already prints 0 and exits 1 when
    # it does, appending a second line and making every later -gt test a bad number.)
    _mnt=$(awk '$4 ~ "/adb/modules/" {n++} END{print n+0}' /proc/self/mountinfo 2>/dev/null); _mnt=${_mnt:-0}
    # Distinguish "the plan is clean" from "the plan was never answered".
    # Parsing an EMPTY capture yields 0 errors / 0 warnings, so a timeout or a
    # crash used to render the card as "healthy" -- the one word it must not say
    # when it does not know. _docok=0 means unknown, and the card says so.
    #
    # `check --plan --json`, not the prose: the old sed matched a summary line
    # ("summary: N errors, M warnings") that no longer exists, so it captured
    # nothing on every boot and the card silently sat in the unknown arm. The
    # plan half reads no running process, which is what makes re-asking it here
    # cheap enough to do after the device pass above.
    _sum_get() {
        printf '%s' "$2" | sed -n 's/.*"summary":{\([^}]*\)}.*/\1/p' \
            | tr ',' '\n' | sed -n "s/^\"$1\"://p" | head -1
    }
    _doc=$(nmto 30 "$BIN" check --plan --json 2>/dev/null)
    _err=$(_sum_get fail "$_doc")
    _wrn=$(_sum_get warn "$_doc")
    case "$_err$_wrn" in
        ''|*[!0-9]*) _docok=0; _err=0; _wrn=0 ;;
        *) _docok=1 ;;
    esac
    unset _doc
    # runtime consistency canary trumps the plan half for card health: a
    # per-UID inconsistency is a live regression, not a plan hazard.
    # Same not-a-verdict rule as the canary loop, but read through _health_get so
    # a record left over from LAST boot cannot supply the answer. _hfresh keeps
    # "the canary said nothing bad" apart from "the canary never spoke" -- without
    # it, "" mapped to _consbad=0 and the ladder below fell through to "healthy"
    # off a file that was stale or absent.
    _health_fresh && _hfresh=1 || _hfresh=0
    _cons=$(_health_get consistency)
    case "$_cons" in
        ok|unchecked*|"") _consbad=0 ;;
        *) _consbad=1 ;;
    esac
    if [ "${_hookran:-1}" = 0 ]; then
        # Ahead of everything else: with no mount pass this boot, every other
        # number on this card describes a device that is serving nothing, and
        # naming a symptom ("0 rules") instead of the cause sends the reader
        # looking in the wrong place.
        _health="⛔ the mount pass never ran — see the Last incident card"
    elif [ "$_consbad" = 1 ]; then
        _health="⚠️ per-UID inconsistency — see the NoMount WebUI"
    elif [ "${_err:-0}" -gt 0 ]; then
        _health="⚠️ $_err error(s) — see the NoMount WebUI"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="$_wrn warning(s)"
    elif [ "${_docok:-0}" = 1 ] && [ "${_hfresh:-0}" = 1 ]; then
        _health="healthy"
    elif [ "${_docok:-0}" = 1 ]; then
        _health="health unknown — no health record this boot"
    else
        _health="health unknown — the plan check did not finish"
    fi
    # Distinguish a LEAK from a mount absorb leaves on purpose (a Zygisk/Xposed
    # hook bind). Counting them the same made the card read
    # "⚠ 1 module mount(s) … fully mountless" in one breath, which is both
    # alarming and self-contradictory, and gave the reader no way to tell an
    # expected mount from a real one.
    # Through _health_get too: a stale record's foreign count describes last
    # boot's mount table, and here it would override the live one we just read.
    _fgn=$(_health_get mounts_foreign)
    # health.rs now writes `unknown` when it could not read the mount table, so it
    # can stop rendering a failed read as a measurement of zero. Anything
    # non-numeric here means "the record does not know", which is the same case as
    # a stale/absent record: fall back to the count we just took live.
    case "$_fgn" in ''|*[!0-9]*) _fgn=$_mnt ;; esac
    if [ "${_fgn:-0}" -gt 0 ]; then
        _mstate="⚠ $_fgn module mount(s)"
        _tail="Prism VFS + RRO injection is mountless; $_fgn foreign mount(s) present"
    elif [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="$_mnt by design"
        # Two causes now, not one. `mounts_foreign` excludes a hook framework's
        # bind (absorb never takes those over) AND a my_* bind the Suite makes
        # itself (that is how my_* is served unless `my_hookless` is set), so
        # naming only the first described the wrong thing on any device with a
        # module shipping my_* content -- which is most OnePlus devices.
        _tail="mountless where it can be: Prism VFS + RRO, su via sucompat ($_mnt mount(s) left alone by design -- a hook framework's, or a my_* bind of ours)"
    else
        _mstate="0 mounts"
        _tail="fully mountless: Prism VFS + RRO, su via sucompat"
    fi
    # The manager's kernel_umount rides along on the card. It can hide nothing
    # the Suite serves -- injections are VFS redirects, so the kernel umount list
    # is empty -- and enabling it on this hardware once cost ~8 reboots. Put it
    # where the user already looks (the module description in their root
    # manager), not only in dmesg. "unknown" means ksud could not be asked, so
    # say nothing rather than accuse a switch of being on.
    # Freshness-gated as well: accusing a switch of being ON off LAST boot's
    # record is exactly the "say nothing rather than accuse" case above.
    _mu=$(_health_get manager_umount | head -1)
    if [ "$_mu" = "on" ]; then
        # shellcheck disable=SC1111  # typographic quotes on purpose: this names
        # the manager's own label inside a sentence shown to the user.
        _muc=" · ⚠️ turn OFF “kernel umount” in your root manager (it hides nothing here)"
        _mul=", ⚠ manager kernel_umount is ON — turn it off"
    else
        _muc=""
        _mul=""
    fi
    # ✅ next to "0 rules" is a contradiction, and this card is the last word on
    # the boot -- it overwrites whatever metamount.sh wrote. Mirror the same
    # guard, so a boot that served nothing cannot end on a green tick here after
    # metamount.sh refused to give it one.
    if [ "${_hookran:-1}" = 0 ]; then _mark="⛔"
    elif [ "${_rules:-0}" = 0 ]; then _mark="⚠️"
    else _mark="✅"; fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "[NoMount $_mark $_rules rules · $_rro RRO · $_mstate] $_health$_muc — $_tail" \
        >/dev/null 2>&1
    nmlog "card refreshed ($_rules rules, $_mstate, $_health$_mul)"
fi
exit 0
