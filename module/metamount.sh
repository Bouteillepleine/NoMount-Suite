#!/system/bin/sh
# NoMount Suite metamodule hook (KSU/APatch, post-fs-data / metamodule stage).
# Runs the Suite mount pass (hookless mountless inject + RRO overlays), guarded by
# a bootloop counter, then signals ready. The Suite does NOT use SUSFS: RRO goes
# through the hookless engine and makes no mount to hide (see the note at the
# mount pass below). The only ksu_susfs reference here is a guard against another
# module's action button clobbering ksud.
# Root/su is NOT managed here (sucompat handles it, mountlessly).
MODDIR="${0%/*}"
NMLOG_TAG=metamount

# ONE notify, and it happens whatever else does.
#
# `ksud kernel notify-module-mounted` is the metamodule hook ksud WAITS on to
# learn that module mounting is finished, so a path that leaves without calling
# it turns whatever went wrong into a stalled boot sequence -- as the arms below
# put it, serving nothing is recoverable, not answering may not be.
#
# There were four explicit calls, one at each exit this script knows about. The
# exits it does NOT know about were uncovered: an arithmetic syntax error kills a
# non-interactive shell on the spot in both mksh and ash -- the exact class the
# bootcount sanitiser exists for -- and so does a `set -e`-style abort or a kill,
# and every one of those left ksud waiting. A trap covers all of them.
#
# Defined here rather than in lib.sh because the very first caller is the arm
# that runs when lib.sh could not be sourced. Idempotent, so the trap firing
# after an explicit call costs nothing.
_nm_notified=0
nm_notify_mounted() {
    [ "$_nm_notified" = 1 ] && return 0
    _nm_notified=1
    ksud kernel notify-module-mounted 2>/dev/null
    return 0
}
trap nm_notify_mounted EXIT
# nmlog / nmto / nm_set_bin / nm_fix_shell_tmp / nm_delink_ksud, and the umask.
# GUARDED: a partial extraction that dropped lib.sh must not leave this pass
# running with every helper undefined -- it says so on the one channel alive this
# early and stops, which is the same treatment a missing engine binary gets below.
# NMDIR is not set yet, so the incident line goes to kmsg alone.
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR — NOTHING was injected this boot; re-flash the zip" > /dev/kmsg 2>/dev/null
    # SIGNAL READY ANYWAY, exactly as the flock back-off below does. This is the
    # METAMODULE hook: ksud waits on it to say module mounting is finished, so an
    # early exit that skips the notify turns a missing file into a stalled boot
    # sequence -- a far worse failure than the one being reported. Serving nothing
    # is recoverable; not answering may not be.
    nm_notify_mounted
    exit 1
}
# 0700: spoof.conf/blocklist are read as root at boot, so anything able to write
# here gets root. The dir was being created under the boot umask (0777).
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"
# The mode/label repair every boot entry point owes the state directory -- see
# nm_state_dir_repair in lib.sh, which is where it lives now so the Magisk path
# gets it too.
nm_state_dir_repair

# --- durable boot log ---------------------------------------------------------
# Every boot diagnostic below used to go ONLY to /dev/kmsg. On this hardware the
# ring is flooded by WMI roam-stats spam within minutes of boot, so by the time
# anyone looks `dmesg | grep -i nomount` comes back empty -- which made the
# loudest signals the Suite has (running WITHOUT a single-run guard, hide list
# apply FAILED, absorb TIMED OUT) unrecoverable in practice. Tee the same lines
# to a file; kmsg stays, because it is the only channel alive early enough to
# survive a boot that never reaches /data.
# $BOOTLOG comes from lib.sh; the ROTATION is here rather than there because this
# is the boot entry point for KSU/APatch and so runs exactly once per boot, while
# service.sh and uidwatch.sh must not rotate at all. The chmod is for a file an
# older build left wide: `tail > $BOOTLOG.tmp` creates the temp under whatever
# umask is in force and `mv` carries that mode onto the log.
nm_boot_log_rotate

# uidwatch.sh's handler lock lives in the state directory now rather than in
# /dev (see the note there). /dev is a tmpfs and cleared every boot, which the
# old path got for free and this one has to be given: a handler SIGKILLed by the
# low-memory killer late in a session would otherwise leave a lock that outlives
# the reboot, and the first package change of the next boot would be dropped
# while the 180s mtime reaper waits. This is the boot entry point, so it runs
# exactly once and before uidwatch.sh can be registered.
rm -f "$NMDIR/.uidwatch.lock" 2>/dev/null

# ...and a stash uninstall.sh left behind. It is consumed by customize.sh at
# install time, so anything still here at boot belongs to an install that never
# finished (an integrity abort, a metamodule conflict, a killed installer). It
# holds `uidhide` -- the list of apps being hidden from -- so leaving it to rot
# under a name derived from ours is exactly what uninstall.sh's own header says
# must not happen.
nm_consume_stash

# --- "a boot entry point ran this boot" stamp ---------------------------------
# On a KernelSU build WITHOUT metamodule support this file is never invoked, and
# post-fs-data.sh exits immediately because $KSU is set -- so the module produced
# no kmsg line, no boot.log entry, no incident.log and no card. A completely
# silent no-op is the worst failure this project can have, because there is
# nothing for the user to report. Stamp the epoch here, BEFORE the bootloop guard
# (a guard trip is still a boot where the hook ran), and let service.sh say so
# when the stamp is missing. post-fs-data.sh writes the same file on the Magisk
# path, so the reader needs no manager detection.
# The stamp is the KERNEL BOOT ID, not a timestamp. Both entry points run at
# post-fs-data, before the RTC is applied, so `date +%s` here returns a 1970
# value that no later epoch comparison can ever accept -- which made this check
# accuse a perfectly working manager on every single boot. boot_id is unique per
# boot and immune to the clock.
# CHECKED. An unwritable $NMDIR makes this a no-op, and the only reader --
# service.sh's _hookran test -- reads a missing stamp as "no boot entry point
# ran", writes an incident report accusing a perfectly good manager ("Update the
# manager.") and paints "⛔ mount pass never ran" on the card. Say which it was.
cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null \
    || nmlog "⚠ could not stamp mountpass.ts — service.sh will report that no boot entry point ran"

# nmlog() and nmto() are lib.sh's -- see the note there on why they are shared
# rather than pasted, and on what a missing `timeout` costs.

# Single-run guard. Was a noclobber file in /dev: world-writable (boot umask),
# named after the project, and "held" by mere existence -- so anything able to
# create that path pre-empted the whole mount pass. flock releases on exit and
# lives in the 0700 state dir.
LOCK="$NMDIR/.mount.lock"
# PROBE THE FILE BEFORE `exec` TOUCHES IT.
#
# `exec` is a POSIX special built-in, so a redirection error on one EXITS a
# non-interactive shell -- and the `2>/dev/null` below, which is there for a
# different and good reason, throws the message away with it. So an unwritable
# $NMDIR (a full or read-only /data, a label that refuses creation, the `mkdir -p`
# above having failed) killed this script right here: no nmlog line, no
# incident.log, and -- the part that matters -- no `ksud kernel
# notify-module-mounted`. That call is the EXIT trap's now (see the top of this
# file), so every exit answers ksud, including the ones no arm here anticipates.
#
# The subshell is what makes this testable at all: a redirection failure on a
# special built-in exits the SUBSHELL, and `if !` reads its status. Same idiom
# uidwatch.sh uses for its own handler lock. Append, never truncate -- the file
# carries nothing but the flock.
#
# Refusing the boot pass, rather than running it unguarded, is deliberate: with
# $NMDIR unwritable the bootcount cannot be written either, so the bootloop guard
# is dead and a pass that wedges the device has no self-recovery.
if ! ( : >> "$LOCK" ) 2>/dev/null; then
    nmlog "⛔ cannot create $LOCK — $NMDIR is not writable, so the bootloop guard cannot arm; NOTHING was injected this boot"
    exit 1
fi
# Silence stderr for the redirection ONLY. Writing `exec 9>"$LOCK" 2>/dev/null`
# applies BOTH redirections to the shell permanently, so every diagnostic any
# later command wrote to stderr -- for the whole rest of the boot pass -- went to
# /dev/null. Save it on fd 8, silence, redirect, restore.
exec 8>&2
exec 9>"$LOCK" 2>/dev/null
exec 2>&8 8>&-
# umask 077 above already gives 0600; keep the chmod for a lock file an older
# build left behind wide.
chmod 0600 "$LOCK" 2>/dev/null
# Three outcomes, not two. `flock -n 9 || exit 0` conflated the last with the
# first: it reads ANY failure as "another pass already holds the lock" and
# returns silently having injected nothing.
#
# mksh (/system/bin/sh) marks a shell-opened fd >= 3 close-on-exec, so an
# external flock never receives fd 9 and fails EBADF no matter what. KSU runs
# module scripts under its bundled busybox ash, where the fd IS inherited and
# the guard works -- but anything invoking this script with /system/bin/sh gets
# a flock that CANNOT succeed, and the silent exit made that indistinguishable
# from a healthy second instance backing off.
#
# The probe asks an EXTERNAL process to look at its own fd table, which is the
# property flock depends on and needs no knowledge of which shell is running --
# `cmd >&9` would not do, because the parent performs that redirection and always
# succeeds. Verified on an OP11 to predict flock's outcome in both shells. An fd
# an external binary cannot see takes the same
# warn-and-continue path as a missing flock: no single-run guard, but said out
# loud, which is the documented behaviour for that case.
if ! command -v flock >/dev/null 2>&1; then
    nmlog "flock unavailable — mount pass running WITHOUT a single-run guard"
elif ! ls /proc/self/fd/9 >/dev/null 2>&1; then
    nmlog "fd 9 is close-on-exec in this shell, so flock cannot use it — mount pass running WITHOUT a single-run guard"
else
    flock -n 9 || exit 0
fi

# ABI / BIN / NM_BIN, with the empty-getprop fallback -- see nm_set_bin in lib.sh.
nm_set_bin
# Did the engine actually run this boot? The status card at the bottom is written
# UNCONDITIONALLY, so a missing/non-executable binary used to leave it reading
# "[NoMount ✅ 0 rules · 0 RRO · 0 modules] fully mountless" -- a green tick on a
# boot that injected nothing. Worse: boot then completes, service.sh clears
# bootcount, and the bootloop guard is re-armed by a pass that never happened.
_pass_ran=0
# ...and whether the KERNEL DRIVER answered. These are two different things and
# the card conflated them: "engine" means the kernel half everywhere the user can
# read it -- the README, the WebUI, customize.sh -- while `_engine_ran` only ever
# meant "our binary was executable and we invoked it". So on a kernel with no
# NoMount driver the card said "engine ran but injected nothing", which is the
# opposite of the truth and sends the reader hunting for a module problem.
_driver_ok=1

# Self-heal executable bits: some installers (and non-recovery ksud extraction)
# don't preserve +x. Without it on nm the whole pass aborts before it can inject.
chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

# The ksud multicall de-link; see nm_delink_ksud in lib.sh for what it protects
# against and why it runs once per boot. service.sh re-asserts it after boot.
nm_delink_ksud "susfs-action guard"

# --- bootloop guard ---
# NB: everything this script still does at post-fs-data runs INSIDE this guard
# (below), not before it. Anything placed above it is something `disabled` never
# suppresses and the counter cannot protect against -- it would keep running
# every boot after the guard had already tripped, leaving a user bootlooping
# with no self-recovery path.
# One implementation of the bootloop guard, in lib.sh. This entry point and
# post-fs-data.sh each used to carry their own ~55-line copy.
if nm_guard_bump "ksu/apatch metamount path"; then
    # Restore /data/local/tmp's AOSP owner/mode/context -- see nm_fix_shell_tmp in
    # lib.sh. Guard-gated, so a tripped counter or a manual `disabled` stops it
    # like everything else; service.sh re-asserts it after boot, because ksud and
    # adbd keep staging files there for the whole of boot.
    nm_fix_shell_tmp

    if [ -x "$BIN" ]; then
        # The bounded pass, its status ladder, the `nomount: WARNING` grep and the
        # durable-whiteout re-apply are all nm_mount_pass in lib.sh now. This
        # block and post-fs-data.sh's were byte-identical for 24 code lines and
        # had already drifted once; see the note on the function for what it sets.
        # It gives us _mrc, _pass_ran and _driver_ok, all read by the card below.
        nm_mount_pass
    else
        # The missing `else`. Without it a binary that is absent, not executable,
        # or sitting under an ABI directory this device does not have produced a
        # completely silent boot: nothing on kmsg, nothing on disk, and a green
        # card. Record it the same way a guard trip is recorded, because from the
        # user's side the symptom is identical -- their modules stopped working --
        # and incident.log is where the WebUI already looks for the reason.
        nm_incident_missing_binary "ksu/apatch metamount path"
    fi
fi

# --- hiding ---
# Nothing to hide: the Suite is now FULLY MOUNTLESS. Hookless VFS injection covers
# regular files AND RRO overlay APKs (injected into /product/overlay etc.; OMS +
# idmap2 pick them up at the system_server scan, which runs after this post-fs-data
# pass). su is sucompat (mountless). There is no overlayfs mount and no work tmpfs,
# so a mount scanner sees only stock mounts — nothing to hide, no SUSFS, no umount.

# --- tag managed modules in the manager with how the Suite serves them ---
if command -v ksud >/dev/null 2>&1; then
    # ONE dump of the rule table, reused for every module below and for the
    # Suite's own card. This used to run `nm list` inside the per-module loop
    # plus twice more afterwards -- 16 full netlink dumps of ~260 rules during
    # post-fs-data on a 14-module device, all returning the same answer. The
    # engine's own directory scan was optimised precisely because this stage sits
    # under the OPlus boot watchdog; spending it again here made no sense.
    # The dump, its status and the three counts are nm_rule_counts in lib.sh --
    # service.sh carried the identical five lines and the identical prose about
    # which rows are excluded. Sets _NMLIST/_nmlrc/_rules/_wo/_rro and _nmcount().
    nm_rule_counts
    _vf=""; _ov=""
    # Skipped when the guard has tripped. Nothing is being served in that state,
    # so every badge below would read "0 served" -- go straight to the Suite's own
    # card, which is the surface that has to say what happened.
    if [ -e "$NMDIR/disabled" ]; then
        nmlog "guard is tripped - skipping per-module tagging (nothing is served)"
    else
    for d in /data/adb/modules/*/; do
        [ -d "$d" ] || continue
        mid=$(basename "$d")
        { [ "$mid" = "meta-nomount" ] || [ "$mid" = "kernelnosu" ]; } && continue
        { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && continue
        # WHAT THIS MODULE CONTRIBUTES, FROM THE PASS THAT DECIDED IT.
        #
        # This used to walk every enabled module's tree here: each top-level
        # directory tested against a VERBATIM COPY of NON_PARTITION_ROOTS from
        # src/mount.rs, then two bounded `find`s to tell overlay from vfs. Two
        # finds per module per boot, at post-fs-data, under the OPlus watchdog --
        # and the third copy of a list that had already drifted twice (this one
        # was missing `data_mirror` and `d`, and excluded `my_*` for a year after
        # the Suite started serving it).
        #
        # The mount pass above already resolved all of it and wrote it down. The
        # live rule list cannot substitute: a whiteout rule names no module, so a
        # DEBLOAT module -- which is nothing but whiteouts -- would go unbadged,
        # which is the bug this loop was fixed for in the first place.
        # ANCHORED on field 1. `grep -F "$mid<TAB>"` matches anywhere in the line,
        # so module id `bar` matched the row of `foo-bar` and `head -1` picked
        # whichever sorted first -- badging one module with another's mechanism
        # and counting it in the wrong _vf/_ov bucket. The file is
        # id<TAB>entries<TAB>overlay<TAB>vfs (src/mount.rs), so compare the field.
        _sum=$(awk -F'\t' -v m="$mid" '$1==m{print;exit}' "$NMDIR/modules.tsv" 2>/dev/null)
        [ -z "$_sum" ] && continue
        _o=$(printf '%s' "$_sum" | cut -f3)
        _v=$(printf '%s' "$_sum" | cut -f4)
        if [ "$_o" = 1 ] && [ "$_v" = 1 ]; then _t="vfs + overlay"; _ov="$_ov $mid";
        elif [ "$_o" = 1 ]; then _t="overlay"; _ov="$_ov $mid";
        else _t="vfs"; _vf="$_vf $mid"; fi
        # How many rules this module actually got, and whether it owns any mount. The
        # rule count is the honest measure of "is this module being served" — a module
        # can be enabled and still contribute nothing. A non-zero mount count is the only
        # thing that breaks the zero-mount posture, so it is called out per module.
        _n=$(_nmcount -F "/data/adb/modules/$mid/")
        # Field 4 = the mount's root within its filesystem, so a module bind reads
        # "/adb/modules/<id>/...", never "/data/adb/modules/...". The old pattern
        # matched nothing, so every module was badged "mountless" regardless.
        # A STRING compare, not a regex: the id was interpolated into the pattern,
        # so a `.` in a module id matched any character and over-counted.
        _m=$(awk -v p="/adb/modules/$mid" '$4==p || index($4, p "/")==1 {n++} END{print n+0}' \
             /proc/self/mountinfo 2>/dev/null); _m=${_m:-0}
        _badge="$_t · $_n served"
        [ "${_m:-0}" -gt 0 ] && _badge="$_badge · ⚠ $_m mount(s)"
        _orig=$(sed -n 's/^description=//p' "$d/module.prop" | head -1)
        KSU_MODULE="$mid" ksud module config set --temp override.description \
            "[NoMount · $_badge] $_orig" >/dev/null 2>&1
    done
    fi

    # The Suite's own card doubles as the at-a-glance status readout, so put the live
    # numbers there rather than restating the tagline the module.prop already carries.
    #
    # ONE LINE, and short enough to be read whole. The manager truncates: measured
    # on an OP15, the old text ran 200+ characters and the card ended
    # "...or a my_* bind of ou…", so the last thing it said was cut off mid-word.
    # A status readout nobody can finish reading is not one. Everything that used
    # to be restated here -- the architecture tagline, the per-mechanism module
    # lists -- is already in module.prop, on the per-module badges, or in the
    # WebUI, and none of it changes between boots.
    #
    # _rules / _wo / _rro came from nm_rule_counts above, which also documents
    # why the (virtual dir) and (whiteout) rows are excluded. Hidden paths get
    # their own field below.
    _mods=0
    # `set -f` around the split: $_vf/$_ov are space-joined module ids, and
    # without it a module literally named `*` would glob-expand against the cwd
    # and be counted many times. Same idiom uidscan.sh uses for $INV.
    set -f
    for _x in $_vf $_ov; do _mods=$((_mods + 1)); done
    set +f
    [ "${_wo:-0}" -gt 0 ] 2>/dev/null && _wof=" · $_wo hidden" || _wof=""
    if [ -e "$NMDIR/disabled" ]; then
        _desc="⛔ disabled — bootloop guard tripped, open the WebUI"
    elif [ "${_driver_ok:-1}" = 0 ]; then
        # The commonest new-user mistake, named as itself. Everything else on this
        # card would describe a device that is serving nothing, and "0 rules" is a
        # symptom, not the cause.
        _desc="⛔ your kernel has no NoMount driver — flash a NoMount kernel, then reboot"
    elif [ "$_pass_ran" = 0 ]; then
        # This block is NOT gated on [ -x "$BIN" ], so it used to render the green
        # card even on the boot where the engine never ran. It is the only surface
        # most users ever read; it must not claim a posture nothing established.
        _desc="⛔ the Suite could not start this boot — open the WebUI"
    elif [ "${_mrc:-0}" -ne 0 ]; then
        # THE PASS ITSELF FAILED. `_pass_ran=1` is set the moment the pass is
        # invoked, so the ladder had no arm between "could not start" and
        # "0 rules": a pass that exited non-zero, or that `timeout` killed at 60s
        # having injected 200 of 260 rules, still ended the boot on
        # "✅ 200 rules · mountless". Two live producers, both reachable -- a zip
        # that lost bin/<abi>/nm (nomount shells out to it), and a partial
        # injection. `_mrc` is unset when the guard tripped or the binary was
        # missing, and both of those arms fire above this one, so :-0 is safe.
        _desc="⚠️ the mount pass FAILED (exit $_mrc) — open the WebUI"
    elif [ "${_nmlrc:-0}" -ne 0 ]; then
        # The pass worked and the DUMP did not. `nm list` is bounded at 15s and
        # its netlink recv has no SO_RCVTIMEO, so a permanent block is the
        # anticipated case -- and it leaves _NMLIST empty, i.e. _rules=0, i.e.
        # the "no module had files to serve" sentence on a boot that injected 257
        # rules. Say which of the two we actually failed to do.
        _desc="✅ served, but the rule table could not be read this boot"
    elif [ "${_rules:-0}" = 0 ]; then
        # ✅ next to "0 rules" is a contradiction the reader has to catch for
        # themselves. The engine ran, so this is not ⛔ — but it served nothing,
        # and a green tick on a boot that injected nothing is the same false
        # green, one branch further down.
        _desc="⚠️ ran, but no module had files to serve — open the WebUI"
    else
        _desc="✅ $_rules rules · $_rro RRO$_wof · $_mods modules · mountless"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description "$_desc" >/dev/null 2>&1
fi

exit 0
