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
cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null

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
        # Capture the status, NOT just the fact that we called it. `_engine_ran=1`
        # below means "the binary was executable and we invoked it", and the status
        # card then renders the green tick as long as SOME rules exist -- so a pass
        # that exited non-zero, or that `timeout` killed at 60s having injected 200
        # of 260 rules, ended the boot on "[NoMount ✅ 200 rules] fully mountless".
        # A partial injection reported as a complete one is the same false green
        # the rest of this file removes, one layer down.
        # `2>&1`, NOT `2>/dev/null`.
        #
        # The pass writes exactly one sentence that explains the commonest
        # new-user failure -- flashing this module on a kernel without
        # CONFIG_NOMOUNT -- and it writes it to STDERR:
        #
        #   "hookless NoMount engine not responding -- is the CONFIG_NOMOUNT
        #    kernel loaded?"   (mount.rs)
        #
        # Both boot paths then deleted it. What survived was a generic "mount pass
        # exited 1 (failed)", no incident.log (that is written only for a guard
        # trip or a missing binary), and a card saying the opposite of the truth.
        # The product wrote the right words and threw them away.
        #
        # `pass_lock` writes here too ("continuing unserialised rather than
        # stalling the boot"), and mount.rs is explicit that it must not be
        # silent: it names the one window in which an app sees the stock tree.
        _mout="$(nmto 60 "$BIN" mount 2>&1)"
        _mrc=$?
        [ -n "$_mout" ] && printf '%s\n' "$_mout"
        if [ "$_mrc" -ne 0 ]; then
            nmlog "⚠ mount pass exited $_mrc ($([ "$_mrc" -eq 124 ] && echo "TIMED OUT after 60s" || echo "failed")) — the injection set may be INCOMPLETE"
            # ...and the REASON, which is now in hand. One line, the engine's own
            # words, on the durable channel.
            _mwhy=$(printf '%s\n' "$_mout" | grep -m1 -i 'not responding\|Caused by\|^Error')
            [ -n "$_mwhy" ] && nmlog "  reason: $_mwhy"
            unset _mwhy
        else
            # A SUCCESSFUL pass left no durable record at all: `$_mout` went to
            # stdout (ksud's log, or nowhere) and boot.log never learned that 257
            # rules had been applied. The user asking "did it work?" had only the
            # card.
            _msum=$(printf '%s\n' "$_mout" | grep -m1 '^nomount(suite):')
            [ -n "$_msum" ] && nmlog "$_msum"
            unset _msum
        fi
        # An exit of 0 does NOT mean every rule landed: the pass deliberately
        # survives individual failures rather than failing the boot over them.
        # Without this, those were invisible -- no log line, and the status card
        # still green because SOME rules exist.
        case "$_mout" in
            *"nomount: WARNING"*)
                nmlog "$(printf '%s\n' "$_mout" | grep "nomount: WARNING" | head -1)"
                ;;
        esac
        unset _mout
        # Durable whiteouts, HERE rather than only in service.sh. A whiteout hides a
        # stock path that is itself the tell, and service.sh does not run it until
        # after sys.boot_completed plus a 10s settle -- so every such path was plainly
        # visible for the whole of boot, to anything that looked early. Nothing here
        # needs packages.list, so it belongs in the same pass as the injections.
        # service.sh still re-applies, which is idempotent and catches a late failure.
        if [ -s "$NMDIR/whiteouts.txt" ]; then
            nmto 30 "$BIN" whiteout apply 2>/dev/null
            _wrc=$?
            # Same reasoning as the mount pass: a whiteout hides a stock path that
            # is itself the tell, so a failed apply means that path is VISIBLE for
            # the whole boot. Never silent.
            [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc — hidden paths are still VISIBLE this boot"
        fi
        _pass_ran=1
        # The pass bails with "engine not responding" when the kernel has no
        # driver; that is the one failure worth its own card.
        case "$_mout" in *"engine not responding"*) _driver_ok=0 ;; esac
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
    # BOUNDED. This runs OUTSIDE the bootloop guard -- it is not gated on
    # `disabled` -- so an unbounded call here can hang post-fs-data on exactly the
    # device that has already self-disabled to recover. `nm`'s netlink recv has no
    # SO_RCVTIMEO, so "the engine accepted the message and never replied" is a
    # permanent block, not a slow one.
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    # grep -c on an empty stream prints 0 and exits 1, so guard the empty case.
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
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
        _sum=$(grep -F "$(printf '%s\t' "$mid")" "$NMDIR/modules.tsv" 2>/dev/null | head -1)
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
        _m=$(awk -v m="$mid" '$4 ~ "/adb/modules/" m "(/|$)" {n++} END{print n+0}' \
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
    # EXCLUDE the (virtual dir) AND the (whiteout) rows. `grep -c .` counts every
    # line of the dump, which on this device is 260 while `nomount check` and
    # health.txt both say 257 -- 3 of them being directories the engine
    # materialises, which are not rules. Whiteouts are the same mistake found
    # later: health.rs counts `rules` as INJECTS and reports `whiteouts`
    # separately, so a device with a debloat module installed had a card saying
    # 259 while every other surface said 257 (measured on an OP15, 2026-09-07,
    # with SAN installed). The card is what most users read; it must not be the
    # one number that disagrees. Hidden paths get their own field instead.
    _rules=$(_nmcount -v -c -E '\(virtual dir\)|\(whiteout\)')
    _wo=$(_nmcount -c '(whiteout)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    _mods=0
    for _x in $_vf $_ov; do _mods=$((_mods + 1)); done
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
