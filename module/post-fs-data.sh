#!/system/bin/sh
# Magisk fallback (no metamodule hook). KSU/APatch use metamount.sh instead.
#
# The KSU/APATCH exit moved DOWN, past the log setup. It used to be line 3, before
# nmlog or $BOOTLOG existed, so on a KernelSU build without metamodule support --
# where metamount.sh is never invoked at all -- the whole module was a silent
# no-op: nothing on kmsg, nothing in boot.log, no incident.log, no card, nothing
# for the user to report. Now this path says out loud that it is handing over, and
# service.sh reports it when the handover led nowhere (see the mountpass.ts stamp).
MODDIR="${0%/*}"
NMLOG_TAG=post-fs-data
# nmlog / nmto / nm_set_bin / nm_fix_shell_tmp / nm_delink_ksud, and the umask.
#
# This block used to be pasted here rather than sourced, and said so: "a `.` of a
# file that a partial install did not extract would leave every nmlog call
# undefined for the rest of the pass". That hazard is real and is why the source
# is GUARDED -- a missing lib.sh is a loud, recorded stop rather than a shell full
# of undefined functions. What the duplication actually cost was drift: 72 of this
# file's 130 code lines were metamount.sh's, and the one script that did NOT get a
# copy of `nmto` was uidwatch.sh, which runs on every app install.
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR — NOTHING was injected this boot; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"

# --- durable boot log ---------------------------------------------------------
# Same reasoning as metamount.sh: /dev/kmsg alone is not recoverable on a device
# whose ring buffer is flooded within minutes of boot. $BOOTLOG is lib.sh's; the
# rotation is here because this is the Magisk boot entry point and so runs once.
nm_boot_log_rotate

# Same two sweeps metamount.sh does, for the Magisk path -- this is that path's
# boot entry point. Done BEFORE the KSU/APatch handover below, because on those
# managers metamount.sh has already run and both calls are then no-ops, while on
# Magisk this is the only place either happens. See the notes in metamount.sh.
rm -f "$NMDIR/.uidwatch.lock" 2>/dev/null
rm -rf /data/adb/nomount.bak 2>/dev/null
# The handover, now that there is somewhere to record it. metamount.sh is the
# metamodule hook and does the whole pass on these managers -- but ONLY if the
# manager supports metamodules. If it does not, nothing else runs and the stamp
# metamount.sh writes never appears; service.sh checks for exactly that.
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    nmlog "KSU/APatch detected — the metamodule hook (metamount.sh) owns this boot"
    exit 0
fi

# Magisk path: THIS script is the mount pass, so it writes the same stamp
# metamount.sh does. service.sh then needs no manager detection to tell "a boot
# entry point ran" from "nothing ran at all".
# The stamp is the KERNEL BOOT ID, not a timestamp. Both entry points run at
# post-fs-data, before the RTC is applied, so `date +%s` here returns a 1970
# value that no later epoch comparison can ever accept -- which made this check
# accuse a perfectly working manager on every single boot. boot_id is unique per
# boot and immune to the clock.
cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null

# The state-directory mode/label repair -- see nm_state_dir_repair in lib.sh.
# BELOW the KSU/APatch handover on purpose: metamount.sh is the boot entry point
# on those managers and has already run it, so doing it again here would be a
# second recursive chcon at post-fs-data for nothing. On Magisk this is the only
# place it happens, and until it moved into lib.sh it did not happen at all --
# $NMDIR kept whatever mode and label an older build had left, for the life of
# the install.
nm_state_dir_repair

# nmto() is lib.sh's -- see the note there on what a missing `timeout` costs.

# ABI / BIN / NM_BIN, with the empty-getprop fallback -- see nm_set_bin in lib.sh.
nm_set_bin
# Self-heal executable bits: some installers don't preserve +x, and without it on
# nm the whole pass aborts before it can inject. metamount.sh has always done
# this; the Magisk path was a degraded twin that did not.
chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

# NB: the pre-zygote absorb pass used to sit HERE, above the guard. It is now in
# the guard's else arm, after the mount pass -- see the block down there for both
# reasons it had to move.

# --- bootloop guard ---
# Everything this script still does at post-fs-data runs INSIDE the guard
# (below), not before it -- same reasoning as metamount.sh: `disabled` has to
# suppress all of it, or the counter cannot protect against whatever wedged the
# boot.
GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
# Sanitize before the arithmetic (see metamount.sh): a bootcount corrupted to
# something like "3 3" makes $((COUNT + 1)) a FATAL arithmetic-syntax error in
# both mksh and ash, so the shell exits on the spot, the counter is never
# rewritten, and the module is a silent no-op on every boot from then on.
case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
COUNT=$((COUNT + 1))
echo "$COUNT" > "$NMDIR/bootcount"

if [ -f "$NMDIR/disabled" ]; then
    # Say so. metamount.sh logs this on the KSU path and this arm was a bare `:`,
    # so a Magisk user whose guard had tripped got nothing at the one stage that
    # knows why nothing is being injected -- and boot.log is the only record this
    # path has. service.sh reports it later; that is not a reason to be silent
    # here, where the decision is actually made.
    nmlog "disabled, skipping the mount pass"
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then
    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
    : > "$NMDIR/disabled"
    # Record WHY, like metamount.sh does. A trip on this path used to leave only
    # an empty `disabled` file, so a Magisk user got the self-recovery but none
    # of the evidence -- and the WebUI's incident card stayed blank.
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX (magisk post-fs-data path)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
        nm_incident_tombstone
    } > "$NMDIR/incident.log" 2>/dev/null
else
    # Restore /data/local/tmp's AOSP owner/mode/context -- see nm_fix_shell_tmp in
    # lib.sh. Same stage and same call as the KSU/APatch metamount hook, for the
    # Magisk path; service.sh re-asserts it after boot.
    nm_fix_shell_tmp
    if [ -x "$BIN" ]; then
        # Bounded, like metamount.sh. A hung mount pass here is a HANG, not a
        # crash, so the bootloop counter never reaches GUARD_MAX and the device
        # never self-recovers -- which makes the timeout matter more on this path
        # than on the KSU one, not less.
        #
        # And the STATUS, not just the fact that we called it: a pass that exited
        # non-zero, or that `timeout` killed at 60s having injected part of the
        # rule set, used to leave no trace anywhere. On this path there is no
        # status card to contradict, which makes boot.log the only record there is.
        _mout="$(nmto 60 "$BIN" mount 2>/dev/null)"
        _mrc=$?
        [ -n "$_mout" ] && printf '%s\n' "$_mout"
        [ "$_mrc" -ne 0 ] && nmlog "⚠ mount pass exited $_mrc — the injection set may be INCOMPLETE"
        # An exit of 0 does NOT mean every rule landed: the pass deliberately
        # survives individual failures rather than failing the boot over them, and
        # prints `nomount: WARNING ...` when it does. mount.rs emits that marker
        # for a boot script to grep -- its comment says so in as many words
        # ("metamount.sh greps for this marker") -- and only metamount.sh was
        # grepping it. On this path the pass's stdout was not even read, so a
        # partial injection ended the boot with a zero exit and nothing in
        # boot.log, which is the one channel this path has.
        case "$_mout" in
            *"nomount: WARNING"*)
                nmlog "$(printf '%s\n' "$_mout" | grep "nomount: WARNING" | head -1)"
                ;;
        esac
        unset _mout
        # Durable whiteouts in the same pass as the injections, for the same
        # reason as metamount.sh: a whiteout hides a stock path that is itself the
        # tell, and there is no service.sh re-apply early enough to cover boot.
        if [ -s "$NMDIR/whiteouts.txt" ]; then
            nmto 30 "$BIN" whiteout apply 2>/dev/null
            _wrc=$?
            [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc — hidden paths are still VISIBLE this boot"
        fi

        # --- pre-zygote absorb (my_* only, trial-gated) ------------------------
        # MAGISK ONLY. KSU/APatch have already exited above and run this from
        # post-mount.sh instead, which is strictly better: it fires after EVERY
        # module's post-fs-data.sh. Magisk has no post-mount stage, so
        # post-fs-data is the last hook before zygote there, and a module whose
        # own post-fs-data.sh runs after ours will still be missed. Measured shape
        # of that miss, on KSU before the stage moved: "nothing mounted over the
        # ROM (posture clean)" while 84 mounts went up afterwards.
        #
        # A module that binds its own content over a my_* path leaves that mount
        # in every app's mountinfo, naming /data/adb/modules -- the loudest root
        # signal there is, and the one thing the mountless posture exists to deny.
        # The runtime pass in service.sh cannot take those over: re-asserting a
        # my_* rule on a live system has rebooted a device (OP11, Suite v1.3.22,
        # engine v14 -- four rules in a burst, clean sys.boot.reason, no
        # tombstone), so it defers them here and says so. Here there is no live
        # system to lose.
        #
        # Gated on the my_hookless TRIAL marker, because taking these over means
        # serving my_* by injection, and a leaf my_* inject may trip zygote's FD
        # allowlist at forkSystemServer. Without the marker this does nothing.
        #
        # IT LIVES HERE, INSIDE THE GUARD AND AFTER THE MOUNT PASS, for two
        # reasons -- it used to sit above both:
        #
        #  1. The counter. metamount.sh states the rule this file has to obey
        #     too: "Anything placed above [the guard] is something `disabled`
        #     never suppresses and the counter cannot protect against." Above the
        #     `echo "$COUNT" > bootcount` line, a boot that DIED inside this
        #     absorb -- which is the exact documented failure of a my_* re-assert
        #     -- never advanced the counter, so GUARD_MAX was unreachable and the
        #     device looped with no self-recovery. The KSU path never had this:
        #     metamount.sh increments first and post-mount.sh runs later.
        #  2. The order. On KSU the sequence is mount pass (metamount.sh) THEN
        #     early absorb (post-mount.sh). Running absorb FIRST here inverted it:
        #     the `nm clear` that opens the mount pass dropped every rule absorb
        #     had just created, and run_mount only re-serves the absorbed record's
        #     APK entries (is_app_apk), so a non-APK takeover was recorded, wiped,
        #     and not re-served until service.sh's pass -- by which time its mount
        #     is gone and there is nothing left to absorb, leaving that path on the
        #     stock file for the whole boot. Same order as KSU now.
        if [ -f "$NMDIR/my_hookless" ] || [ "$NM_MY_HOOKLESS" = 1 ]; then
            _ea=$(nmto 60 "$BIN" absorb --early 2>&1)
            # Status FIRST, then log: nmlog_absorb_notes runs a pipeline, and $? after
            # one is the pipeline's -- the exact footgun the comment on _ab_rc
            # in service.sh documents.
            _ea_rc=$?
            nmlog_absorb_notes "$_ea"
            if [ "$_ea_rc" -eq 124 ]; then
                nmlog "⚠ early absorb TIMED OUT after 60s - continuing boot"
            elif [ "$_ea_rc" -ne 0 ]; then
                nmlog "⚠ early absorb FAILED (rc=$_ea_rc): $(printf '%s\n' "$_ea" | tail -1)"
            else
                nmlog "early absorb: $(printf '%s\n' "$_ea" | tail -1)"
            fi
        fi
    else
        # Never silent. See metamount.sh: with no else arm a missing binary meant
        # a boot that injected nothing and reported nothing.
        nmlog "⛔ engine binary is missing or not executable ($BIN) — NOTHING was injected this boot"
        {
            echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
            echo "reason=engine did not run: no executable at $BIN (magisk post-fs-data path)"
            echo "abi=$ABI (ro.product.cpu.abi=$(getprop ro.product.cpu.abi 2>/dev/null))"
            # shellcheck disable=SC2012  # listing the ABI directories the ZIP shipped, by
            # name, for an incident report. The names are ours (arm64-v8a, x86_64...) and
            # `find` cannot produce a one-line summary without more plumbing than the
            # message is worth.
            echo "shipped_abis=$(ls "$MODDIR/bin" 2>/dev/null | tr '\n' ' ')"
            echo "kernel=$(uname -r)"
            echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
            echo "note=reinstall the module zip; a partial/permission-stripped extraction is the usual cause"
        } > "$NMDIR/incident.log" 2>/dev/null
    fi
fi
exit 0
