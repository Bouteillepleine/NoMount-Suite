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
nm_consume_stash
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
# CHECKED, for the reason metamount.sh gives at the same call: a failed stamp
# makes service.sh accuse a working manager and paint "⛔ mount pass never ran".
cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null \
    || nmlog "⚠ could not stamp mountpass.ts — service.sh will report that no boot entry point ran"

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
# One implementation of the bootloop guard, in lib.sh. This entry point and
# metamount.sh each used to carry their own ~55-line copy.
if nm_guard_bump "magisk post-fs-data path"; then
    # Restore /data/local/tmp's AOSP owner/mode/context -- see nm_fix_shell_tmp in
    # lib.sh. Same stage and same call as the KSU/APatch metamount hook, for the
    # Magisk path; service.sh re-asserts it after boot.
    nm_fix_shell_tmp
    if [ -x "$BIN" ]; then
        # The bounded pass, its 124-aware status ladder, the `nomount: WARNING`
        # grep and the durable-whiteout re-apply are nm_mount_pass in lib.sh now.
        # This block and metamount.sh's were byte-identical for 24 code lines and
        # THIS is the copy that had drifted: it was missing the `2>&1`, the
        # `reason:` line, the 124 naming and the WARNING grep, each back-ported
        # separately over three rounds. There is no status card on the Magisk
        # path, so boot.log is the only record it has -- which is why the drift
        # cost more here than on the KSU one.
        nm_mount_pass

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
        nm_early_absorb
    else
        # Never silent. See metamount.sh: with no else arm a missing binary meant
        # a boot that injected nothing and reported nothing.
        nm_incident_missing_binary "magisk post-fs-data path"
    fi
fi
exit 0
