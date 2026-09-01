#!/system/bin/sh
# Runs when the metamodule is uninstalled.
#
# service.sh writes /data/adb/bindhosts/mode_override.sh to select bindhosts'
# mountless mode. That file is conditional on this Suite being live, so it is
# inert once we are gone -- but leaving it behind is still wrong: install a
# DIFFERENT metamodule later and a file we wrote would start selecting a mode
# under something we do not control.
#
# Only remove our own. A user's hand-written override never carries the marker.
_ovr=/data/adb/bindhosts/mode_override.sh
if [ -f "$_ovr" ] && grep -q 'NoMount Suite' "$_ovr" 2>/dev/null; then
    rm -f "$_ovr"
fi
unset _ovr

# Our whole state directory. Everything in here is ours -- config the WebUI
# writes, caches, logs, and the self-disable flag -- and none of it means
# anything once the module is gone.
#
# `disabled` is the one that actually bites. The bootloop guard writes it and
# only the WebUI clears it, so leaving it behind meant the classic recovery
# ("uninstall, reinstall") produced an install that reports success, injects
# nothing, and never says why -- because the fresh module reads the old
# flag on its first boot.
# BUT NOT THE USER'S OWN CONFIG. ksud runs this on an UPDATE too, not only on a
# real uninstall, so a plain `rm -rf` here silently threw away everything the
# user had configured every time they flashed a newer Suite over an older one.
# Measured on OP15 (2026-08-28, v1.3.106 -> v1.3.107): the hide list, the module
# blocklist and the `my_hookless` opt-in all vanished. Losing the marker alone
# moved 85 my_* files from injection back to bind mounts -- a silent revert to a
# different serving mode, reported by `check` as someone else's foreign mounts.
#
# So: stash the user-owned files, drop everything else, and let customize.sh put
# them back. The operational flags are deliberately NOT stashed -- `disabled` in
# particular MUST die here, because that is the whole reason this rm exists.
#
# ...and ONLY on an update. This script runs for both, and a stash left behind by
# a genuine uninstall is never collected: customize.sh is the only thing that
# removes it, and after a real removal customize.sh never runs again. That left
# /data/adb/nomount.bak on disk forever -- named after the module the user just
# deleted, holding `uidhide`, which is the list of apps they were hiding from.
# The header three paragraphs up promises none of this survives us, so it must
# not.
#
# The discriminator is the manager's own `remove` marker: KernelSU, APatch and
# Magisk all write it into the module directory when the USER asks for removal
# and run this script at the next boot, whereas an update extracts the new module
# over the old one with no marker at all. Belt and braces -- both boot entry
# points (metamount.sh and post-fs-data.sh) also sweep a stash that outlived a
# boot, so a manager that does not use the marker still cannot leave one lying
# around. NOT service.sh, which this comment used to name and which has never
# touched the file; that mistake is also why the removal branch below did not
# think it had to clean up after itself.
MODDIR="${0%/*}"
_bak=/data/adb/nomount.bak
_nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [uninstall] $*" >> /data/adb/nomount/boot.log 2>/dev/null
}
if [ -f "$MODDIR/remove" ]; then
    # ...and take any stash ALREADY on disk with us. Declining to CREATE one is
    # only half the promise the header makes. A stash survives a flash whose
    # customize.sh aborted before it could consume one -- the sha256 refusal and
    # the metamodule-conflict refusal both exit before the restore loop -- and the
    # sweep that would otherwise collect it lives in the two BOOT entry points,
    # neither of which runs again once the module is gone. So it sat there
    # forever, named after the module the user had just deleted, holding `uidhide`:
    # the list of apps they were hiding from.
    _nmlog "removal requested - dropping the state directory, and any stash left by an unfinished install, without saving anything"
    rm -rf "$_bak"
elif [ -d /data/adb/nomount ]; then
    # Everything the USER chose, and the operational records that cannot be
    # rebuilt from anywhere else:
    #   uidhide/.conf/.cache  the hide list, its policy, and the resolved-appid
    #                         mirror the post-fs-data pass hides from. Losing the
    #                         mirror leaves every app unhidden from post-fs-data
    #                         to boot_completed on the first boot after an update.
    #   blocklist             module ids the mount pass must not inject.
    #   my_hookless           the my_* serving mode. Losing it moved 85 files from
    #                         injection back to bind mounts on an OP15.
    #   absorb-skip.txt       hand-edited opt-outs.
    #   whiteouts.txt         durable hides.
    #   snapshot.txt          the baseline `verify` diffs against.
    #   spoof.conf            the user's `fix_shell_tmp` choice. customize.sh says
    #                         in as many words that an existing file "is
    #                         deliberately left where it is ... it may hold a
    #                         deliberate fix_shell_tmp=0" -- which stopped being
    #                         true the moment this rm started running on updates.
    #   absorbed.list         the ONLY thing that can re-serve a patched-APK rule
    #                         for a module that no longer mounts. absorb.rs guards
    #                         this file against a truncating rewrite in three
    #                         places; deleting it wholesale on every update made
    #                         all three moot.
    #   binds.list            the only record of the my_* binds we made, and of the
    #                         ROM SELinux label we put on each backing file. Drop
    #                         it and the next boot cannot tear those down or put
    #                         the labels back, so a module file keeps a partition
    #                         label under /data/adb indefinitely.
    _kept=0
    _lost=0
    rm -rf "$_bak"
    if mkdir -p "$_bak" 2>/dev/null && chmod 0700 "$_bak" 2>/dev/null; then
        # Match the parent's label explicitly rather than relying on the type
        # transition, exactly as customize.sh does for $NMDIR itself: the files
        # inside name which apps are being hidden from.
        chcon u:object_r:adb_data_file:s0 "$_bak" 2>/dev/null
        for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
                  absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
                  absorbed.list binds.list; do
            [ -e "/data/adb/nomount/$_f" ] || continue
            if cp -p "/data/adb/nomount/$_f" "$_bak/$_f" 2>/dev/null; then
                _kept=$((_kept + 1))
            else
                _lost=$((_lost + 1))
            fi
        done
        unset _f
    else
        # NEVER SILENT. The `rm -rf` below runs either way, so a stash that could
        # not be created means the user's configuration is about to be destroyed
        # with nothing to restore it from -- and this script had no diagnostic
        # path at all, which made a total loss indistinguishable from a clean
        # update.
        _lost=-1
    fi
    if [ "$_lost" = "-1" ]; then
        _nmlog "could not create $_bak - the hide list, whiteouts and settings will be LOST by this update"
    elif [ "$_lost" -gt 0 ]; then
        _nmlog "stashed $_kept setting(s) to $_bak, but $_lost could NOT be copied and will be lost"
    else
        _nmlog "stashed $_kept setting(s) to $_bak for the incoming install"
    fi
    unset _kept _lost
fi
unset _bak

rm -rf /data/adb/nomount
