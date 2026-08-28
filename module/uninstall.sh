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
_bak=/data/adb/nomount.bak
if [ -d /data/adb/nomount ]; then
    rm -rf "$_bak"
    for _f in uidhide uidhide.conf blocklist my_hookless absorb-skip.txt whiteouts.txt snapshot.txt; do
        [ -e "/data/adb/nomount/$_f" ] || continue
        [ -d "$_bak" ] || { mkdir -p "$_bak" && chmod 700 "$_bak"; } || break
        cp -p "/data/adb/nomount/$_f" "$_bak/$_f" 2>/dev/null
    done
    unset _f
fi
unset _bak

rm -rf /data/adb/nomount
