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
rm -rf /data/adb/nomount
