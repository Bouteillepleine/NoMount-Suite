#!/system/bin/sh
_ovr=/data/adb/bindhosts/mode_override.sh
if [ -f "$_ovr" ] && grep -q 'NoMount Suite' "$_ovr" 2>/dev/null; then
    rm -f "$_ovr"
fi
unset _ovr

case "$0" in
    */*) MODDIR="${0%/*}" ;;
    *)   MODDIR=/data/adb/modules/meta-nomount ;;
esac
_bak=/data/adb/nomount.bak
_nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [uninstall] $*" >> /data/adb/nomount/boot.log 2>/dev/null
}
_ran=0
for _abi in arm64-v8a armeabi-v7a x86_64 x86; do
    _nmbin="$MODDIR/bin/$_abi/nomount"
    _nmcli="$MODDIR/bin/$_abi/nm"
    [ -x "$_nmbin" ] || continue
    _ran=1
    if command -v timeout >/dev/null 2>&1; then
        timeout 30 "$_nmbin" unbind >/dev/null 2>&1
        _urc=$?
    else
        "$_nmbin" unbind >/dev/null 2>&1
        _urc=$?
    fi
    if [ "$_urc" -eq 0 ]; then
        _nmlog "recorded binds umounted and source labels restored"
    else
        _wipe_ok=0
        _keep_why="unbind did not finish, and binds.list is the only record of which source files still carry a ROM label - the next boot retries it"
        _nmlog "⚠ could not umount every recorded bind - keeping /data/adb/nomount so binds.list survives"
    fi
    # unbind takes down the real binds. The injections are rules inside the
    # kernel, and each holds a reference on the module tree that is about to be
    # unlinked - so without this a ROM path goes on serving a deleted file until
    # the next reboot, and any mapping of it reads "(deleted)". Clearing the
    # table makes the uninstall take effect now.
    if [ -x "$_nmcli" ]; then
        if "$_nmcli" c >/dev/null 2>&1; then
            _nmlog "engine rule table cleared"
        else
            _nmlog "⚠ could not clear the engine rule table - injected paths keep being served until the next reboot"
        fi
    else
        _nmlog "⚠ no nm client at bin/$_abi/nm - injected paths keep being served until the next reboot"
    fi
    break
done
if [ "$_ran" = 0 ]; then
    # The loop never ran a binary, so nothing was unbound and nothing cleared.
    # Wiping binds.list here would leave a real bind mounted with a ROM label on
    # its source and no record anywhere of which file that was.
    _wipe_ok=0
    _keep_why="no executable engine binary was found, so no recorded bind was taken down and binds.list is the only record of which source files still carry a ROM label"
    _nmlog "⛔ no executable nomount under $MODDIR/bin - recorded binds were NOT umounted; keeping /data/adb/nomount"
fi
unset _abi _nmbin _nmcli _urc _ran

if [ -f "$MODDIR/remove" ]; then
    _nmlog "removal requested - dropping the state directory, and any stash left by an unfinished install, without saving anything"
    rm -rf "$_bak"
elif [ -d /data/adb/nomount ]; then
    _kept=0
    _lost=0
    rm -rf "$_bak"
    if mkdir -p "$_bak" 2>/dev/null && chmod 0700 "$_bak" 2>/dev/null; then
        chcon u:object_r:adb_data_file:s0 "$_bak" 2>/dev/null
        for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
                  absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
                  uidconceal ghostpaths \
                  absorbed.list binds.list absorbed-tmpfs.list apkstate.list; do
            [ -e "/data/adb/nomount/$_f" ] || continue
            if cp -p "/data/adb/nomount/$_f" "$_bak/$_f" 2>/dev/null; then
                _kept=$((_kept + 1))
            else
                rm -f "$_bak/$_f" 2>/dev/null
                _lost=$((_lost + 1))
            fi
        done
        unset _f
    else
        _lost=-1
        _wipe_ok=0
    fi
    if [ "$_lost" = "-1" ]; then
        _nmlog "could not create $_bak - keeping the live /data/adb/nomount instead, so the hide list, whiteouts and settings survive"
    elif [ "$_lost" -gt 0 ]; then
        _wipe_ok=0
        _nmlog "stashed $_kept setting(s) to $_bak, but $_lost could not be copied - keeping the live state directory so those survive"
    else
        _nmlog "stashed $_kept setting(s) to $_bak for the incoming install"
    fi
    unset _kept _lost
fi

if [ "${_wipe_ok:-1}" = 0 ]; then
    _nmlog "keeping /data/adb/nomount: ${_keep_why:-the stash failed, so wiping it would destroy the only copy}"
    rm -f /data/adb/nomount/disabled /data/adb/nomount/bootcount 2>/dev/null
else
    rm -rf /data/adb/nomount
fi
