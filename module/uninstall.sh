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
        _nmlog "could not create $_bak - the hide list, whiteouts and settings will be lost by this update"
    elif [ "$_lost" -gt 0 ]; then
        _wipe_ok=0
        _nmlog "stashed $_kept setting(s) to $_bak, but $_lost could not be copied - keeping the live state directory so those survive"
    else
        _nmlog "stashed $_kept setting(s) to $_bak for the incoming install"
    fi
    unset _kept _lost
fi

if [ "${_wipe_ok:-1}" = 0 ]; then
    _nmlog "keeping /data/adb/nomount: the stash failed, so wiping it would destroy the only copy"
    rm -f /data/adb/nomount/disabled /data/adb/nomount/bootcount 2>/dev/null
else
    rm -rf /data/adb/nomount
fi
