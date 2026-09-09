#!/system/bin/sh
_ovr=/data/adb/bindhosts/mode_override.sh
if [ -f "$_ovr" ] && grep -q 'NoMount Suite' "$_ovr" 2>/dev/null; then
    rm -f "$_ovr"
fi
unset _ovr

MODDIR="${0%/*}"
_bak=/data/adb/nomount.bak
_nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [uninstall] $*" >> /data/adb/nomount/boot.log 2>/dev/null
}
if [ -f "$MODDIR/remove" ]; then
    _nmlog "removal requested - dropping the state directory without stashing anything"
elif [ -d /data/adb/nomount ]; then
    _kept=0
    _lost=0
    rm -rf "$_bak"
    if mkdir -p "$_bak" 2>/dev/null && chmod 0700 "$_bak" 2>/dev/null; then
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
        _lost=-1
    fi
    if [ "$_lost" = "-1" ]; then
        _nmlog "could not create $_bak - the hide list, whiteouts and settings will be lost by this update"
    elif [ "$_lost" -gt 0 ]; then
        _nmlog "stashed $_kept setting(s) to $_bak, but $_lost could not be copied and will be lost"
    else
        _nmlog "stashed $_kept setting(s) to $_bak for the incoming install"
    fi
    unset _kept _lost
fi
unset _bak

rm -rf /data/adb/nomount
