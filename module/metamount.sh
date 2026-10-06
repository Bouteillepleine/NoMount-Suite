#!/system/bin/sh
MODDIR="${0%/*}"
NMLOG_TAG=metamount

_nm_notified=0
nm_notify_mounted() {
    [ "$_nm_notified" = 1 ] && return 0
    _nm_notified=1
    ksud kernel notify-module-mounted 2>/dev/null
    return 0
}
trap nm_notify_mounted EXIT
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - nothing was injected this boot; re-flash the zip" > /dev/kmsg 2>/dev/null
    nm_notify_mounted
    exit 1
}
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"
nm_state_dir_repair

nm_boot_log_rotate

rm -f "$NMDIR/.uidwatch.lock" 2>/dev/null

nm_consume_stash

cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null \
    || nmlog "⚠ could not stamp mountpass.ts - service.sh will report that no boot entry point ran"

LOCK="$NMDIR/.mount.lock"
if ! ( : >> "$LOCK" ) 2>/dev/null; then
    nmlog "⛔ cannot create $LOCK - $NMDIR is not writable, so the bootloop guard cannot arm; nothing was injected this boot"
    exit 1
fi
exec 8>&2
exec 9>"$LOCK" 2>/dev/null
exec 2>&8 8>&-
chmod 0600 "$LOCK" 2>/dev/null
if ! command -v flock >/dev/null 2>&1; then
    nmlog "flock unavailable - mount pass running without a single-run guard"
elif ! ls /proc/self/fd/9 >/dev/null 2>&1; then
    nmlog "fd 9 is close-on-exec in this shell, so flock cannot use it - mount pass running without a single-run guard"
else
    flock -n 9 || { _nm_notified=1; exit 0; }
fi

nm_set_bin
_pass_ran=0
_driver_ok=1

chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

nm_delink_ksud "susfs-action guard"

if nm_guard_bump "ksu/apatch metamount path"; then
    nm_fix_shell_tmp

    if [ -x "$BIN" ]; then
        nm_mount_pass
    else
        nm_incident_missing_binary "ksu/apatch metamount path"
    fi
fi

if command -v ksud >/dev/null 2>&1; then
    _nmods=0
    if [ ! -e "$NMDIR/disabled" ]; then
    nm_rule_counts
    for d in /data/adb/modules/*/; do
        [ -d "$d" ] || continue
        d=${d%/}; mid=${d##*/}
        { [ "$mid" = "meta-nomount" ] || [ "$mid" = "kernelnosu" ]; } && continue
        { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && continue
        _sum=$(NM_MID="$mid" awk -F'\t' '$1==ENVIRON["NM_MID"]{print;exit}' "$NMDIR/modules.tsv" 2>/dev/null)
        [ -z "$_sum" ] && continue
        _nmods=$((_nmods + 1))
    done
    fi

    _mods=${_nmods:-0}
    [ "${_wo:-0}" -gt 0 ] 2>/dev/null && _wof=" · $_wo hidden" || _wof=""
    if [ -e "$NMDIR/disabled" ]; then
        _desc="⛔ disabled - bootloop guard tripped, see the WebUI"
    elif [ "${_driver_ok:-1}" = 0 ]; then
        _desc="⛔ no NoMount driver - flash a NoMount kernel and reboot"
    elif [ "$_pass_ran" = 0 ]; then
        _desc="⛔ could not start this boot - see the WebUI"
    elif [ "${_mrc:-0}" -ne 0 ]; then
        _desc="ℹ️ mount pass unfinished (exit $_mrc) - see the WebUI"
    elif [ "${_nmlrc:-0}" -ne 0 ]; then
        _desc="✅ served, rule table unreadable"
    elif [ "${_rules:-0}" = 0 ]; then
        _desc="ℹ️ ran, no module had files to serve"
    else
        _desc="✅ $_rules rules · $_rro RRO$_wof · $_mods modules · mountless"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description "$_desc" >/dev/null 2>&1
fi

exit 0
