#!/system/bin/sh
MODDIR="${0%/*}"
NMLOG_TAG=post-fs-data
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - nothing was injected this boot; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"

nm_boot_log_rotate

# .checkwatch.lock belongs here too: it holds a pid, and after a reboot that pid is just
# an integer. If anything now owns it, checkwatch.sh's `kill -0` says the holder is alive,
# the noclobber acquire fails and every WebUI check request is dropped in silence for the
# whole boot -- which sends the page back to running the check in its own seccomp context.
rm -f "$NMDIR/.uidwatch.lock" "$NMDIR/.uidwatch.digest" "$NMDIR/.checkwatch.lock" 2>/dev/null
nm_consume_stash
nm_lkm_boot_load
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    nmlog "KSU/APatch detected - the metamodule hook (metamount.sh) owns this boot"
    exit 0
fi

cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null \
    || nmlog "⚠ could not stamp mountpass.ts - service.sh will report that no boot entry point ran"

nm_state_dir_repair

nm_set_bin
chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

if ! ( : >> "$NMDIR/.mount.lock" ) 2>/dev/null; then
    nmlog "⛔ cannot write $NMDIR - the bootloop guard cannot arm; nothing was injected this boot"
    exit 0
fi
chmod 0600 "$NMDIR/.mount.lock" 2>/dev/null

if nm_guard_bump "magisk post-fs-data path"; then
    nm_fix_shell_tmp
    if [ -x "$BIN" ]; then
        nm_mount_pass

        nm_early_absorb
    else
        nm_incident_missing_binary "magisk post-fs-data path"
    fi
fi
exit 0
