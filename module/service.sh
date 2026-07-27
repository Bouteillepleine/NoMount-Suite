#!/system/bin/sh
# Bootloop-guard reset: once the system finishes booting, the last boot was
# healthy, so clear the boot counter (re-arms the guard for next time).
NMDIR=/data/adb/nomount
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
    sleep 2
    i=$((i + 1))
done

# NB: unlike the old build we do NOT re-assert kernel_umount here — forcing that
# feature on breaks root for other modules on OP15. Hiding of the Suite's real
# mounts is handled by the manager's per-app-profile default-umount instead.

sleep 10
rm -f "$NMDIR/bootcount"
echo "nomount: boot completed, guard counter reset" > /dev/kmsg 2>/dev/null

# --- ksud de-link re-assertion (self-heal of the susfs-action guard) ---
# metamount.sh de-links ksu_susfs from the ksud multicall at mount time; re-assert it
# here post-boot as a belt-and-suspenders against any timing race (e.g. ksud finishing
# its install stage after our mount pass). If ksud & ksu_susfs still share an inode,
# split ksu_susfs into its own independent copy so the susfs action button can never
# reach the ksud daemon. (A clobbered ksud can't be healed from a module service — if
# ksud were broken this service wouldn't run — so we only re-assert the split here.)
KSUD=/data/adb/ksud
SUSFS_BIN=/data/adb/ksu/bin/ksu_susfs
if [ -f "$KSUD" ] && [ -f "$SUSFS_BIN" ] \
   && [ "$(stat -c %s "$KSUD" 2>/dev/null)" -gt 1000000 ] \
   && [ "$(stat -c %i "$KSUD" 2>/dev/null)" = "$(stat -c %i "$SUSFS_BIN" 2>/dev/null)" ]; then
    chattr -i "$KSUD" 2>/dev/null
    if cp "$KSUD" "$SUSFS_BIN.nm_new" 2>/dev/null; then
        chmod 0755 "$SUSFS_BIN.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$SUSFS_BIN.nm_new" 2>/dev/null
        mv -f "$SUSFS_BIN.nm_new" "$SUSFS_BIN" 2>/dev/null \
            && echo "nomount: re-asserted ksud de-link (service)" > /dev/kmsg 2>/dev/null
    else
        rm -f "$SUSFS_BIN.nm_new" 2>/dev/null
    fi
fi
exit 0
