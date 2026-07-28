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

# --- refresh the manager card with the settled state ---
# metamount.sh tags the card in post-fs-data, when the mount table is not final and
# health cannot be judged yet. Now that boot is complete both are knowable, so restate
# the card with the real mount count and the health-check verdict — that turns the
# module list into a status readout you can trust without opening the WebUI.
MODDIR="${0%/*}"
ABI=$(getprop ro.product.cpu.abi)
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"
if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _rules=$("$NM_BIN" list 2>/dev/null | wc -l)
    _rro=$("$NM_BIN" list 2>/dev/null | grep -c '/overlay/[^ ]*\.apk')
    _mnt=$(grep -c '/data/adb/modules' /proc/self/mountinfo 2>/dev/null || echo 0)
    _doc=$(timeout 30 "$BIN" doctor 2>/dev/null | sed -n 's/^summary: \([0-9]*\) errors, \([0-9]*\) warnings$/\1 \2/p')
    _err=$(echo "$_doc" | awk '{print $1+0}')
    _wrn=$(echo "$_doc" | awk '{print $2+0}')
    if [ "${_err:-0}" -gt 0 ]; then
        _health="⚠️ $_err error(s) — see WebUI › Tools"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="$_wrn warning(s)"
    else
        _health="healthy"
    fi
    if [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="⚠ $_mnt module mount(s)"
    else
        _mstate="0 mounts"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "[NoMount ✅ $_rules rules · $_rro RRO · $_mstate] $_health — fully mountless: hookless VFS + RRO, su via sucompat" \
        >/dev/null 2>&1
    echo "nomount: card refreshed ($_rules rules, $_mstate, $_health)" > /dev/kmsg 2>/dev/null
fi
exit 0
