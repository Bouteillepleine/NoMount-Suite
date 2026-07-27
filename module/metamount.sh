#!/system/bin/sh
# NoMount Suite metamodule hook (KSU/APatch, post-fs-data / metamodule stage).
# Runs the Suite mount pass (hookless mountless inject + RRO overlays), guarded by
# a bootloop counter, hides the RRO mounts via SUSFS if present, then signals ready.
# Root/su is NOT managed here (sucompat handles it, mountlessly).
MODDIR="${0%/*}"
NMDIR=/data/adb/nomount
mkdir -p "$NMDIR"

LOCK="/dev/nomount_metamount.lock"
( set -o noclobber; : > "$LOCK" ) 2>/dev/null || { ksud kernel notify-module-mounted 2>/dev/null; exit 0; }

ABI=$(getprop ro.product.cpu.abi)
BIN="$MODDIR/bin/$ABI/nomount"
# The Suite binary shells out to the hookless `nm` netlink client bundled beside it.
export NM_BIN="$MODDIR/bin/$ABI/nm"

# Self-heal executable bits: some installers (and non-recovery ksud extraction)
# don't preserve +x. Without it on nm the whole pass aborts before it can inject.
chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

# --- ksud multicall guard (susfs4ksu action-button clobber protection) ---
# On this build ksud/ksu_susfs/resetprop are ONE hardlinked multicall binary. The
# SUSFS module's action button runs `cp -f <standalone> /data/adb/ksu/bin/ksu_susfs`,
# which follows the hardlink and overwrites the whole ksud daemon -> breaks su/ksud
# until reflash (a reboot in that state can bootloop). Boot re-creates the hardlink
# every time, so we de-link ksu_susfs into its OWN independent copy once per boot:
# after this, action.sh's cp only hits the copy and the ksud daemon inode is untouched.
# No chattr +i, so legitimate susfs updates still work. Only acts on a genuine (>1MB)
# multicall that actually shares ksud's inode; a clobbered/small ksud is left alone.
KSUD=/data/adb/ksud
SUSFS_BIN=/data/adb/ksu/bin/ksu_susfs
if [ -f "$KSUD" ] && [ -f "$SUSFS_BIN" ] \
   && [ "$(stat -c %i "$KSUD" 2>/dev/null)" = "$(stat -c %i "$SUSFS_BIN" 2>/dev/null)" ] \
   && [ "$(stat -c %s "$KSUD" 2>/dev/null)" -gt 1000000 ]; then
    chattr -i "$KSUD" 2>/dev/null
    if cp "$KSUD" "$SUSFS_BIN.nm_new" 2>/dev/null; then
        chmod 0755 "$SUSFS_BIN.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$SUSFS_BIN.nm_new" 2>/dev/null
        mv -f "$SUSFS_BIN.nm_new" "$SUSFS_BIN" 2>/dev/null \
            && echo "nomount: de-linked ksu_susfs from ksud multicall (susfs-action guard)" > /dev/kmsg 2>/dev/null
    else
        rm -f "$SUSFS_BIN.nm_new" 2>/dev/null
    fi
fi

# --- bootloop guard ---
GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > "$NMDIR/bootcount"

if [ -f "$NMDIR/disabled" ]; then
    echo "nomount: disabled, skipping mount" > /dev/kmsg 2>/dev/null
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then
    echo "nomount: bootloop guard tripped (count=$COUNT) -> self-disabling" > /dev/kmsg 2>/dev/null
    : > "$NMDIR/disabled"
elif [ -x "$BIN" ]; then
    timeout 60 "$BIN" mount 2>/dev/null
fi

# --- hiding ---
# Nothing to hide: the Suite is now FULLY MOUNTLESS. Hookless VFS injection covers
# regular files AND RRO overlay APKs (injected into /product/overlay etc.; OMS +
# idmap2 pick them up at the system_server scan, which runs after this post-fs-data
# pass). su is sucompat (mountless). There is no overlayfs mount and no work tmpfs,
# so a mount scanner sees only stock mounts — nothing to hide, no SUSFS, no umount.

# --- tag managed modules in the manager with how the Suite serves them ---
if command -v ksud >/dev/null 2>&1; then
    _vf=""; _ov=""
    for d in /data/adb/modules/*/; do
        [ -d "$d" ] || continue
        mid=$(basename "$d")
        { [ "$mid" = "meta-nomount" ] || [ "$mid" = "kernelnosu" ]; } && continue
        { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ] || [ ! -d "$d/system" ]; } && continue
        _o=0; _v=0
        [ -n "$(find "$d/system" -path '*/overlay/*.apk' -print -quit 2>/dev/null)" ] && _o=1
        [ -n "$(find "$d/system" -type f ! -path '*/overlay/*' -print -quit 2>/dev/null)" ] && _v=1
        [ "$_o" = 0 ] && [ "$_v" = 0 ] && continue
        if [ "$_o" = 1 ] && [ "$_v" = 1 ]; then _t="vfs + overlay"; _ov="$_ov $mid";
        elif [ "$_o" = 1 ]; then _t="overlay"; _ov="$_ov $mid";
        else _t="vfs"; _vf="$_vf $mid"; fi
        _orig=$(sed -n 's/^description=//p' "$d/module.prop" | head -1)
        KSU_MODULE="$mid" ksud module config set --temp override.description "[NoMount - $_t] $_orig" >/dev/null 2>&1
    done
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "NoMount Suite - fully mountless: hookless VFS + hookless RRO overlays. vfs:$_vf | overlay:$_ov" >/dev/null 2>&1
fi

ksud kernel notify-module-mounted 2>/dev/null
exit 0
