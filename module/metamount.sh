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

# --- spoof add-on (dynamic vbmeta.digest + uname) ---
# Runs in this post-fs-data stage so the props are in place and uname is spoofed
# before zygote/system_server come up. Best-effort: it never aborts the boot, and
# it is kept separate from the mount pass so a spoof failure can't affect mounting.
[ -f "$MODDIR/spoof.sh" ] && sh "$MODDIR/spoof.sh" 2>/dev/null

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
    # Record WHY, while the evidence is still fresh. Without this a trip leaves only an
    # empty `disabled` file and the user has to dig through tombstones by hand to find out
    # what crashed (that is exactly how the /my_product FD-allowlist bootloop was found).
    # Everything here is best-effort and must never fail the boot.
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$("$NM_BIN" list 2>/dev/null | wc -l)"
        echo "modules_enabled=$(for m in /data/adb/modules/*/; do
                [ -f "$m/disable" ] || [ -f "$m/remove" ] || [ -f "$m/skip_mount" ] && continue
                basename "$m"
            done | tr '\n' ' ')"
        # Newest native crash + its abort line: for an early-boot bootloop this is almost
        # always zygote/system_server and names the offending path outright.
        _t=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
        if [ -n "$_t" ]; then
            echo "tombstone=$_t"
            echo "  $(grep -m1 '>>> ' "$_t" 2>/dev/null)"
            echo "  $(grep -m1 'Abort message' "$_t" 2>/dev/null)"
        fi
    } > "$NMDIR/incident.log" 2>/dev/null
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
        { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && continue
        # Mirror the injector (src/mount.rs): content lives under ANY top-level dir that maps
        # to a real partition, not just system/ (auto_mount modules ship product/ directly).
        # Plain `find` (no -L) is deliberate: a module's `system/product -> ../product`
        # layout-convergence symlink must not be followed, or its files count twice.
        _roots=""
        for _pd in "$d"*/; do
            [ -d "$_pd" ] || continue
            # Mirrors the injector's non-following file_type(): a top-level symlink (e.g.
            # OnePlus_Dialer_Universal's `product -> ./system/product`) is not a root to walk;
            # counting it would double-count the files it points at.
            [ -L "${_pd%/}" ] && continue
            _n=$(basename "$_pd")
            case "$_n" in
                data|mnt|dev|proc|sys|cache|metadata|config|storage|sdcard|apex|tmp|\
                debug_ramdisk|linkerconfig|postinstall|second_stage_resources|bin|sbin) continue ;;
                my_*) continue ;;
            esac
            [ -d "/$_n" ] || continue
            _roots="$_roots $_pd"
        done
        [ -z "$_roots" ] && continue
        _o=0; _v=0
        [ -n "$(find $_roots -path '*/overlay/*.apk' -print -quit 2>/dev/null)" ] && _o=1
        [ -n "$(find $_roots -type f ! -path '*/overlay/*' -print -quit 2>/dev/null)" ] && _v=1
        [ "$_o" = 0 ] && [ "$_v" = 0 ] && continue
        if [ "$_o" = 1 ] && [ "$_v" = 1 ]; then _t="vfs + overlay"; _ov="$_ov $mid";
        elif [ "$_o" = 1 ]; then _t="overlay"; _ov="$_ov $mid";
        else _t="vfs"; _vf="$_vf $mid"; fi
        # How many rules this module actually got, and whether it owns any mount. The
        # rule count is the honest measure of "is this module being served" — a module
        # can be enabled and still contribute nothing. A non-zero mount count is the only
        # thing that breaks the zero-mount posture, so it is called out per module.
        _n=$("$NM_BIN" list 2>/dev/null | grep -c "/data/adb/modules/$mid/")
        _m=$(grep -cE "/data/adb/modules/$mid(/|$)" /proc/self/mountinfo 2>/dev/null || echo 0)
        _badge="$_t · $_n served"
        [ "${_m:-0}" -gt 0 ] && _badge="$_badge · ⚠ $_m mount(s)"
        _orig=$(sed -n 's/^description=//p' "$d/module.prop" | head -1)
        KSU_MODULE="$mid" ksud module config set --temp override.description \
            "[NoMount · $_badge] $_orig" >/dev/null 2>&1
    done

    # The Suite's own card doubles as the at-a-glance status readout, so put the live
    # numbers there rather than restating the tagline the module.prop already carries.
    _rules=$("$NM_BIN" list 2>/dev/null | wc -l)
    _rro=$("$NM_BIN" list 2>/dev/null | grep -c '/overlay/[^ ]*\.apk')
    _mods=0
    for _x in $_vf $_ov; do _mods=$((_mods + 1)); done
    _list=""
    [ -n "$_vf" ] && _list="vfs:$_vf"
    [ -n "$_ov" ] && _list="$_list${_list:+ | }overlay:$_ov"
    if [ -f "$NMDIR/disabled" ]; then
        _desc="[NoMount ⛔ disabled] bootloop guard tripped — open WebUI › Tools › Last incident"
    else
        _desc="[NoMount ✅ $_rules rules · $_rro RRO · $_mods modules] fully mountless — hookless VFS + RRO, no overlayfs, su via sucompat${_list:+. $_list}"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description "$_desc" >/dev/null 2>&1
fi

ksud kernel notify-module-mounted 2>/dev/null
exit 0
