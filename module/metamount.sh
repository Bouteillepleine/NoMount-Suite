#!/system/bin/sh
# NoMount Suite metamodule hook (KSU/APatch, post-fs-data / metamodule stage).
# Runs the Suite mount pass (hookless mountless inject + RRO overlays), guarded by
# a bootloop counter, then signals ready. The Suite does NOT use SUSFS: RRO goes
# through the hookless engine and makes no mount to hide (see the note at the
# mount pass below). The only ksu_susfs reference here is a guard against another
# module's action button clobbering ksud.
# Root/su is NOT managed here (sucompat handles it, mountlessly).
MODDIR="${0%/*}"
NMDIR=/data/adb/nomount
# The boot umask is 0, so every state file created from here (and by the binaries
# this script execs, which inherit it) landed 0666 -- observed on absorbed.list,
# binds.lock, uidhide and uidhide.cache. The 0700 directory below is what actually
# protects them, but uidhide IS the hiding policy and should not rely on its
# parent alone. Set the umask once, at the top, so it covers the whole pass.
umask 077
# 0700: spoof.conf/blocklist/pathhide.conf are read as root at boot, so anything
# able to write here gets root. The dir was being created under the boot umask (0777).
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"
# Tighten anything an earlier build already created wide. Cheap and idempotent.
# -type f, because the glob also handed DIRECTORIES to chmod: `rollback-bin` was
# observed on-device as drw------- , i.e. readable but not traversable, so
# nothing inside it could be reached by anything -- including us.
find "$NMDIR" -maxdepth 1 -type f -exec chmod 0600 {} + 2>/dev/null

# --- durable boot log ---------------------------------------------------------
# Every boot diagnostic below used to go ONLY to /dev/kmsg. On this hardware the
# ring is flooded by WMI roam-stats spam within minutes of boot, so by the time
# anyone looks `dmesg | grep -i nomount` comes back empty -- which made the
# loudest signals the Suite has (running WITHOUT a single-run guard, hide list
# apply FAILED, absorb TIMED OUT) unrecoverable in practice. Tee the same lines
# to a file; kmsg stays, because it is the only channel alive early enough to
# survive a boot that never reaches /data.
BOOTLOG="$NMDIR/boot.log"
# Rotate here rather than in service.sh/uidwatch.sh: this is the boot entry point
# for KSU/APatch, so it runs exactly once per boot. Same shape as spoof.sh's log
# rotation, including the chmod for a file an older build left wide.
[ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
    && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
: >> "$BOOTLOG" 2>/dev/null
chmod 0600 "$BOOTLOG" 2>/dev/null
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [metamount] $*" >> "$BOOTLOG" 2>/dev/null
}

# Single-run guard. Was a noclobber file in /dev: world-writable (boot umask),
# named after the project, and "held" by mere existence -- so anything able to
# create that path pre-empted the whole mount pass. flock releases on exit and
# lives in the 0700 state dir.
LOCK="$NMDIR/.mount.lock"
# Silence stderr for the redirection ONLY. Writing `exec 9>"$LOCK" 2>/dev/null`
# applies BOTH redirections to the shell permanently, so every diagnostic any
# later command wrote to stderr -- for the whole rest of the boot pass -- went to
# /dev/null. Save it on fd 8, silence, redirect, restore.
exec 8>&2
exec 9>"$LOCK" 2>/dev/null
exec 2>&8 8>&-
# umask 077 above already gives 0600; keep the chmod for a lock file an older
# build left behind wide.
chmod 0600 "$LOCK" 2>/dev/null
# Three outcomes, not two. `flock -n 9 || exit 0` conflated the last with the
# first: it reads ANY failure as "another pass already holds the lock" and
# returns silently having injected nothing.
#
# mksh (/system/bin/sh) marks a shell-opened fd >= 3 close-on-exec, so an
# external flock never receives fd 9 and fails EBADF no matter what. KSU runs
# module scripts under its bundled busybox ash, where the fd IS inherited and
# the guard works -- but anything invoking this script with /system/bin/sh gets
# a flock that CANNOT succeed, and the silent exit made that indistinguishable
# from a healthy second instance backing off.
#
# The probe asks an EXTERNAL process to look at its own fd table, which is the
# property flock depends on and needs no knowledge of which shell is running --
# `cmd >&9` would not do, because the parent performs that redirection and always
# succeeds. Verified on an OP11 to predict flock's outcome in both shells. An fd
# an external binary cannot see takes the same
# warn-and-continue path as a missing flock: no single-run guard, but said out
# loud, which is the documented behaviour for that case.
if ! command -v flock >/dev/null 2>&1; then
    nmlog "flock unavailable — mount pass running WITHOUT a single-run guard"
elif ! ls /proc/self/fd/9 >/dev/null 2>&1; then
    nmlog "fd 9 is close-on-exec in this shell, so flock cannot use it — mount pass running WITHOUT a single-run guard"
else
    flock -n 9 || { ksud kernel notify-module-mounted 2>/dev/null; exit 0; }
fi

ABI=$(getprop ro.product.cpu.abi)
# An unchecked ABI is a silent no-op: empty gives "$MODDIR/bin//nomount", which
# can never be executable, and the mount pass below is gated on [ -x "$BIN" ]
# with nothing on the other side -- so the whole boot injected nothing and said
# nothing about it. getprop CAN come back empty this early. Fall back to the
# first entry of the abilist, then to the only ABI this module actually ships,
# rather than building a path that cannot resolve.
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
# The Suite binary shells out to the hookless `nm` netlink client bundled beside it.
export NM_BIN="$MODDIR/bin/$ABI/nm"
# Did the engine actually run this boot? The status card at the bottom is written
# UNCONDITIONALLY, so a missing/non-executable binary used to leave it reading
# "[NoMount ✅ 0 rules · 0 RRO · 0 modules] fully mountless" -- a green tick on a
# boot that injected nothing. Worse: boot then completes, service.sh clears
# bootcount, and the bootloop guard is re-armed by a pass that never happened.
_engine_ran=0

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
    # RECORD the flag before clearing it, and put back only what was there.
    # `chattr +i` unconditionally was not a restore: on a device where ksud was
    # never immutable it ADDED immutability every boot, and the next legitimate
    # ksud update then failed with EPERM. (The clear is genuinely needed, but not
    # for the reason the old comment gave -- reading an immutable file is fine;
    # what needs it is the `mv` below, which UNLINKS $SUSFS_BIN, and unlinking a
    # hardlink to an immutable inode is refused.)
    _ksud_imm=0
    lsattr -d "$KSUD" 2>/dev/null | cut -d' ' -f1 | grep -q 'i' && _ksud_imm=1
    chattr -i "$KSUD" 2>/dev/null
    if cp "$KSUD" "$SUSFS_BIN.nm_new" 2>/dev/null; then
        chmod 0755 "$SUSFS_BIN.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$SUSFS_BIN.nm_new" 2>/dev/null
        mv -f "$SUSFS_BIN.nm_new" "$SUSFS_BIN" 2>/dev/null \
            && nmlog "de-linked ksu_susfs from ksud multicall (susfs-action guard)"
    else
        rm -f "$SUSFS_BIN.nm_new" 2>/dev/null
    fi
    [ "$_ksud_imm" = 1 ] && chattr +i "$KSUD" 2>/dev/null
fi

# --- bootloop guard ---
# NB: the spoof add-on runs INSIDE this guard (below), not before it. It used to
# run above, which meant `disabled` never suppressed it and the counter could not
# protect against it: spoof.sh drives resetprop, uname, /proc/cmdline and
# /proc/bootconfig -- a larger bootloop surface than the injection pass -- and it
# kept running every boot after the guard had already tripped, leaving a user
# bootlooping on a spoof setting with no self-recovery path.
GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > "$NMDIR/bootcount"

if [ -f "$NMDIR/disabled" ]; then
    nmlog "disabled, skipping spoof + mount"
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then
    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
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
else
    # --- spoof add-on (dynamic vbmeta.digest) ---
    # Still this post-fs-data stage, so the property is in place before
    # zygote/system_server come up, and still kept separate from the mount pass
    # so a spoof failure can't affect mounting -- but now guard-gated, so a
    # tripped counter (or a manual `disabled`) stops it like everything else.
    [ -f "$MODDIR/spoof.sh" ] && sh "$MODDIR/spoof.sh" 2>/dev/null

    if [ -x "$BIN" ]; then
        timeout 60 "$BIN" mount 2>/dev/null
        # Durable whiteouts, HERE rather than only in service.sh. A whiteout hides a
        # stock path that is itself the tell, and service.sh does not run it until
        # after sys.boot_completed plus a 10s settle -- so every such path was plainly
        # visible for the whole of boot, to anything that looked early. Nothing here
        # needs packages.list, so it belongs in the same pass as the injections.
        # service.sh still re-applies, which is idempotent and catches a late failure.
        [ -s "$NMDIR/whiteouts.txt" ] && timeout 30 "$BIN" whiteout apply 2>/dev/null
        _engine_ran=1
    else
        # The missing `else`. Without it a binary that is absent, not executable,
        # or sitting under an ABI directory this device does not have produced a
        # completely silent boot: nothing on kmsg, nothing on disk, and a green
        # card. Record it the same way a guard trip is recorded, because from the
        # user's side the symptom is identical -- their modules stopped working --
        # and incident.log is where the WebUI already looks for the reason.
        nmlog "⛔ engine binary is missing or not executable ($BIN) — NOTHING was injected this boot"
        {
            echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
            echo "reason=engine did not run: no executable at $BIN"
            echo "abi=$ABI (ro.product.cpu.abi=$(getprop ro.product.cpu.abi 2>/dev/null))"
            echo "shipped_abis=$(ls "$MODDIR/bin" 2>/dev/null | tr '\n' ' ')"
            echo "kernel=$(uname -r)"
            echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
            echo "note=reinstall the module zip; a partial/permission-stripped extraction is the usual cause"
        } > "$NMDIR/incident.log" 2>/dev/null
    fi
fi

# --- hiding ---
# Nothing to hide: the Suite is now FULLY MOUNTLESS. Hookless VFS injection covers
# regular files AND RRO overlay APKs (injected into /product/overlay etc.; OMS +
# idmap2 pick them up at the system_server scan, which runs after this post-fs-data
# pass). su is sucompat (mountless). There is no overlayfs mount and no work tmpfs,
# so a mount scanner sees only stock mounts — nothing to hide, no SUSFS, no umount.

# --- tag managed modules in the manager with how the Suite serves them ---
if command -v ksud >/dev/null 2>&1; then
    # ONE dump of the rule table, reused for every module below and for the
    # Suite's own card. This used to run `nm list` inside the per-module loop
    # plus twice more afterwards -- 16 full netlink dumps of ~260 rules during
    # post-fs-data on a 14-module device, all returning the same answer. The
    # engine's own directory scan was optimised precisely because this stage sits
    # under the OPlus boot watchdog; spending it again here made no sense.
    _NMLIST=$("$NM_BIN" list 2>/dev/null)
    # grep -c on an empty stream prints 0 and exits 1, so guard the empty case.
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
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
        _n=$(_nmcount -F "/data/adb/modules/$mid/")
        # Field 4 = the mount's root within its filesystem, so a module bind reads
        # "/adb/modules/<id>/...", never "/data/adb/modules/...". The old pattern
        # matched nothing, so every module was badged "mountless" regardless.
        _m=$(awk -v m="$mid" '$4 ~ "/adb/modules/" m "(/|$)" {n++} END{print n+0}' \
             /proc/self/mountinfo 2>/dev/null); _m=${_m:-0}
        _badge="$_t · $_n served"
        [ "${_m:-0}" -gt 0 ] && _badge="$_badge · ⚠ $_m mount(s)"
        _orig=$(sed -n 's/^description=//p' "$d/module.prop" | head -1)
        KSU_MODULE="$mid" ksud module config set --temp override.description \
            "[NoMount · $_badge] $_orig" >/dev/null 2>&1
    done

    # The Suite's own card doubles as the at-a-glance status readout, so put the live
    # numbers there rather than restating the tagline the module.prop already carries.
    _rules=$(_nmcount .)
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    _mods=0
    for _x in $_vf $_ov; do _mods=$((_mods + 1)); done
    _list=""
    [ -n "$_vf" ] && _list="vfs:$_vf"
    [ -n "$_ov" ] && _list="$_list${_list:+ | }overlay:$_ov"
    if [ -f "$NMDIR/disabled" ]; then
        _desc="[NoMount ⛔ disabled] bootloop guard tripped — open WebUI › Tools › Last incident"
    elif [ "$_engine_ran" = 0 ]; then
        # This block is NOT gated on [ -x "$BIN" ], so it used to render the green
        # card even on the boot where the engine never ran. It is the only surface
        # most users ever read; it must not claim a posture nothing established.
        _desc="[NoMount ⛔ engine did not run] the mount pass never executed this boot — open WebUI › Tools › Last incident"
    elif [ "${_rules:-0}" = 0 ]; then
        # ✅ next to "0 rules" is a contradiction the reader has to catch for
        # themselves. The engine ran, so this is not ⛔ — but it served nothing,
        # and a green tick on a boot that injected nothing is the same false
        # green, one branch further down.
        _desc="[NoMount ⚠️ 0 rules] engine ran but injected nothing — open WebUI › Tools › Health"
    else
        _desc="[NoMount ✅ $_rules rules · $_rro RRO · $_mods modules] fully mountless — hookless VFS + RRO, no overlayfs, su via sucompat${_list:+. $_list}"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description "$_desc" >/dev/null 2>&1
fi

ksud kernel notify-module-mounted 2>/dev/null
exit 0
