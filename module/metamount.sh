#!/system/bin/sh
MODDIR="${0%/*}"
NMDIR=/data/adb/nomount
umask 077
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"
find "$NMDIR" -maxdepth 1 -type f -exec chmod 0600 {} + 2>/dev/null
find "$NMDIR" -maxdepth 1 -mindepth 1 -type d -exec chmod 0700 {} + 2>/dev/null
chcon -R u:object_r:adb_data_file:s0 "$NMDIR" 2>/dev/null

BOOTLOG="$NMDIR/boot.log"
[ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
    && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
: >> "$BOOTLOG" 2>/dev/null
chmod 0600 "$BOOTLOG" 2>/dev/null

rm -f "$NMDIR/.uidwatch.lock" 2>/dev/null

rm -rf /data/adb/nomount.bak 2>/dev/null

cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null

nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [metamount] $*" >> "$BOOTLOG" 2>/dev/null
}

if command -v timeout >/dev/null 2>&1; then
    nmto() { timeout "$@"; }
else
    nmto() {
        _nmto_s=$1
        shift
        "$@" &
        _nmto_p=$!
        _nmto_n=0
        while [ "$_nmto_n" -lt "$_nmto_s" ]; do
            kill -0 "$_nmto_p" 2>/dev/null || break
            sleep 1
            _nmto_n=$((_nmto_n + 1))
        done
        if kill -0 "$_nmto_p" 2>/dev/null; then
            kill -TERM "$_nmto_p" 2>/dev/null
            sleep 1
            kill -KILL "$_nmto_p" 2>/dev/null
            wait "$_nmto_p" 2>/dev/null
            return 124
        fi
        wait "$_nmto_p"
    }
fi

LOCK="$NMDIR/.mount.lock"
exec 8>&2
exec 9>"$LOCK" 2>/dev/null
exec 2>&8 8>&-
chmod 0600 "$LOCK" 2>/dev/null
if ! command -v flock >/dev/null 2>&1; then
    nmlog "flock unavailable - mount pass running without a single-run guard"
elif ! ls /proc/self/fd/9 >/dev/null 2>&1; then
    nmlog "fd 9 is close-on-exec in this shell, so flock cannot use it - mount pass running without a single-run guard"
else
    flock -n 9 || { ksud kernel notify-module-mounted 2>/dev/null; exit 0; }
fi

ABI=$(getprop ro.product.cpu.abi)
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"
_engine_ran=0

chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

if [ -f "$MODDIR/lkm-load.sh" ]; then
    NM_LKM_SAY=:
    NM_LKM_NM="$NM_BIN"
    NM_LKM_LOADER="$MODDIR/loader"
    export NM_LKM_SAY NM_LKM_NM NM_LKM_LOADER
    . "$MODDIR/lkm-load.sh"
    chmod 0755 "$NM_LKM_LOADER" 2>/dev/null

    if nm_lkm_probe; then
        :
    elif [ -f "$MODDIR/lkm/nomount.ko" ]; then
        if nm_lkm_insert "$MODDIR/lkm/nomount.ko"; then
            nmlog "engine module loaded ($(uname -r))"
        else
            nmlog "⛔ engine module failed to load - nothing will be injected this boot"
        fi
    elif nm_lkm_load_best "$MODDIR/lkm"; then
        nm_lkm_prune "$MODDIR/lkm"
        nmlog "engine module selected and loaded on first boot ($(uname -r))"
    else
        nmlog "⛔ no bundled engine module loads on $(uname -r) - nothing was injected this boot"
    fi
fi

KSUD=/data/adb/ksud
SUSFS_BIN=/data/adb/ksu/bin/ksu_susfs
if [ -f "$KSUD" ] && [ -f "$SUSFS_BIN" ] \
   && [ "$(stat -c %i "$KSUD" 2>/dev/null)" = "$(stat -c %i "$SUSFS_BIN" 2>/dev/null)" ] \
   && [ "$(stat -c %s "$KSUD" 2>/dev/null)" -gt 1000000 ]; then
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

GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
COUNT=$((COUNT + 1))
echo "$COUNT" > "$NMDIR/bootcount"

if [ -f "$NMDIR/disabled" ]; then
    nmlog "disabled, skipping the mount pass"
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then
    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
    : > "$NMDIR/disabled"
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
        echo "modules_enabled=$(for m in /data/adb/modules/*/; do
                [ -f "$m/disable" ] || [ -f "$m/remove" ] || [ -f "$m/skip_mount" ] && continue
                basename "$m"
            done | tr '\n' ' ')"
        # shellcheck disable=SC2010  # `ls -t` is the point: we want the newest
        _t=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
        if [ -n "$_t" ]; then
            echo "tombstone=$_t"
            echo "  $(grep -m1 '>>> ' "$_t" 2>/dev/null)"
            echo "  $(grep -m1 'Abort message' "$_t" 2>/dev/null)"
        fi
    } > "$NMDIR/incident.log" 2>/dev/null
else
    _fst=$(grep "^[ 	]*fix_shell_tmp[ 	]*=" "$NMDIR/spoof.conf" 2>/dev/null \
           | tail -n 1 | sed "s/^[^=]*=//; s/[ 	]#.*//; s/[\"' 	]//g")
    if [ "${_fst:-1}" = "1" ]; then
        [ -d /data/local/tmp ] || mkdir -p /data/local/tmp 2>/dev/null
        if [ ! -d /data/local/tmp ]; then
            nmlog "shell-tmp: /data/local/tmp absent and not creatable"
        else
            _stm=$(stat -c %a /data/local/tmp 2>/dev/null)
            _sto=$(stat -c %u:%g /data/local/tmp 2>/dev/null)
            _stc=$(stat -c %C /data/local/tmp 2>/dev/null)
            case "$_stc" in *:*:*) ;; *) _stc=$(ls -Zd /data/local/tmp 2>/dev/null | awk '{print $1}') ;; esac
            case "$_stc" in *:*:*) ;; *) _stc="" ;; esac
            _stw=""
            [ "$_stm" = "771" ] || { chmod 0771 /data/local/tmp 2>/dev/null && _stw="$_stw mode:${_stm:-?}->771"; }
            [ "$_sto" = "2000:2000" ] || { chown 2000:2000 /data/local/tmp 2>/dev/null && _stw="$_stw owner:${_sto:-?}->2000:2000"; }
            if [ -n "$_stc" ] && [ "$_stc" != "u:object_r:shell_data_file:s0" ]; then
                chcon u:object_r:shell_data_file:s0 /data/local/tmp 2>/dev/null \
                    && _stw="$_stw ctx:$_stc->shell_data_file"
            fi
            [ -n "$_stw" ] && nmlog "shell-tmp:$_stw"
        fi
    fi

    if [ -x "$BIN" ]; then
        _mout="$(nmto 60 "$BIN" mount 2>/dev/null)"
        _mrc=$?
        [ -n "$_mout" ] && printf '%s\n' "$_mout"
        if [ "$_mrc" -ne 0 ]; then
            nmlog "⚠ mount pass exited $_mrc ($([ "$_mrc" -eq 124 ] && echo "TIMED OUT after 60s" || echo "failed")) - the injection set may be incomplete"
        fi
        case "$_mout" in
            *"nomount: WARNING"*)
                nmlog "$(printf '%s\n' "$_mout" | grep "nomount: WARNING" | head -1)"
                ;;
        esac
        unset _mout
        if [ -s "$NMDIR/whiteouts.txt" ]; then
            nmto 30 "$BIN" whiteout apply 2>/dev/null
            _wrc=$?
            [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc - hidden paths are still visible this boot"
        fi
        _engine_ran=1
    else
        nmlog "⛔ engine binary is missing or not executable ($BIN) - nothing was injected this boot"
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

if command -v ksud >/dev/null 2>&1; then
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    _vf=""; _ov=""
    if [ -f "$NMDIR/disabled" ]; then
        nmlog "guard is tripped - skipping per-module tagging (nothing is served)"
    else
    for d in /data/adb/modules/*/; do
        [ -d "$d" ] || continue
        mid=$(basename "$d")
        { [ "$mid" = "meta-nomount" ] || [ "$mid" = "kernelnosu" ]; } && continue
        { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && continue
        _roots=""
        for _pd in "$d"*/; do
            [ -d "$_pd" ] || continue
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
        [ -n "$(nmto 10 find $_roots -path '*/overlay/*.apk' -print -quit 2>/dev/null)" ] && _o=1
        [ -n "$(nmto 10 find $_roots -type f ! -path '*/overlay/*' -print -quit 2>/dev/null)" ] && _v=1
        [ "$_o" = 0 ] && [ "$_v" = 0 ] && continue
        if [ "$_o" = 1 ] && [ "$_v" = 1 ]; then _t="vfs + overlay"; _ov="$_ov $mid";
        elif [ "$_o" = 1 ]; then _t="overlay"; _ov="$_ov $mid";
        else _t="vfs"; _vf="$_vf $mid"; fi
        _n=$(_nmcount -F "/data/adb/modules/$mid/")
        _m=$(awk -v m="$mid" '$4 ~ "/adb/modules/" m "(/|$)" {n++} END{print n+0}' \
             /proc/self/mountinfo 2>/dev/null); _m=${_m:-0}
        _badge="$_t · $_n served"
        [ "${_m:-0}" -gt 0 ] && _badge="$_badge · ⚠ $_m mount(s)"
        _orig=$(sed -n 's/^description=//p' "$d/module.prop" | head -1)
        KSU_MODULE="$mid" ksud module config set --temp override.description \
            "[NoMount · $_badge] $_orig" >/dev/null 2>&1
    done
    fi

    _rules=$(_nmcount -vc '(virtual dir)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    _mods=0
    for _x in $_vf $_ov; do _mods=$((_mods + 1)); done
    _list=""
    [ -n "$_vf" ] && _list="vfs:$_vf"
    [ -n "$_ov" ] && _list="$_list${_list:+ | }overlay:$_ov"
    if [ -f "$NMDIR/disabled" ]; then
        _desc="[NoMount ⛔ disabled] bootloop guard tripped - open the NoMount WebUI"
    elif [ "$_engine_ran" = 0 ]; then
        _desc="[NoMount ⛔ engine did not run] the mount pass never executed this boot - open the NoMount WebUI"
    elif [ "${_rules:-0}" = 0 ]; then
        _desc="[NoMount ⚠️ 0 rules] engine ran but injected nothing - open the NoMount WebUI"
    else
        _desc="[NoMount ✅ $_rules rules · $_rro RRO · $_mods modules] fully mountless - hookless VFS + RRO, no overlayfs, su via sucompat${_list:+. $_list}"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description "$_desc" >/dev/null 2>&1
fi

ksud kernel notify-module-mounted 2>/dev/null
exit 0
