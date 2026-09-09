#!/system/bin/sh
MODDIR="${0%/*}"
NMDIR=/data/adb/nomount
umask 077
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"

BOOTLOG="$NMDIR/boot.log"
[ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
    && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
: >> "$BOOTLOG" 2>/dev/null
chmod 0600 "$BOOTLOG" 2>/dev/null

rm -f "$NMDIR/.uidwatch.lock" 2>/dev/null
rm -rf /data/adb/nomount.bak 2>/dev/null
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data] $*" >> "$BOOTLOG" 2>/dev/null
}

if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    nmlog "KSU/APatch detected - the metamodule hook (metamount.sh) owns this boot"
    exit 0
fi

cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null

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

ABI=$(getprop ro.product.cpu.abi)
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"
chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

if [ ! -f "$NMDIR/disabled" ] && [ -x "$BIN" ] \
   && { [ -f "$NMDIR/my_hookless" ] || [ "$NM_MY_HOOKLESS" = 1 ]; }; then
    _ea=$(nmto 60 "$BIN" absorb --early 2>&1)
    _ea_rc=$?
    if [ "$_ea_rc" -eq 124 ]; then
        nmlog "⚠ early absorb timed out after 60s - continuing boot"
    elif [ "$_ea_rc" -ne 0 ]; then
        nmlog "⚠ early absorb FAILED (rc=$_ea_rc): $(printf '%s\n' "$_ea" | tail -1)"
    else
        nmlog "early absorb: $(printf '%s\n' "$_ea" | tail -1)"
    fi
fi

GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
COUNT=$((COUNT + 1))
echo "$COUNT" > "$NMDIR/bootcount"

if [ -f "$NMDIR/disabled" ]; then
    :
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then
    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
    : > "$NMDIR/disabled"
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX (magisk post-fs-data path)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
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
        nmto 60 "$BIN" mount 2>/dev/null
        _mrc=$?
        [ "$_mrc" -ne 0 ] && nmlog "⚠ mount pass exited $_mrc - the injection set may be incomplete"
        if [ -s "$NMDIR/whiteouts.txt" ]; then
            nmto 30 "$BIN" whiteout apply 2>/dev/null
            _wrc=$?
            [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc - hidden paths are still visible this boot"
        fi
    else
        nmlog "⛔ engine binary is missing or not executable ($BIN) - nothing was injected this boot"
        {
            echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
            echo "reason=engine did not run: no executable at $BIN (magisk post-fs-data path)"
            echo "abi=$ABI (ro.product.cpu.abi=$(getprop ro.product.cpu.abi 2>/dev/null))"
            echo "shipped_abis=$(ls "$MODDIR/bin" 2>/dev/null | tr '\n' ' ')"
            echo "kernel=$(uname -r)"
            echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
            echo "note=reinstall the module zip; a partial/permission-stripped extraction is the usual cause"
        } > "$NMDIR/incident.log" 2>/dev/null
    fi
fi
exit 0
