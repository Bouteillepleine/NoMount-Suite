#!/system/bin/sh

umask 077

NMDIR=/data/adb/nomount
BOOTLOG="$NMDIR/boot.log"

nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [${NMLOG_TAG:-nomount}] $*" >> "$BOOTLOG" 2>/dev/null
}

nmlog_absorb_notes() {
    printf '%s\n' "$1" | grep -i 'uninstalled module' | while IFS= read -r _l; do
        [ -n "$_l" ] && nmlog "$_l"
    done
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

nm_state_dir_repair() {
    find "$NMDIR" -maxdepth 1 -type f -exec chmod 0600 {} + 2>/dev/null
    find "$NMDIR" -maxdepth 1 -mindepth 1 -type d -exec chmod 0700 {} + 2>/dev/null
    chcon -R u:object_r:adb_data_file:s0 "$NMDIR" 2>/dev/null
    return 0
}

nm_consume_stash() {
    _bak=/data/adb/nomount.bak
    [ -d "$_bak" ] || { unset _bak; return 0; }
    _rn=0
    for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
              absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
              absorbed.list binds.list absorbed-tmpfs.list apkstate.list; do
        [ -e "$_bak/$_f" ] || continue
        [ -e "$NMDIR/$_f" ] && continue
        cp -p "$_bak/$_f" "$NMDIR/$_f" 2>/dev/null || { rm -f "$NMDIR/$_f" 2>/dev/null; continue; }
        chmod 0600 "$NMDIR/$_f" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$NMDIR/$_f" 2>/dev/null
        _rn=$((_rn + 1))
    done
    [ "$_rn" -gt 0 ] && nmlog "restored $_rn setting(s) from a stash left by an unfinished install"
    rm -rf "$_bak" 2>/dev/null
    unset _bak _rn _f
    return 0
}

_has_entries() { [ -s "$1" ] && grep -qE '^[[:space:]]*[^[:space:]#]' "$1" 2>/dev/null; }

nm_boot_log_rotate() {
    [ -e "$BOOTLOG" ] && [ ! -f "$BOOTLOG" ] && rm -rf "$BOOTLOG" 2>/dev/null
    [ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
        && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
    touch "$BOOTLOG" 2>/dev/null || return 0
    chmod 0600 "$BOOTLOG" 2>/dev/null
    return 0
}

nm_incident_tombstone() {
    # shellcheck disable=SC2010  # `ls -t` is the point: we want the newest
    _t=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
    [ -n "$_t" ] || return 0
    echo "tombstone=$_t"
    echo "  $(grep -m1 '>>> ' "$_t" 2>/dev/null)"
    echo "  $(grep -m1 'Abort message' "$_t" 2>/dev/null)"
    return 0
}

nm_set_bin() {
    ABI=$(getprop ro.product.cpu.abi)
    [ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
    [ -n "$ABI" ] || ABI=arm64-v8a
    # shellcheck disable=SC2034  # read by the sourcing script, which shellcheck
    BIN="$MODDIR/bin/$ABI/nomount"
    NM_BIN="$MODDIR/bin/$ABI/nm"
    export NM_BIN
}

nm_fix_shell_tmp() {
    _fst=$(grep "^[ 	]*fix_shell_tmp[ 	]*=" "$NMDIR/spoof.conf" 2>/dev/null \
           | tail -n 1 | sed "s/^[^=]*=//; s/[ 	]#.*//; s/[\"' 	]//g")
    [ "${_fst:-1}" = "1" ] || return 0
    [ -d /data/local/tmp ] || mkdir -p /data/local/tmp 2>/dev/null
    if [ ! -d /data/local/tmp ]; then
        nmlog "shell-tmp: /data/local/tmp absent and not creatable"
        return 0
    fi
    _stm=$(stat -c %a /data/local/tmp 2>/dev/null)
    _sto=$(stat -c %u:%g /data/local/tmp 2>/dev/null)
    _stc=$(stat -c %C /data/local/tmp 2>/dev/null)
    # shellcheck disable=SC2012  # `ls -Zd` on one known directory: there is no
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
    return 0
}

nm_delink_ksud() {
    _kd=/data/adb/ksud
    _ks=/data/adb/ksu/bin/ksu_susfs
    [ -f "$_kd" ] && [ -f "$_ks" ] || return 0
    [ "$(stat -c %s "$_kd" 2>/dev/null)" -gt 1000000 ] 2>/dev/null || return 0
    [ "$(stat -c %i "$_kd" 2>/dev/null)" = "$(stat -c %i "$_ks" 2>/dev/null)" ] || return 0
    _kimm=0
    lsattr -d "$_kd" 2>/dev/null | cut -d' ' -f1 | grep -q 'i' && _kimm=1
    chattr -i "$_kd" 2>/dev/null
    if cp "$_kd" "$_ks.nm_new" 2>/dev/null; then
        chmod 0755 "$_ks.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$_ks.nm_new" 2>/dev/null
        mv -f "$_ks.nm_new" "$_ks" 2>/dev/null \
            && nmlog "de-linked ksu_susfs from ksud multicall (${1:-susfs-action guard})"
    else
        rm -f "$_ks.nm_new" 2>/dev/null
    fi
    [ "$_kimm" = 1 ] && chattr +i "$_kd" 2>/dev/null
    return 0
}

nm_mount_pass() {
    _mout="$(nmto 60 "$BIN" mount 2>&1)"
    _mrc=$?
    _pass_ran=1
    [ -n "$_mout" ] && printf '%s\n' "$_mout"
    if [ "$_mrc" -ne 0 ]; then
        nmlog "⚠ mount pass exited $_mrc ($([ "$_mrc" -eq 124 ] && echo "TIMED OUT after 60s" || echo "failed")) - the injection set may be incomplete"
        _mwhy=$(printf '%s\n' "$_mout" | grep -m1 -i 'not responding\|Caused by\|^Error')
        [ -n "$_mwhy" ] && nmlog "  reason: $_mwhy"
        unset _mwhy
    else
        _msum=$(printf '%s\n' "$_mout" | grep -m1 '^nomount(suite):')
        [ -n "$_msum" ] && nmlog "$_msum"
        unset _msum
    fi
    case "$_mout" in
        *"nomount: WARNING"*)
            nmlog "$(printf '%s\n' "$_mout" | grep "nomount: WARNING" | head -1)"
            ;;
    esac
    case "$_mout" in *"engine not responding"*) _driver_ok=0 ;; esac
    unset _mout
    if _has_entries "$NMDIR/whiteouts.txt"; then
        _wout=$(nmto 30 "$BIN" whiteout apply 2>&1)
        _wrc=$?
        [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc - hidden paths are still visible this boot: $(printf '%s\n' "$_wout" | tail -1)"
        unset _wout _wrc
    fi
    return "$_mrc"
}

nm_rule_counts() {
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    _nmlrc=$?
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    _rules=$(_nmcount -v -c -E '\(virtual dir\)|\(whiteout\)')
    _wo=$(_nmcount -c '(whiteout)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    return 0
}

nm_early_absorb() {
    [ -e "$NMDIR/disabled" ] && return 0
    [ -x "$BIN" ] || return 0
    [ -f "$NMDIR/my_hookless" ] || return 0
    _ea=$(nmto 60 "$BIN" absorb --early 2>&1)
    _ea_rc=$?
    nmlog_absorb_notes "$_ea"
    if [ "$_ea_rc" -eq 124 ]; then
        nmlog "⚠ early absorb timed out after 60s - continuing boot"
    elif [ "$_ea_rc" -ne 0 ]; then
        nmlog "⚠ early absorb FAILED (rc=$_ea_rc): $(printf '%s\n' "$_ea" | tail -1)"
    else
        nmlog "early absorb: $(printf '%s\n' "$_ea" | tail -1)"
    fi
}

nm_guard_bump() {
    for _f in bootcount disabled; do
        if [ -e "$NMDIR/$_f" ] && [ ! -f "$NMDIR/$_f" ]; then
            rm -rf "${NMDIR:?}/$_f" 2>/dev/null
            nmlog "⚠ $NMDIR/$_f was not a regular file (the guard cannot use it) - removed"
        fi
    done
    GUARD_MAX=3
    COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
    case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
    COUNT=$((COUNT + 1))
    echo "$COUNT" > "$NMDIR/bootcount"
    [ "$(cat "$NMDIR/bootcount" 2>/dev/null)" = "$COUNT" ] \
        || nmlog "⚠ cannot write $NMDIR/bootcount - the bootloop guard is not arming this boot"
    sync 2>/dev/null

    if [ -e "$NMDIR/disabled" ]; then
        nmlog "disabled, skipping the mount pass"
        return 1
    fi
    [ "$COUNT" -lt "$GUARD_MAX" ] && return 0

    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
    touch "$NMDIR/disabled" 2>/dev/null \
        || nmlog "⚠ could not create $NMDIR/disabled - the guard tripped but cannot self-disable"
    sync 2>/dev/null
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX ($1)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
        echo "modules_enabled=$(for m in /data/adb/modules/*/; do
                [ -f "$m/disable" ] || [ -f "$m/remove" ] || [ -f "$m/skip_mount" ] && continue
                basename "$m"
            done | tr '\n' ' ')"
        nm_incident_tombstone
    } > "$NMDIR/incident.log" 2>/dev/null
    return 2
}

nm_incident_missing_binary() {
    nmlog "⛔ engine binary is missing or not executable ($BIN) - nothing was injected this boot"
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "reason=engine did not run: no executable at $BIN ($1)"
        echo "abi=$ABI (ro.product.cpu.abi=$(getprop ro.product.cpu.abi 2>/dev/null))"
        # shellcheck disable=SC2012  # listing the ABI directories the ZIP shipped, by
        echo "shipped_abis=$(ls "$MODDIR/bin" 2>/dev/null | tr '\n' ' ')"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "note=reinstall the module zip; a partial/permission-stripped extraction is the usual cause"
    } > "$NMDIR/incident.log" 2>/dev/null
}
