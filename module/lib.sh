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
    _fail=0
    for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
              absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
              absorbed.list binds.list absorbed-tmpfs.list apkstate.list; do
        [ -e "$_bak/$_f" ] || continue
        [ -e "$NMDIR/$_f" ] && continue
        if cp -p "$_bak/$_f" "$NMDIR/$_f" 2>/dev/null; then
            chmod 0600 "$NMDIR/$_f" 2>/dev/null
            chcon u:object_r:adb_data_file:s0 "$NMDIR/$_f" 2>/dev/null
            _rn=$((_rn + 1))
        else
            rm -f "$NMDIR/$_f" 2>/dev/null
            _fail=$((_fail + 1))
        fi
    done
    if [ "$_rn" -gt 0 ]; then
        nmlog "restored $_rn setting(s) from a stash left by an unfinished install"
    fi
    if [ "$_fail" -eq 0 ]; then
        rm -rf "$_bak" 2>/dev/null
    else
        nmlog "⚠ $_fail stashed setting(s) could not be restored - KEEPING $_bak so they are not lost; free some space and reboot"
    fi
    unset _bak _rn _fail _f
    return 0
}

_rl_summary() {
    _rls=$(printf '%s\n' "$1" | grep -m1 '^nomount reload:')
    [ -n "$_rls" ] || _rls=$(printf '%s\n' "$1" | tail -1)
    printf '%s' "$_rls"
    unset _rls
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
    [ -e "$NMDIR/disabled" ] && return 0
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
    _rro=$(printf '%s\n' "$_NMLIST" | awk '
        /\(whiteout\)|\(virtual dir\)/ { next }
        {
            t = $0
            sub(/[ \t]+\[UID:[ \t]*[0-9]+\][ \t]*$/, "", t)
            sub(/ \(public\)$/, "", t)
            sub(/ -> .*$/, "", t)
            if (t ~ /\/overlay\/[^ ]*\.apk$/) n++
        }
        END { print n+0 }')
    return 0
}

nm_early_absorb() {
    [ -e "$NMDIR/disabled" ] && return 0
    nm_guard_armed || return 0
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
    if [ "$(cat "$NMDIR/bootcount" 2>/dev/null)" != "$COUNT" ]; then
        nmlog "⛔ cannot write $NMDIR/bootcount - the bootloop guard cannot arm, so nothing is being injected this boot. /data being full is the usual cause; free space and reboot."
        return 3
    fi
    cat /proc/sys/kernel/random/boot_id > "$NMDIR/guard.ts" 2>/dev/null
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

nm_guard_armed() {
    _gab=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
    [ -n "$_gab" ] || return 0
    [ "$(cat "$NMDIR/guard.ts" 2>/dev/null)" = "$_gab" ]
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

# ---------------------------------------------------------------------------
# Zygisk library redirect
#
# A Zygisk implementation dlopen()s each enabled module's payload into app
# processes straight out of /data/adb, so that path lands in the app's OWN
# mapping list. The maps cloak answers that by deleting the line, and the hole
# it leaves is its own tell: on OP15 6.12.58, MAP_FIXED_NOREPLACE answers
# -EEXIST on the hidden range, reading the range returns an ELF header, and
# VmRSS minus smaps_rollup Rss is non-zero where no stock device produces that.
# None of it is closeable by rewriting what maps prints, because the leak is the
# mapped bytes, not the line.
#
# So serve the payload from a ROM path instead and leave a symlink behind. The
# loader opens the name it always did, the mapping names an ordinary system
# library, dev/ino match a stat() of it, and the bytes ARE that file's. Nothing
# needs hiding, so no hole exists to find.
#
# Three phases, around nm_mount_pass(), because each one depends on the last:
#
#   stage   hardlink the payload into the module's own system/lib64 tree and
#           declare the ROM path in public.txt. The original is NOT touched, so
#           a failure here or in the mount pass costs nothing.
#   (mount) the boot pass walks module trees and serves the new path. It reads
#           public.txt at add time, which is why staging has to come first --
#           that is what makes the rule `(public)` and so invisible to
#           `ghost sync`. Without it a blocked app would have the library
#           mapped while stat() of the same path answered ENOENT, which is a
#           sharper tell than the hole this replaces.
#   commit  read the ROM path back, compare it against the payload, and only
#           then replace the payload with a symlink to it.
#
# Every boot restores first and redirects second, so a boot where the engine
# never came up leaves the real files in place rather than a dangling link.
# The loader's own library is deliberately NOT redirected: it is loaded into
# zygote, and getting it wrong costs the boot rather than a module.
# ---------------------------------------------------------------------------

NM_ZR_STATE="$NMDIR/zygisk-redirect.list"
NM_ZR_PUBLIC="$NMDIR/public.txt"
NM_ZR_BEGIN="# >>> nomount zygisk-redirect (managed; edits here are lost)"
NM_ZR_END="# <<< nomount zygisk-redirect"

nm_zr_enabled() {
    [ -e "$NMDIR/no-zygisk-redirect" ] && return 1
    [ -e "$NMDIR/disabled" ] && return 1
    return 0
}

# size + sha256 of the first and last 64 KiB. Enough to catch a truncated or
# wrong-file serve without reading a megabyte twice on every boot.
nm_zr_fp() {
    [ -f "$1" ] || { echo "-"; return 0; }
    printf '%s:' "$(stat -c %s "$1" 2>/dev/null)"
    { head -c 65536 "$1"; tail -c 65536 "$1"; } 2>/dev/null \
        | sha256sum 2>/dev/null | cut -d' ' -f1
}

# A payload the device can never load must not be planted in the ROM: the file
# name IS its ABI, and an x86_64 ELF sitting in /system/lib64 on an arm64-only
# device is a louder anomaly than the mapping this redirect removes.
nm_zr_abi_ok() {
    case ",$_zabilist," in
        *",$1,"*) return 0 ;;
    esac
    return 1
}

nm_zr_rom_path() {
    _zh=$(printf '%s/%s' "$1" "$2" | sha256sum 2>/dev/null | cut -c1-12)
    [ -n "$_zh" ] || return 1
    case "$2" in
        *64*) printf '/system/lib64/lib%s.so' "$_zh" ;;
        *)    printf '/system/lib/lib%s.so'   "$_zh" ;;
    esac
}

# Undo everything a previous boot left behind, whatever state it is in.
nm_zr_restore() {
    [ -f "$NM_ZR_STATE" ] || return 0
    while IFS='	' read -r _zrom _zreal _zmat; do
        [ -n "$_zreal" ] || continue
        if [ -L "$_zreal" ]; then
            rm -f "$_zreal" 2>/dev/null
            [ -f "$_zreal.nmsrc" ] && mv -f "$_zreal.nmsrc" "$_zreal" 2>/dev/null
        elif [ -f "$_zreal" ] && [ -f "$_zreal.nmsrc" ]; then
            # the module was reinstalled under us; its own file wins
            rm -f "$_zreal.nmsrc" 2>/dev/null
        fi
        [ -n "$_zmat" ] && rm -f "$_zmat" 2>/dev/null
    done < "$NM_ZR_STATE"
    rm -f "$NM_ZR_STATE" 2>/dev/null
    # and drop the managed block: a declaration naming paths nothing serves any
    # more is stale state, and stale state is what every other bug this file
    # guards against started as.
    rm -f "$NMDIR/.zr-public.$$" 2>/dev/null
    nm_zr_public_rewrite
    unset _zrom _zreal _zmat
}

nm_zr_public_rewrite() {
    _zp="$NM_ZR_PUBLIC"
    _zt="$NMDIR/.public.txt.$$"
    : > "$_zt" || return 1
    if [ -f "$_zp" ]; then
        awk -v b="$NM_ZR_BEGIN" -v e="$NM_ZR_END" \
            'index($0,b)==1{skip=1;next} index($0,e)==1{skip=0;next} !skip' \
            "$_zp" >> "$_zt" 2>/dev/null
    fi
    if [ -s "$NMDIR/.zr-public.$$" ]; then
        printf '%s\n' "$NM_ZR_BEGIN" >> "$_zt"
        cat "$NMDIR/.zr-public.$$" >> "$_zt"
        printf '%s\n' "$NM_ZR_END" >> "$_zt"
    fi
    chmod 0600 "$_zt" 2>/dev/null
    mv -f "$_zt" "$_zp" 2>/dev/null
    unset _zp _zt
}

nm_zr_stage() {
    nm_zr_restore
    nm_zr_enabled || { rm -f "$NMDIR/.zr-public.$$" 2>/dev/null; nm_zr_public_rewrite; return 0; }

    _zabilist=$(getprop ro.product.cpu.abilist 2>/dev/null)
    [ -n "$_zabilist" ] || _zabilist=$(getprop ro.product.cpu.abi 2>/dev/null)
    [ -n "$_zabilist" ] || return 0

    : > "$NMDIR/.zr-public.$$" 2>/dev/null || return 0
    : > "$NM_ZR_STATE" 2>/dev/null || { rm -f "$NMDIR/.zr-public.$$"; return 0; }
    chmod 0600 "$NM_ZR_STATE" 2>/dev/null

    for _zso in /data/adb/modules/*/zygisk/*.so; do
        [ -f "$_zso" ] || continue
        case "$_zso" in *'*'*) continue ;; esac
        [ -L "$_zso" ] && continue
        _zmid=${_zso#/data/adb/modules/}; _zmid=${_zmid%%/*}
        [ "$_zmid" = meta-nomount ] && continue
        { [ -f "/data/adb/modules/$_zmid/disable" ] || [ -f "/data/adb/modules/$_zmid/remove" ] \
          || [ -f "/data/adb/modules/$_zmid/skip_mount" ]; } && continue
        _zabi=${_zso##*/}; _zabi=${_zabi%.so}
        nm_zr_abi_ok "$_zabi" || continue
        _zrom=$(nm_zr_rom_path "$_zmid" "$_zabi") || continue
        _zdir=/data/adb/modules/$_zmid${_zrom%/*}
        _zmat="$_zdir/${_zrom##*/}"
        mkdir -p "$_zdir" 2>/dev/null || continue
        rm -f "$_zmat" 2>/dev/null
        # hardlink, not a copy: same filesystem, so the bytes cannot drift and
        # a module update leaves a stale link we drop on the next restore.
        ln "$_zso" "$_zmat" 2>/dev/null || cp -f "$_zso" "$_zmat" 2>/dev/null || continue
        printf '%s\n' "$_zrom" >> "$NMDIR/.zr-public.$$"
        printf '%s\t%s\t%s\n' "$_zrom" "$_zso" "$_zmat" >> "$NM_ZR_STATE"
    done
    nm_zr_public_rewrite
    rm -f "$NMDIR/.zr-public.$$" 2>/dev/null
    unset _zso _zmid _zabi _zrom _zdir _zmat _zabilist
}

nm_zr_commit() {
    [ -f "$NM_ZR_STATE" ] || return 0
    nm_zr_enabled || { nm_zr_restore; return 0; }
    _zok=0; _zno=0
    while IFS='	' read -r _zrom _zreal _zmat; do
        if [ -z "$_zrom" ] || [ -z "$_zreal" ]; then continue; fi
        [ -f "$_zreal" ] || { _zno=$((_zno + 1)); continue; }
        if [ "$(nm_zr_fp "$_zrom")" != "$(nm_zr_fp "$_zreal")" ]; then
            rm -f "$_zmat" 2>/dev/null
            _zno=$((_zno + 1))
            continue
        fi
        if mv -f "$_zreal" "$_zreal.nmsrc" 2>/dev/null; then
            if ln -s "$_zrom" "$_zreal" 2>/dev/null; then
                _zok=$((_zok + 1))
            else
                mv -f "$_zreal.nmsrc" "$_zreal" 2>/dev/null
                rm -f "$_zmat" 2>/dev/null
                _zno=$((_zno + 1))
            fi
        else
            _zno=$((_zno + 1))
        fi
    done < "$NM_ZR_STATE"
    if [ "$_zok" -gt 0 ] || [ "$_zno" -gt 0 ]; then
        nmlog "zygisk redirect: $_zok library(ies) now served from the ROM$([ "$_zno" -gt 0 ] && echo ", $_zno left in /data/adb (served path did not read back)")"
    fi
    unset _zok _zno _zrom _zreal _zmat
}
