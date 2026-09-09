#!/system/bin/sh
NMDIR=/data/adb/nomount
umask 077

MODDIR="${0%/*}"
ABI=$(getprop ro.product.cpu.abi)
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"

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

BOOTLOG="$NMDIR/boot.log"
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [service] $*" >> "$BOOTLOG" 2>/dev/null
}

_now=$(date +%s 2>/dev/null || echo 0)
_up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
_epoch_known=1
case "$_now$_up" in *[!0-9]*|"") _now=0; _up=0; _epoch_known=0 ;; esac
_bootepoch=$((_now - _up))
[ "$_bootepoch" -ge 1000000000 ] 2>/dev/null || _epoch_known=0
_health_fresh() {
    [ "$_epoch_known" = 1 ] || return 1
    _hts=$(sed -n 's/^ts=//p' "$NMDIR/health.txt" 2>/dev/null)
    case "$_hts" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_hts" -ge "$_bootepoch" ]
}
_health_get() {
    _health_fresh || return 0
    sed -n "s/^$1=//p" "$NMDIR/health.txt" 2>/dev/null
}

i=0
booted=0
while [ "$i" -lt 120 ]; do
    if [ "$(getprop sys.boot_completed)" = "1" ]; then booted=1; break; fi
    sleep 2
    i=$((i + 1))
done

sleep 10
if [ "$booted" = "1" ]; then
    rm -f "$NMDIR/bootcount"
    nmlog "boot completed, guard counter reset"
else
    nmlog "boot_completed never set - leaving guard counter armed"
fi

_hookran=1
_bootid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if [ -n "$_bootid" ]; then
    [ "$(cat "$NMDIR/mountpass.ts" 2>/dev/null)" = "$_bootid" ] || _hookran=0
fi
if [ "$_hookran" = 0 ]; then
    nmlog "⛔ the mount pass never ran this boot - nothing was injected. On KernelSU this means the manager has no metamodule support (metamount.sh is never invoked); on Magisk it means post-fs-data.sh did not run."
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "reason=no boot entry point ran: $NMDIR/mountpass.ts is absent or stale"
        echo "ksu_env_seen_by_post_fs_data=see boot.log [post-fs-data] lines"
        echo "manager=$(ksud -V 2>/dev/null | head -1)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "note=NoMount is a metamodule. It needs a KernelSU/SukiSU/APatch build that supports metamodules, or Magisk. Update the manager."
    } > "$NMDIR/incident.log" 2>/dev/null
fi

if [ -x "$NM_BIN" ] && "$NM_BIN" k g >/dev/null 2>&1; then
    nmto 10 "$NM_BIN" k g "p-" >/dev/null 2>&1 || nmlog "⚠ ghost: path table clear FAILED"
    nmto 10 "$NM_BIN" k g "u-" >/dev/null 2>&1 || nmlog "⚠ ghost: uid table clear FAILED"

    _ghn=0; _ghg=0; _ghf=0
    _ghprobe=""
    if [ -f "$NMDIR/uidhide.cache" ]; then
        while IFS= read -r _ghl; do
            _ghl=$(echo "$_ghl" | tr -d '\r')
            case "$_ghl" in ''|\#*) continue ;; esac
            _ghi=${_ghl##*[!0-9]}
            case "$_ghi" in ''|*[!0-9]*) continue ;; esac
            [ "$_ghi" = "0" ] && continue
            _ghprobe="$_ghi"; break
        done < "$NMDIR/uidhide.cache"
    fi
    _ghraw=$(nmto 10 "$NM_BIN" l 2>/dev/null); _ghrc=$?
    if [ "$_ghrc" -ne 0 ]; then
        nmlog "⚠ ghost: rule dump FAILED (nm exit $_ghrc) - path table not populated"
        _ghcand=
    else
        _ghcand=$(printf '%s\n' "$_ghraw" | sed 's/ ->.*//; s/ (.*//' | grep '^/' | sort -u)
    fi
    _ghn=$(printf '%s\n' "$_ghcand" | grep -c '^/')
    if [ -n "$_ghprobe" ] && [ "$_ghn" -gt 0 ]; then
        _ghlist=$(printf '%s\n' "$_ghcand" | su "$_ghprobe" -c \
            'while IFS= read -r p; do d=${p%/*}; [ -n "$d" ] || d=/; \
             [ -x "$d" ] || continue; \
             [ -e "$p" ] || printf "%s\n" "$p"; done' 2>/dev/null)
        _ghrej=""
        _oifs=$IFS
        IFS='
'
        for _ghp in $_ghlist; do
            IFS=$_oifs
            case "$_ghp" in /*) ;; *) IFS='
'; continue ;; esac
            _ghg=$((_ghg + 1))
            if ! nmto 10 "$NM_BIN" k g "p+$_ghp" >/dev/null 2>&1; then
                _ghf=$((_ghf + 1))
                [ "$_ghf" -le 3 ] && _ghrej="$_ghrej $_ghp"
            fi
            IFS='
'
        done
        IFS=$_oifs
    else
        nmlog "⚠ ghost: no hidden uid to probe with - path table left empty (cloak inert)"
    fi

    _ghu=0; _ghuf=0
    if [ -f "$NMDIR/uidhide.cache" ]; then
        while IFS= read -r _ghl; do
            _ghl=$(echo "$_ghl" | tr -d '\r')
            case "$_ghl" in ''|\#*) continue ;; esac
            _ghi=${_ghl##*[!0-9]}
            case "$_ghi" in ''|*[!0-9]*) continue ;; esac
            [ "$_ghi" = "0" ] && continue
            _ghu=$((_ghu + 1))
            nmto 10 "$NM_BIN" k g "u+$_ghi" >/dev/null 2>&1 || _ghuf=$((_ghuf + 1))
        done < "$NMDIR/uidhide.cache"
    fi

    if [ "$_ghf" -gt 0 ] || [ "$_ghuf" -gt 0 ]; then
        nmlog "⚠ ghost cloak: $_ghf/$_ghg path(s) and $_ghuf/$_ghu uid(s) rejected - the existence oracles stay open for those; first:$_ghrej (table full, or a path over the kernel's rule-length cap)"
    elif [ "$_ghg" = 0 ] || [ "$_ghu" = 0 ]; then
        nmlog "⚠ ghost cloak inert: $_ghg of $_ghn path(s), $_ghu uid(s) - both tables must be non-empty for any guard to fire"
    else
        nmlog "ghost cloak populated ($_ghg of $_ghn paths ghostable, $_ghu uids)"
    fi
fi

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

KSUD=/data/adb/ksud
SUSFS_BIN=/data/adb/ksu/bin/ksu_susfs
if [ -f "$KSUD" ] && [ -f "$SUSFS_BIN" ] \
   && [ "$(stat -c %s "$KSUD" 2>/dev/null)" -gt 1000000 ] \
   && [ "$(stat -c %i "$KSUD" 2>/dev/null)" = "$(stat -c %i "$SUSFS_BIN" 2>/dev/null)" ]; then
    _ksud_imm=0
    lsattr -d "$KSUD" 2>/dev/null | cut -d' ' -f1 | grep -q 'i' && _ksud_imm=1
    chattr -i "$KSUD" 2>/dev/null
    if cp "$KSUD" "$SUSFS_BIN.nm_new" 2>/dev/null; then
        chmod 0755 "$SUSFS_BIN.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$SUSFS_BIN.nm_new" 2>/dev/null
        mv -f "$SUSFS_BIN.nm_new" "$SUSFS_BIN" 2>/dev/null \
            && nmlog "re-asserted ksud de-link (service)"
    else
        rm -f "$SUSFS_BIN.nm_new" 2>/dev/null
    fi
    [ "$_ksud_imm" = 1 ] && chattr +i "$KSUD" 2>/dev/null
fi

_bh_dir=/data/adb/bindhosts
_bh_ovr="$_bh_dir/mode_override.sh"
if [ -d "$_bh_dir" ] && [ -d /data/adb/modules/bindhosts ] &&
   [ ! -f /data/adb/modules/bindhosts/remove ] && [ -L /data/adb/metamodule ]; then
    if [ ! -e "$_bh_ovr" ] || grep -q 'NoMount Suite' "$_bh_ovr" 2>/dev/null; then
        cat > "$_bh_ovr.nm_new" <<'BHEOF'
# Written by the NoMount Suite. Safe to delete.
#
# bindhosts mode 0 = ship system/etc/hosts as a normal module file and let the
# metamodule serve it, with no mount of its own. bindhosts already prefers this
# when it detects a nomount metamodule; its check looks for
# /data/adb/modules/nomount and this Suite installs as meta-nomount, so it does
# not match. Resolve the metamodule symlink instead.
#
# Conditional on our metamodule being live, not merely on one existing: the
# sha256sums manifest is ours. Without that test a leftover copy of this file
# would force mode 0 under a different metamodule after NoMount was removed.
_nm=$(readlink -f /data/adb/metamodule 2>/dev/null)
if [ -n "$_nm" ] && [ -d "$_nm" ] && [ -f "$_nm/nomount.sha256sums" ] &&
   [ ! -f "$_nm/disable" ] && [ ! -f "$_nm/remove" ] &&
   [ ! -f /data/adb/nomount/disabled ]; then
    mode=0
fi
unset _nm
BHEOF
        _bh_rc=$?
        if [ "$_bh_rc" -eq 0 ] && mv -f "$_bh_ovr.nm_new" "$_bh_ovr" 2>/dev/null; then
            chmod 0644 "$_bh_ovr" 2>/dev/null
            nmlog "bindhosts: wrote mode_override.sh - it will use its mountless mode 0 from the next boot"
        else
            rm -f "$_bh_ovr.nm_new"
            nmlog "⚠ bindhosts: could not write mode_override.sh (rc=$_bh_rc) - it keeps its own mount mode"
        fi
    fi
fi
unset _bh_dir _bh_ovr _bh_rc

if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _rl_all=$(nmto 60 "$BIN" reload 2>&1)
    _rl_rc=$?
    _rl=$(printf '%s\n' "$_rl_all" | tail -1)
    if [ "$_rl_rc" -eq 124 ]; then
        nmlog "post-boot reload timed out after 60s - late module content may be unserved"
    elif [ "$_rl_rc" -ne 0 ]; then
        nmlog "⚠ post-boot reload FAILED (exit $_rl_rc) - content written by module service.sh is not served: $_rl"
    else
        nmlog "post-boot reload: $_rl"
    fi
fi

if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _ab_all=$(nmto 90 "$BIN" absorb 2>&1)
    _ab_rc=$?
    _ab=$(printf '%s\n' "$_ab_all" | tail -1)
    if [ "$_ab_rc" -eq 124 ]; then
        nmlog "absorb timed out after 90s - continuing boot"
    elif [ "$_ab_rc" -ne 0 ]; then
        nmlog "⚠ absorb FAILED (exit $_ab_rc) - foreign mounts may still be visible: $_ab"
    else
        nmlog "$_ab"
    fi
    (
        sleep 45
        _rl2_all=$(nmto 60 "$BIN" reload 2>&1)
        _rl2_rc=$?
        if [ "$_rl2_rc" -eq 124 ]; then
            nmlog "late reload pass timed out after 60s"
        elif [ "$_rl2_rc" -ne 0 ]; then
            nmlog "⚠ late reload pass FAILED (exit $_rl2_rc): $(printf '%s\n' "$_rl2_all" | tail -1)"
        else
            nmlog "late reload pass: $(printf '%s\n' "$_rl2_all" | tail -1)"
        fi
        _ab2_all=$(nmto 90 "$BIN" absorb 2>&1)
        _ab2_rc=$?
        _ab2=$(printf '%s
' "$_ab2_all" | tail -1)
        if [ "$_ab2_rc" -eq 124 ]; then
            nmlog "late absorb pass timed out after 90s"
        elif [ "$_ab2_rc" -ne 0 ]; then
            nmlog "⚠ late absorb pass FAILED (exit $_ab2_rc): $_ab2"
        else
            nmlog "late absorb pass: $_ab2"
        fi
    ) &
fi

if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/whiteouts.txt" ]; then
    _wo_all=$(nmto 30 "$BIN" whiteout apply 2>&1)
    _wo_rc=$?
    _wo=$(printf '%s
' "$_wo_all" | tail -1)
    if [ "$_wo_rc" -ne 0 ]; then
        nmlog "⚠ whiteout apply FAILED (exit $_wo_rc) - hidden paths are still visible: $_wo"
    else
        nmlog "$_wo"
    fi
fi

if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/uidhide" ]; then
    _bl=$(nmto 60 "$BIN" uid apply 2>&1)
    if [ $? -eq 0 ]; then
        nmlog "hide list re-applied ($_bl)"
    else
        nmlog "⚠ hide list apply FAILED ($_bl)"
    fi
fi

if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] \
   && command -v inotifyd >/dev/null 2>&1 && [ -f "$MODDIR/uidwatch.sh" ]; then
    inotifyd "$MODDIR/uidwatch.sh" /data/system >/dev/null 2>&1 &
    nmlog "hide-list package watcher started"
fi

if [ ! -x "$BIN" ]; then
    nmlog "⛔ engine binary is missing or not executable ($BIN) - absorb, whiteouts, per-app hiding and the health canary were all skipped this boot"
fi

if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _try=0
    _arc=0
    while [ "$_try" -lt 6 ]; do
        nmto 60 "$BIN" check --write >/dev/null 2>&1
        _arc=$?
        [ "$_arc" -eq 124 ] && break
        _cons=$(_health_get consistency)
        if ! _health_fresh; then
            break
        fi
        case "$_cons" in
            ok|unchecked*|"") break ;;
        esac
        _try=$((_try + 1))
        [ "$_try" -lt 6 ] || break
        sleep 15
    done
    if _health_fresh; then
        _hv=$(_health_get verdict)
        nmlog "check verdict=${_hv:-unknown} consistency=${_cons:-unknown} (settle tries=$_try)"
    else
        nmlog "⚠ check wrote no health record this boot - health is unknown, not healthy"
    fi
    if [ "$_arc" -eq 0 ]; then
        nmlog "check cached - nothing open"
    elif [ "$_arc" -eq 124 ]; then
        rm -f "$NMDIR/audit.json"
        nmlog "⚠ check timed out after 60s - dropped the stale cache; the WebUI will show no verdict"
    elif [ -s "$NMDIR/audit.json" ]; then
        nmlog "check cached - one or more findings are open (see the Detection audit card)"
    else
        rm -f "$NMDIR/audit.json"
        nmlog "⚠ check did not complete - the WebUI will show no cached verdict"
    fi
    unset _arc
fi

if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    _rules=$(_nmcount -vc '(virtual dir)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    _mnt=$(awk '$4 ~ "/adb/modules/" {n++} END{print n+0}' /proc/self/mountinfo 2>/dev/null); _mnt=${_mnt:-0}
    _sum_get() {
        printf '%s' "$2" | sed -n 's/.*"summary":{\([^}]*\)}.*/\1/p' \
            | tr ',' '\n' | sed -n "s/^\"$1\"://p" | head -1
    }
    _doc=$(nmto 30 "$BIN" check --plan --json 2>/dev/null)
    _err=$(_sum_get fail "$_doc")
    _wrn=$(_sum_get warn "$_doc")
    case "$_err$_wrn" in
        ''|*[!0-9]*) _docok=0; _err=0; _wrn=0 ;;
        *) _docok=1 ;;
    esac
    unset _doc
    _health_fresh && _hfresh=1 || _hfresh=0
    _cons=$(_health_get consistency)
    case "$_cons" in
        ok|unchecked*|"") _consbad=0 ;;
        *) _consbad=1 ;;
    esac
    if [ "${_hookran:-1}" = 0 ]; then
        _health="⛔ the mount pass never ran - see the Last incident card"
    elif [ "$_consbad" = 1 ]; then
        _health="⚠️ per-UID inconsistency - see the NoMount WebUI"
    elif [ "${_err:-0}" -gt 0 ]; then
        _health="⚠️ $_err error(s) - see the NoMount WebUI"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="$_wrn warning(s)"
    elif [ "${_docok:-0}" = 1 ] && [ "${_hfresh:-0}" = 1 ]; then
        _health="healthy"
    elif [ "${_docok:-0}" = 1 ]; then
        _health="health unknown - no health record this boot"
    else
        _health="health unknown - the plan check did not finish"
    fi
    _fgn=$(_health_get mounts_foreign)
    case "$_fgn" in ''|*[!0-9]*) _fgn=$_mnt ;; esac
    if [ "${_fgn:-0}" -gt 0 ]; then
        _mstate="⚠ $_fgn module mount(s)"
        _tail="Prism VFS + RRO injection is mountless; $_fgn foreign mount(s) present"
    elif [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="$_mnt by design"
        _tail="mountless where it can be: Prism VFS + RRO, su via sucompat ($_mnt mount(s) left alone by design - a hook framework's, or a my_* bind of ours)"
    else
        _mstate="0 mounts"
        _tail="fully mountless: Prism VFS + RRO, su via sucompat"
    fi
    _mu=$(_health_get manager_umount | head -1)
    if [ "$_mu" = "on" ]; then
        # shellcheck disable=SC1111  # typographic quotes on purpose: this names
        _muc=" · ⚠️ turn OFF “kernel umount” in your root manager (it hides nothing here)"
        _mul=", ⚠ manager kernel_umount is ON - turn it off"
    else
        _muc=""
        _mul=""
    fi
    if [ "${_hookran:-1}" = 0 ]; then _mark="⛔"
    elif [ "${_rules:-0}" = 0 ]; then _mark="⚠️"
    else _mark="✅"; fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "[NoMount $_mark $_rules rules · $_rro RRO · $_mstate] $_health$_muc - $_tail" \
        >/dev/null 2>&1
    nmlog "card refreshed ($_rules rules, $_mstate, $_health$_mul)"
fi
exit 0
