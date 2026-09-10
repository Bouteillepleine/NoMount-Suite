#!/system/bin/sh
MODDIR="${0%/*}"
NMLOG_TAG=service
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - the post-boot pass did not run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
nm_set_bin

_now=$(date +%s 2>/dev/null || echo 0)
_up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
_epoch_known=1
case "$_now" in ''|*[!0-9]*) _now=0; _epoch_known=0 ;; esac
case "$_up"  in ''|*[!0-9]*) _up=0;  _epoch_known=0 ;; esac
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

nm_fix_shell_tmp

nm_delink_ksud service

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
#
# `-e`, not `-f`, on the disable flag: mount::guard_tripped tests Path::exists(),
# so a `disabled` that is a directory makes every serving verb refuse while `-f`
# reads false - bindhosts would then pick mode 0 ("the metamodule serves my
# hosts file") on a device where nothing is being served, and adblocking is
# silently off with no mount to replace it. Every read in module/*.sh is `-e`.
_nm=$(readlink -f /data/adb/metamodule 2>/dev/null)
if [ -n "$_nm" ] && [ -d "$_nm" ] && [ -f "$_nm/nomount.sha256sums" ] &&
   [ ! -f "$_nm/disable" ] && [ ! -f "$_nm/remove" ] &&
   [ ! -e /data/adb/nomount/disabled ]; then
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

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ]; then
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

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ]; then
    _ab_all=$(nmto 90 "$BIN" absorb 2>&1)
    _ab_rc=$?
    nmlog_absorb_notes "$_ab_all"
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
        nmlog_absorb_notes "$_ab2_all"
        _ab2=$(printf '%s\n' "$_ab2_all" | tail -1)
        if [ "$_ab2_rc" -eq 124 ]; then
            nmlog "late absorb pass timed out after 90s"
        elif [ "$_ab2_rc" -ne 0 ]; then
            nmlog "⚠ late absorb pass FAILED (exit $_ab2_rc): $_ab2"
        else
            nmlog "late absorb pass: $_ab2"
        fi
    ) &
fi

if [ "$booted" = "1" ]; then
    rm -f "$NMDIR/bootcount"
    nmlog "boot completed, guard counter reset"
else
    nmlog "boot_completed never set - leaving guard counter armed"
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && _has_entries "$NMDIR/whiteouts.txt"; then
    _wo_all=$(nmto 30 "$BIN" whiteout apply 2>&1)
    _wo_rc=$?
    _wo_last=$(printf '%s\n' "$_wo_all" | tail -1)
    if [ "$_wo_rc" -ne 0 ]; then
        nmlog "⚠ whiteout apply FAILED (exit $_wo_rc) - hidden paths are still visible: $_wo_last"
    else
        nmlog "$_wo_last"
    fi
    unset _wo_all _wo_rc _wo_last
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ -s "$NMDIR/uidhide" ]; then
    _bl=$(nmto 60 "$BIN" uid apply 2>&1)
    _bl_rc=$?
    if [ "$_bl_rc" -eq 0 ]; then
        nmlog "hide list re-applied ($_bl)"
    elif [ "$_bl_rc" -eq 124 ]; then
        nmlog "⚠ hide list apply timed out after 60s - apps you believe are hidden are not"
    else
        nmlog "⚠ hide list apply FAILED (exit $_bl_rc): $_bl"
    fi
    unset _bl _bl_rc
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ]; then
    _gh=$(nmto 60 "$BIN" ghost sync 2>&1)
    _gh_rc=$?
    if [ "$_gh_rc" -eq 124 ]; then
        nmlog "⚠ ghost sync timed out after 60s - the existence oracles stay open this boot"
    elif [ "$_gh_rc" -ne 0 ]; then
        nmlog "⚠ ghost sync FAILED (rc=$_gh_rc): $(printf '%s\n' "$_gh" | tail -1)"
    elif [ -n "$_gh" ]; then
        nmlog "$(printf '%s\n' "$_gh" | tail -1)"
    fi
    unset _gh _gh_rc
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] \
   && command -v inotifyd >/dev/null 2>&1 && [ -f "$MODDIR/uidwatch.sh" ]; then
    inotifyd "$MODDIR/uidwatch.sh" /data/system >/dev/null 2>&1 &
    nmlog "hide-list package watcher started"
fi

if [ ! -x "$BIN" ]; then
    nmlog "⛔ engine binary is missing or not executable ($BIN) - absorb, whiteouts, per-app hiding and the health canary were all skipped this boot"
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ]; then
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

if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ]; then
    nm_rule_counts
    _mnt=$(awk '$4 ~ "/adb/modules/" {n++} END{print n+0}' /proc/self/mountinfo 2>/dev/null); _mnt=${_mnt:-0}
    _sum_get() {
        printf '%s' "$2" | sed -n 's/.*"summary":{\([^}]*\)}.*/\1/p' \
            | tr ',' '\n' | sed -n "s/^\"$1\"://p" | head -1
    }
    _doc=$(nmto 30 "$BIN" check --plan --json 2>/dev/null)
    _err=$(_sum_get fail "$_doc")
    _wrn=$(_sum_get warn "$_doc")
    _unm=$(_sum_get unmeasured "$_doc")
    case "$_unm" in ''|*[!0-9]*) _unm=0 ;; esac
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
        _health="⛔ mount pass never ran - see the WebUI"
    elif [ "$(_health_get engine)" = "down" ]; then
        _health="⛔ your kernel has no NoMount driver - flash a NoMount kernel, then reboot"
    elif [ "${_rl_rc:-0}" -ne 0 ]; then
        _health="⚠️ late module content may not be served - tap Reload in the WebUI"
    elif [ "$_consbad" = 1 ]; then
        _health="⚠️ per-UID inconsistency - see the WebUI"
    elif [ "${_err:-0}" -gt 0 ]; then
        _health="⚠️ $_err error(s) - see the WebUI"
    elif [ -n "$_hv" ] && [ "$_hv" != "clean" ]; then
        _health="⚠️ $_hv - see the WebUI"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="$_wrn warning(s)"
    elif [ "${_unm:-0}" -gt 0 ]; then
        _health="not fully measured - see the WebUI"
    elif [ "${_nmlrc:-0}" -ne 0 ]; then
        _health="serving normally - the rule count just could not be read"
    elif [ "${_docok:-0}" = 1 ] && [ "${_hfresh:-0}" = 1 ]; then
        _health="healthy"
    elif [ "${_docok:-0}" = 1 ]; then
        _health="health unknown - no record this boot"
    else
        _health="health unknown - plan check did not finish"
    fi
    _fgn=$(_health_get mounts_foreign)
    case "$_fgn" in ''|*[!0-9]*) _fgn=$_mnt ;; esac
    if [ "${_fgn:-0}" -gt 0 ]; then
        _mstate="⚠ $_fgn foreign mount(s)"
    elif [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="$_mnt mount by design"
    else
        _mstate="0 mounts"
    fi
    _mu=$(_health_get manager_umount | head -1)
    if [ "$_mu" = "on" ]; then
        # shellcheck disable=SC1111  # typographic quotes on purpose: this names
        if [ "${_mnt:-0}" -gt 0 ]; then
            _muc=" · “kernel umount” ON (it hides our $_mnt bind(s))"
            _mul=", manager kernel_umount is ON (hides our $_mnt bind(s))"
        else
            _muc=" · “kernel umount” ON (nothing here to unmount)"
            _mul=", manager kernel_umount is ON (nothing here to unmount)"
        fi
    else
        _muc=""
        _mul=""
    fi
    if [ "${_hookran:-1}" = 0 ] || [ "$(_health_get engine)" = "down" ]; then _mark="⛔"
    elif [ "${_nmlrc:-0}" -ne 0 ]; then _mark="✅"
    elif [ "${_rules:-0}" = 0 ]; then _mark="⚠️"
    else _mark="✅"; fi
    [ "${_wo:-0}" -gt 0 ] 2>/dev/null && _wof=" · $_wo hidden" || _wof=""
    if [ "${_nmlrc:-0}" -ne 0 ]; then
        _rphr="rule count unavailable"
    else
        _rphr="$_rules rules · $_rro RRO$_wof"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "$_mark $_rphr · $_mstate - $_health$_muc" \
        >/dev/null 2>&1
    nmlog "card refreshed ($_rphr, $_mstate, $_health$_mul)"
fi
exit 0
