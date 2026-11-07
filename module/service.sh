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
while [ "$i" -lt 450 ]; do
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
_armed=1
nm_guard_armed || _armed=0
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

if [ ! -e "$NMDIR/disabled" ]; then
    nm_fix_shell_tmp
    nm_delink_ksud service
fi

_bh_dir=/data/adb/bindhosts
_bh_ovr="$_bh_dir/mode_override.sh"
if [ -d "$_bh_dir" ] && [ -d /data/adb/modules/bindhosts ] &&
   [ ! -f /data/adb/modules/bindhosts/remove ] && [ -L /data/adb/metamodule ]; then
    if [ ! -e "$_bh_ovr" ] || grep -q 'NoMount Suite' "$_bh_ovr" 2>/dev/null; then
        cat > "$_bh_ovr.nm_new" <<'BHEOF'
# Written by the NoMount Suite. Safe to delete.
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

if [ "$_armed" = 0 ] && [ ! -e "$NMDIR/disabled" ]; then
    nmlog "⛔ the bootloop guard did not arm this boot - the post-boot reload, absorb, whiteouts, hide list and ghost sync are skipped too, so nothing is injected without a counter to stop a panic loop"
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ "$_armed" = 1 ]; then
    _rl_all=$(nmto 60 "$BIN" reload 2>&1)
    _rl_rc=$?
    _rl=$(_rl_summary "$_rl_all")
    if [ "$_rl_rc" -eq 124 ]; then
        nmlog "post-boot reload timed out after 60s - late module content may be unserved"
    elif [ "$_rl_rc" -ne 0 ]; then
        nmlog "⚠ post-boot reload FAILED (exit $_rl_rc) - content written by module service.sh is not served: $_rl"
    else
        nmlog "post-boot reload: $_rl"
    fi
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ "$_armed" = 1 ]; then
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
        [ -e "$NMDIR/disabled" ] && exit 0
        _rl2_all=$(nmto 60 "$BIN" reload 2>&1)
        _rl2_rc=$?
        if [ "$_rl2_rc" -eq 124 ]; then
            nmlog "late reload pass timed out after 60s"
        elif [ "$_rl2_rc" -ne 0 ]; then
            nmlog "⚠ late reload pass FAILED (exit $_rl2_rc): $(_rl_summary "$_rl2_all")"
        else
            nmlog "late reload pass: $(_rl_summary "$_rl2_all")"
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

if [ "$booted" != "1" ]; then
    nmlog "boot_completed never set - leaving guard counter armed"
fi

if [ "$_armed" = 1 ]; then
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
fi

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ "$_armed" = 1 ] \
   && { _has_entries "$NMDIR/uidhide" || _follow_ksu; }; then
    _bl=$(export NM_REDACT_HIDE_LIST=1; nmto 60 "$BIN" uid apply 2>&1)
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

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ "$_armed" = 1 ]; then
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

# The maps cloak. Separate from ghost on purpose: ghost covers paths the Suite
# itself injects, this covers what a Zygisk implementation dlopen()s into an app
# (/data/adb/modules/<mod>/...), which shows up in that app's OWN mapping list.
# A kernel without the pathhide knob answers "unknown knob" and the sync reports
# the cloak as unavailable rather than failing the boot.
if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ "$_armed" = 1 ]; then
    _ph=$(nmto 60 "$BIN" pathhide sync 2>&1)
    _ph_rc=$?
    if [ "$_ph_rc" -eq 124 ]; then
        nmlog "⚠ pathhide sync timed out after 60s - the root stack stays visible in app mapping lists this boot"
    elif [ "$_ph_rc" -ne 0 ]; then
        nmlog "⚠ pathhide sync FAILED (rc=$_ph_rc): $(printf '%s
' "$_ph" | tail -1)"
    elif [ -n "$_ph" ]; then
        nmlog "$(printf '%s
' "$_ph" | tail -1)"
    fi
    unset _ph _ph_rc
fi

# Reset the bootloop counter HERE, not at boot_completed.
#
# It used to clear as soon as sys.boot_completed went to 1, which is before whiteout
# apply, uid apply, ghost sync and pathhide sync have run -- the four passes that install
# rules in the kernel, and so the four most likely to panic. A panic in any of them
# produced a reboot cycle that reached boot_completed every time, cleared the counter
# every time, and therefore never reached GUARD_MAX: the guard could not park the Suite,
# and the only way out was recovery. The passes above have all returned by this line.
if [ "$booted" = "1" ]; then
    rm -f "$NMDIR/bootcount"
    nmlog "boot completed and the late passes returned, guard counter reset"
fi

# inotifyd EXECS its handler, so the handler carries the exec bit -- and the installer's
# modes do not reliably survive it. checkwatch.sh shipped 0644: inotifyd started, stayed
# resident, wrote its pid, and then failed to exec the handler on every single event, in
# silence, because the spawn itself had succeeded. Re-assert the bit here the way
# post-fs-data.sh and metamount.sh already re-assert $BIN's, so a device already in that
# state heals on its next boot instead of waiting for a reflash.
#
# Note what this does NOT do: a liveness check on the spawned pid cannot see that bug,
# because inotifyd is the process that lives and the handler is what fails later. The
# -x test is the one that catches it, and it is deterministic.
nm_watch() {
    _w_h="$1"; _w_dir="$2"; _w_mask="$3"; _w_label="$4"
    NM_WATCH_PID=""
    if [ ! -f "$_w_h" ]; then
        nmlog "⛔ $_w_label watcher NOT started: $_w_h is missing"
        return 1
    fi
    [ -x "$_w_h" ] || chmod 0755 "$_w_h" 2>/dev/null
    if [ ! -x "$_w_h" ]; then
        nmlog "⛔ $_w_label watcher NOT started: $_w_h is not executable and chmod failed"
        return 1
    fi
    inotifyd "$_w_h" "$_w_dir:$_w_mask" >/dev/null 2>&1 &
    NM_WATCH_PID=$!
    nmlog "$_w_label watcher started (pid $NM_WATCH_PID)"
    return 0
}

if [ -x "$BIN" ] && [ ! -e "$NMDIR/disabled" ] && [ "$_armed" = 1 ] \
   && command -v inotifyd >/dev/null 2>&1 && [ -f "$MODDIR/uidwatch.sh" ]; then
    _watchers=""
    nm_watch "$MODDIR/uidwatch.sh" /data/system cewDMmynd "hide-list-package" \
        && _watchers="$_watchers $NM_WATCH_PID=hide-list-package"
    # Started regardless of the knob: uidwatch.sh drops .allowlist events while it is
    # off, so turning it on takes effect without a reboot.
    if [ -d /data/adb/ksu ]; then
        nm_watch "$MODDIR/uidwatch.sh" /data/adb/ksu cewDMmynd "KernelSU-DenyList" \
            && _watchers="$_watchers $NM_WATCH_PID=KernelSU-DenyList"
    fi
    # Lets the WebUI have a check run OUTSIDE its own context. Its exec inherits the
    # manager app's seccomp filter, which denies setgroups, so four device checks cannot
    # run there at all; this watcher is reparented to init and carries no filter. Its own
    # directory, not $NMDIR, so the Suite's own writes do not spawn a handler per event.
    if [ -f "$MODDIR/checkwatch.sh" ]; then
        mkdir -p "$NMDIR/request" 2>/dev/null
        chmod 700 "$NMDIR/request" 2>/dev/null
        # Also clears a request left behind by a watcher that could not exec its handler:
        # the handler is what deletes it, so a stale one sits there and, because `touch`
        # on an existing file raises only IN_ATTRIB, no later request matches the cn mask.
        rm -f "$NMDIR/request"/* 2>/dev/null
        rm -f "$NMDIR/.checkwatch.pid" 2>/dev/null
        if nm_watch "$MODDIR/checkwatch.sh" "$NMDIR/request" cn "check-on-request"; then
            echo "$NM_WATCH_PID" > "$NMDIR/.checkwatch.pid" 2>/dev/null
            _watchers="$_watchers $NM_WATCH_PID=check-on-request"
        fi
    fi

    # The fork always succeeds, so inotifyd failing to exec shows only as the child
    # already being gone. Swept here rather than at each spawn so the intervening work
    # gives a doomed exec time to land; still a race, so silence here is weaker evidence
    # than the -x test above, and a complaint is worth believing.
    for _w in $_watchers; do
        kill -0 "${_w%%=*}" 2>/dev/null \
            || nmlog "⛔ ${_w#*=} watcher died immediately after starting (pid ${_w%%=*})"
    done
    unset _w _watchers NM_WATCH_PID
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
            # probe-unavailable is the one unchecked value a retry can clear: it means the
            # probe machinery itself did not answer, not that there was nothing to sample.
            # Treating it as settled is why every boot logged "settle tries=0".
            unchecked:probe-unavailable) ;;
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
        nmlog "check cached - one or more findings are open (see the Diagnostics card)"
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
    if [ "${_hookran:-1}" = 0 ] || [ "$_armed" = 0 ]; then
        _health="⛔ mount pass never ran - see the WebUI"
    elif [ "$(_health_get engine)" = "down" ]; then
        _health="⛔ your kernel has no NoMount driver - flash a NoMount kernel, then reboot"
    elif [ "${_rl_rc:-0}" -ne 0 ]; then
        _health="ℹ️ late module content may not be served - tap Reload in the WebUI"
    elif [ "$_consbad" = 1 ]; then
        _health="ℹ️ per-UID inconsistency - see the WebUI"
    elif [ "${_err:-0}" -gt 0 ]; then
        _health="ℹ️ $_err finding(s) - see the WebUI"
    elif [ -n "$_hv" ] && [ "$_hv" != "clean" ]; then
        _health="ℹ️ $_hv - see the WebUI"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="ℹ️ $_wrn finding(s) - see the WebUI"
    elif [ "${_unm:-0}" -gt 0 ]; then
        _health="not fully measured - see the WebUI"
    elif [ "${_nmlrc:-0}" -ne 0 ]; then
        _health="serving, rule count unreadable"
    elif [ "${_docok:-0}" = 1 ] && [ "${_hfresh:-0}" = 1 ]; then
        _health="healthy"
    elif [ "${_docok:-0}" = 1 ]; then
        _health="health unknown (no record)"
    else
        _health="health unknown (check incomplete)"
    fi
    _fgn=$(_health_get mounts_foreign)
    case "$_fgn" in
        ''|*[!0-9]*)
            _fgn=""
            ;;
    esac
    if [ -z "$_fgn" ]; then
        if [ "${_mnt:-0}" -gt 0 ]; then
            _mstate="$_mnt mount(s), origin unknown"
        else
            _mstate="0 mounts"
        fi
    elif [ "$_fgn" -gt 0 ]; then
        _mstate="ℹ $_fgn foreign mount(s)"
    elif [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="$_mnt mount by design"
    else
        _mstate="0 mounts"
    fi
    _mu=$(_health_get manager_umount | head -1)
    if [ "$_mu" = "on" ]; then
        # shellcheck disable=SC1111  # typographic quotes on purpose: this names
        if [ "${_mnt:-0}" -gt 0 ]; then
            _muc=" · “kernel umount” ON (hides our $_mnt bind(s))"
            _mul=", manager kernel_umount is ON (hides our $_mnt bind(s))"
        else
            _muc=" · “kernel umount” ON (nothing to unmount)"
            _mul=", manager kernel_umount is ON (nothing here to unmount)"
        fi
    else
        _muc=""
        _mul=""
    fi
    if [ "${_hookran:-1}" = 0 ] || [ "$_armed" = 0 ] || [ "$(_health_get engine)" = "down" ]; then _mark="⛔"
    elif [ "${_nmlrc:-0}" -ne 0 ]; then _mark="✅"
    elif [ "${_rules:-0}" = 0 ]; then _mark="ℹ️"
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
