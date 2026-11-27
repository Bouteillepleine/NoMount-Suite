#!/system/bin/sh

umask 077

NMDIR=/data/adb/nomount
BOOTLOG="$NMDIR/boot.log"
: "${NM_BOOT_ID:=/proc/sys/kernel/random/boot_id}"

# The boot log always; /dev/kmsg only if asked for.
#
# The kernel ring buffer is the one place the Suite was still writing its own
# name on every boot. The engine goes to some trouble to avoid that - a built-in
# engine is no discrete object at all, and the LKM unlinks itself from
# /proc/modules, /sys/module and /proc/kallsyms - and then this put
# "nomount: ..." into dmesg regardless, on both builds. dmesg_restrict keeps
# apps out, so it is a thin surface rather than an open one, but it is one, and
# $BOOTLOG already carries the same lines with timestamps and a tag.
#
# Opt back in with:  touch /data/adb/nomount/kmsg
nmlog() {
    if [ -e "$NMDIR/kmsg" ]; then
        echo "nomount: $*" > /dev/kmsg 2>/dev/null
    fi
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

# The manager's module card. ksud keeps a per-boot override; APatch and Magisk read
# module.prop, and Magisk has no WebUI to point at.
nm_card() {
    if command -v ksud >/dev/null 2>&1; then
        nmto 10 env KSU_MODULE=meta-nomount ksud module config set --temp \
            override.description "$1" >/dev/null 2>&1
        return
    fi
    _cd=$1
    if [ -z "$APATCH" ] && ! command -v apd >/dev/null 2>&1; then
        _cd=$(printf '%s' "$_cd" | sed 's/tap Reload in the WebUI/run nomount reload/; s/see the WebUI/run nomount check/')
    fi
    _cp="$MODDIR/module.prop"
    [ -f "$_cp" ] || return 1
    [ "$(sed -n 's/^description=//p' "$_cp" | head -1)" = "$_cd" ] && return 0
    _cx=$(stat -c %C "$_cp" 2>/dev/null)
    case "$_cx" in u:*) ;; *) _cx="" ;; esac
    if NM_DESC="$_cd" awk '/^description=/ { print "description=" ENVIRON["NM_DESC"]; next } { print }' \
            "$_cp" > "$_cp.nm$$" 2>/dev/null \
        && chmod 0644 "$_cp.nm$$" && { [ -z "$_cx" ] || chcon "$_cx" "$_cp.nm$$"; } 2>/dev/null \
        && mv -f "$_cp.nm$$" "$_cp" 2>/dev/null; then
        return 0
    fi
    rm -f "$_cp.nm$$" 2>/dev/null
    return 1
}

# package.sh points the LKM zip's updateJson at update-lkm.json; the WebUI tells them apart the same way.
nm_lkm_zip() { grep -q 'update-lkm.json' "$MODDIR/module.prop" 2>/dev/null; }

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
    # KEEP IN SYNC with the stash list in uninstall.sh and the restore in customize.sh.
    for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
              absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
              uidconceal ghostpaths kmsg incident.log incident.prev nomount.ko \
              absorbed.list binds.list absorbed-tmpfs.list apkstate.list \
              apkscope public.txt accepted.list absorb-skip; do
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

_follow_ksu() { grep -qiE '^[[:space:]]*follow_ksu_denylist[[:space:]]*=[[:space:]]*(1|true|yes|on)[[:space:]]*$' "$NMDIR/uidhide.conf" 2>/dev/null; }

nm_boot_log_rotate() {
    [ -e "$BOOTLOG" ] && [ ! -f "$BOOTLOG" ] && rm -rf "$BOOTLOG" 2>/dev/null
    # Only swap in a rotation that wrote something. On a full /data `tail` can
    # leave an empty file behind, and moving that over the log threw away the one
    # record that says why the previous boot went wrong - at exactly the moment
    # someone needs it. A short write still swaps; an empty one no longer does.
    if [ -s "$BOOTLOG" ]; then
        if tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null && [ -s "$BOOTLOG.tmp" ]; then
            mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
        else
            rm -f "$BOOTLOG.tmp" 2>/dev/null
        fi
    fi
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

# Load the engine module on a kernel that does not carry NoMount built in.
# This is called from post-fs-data.sh BEFORE the metamodule early-exit, because
# post-fs-data.sh runs for every enabled module while metamount.sh only runs if
# we own the metamodule slot - loading there would leave the engine down
# whenever something else owns it. Safe to call twice: it probes first.
nm_lkm_boot_load() {
    [ -f "$MODDIR/lkm-load.sh" ] || return 0
    # The guard's own self-disable has to stop the insmod too: this ran four calls before
    # the first `disabled` test, so a parked Suite still inserted the engine module.
    [ -e "$NMDIR/disabled" ] && return 0
    nm_set_bin
    # Count and trip before inserting kernel code: an insmod that panics never reaches a later bump.
    nm_guard_bump "engine module load" || return 0
    NM_LKM_SAY=:
    NM_LKM_NM="$NM_BIN"
    NM_LKM_LOADER="$MODDIR/loader"
    export NM_LKM_SAY NM_LKM_NM NM_LKM_LOADER
    chmod 0755 "$NM_LKM_NM" "$NM_LKM_LOADER" 2>/dev/null
    # shellcheck source=module/lkm-load.sh
    . "$MODDIR/lkm-load.sh" 2>/dev/null || return 0

    nm_lkm_probe && return 0
    # metamount.sh calls this again after post-fs-data.sh. When the module went in but nm
    # cannot answer (rc 2) the probe fails there too, and every loader would run a second init.
    _lgid=$(cat "$NM_BOOT_ID" 2>/dev/null)
    if [ -n "$_lgid" ] && [ "$(cat "$NMDIR/.lkm.boot" 2>/dev/null)" = "$_lgid" ]; then
        unset _lgid
        return 0
    fi
    nm_lkm_load_best "$MODDIR/lkm"
    _lrc=$?
    case "$_lrc" in 0|2) [ -n "$_lgid" ] && echo "$_lgid" > "$NMDIR/.lkm.boot" 2>/dev/null ;; esac
    if [ "$_lrc" = 0 ]; then
        nmlog "engine module loaded from ${NM_LKM_SOURCE:-?} ($(uname -r))"
        nm_lkm_prune "$MODDIR/lkm"
    elif [ "$_lrc" = 2 ]; then
        nmlog "⚠ engine module loaded from ${NM_LKM_SOURCE:-?} but $NM_BIN did not answer - the ENGINE IS UP; the probe binary is missing, built for another ABI, or not executable. Do not reflash the kernel."
        nm_lkm_prune "$MODDIR/lkm"
    elif [ "${NM_LKM_NOMATCH:-}" = 1 ] && [ ! -f "${NM_LKM_DEVICE_KO:-/data/adb/nomount/nomount.ko}" ]; then
        nmlog "⛔ this zip has no engine module for $(uname -r) - nothing will be injected this boot. Use a kernel with NoMount built in and the 00_ zip."
    elif [ -d "$MODDIR/lkm" ] || [ -f "${NM_LKM_DEVICE_KO:-/data/adb/nomount/nomount.ko}" ]; then
        nmlog "⛔ no engine module loads on $(uname -r) - nothing will be injected this boot"
    fi
    unset _lrc _lgid
}

nm_fix_shell_tmp() {
    _fst=$(grep "^[ 	]*fix_shell_tmp[ 	]*=" "$NMDIR/spoof.conf" 2>/dev/null \
           | tail -n 1 | tr -d '\r' | sed "s/^[^=]*=//; s/[ 	]#.*//; s/[\"' 	]//g")
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

# The counter half of the guard. Idempotent for the boot: guard.ts holds this boot's
# boot_id once armed, so a second nm_guard_bump in the same boot does not count twice.
# If boot_id cannot be read every call counts, so one boot reaches GUARD_MAX and trips it.
nm_guard_arm() {
    for _f in bootcount disabled; do
        if [ -e "$NMDIR/$_f" ] && [ ! -f "$NMDIR/$_f" ]; then
            rm -rf "${NMDIR:?}/$_f" 2>/dev/null
            nmlog "⚠ $NMDIR/$_f was not a regular file (the guard cannot use it) - removed"
        fi
    done
    unset _f
    _gid=$(cat "$NM_BOOT_ID" 2>/dev/null)
    if [ -n "$_gid" ] && [ "$(cat "$NMDIR/guard.ts" 2>/dev/null)" = "$_gid" ]; then
        unset _gid
        return 0
    fi
    COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
    case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
    COUNT=$((COUNT + 1))
    echo "$COUNT" > "$NMDIR/bootcount"
    if [ "$(cat "$NMDIR/bootcount" 2>/dev/null)" != "$COUNT" ]; then
        nmlog "⛔ cannot write $NMDIR/bootcount - the bootloop guard cannot arm, so nothing is being injected this boot. /data being full is the usual cause; free space and reboot."
        unset _gid
        return 3
    fi
    if [ -n "$_gid" ]; then
        echo "$_gid" > "$NMDIR/guard.ts" 2>/dev/null
    else
        cat "$NM_BOOT_ID" > "$NMDIR/guard.ts" 2>/dev/null
    fi
    unset _gid
    sync 2>/dev/null
    return 0
}

nm_guard_bump() {
    nm_guard_arm || return $?
    GUARD_MAX=3
    COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
    case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac

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
        echo "modules_enabled=$(nm_incident_modules)"
        nm_incident_tombstone
    } > "$NMDIR/incident.log" 2>/dev/null
    return 2
}

nm_incident_modules() {
    for m in /data/adb/modules/*/; do
        [ -f "$m/disable" ] || [ -f "$m/remove" ] || [ -f "$m/skip_mount" ] && continue
        basename "$m"
    done | tr '\n' ' '
}

# A system_server crash loop restarts zygote and system_server inside one kernel boot, so
# post-fs-data never runs again and the boot count above stays at 1 while Android's own
# rescue escalates towards a factory-reset prompt. $1 = sys.system_server.start_count, 1 on
# the first start; NM_SOFT_LOOP_MAX starts before boot_completed park the Suite, fewer never
# do. Parking here also clears the rule table, so the next start reads stock files.
nm_guard_soft_loop() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge "${NM_SOFT_LOOP_MAX:-4}" ] || return 1
    [ -e "$NMDIR/disabled" ] && return 1
    nm_guard_armed || return 1
    nmlog "⛔ system_server started $1 times before boot completed - parking the Suite and clearing its rules so the next start reads stock files"
    touch "$NMDIR/disabled" 2>/dev/null \
        || nmlog "⚠ could not create $NMDIR/disabled - the crash loop was seen but the Suite cannot park itself"
    sync 2>/dev/null
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "reason=system_server restarted $(($1 - 1)) times before boot completed (start_count=$1, parks at ${NM_SOFT_LOOP_MAX:-4})"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
        echo "modules_enabled=$(nm_incident_modules)"
        nm_incident_tombstone
    } > "$NMDIR/incident.log" 2>/dev/null
    nmto 15 "$NM_BIN" clear >/dev/null 2>&1 \
        || nmlog "⚠ could not clear the engine's rules - they stay served until the next boot, which comes up parked"
    return 0
}

# The foreground passes returned: this boot stops counting. The late reload/absorb at +45 s
# installs rules too, so it holds the count again while it runs, and only after this
# marker - a slow foreground would otherwise clear the hold it had just taken.
nm_guard_fg_done() {
    rm -f "$NMDIR/bootcount"
    : > "$NMDIR/.guard_fg"
}

# $1 = this boot's count, read before the late pass was forked.
nm_guard_late_hold() {
    _gw=0
    while [ ! -e "$NMDIR/.guard_fg" ] && [ "$_gw" -lt "${NM_GUARD_FG_WAIT:-60}" ]; do
        sleep 2
        _gw=$((_gw + 1))
    done
    unset _gw
    case "$1" in ''|*[!0-9]*|0) return 0 ;; esac
    echo "$1" > "$NMDIR/bootcount"
}

nm_guard_late_release() {
    rm -f "$NMDIR/bootcount" "$NMDIR/.guard_fg"
}

nm_guard_armed() {
    _gab=$(cat "$NM_BOOT_ID" 2>/dev/null)
    [ -n "$_gab" ] || return 0
    [ "$(cat "$NMDIR/guard.ts" 2>/dev/null)" = "$_gab" ]
}

# Never over a record of the guard firing: that one names what crashed, and this says only
# that the manager ran no boot entry point.
nm_incident_no_entry() {
    grep -qE '^(bootcount=|reason=system_server)' "$NMDIR/incident.log" 2>/dev/null && return 0
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "reason=no boot entry point ran: $NMDIR/mountpass.ts is absent or stale"
        echo "ksu_env_seen_by_post_fs_data=see boot.log [post-fs-data] lines"
        echo "manager=$(ksud -V 2>/dev/null | head -1)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "note=NoMount is a metamodule. It needs a KernelSU/SukiSU/APatch build that supports metamodules, or Magisk. Update the manager."
    } > "$NMDIR/incident.log" 2>/dev/null
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
