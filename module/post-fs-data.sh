#!/system/bin/sh
# Magisk fallback (no metamodule hook). KSU/APatch use metamount.sh instead.
#
# The KSU/APATCH exit moved DOWN, past the log setup. It used to be line 3, before
# nmlog or $BOOTLOG existed, so on a KernelSU build without metamodule support --
# where metamount.sh is never invoked at all -- the whole module was a silent
# no-op: nothing on kmsg, nothing in boot.log, no incident.log, no card, nothing
# for the user to report. Now this path says out loud that it is handing over, and
# service.sh reports it when the handover led nowhere (see the mountpass.ts stamp).
MODDIR="${0%/*}"
NMDIR=/data/adb/nomount
umask 077                     # see metamount.sh
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"

# --- durable boot log ---------------------------------------------------------
# Same reasoning as metamount.sh: /dev/kmsg alone is not recoverable on a device
# whose ring buffer is flooded within minutes of boot, and this path had exactly
# ONE diagnostic in it to begin with. Duplicated rather than sourced: this is the
# Magisk post-fs-data stage, and a `.` of a file that a partial install did not
# extract would leave every nmlog call undefined for the rest of the pass.
BOOTLOG="$NMDIR/boot.log"
[ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
    && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
: >> "$BOOTLOG" 2>/dev/null
chmod 0600 "$BOOTLOG" 2>/dev/null
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [post-fs-data] $*" >> "$BOOTLOG" 2>/dev/null
}

# The handover, now that there is somewhere to record it. metamount.sh is the
# metamodule hook and does the whole pass on these managers -- but ONLY if the
# manager supports metamodules. If it does not, nothing else runs and the stamp
# metamount.sh writes never appears; service.sh checks for exactly that.
if [ -n "$KSU" ] || [ -n "$APATCH" ]; then
    nmlog "KSU/APatch detected — the metamodule hook (metamount.sh) owns this boot"
    exit 0
fi

# Magisk path: THIS script is the mount pass, so it writes the same stamp
# metamount.sh does. service.sh then needs no manager detection to tell "a boot
# entry point ran" from "nothing ran at all".
# The stamp is the KERNEL BOOT ID, not a timestamp. Both entry points run at
# post-fs-data, before the RTC is applied, so `date +%s` here returns a 1970
# value that no later epoch comparison can ever accept -- which made this check
# accuse a perfectly working manager on every single boot. boot_id is unique per
# boot and immune to the clock.
cat /proc/sys/kernel/random/boot_id > "$NMDIR/mountpass.ts" 2>/dev/null

# Bounded exec (see metamount.sh). On a device without toybox `timeout` a bare
# `timeout 60 cmd` does not run the command unbounded, it does not run it at all
# -- the silent no-op this file exists to remove. Prefer the bound, fall back to
# running bare.
if command -v timeout >/dev/null 2>&1; then
    nmto() { timeout "$@"; }
else
    # No toybox `timeout`. Poll a backgrounded child rather than running it
    # unbounded: every caller here has a 124 recovery path, and dropping the
    # bound turns a hung engine call into a hung boot -- absorb, the whiteout
    # re-apply, `uid apply`, uidwatch and `check` all run after these.
    # Same contract as timeout(1): the command's status, or 124 if killed.
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
# Unchecked, an empty ABI builds "$MODDIR/bin//nomount" and the [ -x "$BIN" ]
# test below then fails forever, silently (see metamount.sh).
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
# The Suite binary shells out to the hookless `nm` netlink client bundled beside
# it. This path was missing entirely here, so on Magisk the engine fell back to
# whatever `nm` it could find on PATH -- or to none at all.
export NM_BIN="$MODDIR/bin/$ABI/nm"
# Self-heal executable bits: some installers don't preserve +x, and without it on
# nm the whole pass aborts before it can inject. metamount.sh has always done
# this; the Magisk path was a degraded twin that did not.
chmod 0755 "$BIN" "$NM_BIN" 2>/dev/null

# --- pre-zygote absorb (my_* only, trial-gated) --------------------------------
# MAGISK ONLY. KSU/APatch have already exited above and run this from
# post-mount.sh instead, which is strictly better: it fires after EVERY module's
# post-fs-data.sh. Magisk has no post-mount stage, so post-fs-data is the last
# hook before zygote there, and a module whose own post-fs-data.sh runs after
# ours will still be missed. Measured shape of that miss, on KSU before the
# stage moved: "nothing mounted over the ROM (posture clean)" while 84 mounts
# went up afterwards.
# A module that binds its own content over a my_* path leaves that mount in every
# app's mountinfo, naming /data/adb/modules -- the loudest root signal there is,
# and the one thing the mountless posture exists to deny. The runtime pass in
# service.sh cannot take those over: re-asserting a my_* rule on a live system has
# rebooted a device (OP11, Suite v1.3.22, engine v14 -- four rules in a burst,
# clean sys.boot.reason, no tombstone), so it defers them here and says so.
#
# Here there is no live system to lose. Module post-fs-data.sh scripts run in
# module-id order, so this catches every module sorted before `meta-nomount` --
# which is the common case, and NOT a claim to catch all of them. A module sorted
# after us still binds after this runs and stays deferred; `nomount check` names
# whatever is left either way.
#
# Gated on the my_hookless TRIAL marker, because taking these over means serving
# my_* by injection, and a leaf my_* inject may trip zygote's FD allowlist at
# forkSystemServer. Without the marker this block does nothing at all. With it,
# the bootloop guard below (and metamount.sh's, on KSU) still writes `disabled`
# after GUARD_MAX failed boots, and this block honours that file -- so a bad trial
# self-recovers instead of needing a flash.
if [ ! -f "$NMDIR/disabled" ] && [ -x "$BIN" ] \
   && { [ -f "$NMDIR/my_hookless" ] || [ "$NM_MY_HOOKLESS" = 1 ]; }; then
    _ea=$(nmto 60 "$BIN" absorb --early 2>&1)
    _ea_rc=$?
    if [ "$_ea_rc" -eq 124 ]; then
        nmlog "⚠ early absorb TIMED OUT after 60s - continuing boot"
    elif [ "$_ea_rc" -ne 0 ]; then
        nmlog "⚠ early absorb FAILED (rc=$_ea_rc): $(printf '%s\n' "$_ea" | tail -1)"
    else
        nmlog "early absorb: $(printf '%s\n' "$_ea" | tail -1)"
    fi
fi

# --- bootloop guard ---
# Everything this script still does at post-fs-data runs INSIDE the guard
# (below), not before it -- same reasoning as metamount.sh: `disabled` has to
# suppress all of it, or the counter cannot protect against whatever wedged the
# boot.
GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
# Sanitize before the arithmetic (see metamount.sh): a bootcount corrupted to
# something like "3 3" makes $((COUNT + 1)) a FATAL arithmetic-syntax error in
# both mksh and ash, so the shell exits on the spot, the counter is never
# rewritten, and the module is a silent no-op on every boot from then on.
case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
COUNT=$((COUNT + 1))
echo "$COUNT" > "$NMDIR/bootcount"

if [ -f "$NMDIR/disabled" ]; then
    :
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then
    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
    : > "$NMDIR/disabled"
    # Record WHY, like metamount.sh does. A trip on this path used to leave only
    # an empty `disabled` file, so a Magisk user got the self-recovery but none
    # of the evidence -- and the WebUI's incident card stayed blank.
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX (magisk post-fs-data path)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
        # shellcheck disable=SC2010  # `ls -t` is the point: we want the NEWEST
        # tombstone and a glob cannot sort by mtime. The names here are
        # generated by the platform (tombstone_NN), so the usual
        # hostile-filename argument does not apply.
        _t=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
        if [ -n "$_t" ]; then
            echo "tombstone=$_t"
            echo "  $(grep -m1 '>>> ' "$_t" 2>/dev/null)"
            echo "  $(grep -m1 'Abort message' "$_t" 2>/dev/null)"
        fi
    } > "$NMDIR/incident.log" 2>/dev/null
else
    # --- /data/local/tmp: restore the AOSP owner/mode/context ---
    # Same stage and same block as the KSU/APatch metamount hook, but for the
    # Magisk path; service.sh re-asserts it after boot and carries the long-form
    # reasoning. ksud stages files there and commonly leaves it 0777 and/or
    # root:root against the 0771 shell:shell u:object_r:shell_data_file:s0 AOSP
    # ships, which is a detector probe any app can stat without root.
    # Restorative only, so a clean device is a no-op. Guard-gated, and gated
    # again by `fix_shell_tmp` in spoof.conf (default on) -- PARSED, never
    # sourced, because this file is read as root.
    _fst=$(grep "^[ 	]*fix_shell_tmp[ 	]*=" "$NMDIR/spoof.conf" 2>/dev/null \
           | tail -n 1 | sed "s/^[^=]*=//; s/[ 	]#.*//; s/[\"' 	]//g")
    if [ "${_fst:-1}" = "1" ]; then
        [ -d /data/local/tmp ] || mkdir -p /data/local/tmp 2>/dev/null
        if [ ! -d /data/local/tmp ]; then
            nmlog "shell-tmp: /data/local/tmp absent and not creatable"
        else
            # `stat -c %C` comes back as the bare letter "C" in this context
            # rather than a label, so trust a reading only when it looks like a
            # context and fall back to `ls -Zd`; empty means "could not read",
            # which is not "wrong".
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
        # Bounded, like metamount.sh. A hung mount pass here is a HANG, not a
        # crash, so the bootloop counter never reaches GUARD_MAX and the device
        # never self-recovers -- which makes the timeout matter more on this path
        # than on the KSU one, not less.
        #
        # And the STATUS, not just the fact that we called it: a pass that exited
        # non-zero, or that `timeout` killed at 60s having injected part of the
        # rule set, used to leave no trace anywhere. On this path there is no
        # status card to contradict, which makes boot.log the only record there is.
        nmto 60 "$BIN" mount 2>/dev/null
        _mrc=$?
        [ "$_mrc" -ne 0 ] && nmlog "⚠ mount pass exited $_mrc — the injection set may be INCOMPLETE"
        # Durable whiteouts in the same pass as the injections, for the same
        # reason as metamount.sh: a whiteout hides a stock path that is itself the
        # tell, and there is no service.sh re-apply early enough to cover boot.
        if [ -s "$NMDIR/whiteouts.txt" ]; then
            nmto 30 "$BIN" whiteout apply 2>/dev/null
            _wrc=$?
            [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc — hidden paths are still VISIBLE this boot"
        fi
    else
        # Never silent. See metamount.sh: with no else arm a missing binary meant
        # a boot that injected nothing and reported nothing.
        nmlog "⛔ engine binary is missing or not executable ($BIN) — NOTHING was injected this boot"
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
