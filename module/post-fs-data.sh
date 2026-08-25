#!/system/bin/sh
# Magisk fallback (no metamodule hook). KSU/APatch use metamount.sh instead.
[ -n "$KSU" ] && exit 0
[ -n "$APATCH" ] && exit 0
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

# Bounded exec (see metamount.sh). On a device without toybox `timeout` a bare
# `timeout 60 cmd` does not run the command unbounded, it does not run it at all
# -- the silent no-op this file exists to remove. Prefer the bound, fall back to
# running bare.
if command -v timeout >/dev/null 2>&1; then
    nmto() { timeout "$@"; }
else
    nmto() { shift; "$@"; }
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
# after us still binds after this runs and stays deferred; `nomount doctor` names
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
# The spoof add-on runs INSIDE the guard (below), not before it -- same reasoning
# as metamount.sh: `disabled` has to suppress spoof.sh too, or the counter cannot
# protect against the one script most able to wedge a boot (resetprop, uname,
# /proc/cmdline, /proc/bootconfig).
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
        _t=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
        if [ -n "$_t" ]; then
            echo "tombstone=$_t"
            echo "  $(grep -m1 '>>> ' "$_t" 2>/dev/null)"
            echo "  $(grep -m1 'Abort message' "$_t" 2>/dev/null)"
        fi
    } > "$NMDIR/incident.log" 2>/dev/null
else
    # --- spoof add-on (dynamic vbmeta.digest) ---
    # Same stage as the KSU/APatch metamount hook, but for the Magisk path.
    # BOUNDED, like the engine calls below -- spoof.sh was the one call on this
    # path with no bound at all, despite driving resetprop, uname, /proc/cmdline
    # and /proc/bootconfig AND shelling out to `nm`, whose netlink recv has no
    # SO_RCVTIMEO (userspace/src/nm.h do_nm_cmd). A kernel that accepts the
    # message and never answers hangs post-fs-data forever.
    [ -f "$MODDIR/spoof.sh" ] && nmto 90 sh "$MODDIR/spoof.sh" 2>/dev/null
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
