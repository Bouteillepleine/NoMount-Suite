#!/system/bin/sh
# Bootloop-guard reset: once the system finishes booting, the last boot was
# healthy, so clear the boot counter (re-arms the guard for next time).
NMDIR=/data/adb/nomount
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 120 ]; do
    sleep 2
    i=$((i + 1))
done

# NB: unlike the old build we do NOT re-assert kernel_umount here — forcing that
# feature on breaks root for other modules on OP15. Hiding of the Suite's real
# mounts is handled by the manager's per-app-profile default-umount instead.

sleep 10
rm -f "$NMDIR/bootcount"
echo "nomount: boot completed, guard counter reset" > /dev/kmsg 2>/dev/null

# --- Cloak: re-apply the pathhide maps/fd rule list (managed by the WebUI) ---
# Hides selected module APKs from every /proc/<pid>/maps and /proc/<pid>/fd via
# the kernel pathhide interface. Inert on a kernel without /proc/pathhide.
if [ -e /proc/pathhide ]; then
    echo - > /proc/pathhide 2>/dev/null
    if [ -f "$NMDIR/pathhide.conf" ]; then
        while IFS= read -r _phr; do
            _phr=$(echo "$_phr" | tr -d '\r')
            [ -z "$_phr" ] && continue
            case "$_phr" in \#*) continue ;; esac
            echo "+$_phr" > /proc/pathhide 2>/dev/null
        done < "$NMDIR/pathhide.conf"
        echo "nomount: pathhide cloak rules re-applied" > /dev/kmsg 2>/dev/null
    fi
fi

# Pre-build the Cloak Xposed-module cache in the background so the WebUI opens
# instantly (reads the cache) instead of scanning ~all installed APKs on open.
[ -f /data/adb/modules/meta-nomount/scan.sh ] && \
    (sh /data/adb/modules/meta-nomount/scan.sh >/dev/null 2>&1 &)

# --- ksud de-link re-assertion (self-heal of the susfs-action guard) ---
# metamount.sh de-links ksu_susfs from the ksud multicall at mount time; re-assert it
# here post-boot as a belt-and-suspenders against any timing race (e.g. ksud finishing
# its install stage after our mount pass). If ksud & ksu_susfs still share an inode,
# split ksu_susfs into its own independent copy so the susfs action button can never
# reach the ksud daemon. (A clobbered ksud can't be healed from a module service — if
# ksud were broken this service wouldn't run — so we only re-assert the split here.)
KSUD=/data/adb/ksud
SUSFS_BIN=/data/adb/ksu/bin/ksu_susfs
if [ -f "$KSUD" ] && [ -f "$SUSFS_BIN" ] \
   && [ "$(stat -c %s "$KSUD" 2>/dev/null)" -gt 1000000 ] \
   && [ "$(stat -c %i "$KSUD" 2>/dev/null)" = "$(stat -c %i "$SUSFS_BIN" 2>/dev/null)" ]; then
    chattr -i "$KSUD" 2>/dev/null
    if cp "$KSUD" "$SUSFS_BIN.nm_new" 2>/dev/null; then
        chmod 0755 "$SUSFS_BIN.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$SUSFS_BIN.nm_new" 2>/dev/null
        mv -f "$SUSFS_BIN.nm_new" "$SUSFS_BIN" 2>/dev/null \
            && echo "nomount: re-asserted ksud de-link (service)" > /dev/kmsg 2>/dev/null
    else
        rm -f "$SUSFS_BIN.nm_new" 2>/dev/null
    fi
fi

# --- refresh the manager card with the settled state ---
# metamount.sh tags the card in post-fs-data, when the mount table is not final and
# health cannot be judged yet. Now that boot is complete both are knowable, so restate
# the card with the real mount count and the health-check verdict — that turns the
# module list into a status readout you can trust without opening the WebUI.
MODDIR="${0%/*}"
ABI=$(getprop ro.product.cpu.abi)
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"

# --- re-apply the persistent per-app block list ---
# Per-UID hiding lives in kernel memory and is empty after every reboot; the
# block list on disk (package names / UIDs) is the durable record. Now that boot
# is complete, packages.list is populated and app UIDs are stable, so resolve the
# list and re-block each app. Runs only when the guard hasn't tripped.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/blocklist" ]; then
    _bl=$("$BIN" uid apply 2>/dev/null)
    echo "nomount: block list re-applied ($_bl)" > /dev/kmsg 2>/dev/null
fi

# --- runtime health canary (writes health.txt; complements plan-time doctor) ---
# Runs the per-UID self-consistency probe that the d_drop regression would have
# failed on the first boot: does a normal app see the same injected files as root?
# The probe can transiently disagree right after boot, before every app UID has
# launched and materialised its per-UID injection, so retry across a settle window
# and keep the *settled* verdict — a boot-time blip must not stamp a scary
# "inconsistency" on the card. Only a verdict that PERSISTS through the whole
# window is a real d_drop-style regression. Non-fatal; surfaced on the card / WebUI.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _try=0
    while [ "$_try" -lt 6 ]; do
        "$BIN" selfcheck --write >/dev/null 2>&1
        _cons=$(sed -n 's/^consistency=//p' "$NMDIR/health.txt" 2>/dev/null)
        if [ "$_cons" = "ok" ] || [ "$_cons" = "unchecked" ] || [ -z "$_cons" ]; then
            break
        fi
        _try=$((_try + 1))
        sleep 15
    done
    _hv=$(sed -n 's/^verdict=//p' "$NMDIR/health.txt" 2>/dev/null)
    echo "nomount: selfcheck verdict=${_hv:-unknown} consistency=${_cons:-unknown} (settle tries=$_try)" > /dev/kmsg 2>/dev/null
fi

if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _rules=$("$NM_BIN" list 2>/dev/null | wc -l)
    _rro=$("$NM_BIN" list 2>/dev/null | grep -c '/overlay/[^ ]*\.apk')
    _mnt=$(grep -c '/data/adb/modules' /proc/self/mountinfo 2>/dev/null || echo 0)
    _doc=$(timeout 30 "$BIN" doctor 2>/dev/null | sed -n 's/^summary: \([0-9]*\) errors, \([0-9]*\) warnings$/\1 \2/p')
    _err=$(echo "$_doc" | awk '{print $1+0}')
    _wrn=$(echo "$_doc" | awk '{print $2+0}')
    # runtime consistency canary trumps plan-time doctor for card health: a
    # per-UID inconsistency is a live regression, not a plan hazard.
    _cons=$(sed -n 's/^consistency=//p' "$NMDIR/health.txt" 2>/dev/null)
    if [ -n "$_cons" ] && [ "$_cons" != "ok" ] && [ "$_cons" != "unchecked" ]; then
        _health="⚠️ per-UID inconsistency — see WebUI › Tools"
    elif [ "${_err:-0}" -gt 0 ]; then
        _health="⚠️ $_err error(s) — see WebUI › Tools"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="$_wrn warning(s)"
    else
        _health="healthy"
    fi
    if [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="⚠ $_mnt module mount(s)"
    else
        _mstate="0 mounts"
    fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "[NoMount ✅ $_rules rules · $_rro RRO · $_mstate] $_health — fully mountless: hookless VFS + RRO, su via sucompat" \
        >/dev/null 2>&1
    echo "nomount: card refreshed ($_rules rules, $_mstate, $_health)" > /dev/kmsg 2>/dev/null
fi
exit 0
