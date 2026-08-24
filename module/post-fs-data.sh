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

# --- bootloop guard ---
# The spoof add-on runs INSIDE the guard (below), not before it -- same reasoning
# as metamount.sh: `disabled` has to suppress spoof.sh too, or the counter cannot
# protect against the one script most able to wedge a boot (resetprop, uname,
# /proc/cmdline, /proc/bootconfig).
GUARD_MAX=3
COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
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
        echo "rules_at_trip=$("$NM_BIN" list 2>/dev/null | wc -l)"
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
    [ -f "$MODDIR/spoof.sh" ] && sh "$MODDIR/spoof.sh" 2>/dev/null
    if [ -x "$BIN" ]; then
        # Bounded, like metamount.sh. A hung mount pass here is a HANG, not a
        # crash, so the bootloop counter never reaches GUARD_MAX and the device
        # never self-recovers -- which makes the timeout matter more on this path
        # than on the KSU one, not less.
        timeout 60 "$BIN" mount 2>/dev/null
        # Durable whiteouts in the same pass as the injections, for the same
        # reason as metamount.sh: a whiteout hides a stock path that is itself the
        # tell, and there is no service.sh re-apply early enough to cover boot.
        [ -s "$NMDIR/whiteouts.txt" ] && timeout 30 "$BIN" whiteout apply 2>/dev/null
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
