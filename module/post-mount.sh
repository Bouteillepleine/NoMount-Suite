#!/system/bin/sh
# NoMount Suite — KSU/APatch post-mount stage.
#
# EXISTS FOR ONE JOB: take over bind mounts other modules made, before zygote.
#
# A module that binds its own content over the ROM leaves that mount in every
# app's mountinfo, naming /data/adb/modules — the loudest root signal there is,
# and precisely what the mountless posture exists to deny. The runtime pass in
# service.sh cannot take over a `my_*` one: re-asserting a my_* rule on a live
# system has rebooted a device (OP11, Suite v1.3.22, engine v14 — four rules in
# a burst, clean sys.boot.reason, no tombstone), so it defers them and says so.
#
# WHY THIS STAGE AND NOT post-fs-data.sh
#
# Measured on an OP13R (CPH2645, 6.1, ksud 4.1.0): the same block in
# post-fs-data.sh ran BEFORE another module's binds existed and reported
# "nothing mounted over the ROM (posture clean)" while 84 of that module's
# mounts went up afterwards. Module id order does not save us — the Suite is a
# metamodule and ksud runs its scripts ahead of the ordinary ones — so
# post-fs-data is structurally too early no matter how the ids sort.
# post-mount runs after EVERY module's post-fs-data.sh and still before zygote,
# which is the only window where this work is both possible and safe.
#
# Magisk has no post-mount stage; post-fs-data.sh keeps its own copy of this
# block for that path, where it is the last hook before zygote available at all.
MODDIR="${0%/*}"
NMLOG_TAG=post-mount
# nmlog / nmto / nm_set_bin, and the umask. GUARDED for the reason
# post-fs-data.sh spells out: a partial extraction must stop loudly rather than
# run with every helper undefined.
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR — the pre-zygote absorb did not run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR" 2>/dev/null

# nmto() is lib.sh's -- see the note there on what a missing `timeout` costs.

# ABI / BIN / NM_BIN, with the empty-getprop fallback -- see nm_set_bin in lib.sh.
nm_set_bin

# Gated on the my_hookless TRIAL marker: taking a my_* bind over means serving
# that path by injection, and a leaf my_* inject may trip zygote's FD allowlist
# at forkSystemServer. Without the marker this script does nothing at all.
#
# `disabled` is honoured so the bootloop guard in metamount.sh still recovers a
# bad trial on its own: three failed boots write that file, and the next boot
# skips this entirely rather than needing a flash.
if [ ! -f "$NMDIR/disabled" ] && [ -x "$BIN" ] \
   && { [ -f "$NMDIR/my_hookless" ] || [ "$NM_MY_HOOKLESS" = 1 ]; }; then
    _ea=$(nmto 60 "$BIN" absorb --early 2>&1)
    # Status FIRST, then log: nmlog_absorb_notes runs a pipeline, and $? after
    # one is the pipeline's -- the exact footgun the comment on _ab_rc
    # in service.sh documents.
    _ea_rc=$?
    nmlog_absorb_notes "$_ea"
    if [ "$_ea_rc" -eq 124 ]; then
        nmlog "⚠ early absorb TIMED OUT after 60s - continuing boot"
    elif [ "$_ea_rc" -ne 0 ]; then
        nmlog "⚠ early absorb FAILED (rc=$_ea_rc): $(printf '%s\n' "$_ea" | tail -1)"
    else
        nmlog "early absorb: $(printf '%s\n' "$_ea" | tail -1)"
    fi
fi
