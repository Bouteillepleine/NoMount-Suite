#!/system/bin/sh
# Shared by every NoMount entry point. Sourced, never executed.
#
# WHY THIS EXISTS. These helpers used to be pasted into each script. `nmto()` was
# byte-identical in four of them, the /data/local/tmp restore in three, the ksud
# de-link in two, and `nmlog` + the ABI fallback in five -- 72 of post-fs-data.sh's
# 130 code lines were the same lines as metamount.sh's. Copies drift, and one
# already had: uidwatch.sh, the script that runs on EVERY app install, was the one
# without `nmto` (so on a device with no toybox `timeout` its work did not run at
# all) and without the failure arm its neighbours carry (so a failed `absorb` was
# logged in the voice of a success). Neither was a decision; both were a copy that
# was never made.
#
# THE OBJECTION THIS ANSWERS. post-fs-data.sh used to say, in a comment: "Duplicated
# rather than sourced: a `.` of a file that a partial install did not extract would
# leave every nmlog call undefined for the rest of the pass." That is a real hazard
# and it is why nothing here is sourced blind -- every caller uses the guarded form
#
#     . "$MODDIR/lib.sh" 2>/dev/null || { <say so loudly>; exit 1; }
#
# so a missing lib.sh is a recorded abort instead of a shell running with undefined
# functions. That is strictly better than the state the duplication produced: with
# four copies the *partial-install* case was covered and the *drift* case was not,
# and drift is the one that actually happened.
#
# CONTRACT. The caller sets MODDIR (and NMLOG_TAG, if it wants its lines labelled)
# BEFORE sourcing. This file sets NMDIR, BOOTLOG and the umask, and defines
# functions only -- it starts nothing, writes nothing and never exits, so sourcing
# it is safe at any stage.

# The boot umask is 0, so every state file created from here (and by the binaries
# these scripts exec, which inherit it) landed 0666 -- observed on absorbed.list,
# binds.lock, uidhide and uidhide.cache. The 0700 directory is what actually gates
# access, but uidhide IS the hiding policy and should not rely on its parent alone.
umask 077

NMDIR=/data/adb/nomount
BOOTLOG="$NMDIR/boot.log"

# Tee every diagnostic to a durable log as well as /dev/kmsg. On this hardware the
# kernel ring is flooded by WMI roam-stats spam within minutes of boot, so
# `dmesg | grep -i nomount` comes back empty long before anyone looks -- and the
# loudest lines these scripts have (absorb TIMED OUT, hide list apply FAILED) were
# therefore unrecoverable in practice.
#
# NMLOG_TAG names the stage, so one log reads as a sequence. Rotation is NOT here:
# only a boot entry point may rotate, and it must do it exactly once per boot.
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [${NMLOG_TAG:-nomount}] $*" >> "$BOOTLOG" 2>/dev/null
}

# Bounded exec. Every engine call goes through this. `timeout` is toybox's and is
# not guaranteed present: without it `timeout 60 cmd` does not run the command
# unbounded, it does not run it AT ALL ("timeout: not found"), which is the silent
# no-op most of the commentary in these scripts exists to remove. Prefer the bound;
# fall back to polling a backgrounded child, with timeout(1)'s own contract -- the
# command's status, or 124 if it had to be killed.
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

# Repair the state directory's modes and SELinux label. Idempotent; a clean
# device pays three finds and a chcon.
#
# WHY IT IS HERE. metamount.sh has done this at every boot since the drift was
# measured; post-fs-data.sh, which is the boot entry point on Magisk, never did --
# so on that manager the repair simply did not exist, and $NMDIR kept whatever an
# older build had left. That is the same copy-that-was-never-made this file was
# created to end, so the code moves here rather than being pasted a second time.
# Call it once per boot, from a boot entry point, right after $NMDIR is created.
#
# -type f, because the glob also handed DIRECTORIES to chmod: `rollback-bin` was
# observed on-device as drw------- , i.e. readable but not traversable, so nothing
# inside it could be reached by anything -- including us. The -type d pass REPAIRS
# a directory an earlier build already damaged: restricting the file pass stops
# new breakage but cannot undo old, and a device that ran the buggy build keeps
# its drw------- directory forever (measured on OP15, two days, several updates).
#
# The label had drifted the same way. Measured on OP15: $NMDIR carried
# u:object_r:system_file:s0 while its parent /data/adb carries adb_data_file. That
# matters because the live policy grants every app domain read+search on
# system_file (dir 0x11140053, file 0x2044412) and NOTHING on adb_data_file (0 for
# both) -- so the only thing keeping spoof.conf, uidhide and blocklist away from an
# app was the parent refusing traversal. Unreachable today, but the files name
# exactly which apps we hide, so match the parent and stop relying on one directory
# up. Nothing in the Suite ever set system_file here; it is drift, not intent.
nm_state_dir_repair() {
    find "$NMDIR" -maxdepth 1 -type f -exec chmod 0600 {} + 2>/dev/null
    find "$NMDIR" -maxdepth 1 -mindepth 1 -type d -exec chmod 0700 {} + 2>/dev/null
    chcon -R u:object_r:adb_data_file:s0 "$NMDIR" 2>/dev/null
    return 0
}

# Rotate the durable boot log. ONLY a boot entry point may call this, and only
# once per boot -- service.sh and uidwatch.sh run many times and must not.
#
# The chmod is for a file an older build left wide: `tail > $BOOTLOG.tmp` creates
# the temp under whatever umask is in force and `mv` carries that mode onto the log.
nm_boot_log_rotate() {
    [ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
        && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
    : >> "$BOOTLOG" 2>/dev/null
    chmod 0600 "$BOOTLOG" 2>/dev/null
    return 0
}

# The newest native crash and its abort line, for incident.log. For an early-boot
# bootloop this is almost always zygote or system_server and names the offending
# path outright -- it is how the /my_product FD-allowlist bootloop was found.
# Prints nothing when there is no tombstone. Best-effort; never fails the boot.
nm_incident_tombstone() {
    # shellcheck disable=SC2010  # `ls -t` is the point: we want the NEWEST
    # tombstone and a glob cannot sort by mtime. The names here are generated by
    # the platform (tombstone_NN), so the usual hostile-filename argument does
    # not apply.
    _t=$(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\.pb$' | head -1)
    [ -n "$_t" ] || return 0
    echo "tombstone=$_t"
    echo "  $(grep -m1 '>>> ' "$_t" 2>/dev/null)"
    echo "  $(grep -m1 'Abort message' "$_t" 2>/dev/null)"
    return 0
}

# Resolve the per-ABI binaries into ABI / BIN / NM_BIN.
#
# An unchecked ABI is a silent no-op: empty gives "$MODDIR/bin//nomount", which can
# never be executable, and every caller gates on [ -x "$BIN" ]. getprop CAN come
# back empty this early, so fall back to the first entry of the abilist and then to
# the only ABI the zip actually ships.
nm_set_bin() {
    ABI=$(getprop ro.product.cpu.abi)
    [ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
    [ -n "$ABI" ] || ABI=arm64-v8a
    # shellcheck disable=SC2034  # read by the SOURCING script, which shellcheck
    # only sees when it is invoked with -x. It is not exported on purpose: BIN is
    # a path each caller gates on, not something the binaries it runs should read.
    BIN="$MODDIR/bin/$ABI/nomount"
    # The Suite binary shells out to the hookless `nm` netlink client beside it.
    NM_BIN="$MODDIR/bin/$ABI/nm"
    export NM_BIN
}

# --- /data/local/tmp: restore the AOSP owner/mode/context ---
#
# ksud (and anything else that stages files there) commonly leaves it 0777 and/or
# root:root; AOSP ships 0771 shell:shell u:object_r:shell_data_file:s0. The drift is
# caused by having a root manager rather than by anything the Suite hides, so it is
# a zero-false-positive probe for any app that can stat the path without root, and
# no amount of mount-hiding answers it. Restorative only: each field is touched
# solely when it already differs, so a clean device is a no-op. Run at post-fs-data
# AND again after boot, because ksud and adbd keep staging files there all boot long.
#
# `fix_shell_tmp` in spoof.conf gates it (default on). PARSED, never sourced: the
# file is read as root, and sourcing a writable config is root code execution.
nm_fix_shell_tmp() {
    _fst=$(grep "^[ 	]*fix_shell_tmp[ 	]*=" "$NMDIR/spoof.conf" 2>/dev/null \
           | tail -n 1 | sed "s/^[^=]*=//; s/[ 	]#.*//; s/[\"' 	]//g")
    [ "${_fst:-1}" = "1" ] || return 0
    [ -d /data/local/tmp ] || mkdir -p /data/local/tmp 2>/dev/null
    if [ ! -d /data/local/tmp ]; then
        nmlog "shell-tmp: /data/local/tmp absent and not creatable"
        return 0
    fi
    # `stat -c %C` answers correctly from an interactive root shell but comes back
    # as the bare letter "C" in a service context, so the label always compared
    # unequal and every boot re-ran chcon over a change that had not happened. Take
    # the reading only when it looks like a context and fall back to `ls -Zd`; an
    # empty answer means "could not read", not "wrong".
    _stm=$(stat -c %a /data/local/tmp 2>/dev/null)
    _sto=$(stat -c %u:%g /data/local/tmp 2>/dev/null)
    _stc=$(stat -c %C /data/local/tmp 2>/dev/null)
    # shellcheck disable=SC2012  # `ls -Zd` on ONE known directory: there is no
    # find(1) equivalent that prints a context, and the path is a literal.
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

# --- ksud multicall guard (susfs4ksu action-button clobber protection) ---
#
# On this build ksud/ksu_susfs/resetprop are ONE hardlinked multicall binary. The
# SUSFS module's action button runs `cp -f <standalone> /data/adb/ksu/bin/ksu_susfs`,
# which follows the hardlink and overwrites the whole ksud daemon -> breaks su/ksud
# until reflash (a reboot in that state can bootloop). Boot re-creates the hardlink
# every time, so de-link ksu_susfs into its OWN independent copy once per boot:
# after this, action.sh's cp only hits the copy and the ksud daemon inode is
# untouched. No chattr +i, so legitimate susfs updates still work. Only acts on a
# genuine (>1MB) multicall that actually shares ksud's inode; a clobbered/small ksud
# is left alone.
#
# Called at post-fs-data AND again after boot: ksud can finish its install stage
# after the mount pass, which re-creates the hardlink.
#
# $1 is the word for the log line, so the two callers stay distinguishable.
nm_delink_ksud() {
    _kd=/data/adb/ksud
    _ks=/data/adb/ksu/bin/ksu_susfs
    [ -f "$_kd" ] && [ -f "$_ks" ] || return 0
    [ "$(stat -c %s "$_kd" 2>/dev/null)" -gt 1000000 ] 2>/dev/null || return 0
    [ "$(stat -c %i "$_kd" 2>/dev/null)" = "$(stat -c %i "$_ks" 2>/dev/null)" ] || return 0
    # RECORD the flag before clearing it, and put back only what was there. `chattr
    # +i` unconditionally was not a restore: on a device where ksud was never
    # immutable it ADDED immutability every boot, and the next legitimate ksud
    # update then failed with EPERM. (The clear is genuinely needed, but not for the
    # reason the old comment gave -- reading an immutable file is fine; what needs
    # it is the `mv` below, which UNLINKS $_ks, and unlinking a hardlink to an
    # immutable inode is refused.)
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
