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

# Log the lines absorb prints BEFORE its summary.
#
# Every caller keeps only `tail -1`, which is the summary -- so absorb's record
# retirements ("dropped N recorded row(s) from uninstalled module(s): ...") were
# emitted on every boot and recorded on none. They matter because that write is
# the one thing absorb does to persistent state on a device where it absorbs
# nothing at all.
#
# Called at ALL FIVE capture sites, not just service.sh: the prune runs at the
# top of every pass, so it fires on the FIRST one to execute -- post-fs-data's
# `absorb --early` -- and a log line in service.sh alone would never see it.
#
# FOUR call sites, so a fifth cannot be added without noticing this list:
# nm_early_absorb (which is BOTH early passes -- post-fs-data.sh on Magisk and
# post-mount.sh on KSU/APatch), service.sh foreground, service.sh late
# background, uidwatch.sh. It said five while the two early passes were still
# separate copies; uidwatch.sh -- the handler that runs on every install, update
# and uninstall, i.e. exactly when a module's directory disappears and the prune
# has something to say -- was the one the list was written for.
nmlog_absorb_notes() {
    printf '%s
' "$1" | grep -i 'uninstalled module' | while IFS= read -r _l; do
        [ -n "$_l" ] && nmlog "$_l"
    done
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

# Consume an update stash left behind by an install that never finished.
#
# `uninstall.sh` stashes the user's settings to /data/adb/nomount.bak and then
# removes the state directory; `customize.sh` is the only thing that puts them
# back, and TWO aborts sit above its restore loop (the sha256 refusal and the
# metamodule-conflict refusal). After either -- or after any kill of the
# installer, a reboot mid-flash, ksud OOM-killed -- $NMDIR is gone and the stash
# is the ONLY copy of the hide list, the durable whiteouts, binds.list with the
# ROM SELinux labels needed to tear those binds down, and both absorb records.
#
# Both boot entry points then ran a bare `rm -rf /data/adb/nomount.bak`. The
# motive was right and is kept below -- a stash named after this module, holding
# `uidhide`, must not rot on disk -- but the remedy was deletion. It is now
# RESTORE, then delete: the stash still does not survive the boot, and the
# settings do.
#
# `[ -e ]` before each copy, never overwrite: a file already in $NMDIR is the
# newer truth, exactly as customize.sh reasons. The list is the one both
# uninstall.sh and customize.sh carry, and `statefile.rs`'s test pins all three
# together.
nm_consume_stash() {
    _bak=/data/adb/nomount.bak
    [ -d "$_bak" ] || { unset _bak; return 0; }
    _rn=0
    for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
              absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
              absorbed.list binds.list absorbed-tmpfs.list apkstate.list; do
        [ -e "$_bak/$_f" ] || continue
        [ -e "$NMDIR/$_f" ] && continue
        # REMOVE what a failed copy left. uninstall.sh states the rule for the
        # stash side ("A file we could not copy whole must not be there") and
        # this is the same hazard pointing the other way, and worse: a `cp -p`
        # that dies part-way (ENOSPC) leaves a TRUNCATED file in the LIVE state
        # directory, where every later `[ -e ]` guard -- this loop's included --
        # treats it as the newer truth, so nothing ever repairs it. A half-copied
        # `uidhide` is a legal hide list that hides nobody.
        cp -p "$_bak/$_f" "$NMDIR/$_f" 2>/dev/null || { rm -f "$NMDIR/$_f" 2>/dev/null; continue; }
        chmod 0600 "$NMDIR/$_f" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$NMDIR/$_f" 2>/dev/null
        _rn=$((_rn + 1))
    done
    [ "$_rn" -gt 0 ] && nmlog "restored $_rn setting(s) from a stash left by an unfinished install"
    rm -rf "$_bak" 2>/dev/null
    unset _bak _rn _f
    return 0
}

# Rotate the durable boot log. ONLY a boot entry point may call this -- service.sh
# and uidwatch.sh run many times and must not. On KSU it runs TWICE per boot
# (metamount.sh, then post-fs-data.sh before it hands over); that is harmless,
# because `tail -n 400` of a file already at or under 400 lines is a no-op, and
# it is cheaper than teaching the second caller to detect the first.
#
# The chmod is for a file an older build left wide: `tail > $BOOTLOG.tmp` creates
# the temp under whatever umask is in force and `mv` carries that mode onto the log.
nm_boot_log_rotate() {
    [ -f "$BOOTLOG" ] && tail -n 400 "$BOOTLOG" > "$BOOTLOG.tmp" 2>/dev/null \
        && mv -f "$BOOTLOG.tmp" "$BOOTLOG" 2>/dev/null
    # `touch`, NOT `: >> "$BOOTLOG"`. `:` is a POSIX SPECIAL BUILT-IN, so a
    # redirection error on it aborts a non-interactive shell -- and ksud runs
    # module scripts under its bundled busybox ash with ASH_STANDALONE, where
    # that abort kills the WHOLE script, not just this function (measured, this
    # session: dash exits 2 in both positions; mksh exits 1 at top level and
    # survives inside a function). With $BOOTLOG unwritable -- a read-only /data
    # after an ext4 error, a full /data, or a `boot.log` some root script left as
    # a DIRECTORY -- the caller died HERE, 62 lines above metamount.sh's
    # deliberate "$NMDIR is not writable, so the bootloop guard cannot arm"
    # refusal, which is written for exactly this case and was unreachable.
    # `touch` is an ordinary command, so its failure is a status.
    touch "$BOOTLOG" 2>/dev/null || return 0
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

# THE MOUNT PASS ITSELF, in one place.
#
# metamount.sh and post-fs-data.sh carried this twice, and stripped of comments
# and indentation the two ranges were byte-identical -- 24 code lines, verified
# by diff: the bounded `mount` call, the status capture, the _mwhy/_msum greps,
# the `nomount: WARNING` case and the whole whiteout block. This file exists to
# end exactly that, and this was the LARGEST copy of all and the one that runs
# the pass. It had already drifted once, in the documented direction: the Magisk
# copy was missing the `2>&1`, the `reason:` line, the 124 naming and the WARNING
# grep, and each was back-ported separately over three rounds. The `_driver_ok`
# case below still existed in only one of the two.
#
# The caller owns the `[ -x "$BIN" ]` test: its else arm is an incident report
# that has to name which entry point wrote it.
#
# Sets three globals for the caller's status card, and returns the pass's status:
#   _mrc       the mount pass's exit status (124 = `timeout` killed it)
#   _pass_ran  1 once the pass has been invoked at all
#   _driver_ok 0 when the engine did not answer -- i.e. no CONFIG_NOMOUNT kernel
nm_mount_pass() {
    # Capture the STATUS, not just the fact that we called it. `_pass_ran` alone
    # means "the binary was executable and we invoked it", and the status card
    # then renders the green tick as long as SOME rules exist -- so a pass that
    # exited non-zero, or that `timeout` killed at 60s having injected 200 of 260
    # rules, ended the boot on "[NoMount ✅ 200 rules] fully mountless". A partial
    # injection reported as a complete one is the same false green.
    #
    # The bound matters MORE on the Magisk path, not less: a hung mount pass
    # there is a HANG, not a crash, so the bootloop counter never reaches
    # GUARD_MAX and the device never self-recovers.
    #
    # `2>&1`, NOT `2>/dev/null`. The pass writes exactly one sentence that
    # explains the commonest new-user failure -- flashing this module on a kernel
    # without CONFIG_NOMOUNT -- and it writes it to STDERR:
    #
    #   "hookless NoMount engine not responding -- is the CONFIG_NOMOUNT
    #    kernel loaded?"   (mount.rs)
    #
    # Both boot paths used to delete it. What survived was a generic "mount pass
    # exited 1 (failed)", no incident.log (that is written only for a guard trip
    # or a missing binary), and a card saying the opposite of the truth. The
    # product wrote the right words and threw them away. `pass_lock` writes here
    # too ("continuing unserialised rather than stalling the boot"), and mount.rs
    # is explicit that it must not be silent: it names the one window in which an
    # app sees the stock tree.
    _mout="$(nmto 60 "$BIN" mount 2>&1)"
    _mrc=$?
    _pass_ran=1
    [ -n "$_mout" ] && printf '%s\n' "$_mout"
    # 124 named. A hang and a refusal are different problems -- one is the engine
    # not answering, the other is the pass deciding it cannot run -- and on the
    # Magisk path boot.log is the only record there is, so collapsing them made
    # the commonest failure indistinguishable from a bad rule set.
    if [ "$_mrc" -ne 0 ]; then
        nmlog "⚠ mount pass exited $_mrc ($([ "$_mrc" -eq 124 ] && echo "TIMED OUT after 60s" || echo "failed")) — the injection set may be INCOMPLETE"
        # ...and the REASON, which is now in hand. One line, the engine's own
        # words, on the durable channel.
        _mwhy=$(printf '%s\n' "$_mout" | grep -m1 -i 'not responding\|Caused by\|^Error')
        [ -n "$_mwhy" ] && nmlog "  reason: $_mwhy"
        unset _mwhy
    else
        # A SUCCESSFUL pass left no durable record at all: `$_mout` went to stdout
        # (ksud's log, or nowhere) and boot.log never learned that 257 rules had
        # been applied. The user asking "did it work?" had only the card.
        _msum=$(printf '%s\n' "$_mout" | grep -m1 '^nomount(suite):')
        [ -n "$_msum" ] && nmlog "$_msum"
        unset _msum
    fi
    # An exit of 0 does NOT mean every rule landed: the pass deliberately
    # survives individual failures rather than failing the boot over them, and
    # prints `nomount: WARNING ...` when it does -- mount.rs emits that marker for
    # a boot script to grep and its comment says so in as many words. Without
    # this those were invisible: no log line, and the card still green because
    # SOME rules exist.
    case "$_mout" in
        *"nomount: WARNING"*)
            nmlog "$(printf '%s\n' "$_mout" | grep "nomount: WARNING" | head -1)"
            ;;
    esac
    # BEFORE the unset, which is where this used to sit AFTER it. `unset _mout`
    # ran 18 lines above the `case` that reads it, so `$_mout` was empty here,
    # the case never matched, and `_driver_ok` was permanently 1 -- making the
    # "your kernel has no NoMount driver" card, the one written for the single
    # commonest new-user failure, unreachable. It fell through to "ran, but no
    # module had files to serve", which sends the reader to look at their modules
    # instead of at their kernel. Replayed under the device's own busybox ash and
    # under mksh, this session: _driver_ok stayed 1 in both.
    case "$_mout" in *"engine not responding"*) _driver_ok=0 ;; esac
    unset _mout
    # Durable whiteouts, HERE rather than only in service.sh. A whiteout hides a
    # stock path that is itself the tell, and service.sh does not run it until
    # after sys.boot_completed plus a 10s settle -- so every such path was plainly
    # visible for the whole of boot, to anything that looked early. Nothing here
    # needs packages.list, so it belongs in the same pass as the injections.
    # service.sh still re-applies, which is idempotent and catches a late failure.
    if [ -s "$NMDIR/whiteouts.txt" ]; then
        # `2>&1` and KEEP the line, exactly as service.sh's re-apply does. Both
        # boot paths threw the engine's own diagnosis away and logged a bare exit
        # number -- the same `2>/dev/null`-eats-the-reason pattern that was
        # removed from the mount call above and not from this one, for a failure
        # whose meaning is "that path is VISIBLE for the whole boot".
        _wout=$(nmto 30 "$BIN" whiteout apply 2>&1)
        _wrc=$?
        [ "$_wrc" -ne 0 ] && nmlog "⚠ whiteout apply exited $_wrc — hidden paths are still VISIBLE this boot: $(printf '%s\n' "$_wout" | tail -1)"
        unset _wout _wrc
    fi
    return "$_mrc"
}

# The live rule table, dumped ONCE, with the counts every card derives from it.
#
# metamount.sh and service.sh each carried this dump, the `_nmcount` helper and
# the same three counts, plus ~12 lines apiece of the identical prose explaining
# the two exclusions. Only a comment differed.
#
# Sets: _NMLIST (the raw dump), _nmlrc (its exit status), _rules, _wo, _rro, and
# defines _nmcount() for callers that want their own slice of the same dump.
#
# BOUNDED. In metamount.sh this runs OUTSIDE the bootloop guard -- it is not
# gated on `disabled` -- so an unbounded call can hang post-fs-data on exactly
# the device that has already self-disabled to recover. `nm`'s netlink recv has
# no SO_RCVTIMEO, so "the engine accepted the message and never replied" is a
# permanent block, not a slow one.
#
# EXCLUDE the (virtual dir) AND the (whiteout) rows. `grep -c .` counts every
# line of the dump, which on this device is 260 while `nomount check` and
# health.txt both say 257 -- 3 of them being directories the engine materialises,
# which are not rules. Whiteouts are the same mistake found one kind later:
# health.rs counts `rules` as INJECTS and reports `whiteouts` separately, so a
# device with a debloat module installed had a card saying 259 while every other
# surface said 257 (measured on an OP15, 2026-09-07, with SAN installed). The
# card is what most users read; it must not be the one number that disagrees.
nm_rule_counts() {
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    _nmlrc=$?
    # grep -c on an empty stream prints 0 and exits 1, so guard the empty case.
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    _rules=$(_nmcount -v -c -E '\(virtual dir\)|\(whiteout\)')
    _wo=$(_nmcount -c '(whiteout)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    return 0
}

# The early absorb pass, in one place.
#
# Run from post-mount.sh under KernelSU/APatch, and from post-fs-data.sh on
# Magisk (which has no post-mount stage). The two bodies were byte-identical.
#
# Only under the `my_hookless` marker: without it my_* targets are served by a
# REAL BIND, and absorbing at this point would take over a bind the pass is about
# to make.
#
# The `NM_MY_HOOKLESS=1` half of the gate is gone. Nothing in the module ever set
# that variable -- and a boot script inherits no environment from a person's
# shell, so it could not have arrived here anyway -- while `my_hookless_enabled()`
# in src/mount.rs accepts ANY non-empty value that is not "0". So the one case
# where the variable did something (a hand-run `NM_MY_HOOKLESS=yes nomount
# mount`) took the injection path in Rust while these scripts stayed on the bind
# path. The marker file is the durable state both sides agree on.
nm_early_absorb() {
    [ -e "$NMDIR/disabled" ] && return 0
    [ -x "$BIN" ] || return 0
    [ -f "$NMDIR/my_hookless" ] || return 0
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
}

# The bootloop guard, in one place.
#
# Counts this boot, trips at GUARD_MAX, and records why. `$1` names the entry
# point for incident.log -- the only thing the two callers ever disagreed about.
#
# Returns 0 to proceed, 1 when the Suite is already disabled, 2 when this call
# tripped the guard. Both callers used to carry their own copy of the whole
# thing, ~55 lines each, and the copies had already drifted: the Magisk one was
# silent on the "already disabled" arm and its incident report was missing
# `modules_enabled` -- the single most useful line in the file, since a guard trip
# is almost always "which module did I install just before this" and the answer is
# gone by the time the user reads the report.
#
# This is the mechanism that recovers a device that will not boot. It is the last
# place that should have had two implementations.
nm_guard_bump() {
    # The guard's own state must be a plain FILE, and a directory there disarms
    # it completely. `cat` on a directory prints nothing and exits 1, so COUNT is
    # 0; `echo >` on a directory fails, but `echo` is not a POSIX special builtin
    # so the shell carries on -- leaving COUNT at 1 on EVERY boot, GUARD_MAX
    # unreachable, and the one mechanism that recovers a wedged device dead.
    # Measured on an OP15's own mksh, 2026-09-07: boots 1 through 5, COUNT=1,
    # trips=no, every time, with the shell's complaint going to a stderr this
    # path sends to /dev/null.
    #
    # `disabled` as a directory is worse than useless: the five shell entry
    # points test `-f` (false -> serve normally) while `mount::guard_tripped`
    # tests `Path::exists()` (true -> every WebUI serving verb refuses), and the
    # WebUI's re-arm is `rm -f`, which fails on a directory -- so the user cannot
    # clear it. All three verified on device.
    #
    # Any root script can `mkdir` these, and so can a fat-fingered shell.
    for _f in bootcount disabled; do
        if [ -e "$NMDIR/$_f" ] && [ ! -f "$NMDIR/$_f" ]; then
            rm -rf "${NMDIR:?}/$_f" 2>/dev/null
            nmlog "⚠ $NMDIR/$_f was not a regular file (the guard cannot use it) - removed"
        fi
    done
    GUARD_MAX=3
    COUNT=$(cat "$NMDIR/bootcount" 2>/dev/null || echo 0)
    # Sanitize before the arithmetic. A bootcount corrupted to something like
    # "3 3" (power loss mid-write, or a stray editor) makes $((COUNT + 1)) a FATAL
    # arithmetic-syntax error in both mksh and ash -- the shell exits on the spot,
    # so the counter is never rewritten, nothing is injected, nothing is logged,
    # and the module stays a silent no-op on every boot from then on. Unparsable
    # means "start over", which re-arms the guard rather than wedging it.
    case "$COUNT" in ''|*[!0-9]*) COUNT=0 ;; esac
    COUNT=$((COUNT + 1))
    echo "$COUNT" > "$NMDIR/bootcount"
    # ...and CHECK it landed. `echo` is not a special builtin, so a failed write
    # leaves the counter at its previous value and the shell carries on. On a full
    # /data the file is created and truncated to 0 bytes, the sanitiser above then
    # reads '' -> COUNT=0 -> COUNT=1 on EVERY boot, GUARD_MAX is unreachable, and
    # the one mechanism that recovers a wedged device is dead precisely on the
    # disk-full condition that is a plausible cause of the wedge. metamount.sh
    # refuses the pass outright when $NMDIR is unwritable; post-fs-data.sh (the
    # Magisk entry point) has no such refusal, so this is the only notice there is.
    [ "$(cat "$NMDIR/bootcount" 2>/dev/null)" = "$COUNT" ] \
        || nmlog "⚠ cannot write $NMDIR/bootcount — the bootloop guard is NOT arming this boot"
    # SYNC. This is the most crash-adjacent write in the project and the only one
    # where "the next boot repairs it" is false by construction: a boot that
    # wedges and is watchdog-reset inside the ext4 commit interval loses the
    # counter, the sanitizer above reads the empty file as 0, and GUARD_MAX is
    # never reached. Every other durable file goes through
    # statefile::write_atomic, which syncs.
    sync 2>/dev/null

    if [ -e "$NMDIR/disabled" ]; then
        nmlog "disabled, skipping the mount pass"
        return 1
    fi
    [ "$COUNT" -lt "$GUARD_MAX" ] && return 0

    nmlog "bootloop guard tripped (count=$COUNT) -> self-disabling"
    # `touch`, not `: > ...`, for the reason nm_boot_log_rotate spells out -- and
    # this is the worst possible moment for it: under busybox ash a redirection
    # failure on the special builtin `:` kills the script HERE, so incident.log
    # (the whole point of this arm) is never written; under mksh-in-a-function it
    # survives, `disabled` is never created, and the guard "trips" silently on
    # every boot forever while the WebUI still shows Armed.
    touch "$NMDIR/disabled" 2>/dev/null \
        || nmlog "⚠ could not create $NMDIR/disabled — the guard tripped but CANNOT self-disable"
    sync 2>/dev/null
    # Record WHY, while the evidence is still fresh. Without this a trip leaves
    # only an empty `disabled` file and the user has to dig through tombstones by
    # hand to find out what crashed -- that is exactly how the /my_product
    # FD-allowlist bootloop was found. Everything here is best-effort and must
    # never fail the boot.
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "bootcount=$COUNT guard_max=$GUARD_MAX ($1)"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "rules_at_trip=$(nmto 15 "$NM_BIN" list 2>/dev/null | wc -l)"
        echo "modules_enabled=$(for m in /data/adb/modules/*/; do
                [ -f "$m/disable" ] || [ -f "$m/remove" ] || [ -f "$m/skip_mount" ] && continue
                basename "$m"
            done | tr '\n' ' ')"
        nm_incident_tombstone
    } > "$NMDIR/incident.log" 2>/dev/null
    return 2
}

# "The engine binary is not there", recorded once.
#
# Never silent: with no else arm on the `[ -x "$BIN" ]` test, a missing binary
# meant a boot that injected nothing and reported nothing. `$1` names the entry
# point, which is all the two copies of this ever differed by.
nm_incident_missing_binary() {
    nmlog "⛔ engine binary is missing or not executable ($BIN) — NOTHING was injected this boot"
    {
        echo "when=$(date '+%Y-%m-%d %H:%M:%S') epoch=$(date +%s)"
        echo "reason=engine did not run: no executable at $BIN ($1)"
        echo "abi=$ABI (ro.product.cpu.abi=$(getprop ro.product.cpu.abi 2>/dev/null))"
        # shellcheck disable=SC2012  # listing the ABI directories the ZIP shipped, by
        # name, for an incident report. The names are ours (arm64-v8a, x86_64...) and
        # `find` cannot produce a one-line summary without more plumbing than the
        # message is worth.
        echo "shipped_abis=$(ls "$MODDIR/bin" 2>/dev/null | tr '\n' ' ')"
        echo "kernel=$(uname -r)"
        echo "suite=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -1)"
        echo "note=reinstall the module zip; a partial/permission-stripped extraction is the usual cause"
    } > "$NMDIR/incident.log" 2>/dev/null
}
