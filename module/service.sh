#!/system/bin/sh
# Bootloop-guard reset: once the system finishes booting, the last boot was
# healthy, so clear the boot counter (re-arms the guard for next time).
NMDIR=/data/adb/nomount
umask 077                     # state files are 0600, not the boot umask 0666 (see metamount.sh)

# Binary paths, hoisted to the top because the cloak block below now needs `nm`
# too -- it used to write to /proc/pathhide, which needed nothing. $0 does not
# change, so these are the same values the later section used to recompute.
MODDIR="${0%/*}"
ABI=$(getprop ro.product.cpu.abi)
# The SAME fallback metamount.sh and post-fs-data.sh both carry, which this path
# was missing. An empty ABI builds "$MODDIR/bin//nomount", which can never be
# executable -- and EVERY block below is gated on [ -x "$BIN" ] with no else arm,
# so absorb, the whiteout re-apply, the authoritative `uid apply`, the package
# watcher, the selfcheck canary and the card refresh all silently did nothing.
# The card then kept whatever metamount.sh wrote at post-fs-data, so the boot
# looked complete.
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"

# Bounded exec (see metamount.sh): prefer `timeout`, fall back to running bare
# rather than not running the command at all where toybox timeout is absent.
if command -v timeout >/dev/null 2>&1; then
    nmto() { timeout "$@"; }
else
    nmto() { shift; "$@"; }
fi

# Tee every diagnostic to a durable log as well as /dev/kmsg. On this hardware
# the kernel ring is flooded by WMI roam-stats spam within minutes of boot, so
# `dmesg | grep -i nomount` comes back empty long before anyone looks -- and the
# loudest lines this script has (absorb TIMED OUT, ⚠ hide list apply FAILED) were
# therefore unrecoverable in practice. No rotation here: the boot entry point
# (metamount.sh / post-fs-data.sh) already rotated once this boot.
BOOTLOG="$NMDIR/boot.log"
nmlog() {
    echo "nomount: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') [service] $*" >> "$BOOTLOG" 2>/dev/null
}

# --- health.txt freshness -----------------------------------------------------
# health.txt carries a `ts=` field (written by src/health.rs) that NOTHING read.
# So a selfcheck that failed to write -- or an engine that hung and never
# returned -- silently left LAST BOOT's file in place, and every consumer below
# sed'd yesterday's verdict out of it as if it were current. Worse, the empty
# case mapped to _consbad=0 and the card printed "healthy" off a file that did
# not exist at all.
#
# Boot epoch = now minus uptime. A record stamped before that is not this boot's.
_now=$(date +%s 2>/dev/null || echo 0)
_up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
# FAIL CLOSED when the boot epoch is unknowable. Zeroing both left
# _bootepoch=0, which makes the >= test below true for EVERY timestamp -- so the
# one input that defeats the freshness check (an unreadable date or
# /proc/uptime) made a stale record from last boot read as this boot's, which is
# precisely the false green the check exists to stop. "Cannot tell" has to mean
# "not fresh", the same way an unparsable ts= already does.
_epoch_known=1
case "$_now$_up" in *[!0-9]*|"") _now=0; _up=0; _epoch_known=0 ;; esac
_bootepoch=$((_now - _up))
# ...and refuse an IMPLAUSIBLE epoch too, not just an unreadable one. On a device
# that lost its RTC (or had the clock set backward across the reboot) _bootepoch
# comes out small or negative, and LAST boot's ts -- a real, large epoch -- then
# satisfies ">= -60" and reads as fresh. That is the precise scenario the
# freshness check was added for, so the check must not be the thing that misses
# it. 1000000000 = 2001-09-09; anything below it is not a real wall clock.
[ "$_bootepoch" -ge 1000000000 ] 2>/dev/null || _epoch_known=0
# 0 unless health.txt exists AND was stamped at or after this boot began.
_health_fresh() {
    [ "$_epoch_known" = 1 ] || return 1
    _hts=$(sed -n 's/^ts=//p' "$NMDIR/health.txt" 2>/dev/null)
    case "$_hts" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_hts" -ge "$_bootepoch" ]
}
# Read a key only from a fresh record; prints nothing at all otherwise, so a
# stale file behaves exactly like a missing one instead of like a verdict.
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

# NB: unlike the old build we do NOT re-assert kernel_umount here — forcing that
# feature on breaks root for other modules on OP15. Hiding of the Suite's real
# mounts is handled by the manager's per-app-profile default-umount instead.

sleep 10
# Only re-arm when the boot really finished. Clearing the counter after the wait
# merely TIMED OUT disarms the bootloop guard on exactly the hanging boots it
# exists to catch, so it could never reach GUARD_MAX.
if [ "$booted" = "1" ]; then
    rm -f "$NMDIR/bootcount"
    nmlog "boot completed, guard counter reset"
else
    nmlog "boot_completed never set - leaving guard counter armed"
fi

# --- Cloak: re-apply the pathhide maps/fd rule list (managed by the WebUI) ---
# Hides selected module APKs from every /proc/<pid>/maps and /proc/<pid>/fd.
#
# Driven over nomount's netlink knob (`nm k p`), not the old /proc/pathhide node.
# That node was created unconditionally and any app could find it with a single
# readdir of /proc -- a self-naming tell louder than the packages it concealed --
# so it is gone unless a kernel was deliberately built with -DPH_ENABLE_PROC.
# `nm k p` with no value is the presence probe: it exits 0 only when the pathhide
# patch set is compiled in, so this stays inert on a kernel without it.
if [ -x "$NM_BIN" ] && "$NM_BIN" k p >/dev/null 2>&1; then
    # No clear here. The kernel's list starts EMPTY at boot, so clearing achieves
    # nothing on the only path this runs -- except when another module has
    # already added its rules, in which case it silently unhides everything that
    # module was asked to hide. Removing one of OUR rules still works: it is
    # dropped from pathhide.conf and simply not re-added on the next boot, and
    # the WebUI's Apply handles the live case.
    if [ -f "$NMDIR/pathhide.conf" ]; then
        # COUNT the rejections. Every add was sent to /dev/null with its status
        # discarded and the line below then said "re-applied" whatever happened --
        # so a kernel that refused every rule (list full, malformed needle, a
        # pathhide build that answers the presence probe but not the add) reported
        # the cloak as restored while nothing was hidden. The WebUI's Apply button
        # counts its failures for exactly this reason; the boot path did not.
        # Redirected `while … done < file`, not `cat | while`: a pipeline puts the
        # loop in a subshell and every _phf increment would be lost on exit.
        _phn=0; _phf=0
        while IFS= read -r _phr; do
            _phr=$(echo "$_phr" | tr -d '\r')
            [ -z "$_phr" ] && continue
            case "$_phr" in \#*) continue ;; esac
            _phn=$((_phn + 1))
            nmto 10 "$NM_BIN" k p "+$_phr" >/dev/null 2>&1 || _phf=$((_phf + 1))
        done < "$NMDIR/pathhide.conf"
        if [ "$_phf" -gt 0 ]; then
            nmlog "⚠ pathhide cloak: $_phf of $_phn rule(s) REJECTED by the kernel — those paths are still visible in /proc/<pid>/maps and fd"
        else
            nmlog "pathhide cloak rules re-applied ($_phn)"
        fi
    fi
fi

# --- Ghost: populate the existence cloak's two tables ------------------------
# _ghost closes the four (now seven) "resolve a path, then act" oracles that no
# hijacked filesystem op can answer -- O_PATH handing back the path, getxattr
# handing back the SELinux label, a trailing component answering ENOTDIR, link()
# answering EXDEV, and truncate/utimensat/chmod answering EROFS where an absent
# path answers ENOENT.
#
# Its guards are DEAD CODE until both tables are populated: ghost_hidden_path()
# short-circuits to false on an empty table. Measured on OP15 -- a kernel built
# WITH the _ghost patches but with nothing feeding it leaked all four oracles
# exactly as an unpatched kernel does. This block is what makes them live.
#
# `nm k g` with no value is the presence probe: it exits 0 only when _ghost is
# compiled in AND the engine is >= v26 (the knob does not exist below that), so
# this stays inert on every other kernel.
if [ -x "$NM_BIN" ] && "$NM_BIN" k g >/dev/null 2>&1; then
    # Clear first, unlike the pathhide block above. There the kernel's list is
    # empty at boot and a clear could only stomp another module's rules; here the
    # tables describe OUR rule set, which the mount pass has just rebuilt, so a
    # stale entry from a previous configuration is the thing to avoid. Both
    # clears are separate commands, so a failure of one is still visible.
    nmto 10 "$NM_BIN" k g "p-" >/dev/null 2>&1 || nmlog "⚠ ghost: path table clear FAILED"
    nmto 10 "$NM_BIN" k g "u-" >/dev/null 2>&1 || nmlog "⚠ ghost: uid table clear FAILED"

    # Paths: ONLY those a hidden caller is supposed to see NOTHING at.
    #
    # Feeding it every injection target was wrong, and measurably worse than not
    # running _ghost at all. Where a rule SHADOWS a stock file the engine serves
    # the hidden reader that stock file on purpose ("Hidden reader of a shadowing
    # rule: report the stock file it is entitled to", nomount.c), and a PUBLIC
    # rule stays visible on purpose too. Ghosting either makes ONE path answer
    # stat=OK and chmod/truncate/utimensat/listxattr=ENOENT at the same time --
    # a self-contradiction no real file can produce, so a scanner does not even
    # need a control path to see it. Measured on OP15 at v1.3.57: of 260 rules
    # 259 were of this kind, i.e. the cloak closed the oracle on ONE path and
    # opened a louder one on the other 259.
    #
    # The predicate is the engine's own behaviour, asked rather than modelled:
    # become a uid that IS hidden and test the path. Absent -> injected-only ->
    # ghost it. Visible -> the engine intends it to be seen -> leave it alone.
    # That covers shadowing, public and virtual-dir rules without this script
    # having to know which is which. ONE `su` for the whole list: 260 separate
    # ones is slow at boot and is exactly the root-exec burst OOS flags.
    #
    # Fail-safe by construction: if the hide pass has not taken effect, or `su`
    # will not run, every path reads as visible, the table stays EMPTY and
    # _ghost is inert. Inert is the honest state -- a half-populated table
    # cloaks some paths and not others, which is a pattern of its own.
    _ghn=0; _ghg=0; _ghf=0
    _ghprobe=""
    if [ -f "$NMDIR/uidhide.cache" ]; then
        while IFS= read -r _ghl; do
            _ghl=$(echo "$_ghl" | tr -d '\r')
            case "$_ghl" in ''|\#*) continue ;; esac
            _ghi=${_ghl##*[!0-9]}
            case "$_ghi" in ''|*[!0-9]*) continue ;; esac
            [ "$_ghi" = "0" ] && continue
            _ghprobe="$_ghi"; break
        done < "$NMDIR/uidhide.cache"
    fi
    # `vfs list` appends " -> target", " (public)" and " (virtual dir)", so strip
    # from the first space; a stray annotation would be sent as a path and
    # rejected. Whiteouts are already excluded upstream -- a whiteout's whole job
    # is to make a name absent, which is what a hidden reader sees anyway.
    _ghcand=$("$NM_BIN" l 2>/dev/null | sed 's/ ->.*//; s/ (.*//' | grep '^/' | sort -u)
    _ghn=$(printf '%s\n' "$_ghcand" | grep -c '^/')
    if [ -n "$_ghprobe" ] && [ "$_ghn" -gt 0 ]; then
        # `[ -e ]` is false for ENOENT and for EACCES alike, and the two must not
        # be conflated: ghosting a path that is merely UNREACHABLE turns its EACCES
        # into ENOENT, while a genuinely absent name under the same unsearchable
        # parent still answers EACCES -- a new tell, of exactly the shape this
        # cloak exists to remove. There is no errno in shell, so test the parent's
        # searchability first and skip the path when we cannot tell the two apart.
        # Measured on OP15 v1.3.63: 0 of 260 rule paths answer EACCES to a hidden
        # uid, so this changes nothing there. It is the device where a rule sits
        # under a non-world-searchable directory that needs it.
        _ghlist=$(printf '%s\n' "$_ghcand" | su "$_ghprobe" -c \
            'while IFS= read -r p; do d=${p%/*}; [ -n "$d" ] || d=/; \
             [ -x "$d" ] || continue; \
             [ -e "$p" ] || printf "%s\n" "$p"; done' 2>/dev/null)
        _ghrej=""
        # NEWLINE-ONLY IFS around the loop. Unquoted, the default IFS splits on
        # spaces too, so a rule target containing one was torn in half: the
        # fragment "/product/app/My" passed the /* test AND ghost_rule_sane() and
        # was submitted as a rule, "App.apk" was dropped by the case guard, and
        # _ghg counted the fragment -- so the summary below reported the cloak
        # fully populated while that path's existence oracles stayed wide open.
        # Silent, and only on a module that ships a filename with a space.
        #
        # A `while read` pipeline would be the idiomatic fix and is wrong here:
        # it puts the loop in a subshell, so _ghg/_ghf/_ghrej would be discarded
        # and the report would always read 0 of 0. Save and restore instead.
        _oifs=$IFS
        IFS='
'
        for _ghp in $_ghlist; do
            IFS=$_oifs
            case "$_ghp" in /*) ;; *) IFS='
'; continue ;; esac
            _ghg=$((_ghg + 1))
            if ! nmto 10 "$NM_BIN" k g "p+$_ghp" >/dev/null 2>&1; then
                _ghf=$((_ghf + 1))
                # Keep the first few. A count alone is not diagnosable: working out
                # WHICH of the rules an overflow dropped took a separate `nm l g`
                # and an argument about sort order. The cap is the kernel's
                # GH_MAX_RULES (512 since "size the ghost path table for a real
                # rule set"); this message deliberately does not name a number,
                # because the last one it named went stale at 256 and sent whoever
                # read it looking for the wrong cause.
                [ "$_ghf" -le 3 ] && _ghrej="$_ghrej $_ghp"
            fi
            IFS='
'
        done
        IFS=$_oifs
    else
        nmlog "⚠ ghost: no hidden uid to probe with — path table left EMPTY (cloak inert)"
    fi

    # Uids: exactly the set per-UID hiding already uses, read from the cache the
    # hide pass just wrote. Deriving it a second way is how the two would drift,
    # and a uid in one table but not the other is a path that is hidden by the
    # ops but not by the guards, or the reverse.
    _ghu=0; _ghuf=0
    if [ -f "$NMDIR/uidhide.cache" ]; then
        while IFS= read -r _ghl; do
            _ghl=$(echo "$_ghl" | tr -d '\r')
            case "$_ghl" in ''|\#*) continue ;; esac
            # cache lines are "<pkg>	<uid>" -- TAB separated, verified on device.
            # Strip up to the last NON-DIGIT rather than up to the last space:
            # "${_ghl##* }" silently matched nothing on a tab, skipped every uid,
            # and left the table empty -- i.e. _ghost stays inert, which is the
            # exact failure this block exists to fix. This form handles either
            # separator, and a package name ending in a digit too.
            _ghi=${_ghl##*[!0-9]}
            case "$_ghi" in ''|*[!0-9]*) continue ;; esac
            [ "$_ghi" = "0" ] && continue          # root is never hidden from
            _ghu=$((_ghu + 1))
            nmto 10 "$NM_BIN" k g "u+$_ghi" >/dev/null 2>&1 || _ghuf=$((_ghuf + 1))
        done < "$NMDIR/uidhide.cache"
    fi

    # Report the truth. A partially populated table is WORSE than an empty one:
    # empty is honestly inert, partial means some paths are cloaked and others
    # are not, which is itself a pattern.
    if [ "$_ghf" -gt 0 ] || [ "$_ghuf" -gt 0 ]; then
        # The kernel refuses a path for exactly two reasons, and they need
        # different responses: the table is full (GH_MAX_RULES), or the path is
        # too long for GH_RULE_LEN. Measured on OP15: the longest rule is 68
        # chars and the longest path on the whole ROM is 134, against a 191 cap,
        # so full-table is the one to suspect first. Neither number is repeated
        # in the message: the kernel owns them, they have already moved once
        # (GH_MAX_RULES 256 -> 512), and a diagnostic that names a stale constant
        # sends its reader after the wrong cause.
        nmlog "⚠ ghost cloak: $_ghf/$_ghg path(s) and $_ghuf/$_ghu uid(s) REJECTED — the existence oracles stay OPEN for those; first:$_ghrej (table full, or a path over the kernel's rule-length cap)"
    elif [ "$_ghg" = 0 ] || [ "$_ghu" = 0 ]; then
        nmlog "⚠ ghost cloak inert: $_ghg of $_ghn path(s), $_ghu uid(s) — BOTH tables must be non-empty for any guard to fire"
    else
        nmlog "ghost cloak populated ($_ghg of $_ghn paths ghostable, $_ghu uids)"
    fi
fi

# Pre-build the Cloak Xposed-module cache in the background so the WebUI opens
# instantly (reads the cache) instead of scanning ~all installed APKs on open.
[ -f /data/adb/modules/meta-nomount/scan.sh ] && \
    (sh /data/adb/modules/meta-nomount/scan.sh >/dev/null 2>&1 &)

# --- /data/local/tmp: re-assert after boot ---
# spoof.sh already normalized it at post-fs-data, but ksud and adbd stage files
# there for the whole of boot and can put the mode/owner back.
[ -f /data/adb/modules/meta-nomount/spoof.sh ] && \
    sh /data/adb/modules/meta-nomount/spoof.sh shell-tmp >/dev/null 2>&1

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
    # Record-then-restore, same as metamount.sh: `chattr +i` unconditionally
    # ADDED immutability on a device that never had it, breaking the next ksud
    # update with EPERM. The clear is needed for the `mv` (which unlinks a
    # hardlink to the inode), not to read it.
    _ksud_imm=0
    lsattr -d "$KSUD" 2>/dev/null | cut -d' ' -f1 | grep -q 'i' && _ksud_imm=1
    chattr -i "$KSUD" 2>/dev/null
    if cp "$KSUD" "$SUSFS_BIN.nm_new" 2>/dev/null; then
        chmod 0755 "$SUSFS_BIN.nm_new" 2>/dev/null
        chcon u:object_r:adb_data_file:s0 "$SUSFS_BIN.nm_new" 2>/dev/null
        mv -f "$SUSFS_BIN.nm_new" "$SUSFS_BIN" 2>/dev/null \
            && nmlog "re-asserted ksud de-link (service)"
    else
        rm -f "$SUSFS_BIN.nm_new" 2>/dev/null
    fi
    [ "$_ksud_imm" = 1 ] && chattr +i "$KSUD" 2>/dev/null
fi

# --- refresh the manager card with the settled state ---
# metamount.sh tags the card in post-fs-data, when the mount table is not final and
# health cannot be judged yet. Now that boot is complete both are knowable, so restate
# the card with the real mount count and the health-check verdict — that turns the
# module list into a status readout you can trust without opening the WebUI.
# (MODDIR/ABI/BIN/NM_BIN are set at the top of this script.)

# --- let bindhosts take the mountless path it already has ---
#
# bindhosts probes its environment and picks one of eleven operating modes. One
# of them, mode 0, exists precisely for a metamodule like this one -- its own
# comment reads "for nomount metamodule, just use mode 0. it performs injection
# rather than mounts". Mode 0's handler does nothing at all: it ships
# system/etc/hosts as an ordinary module file and lets the metamodule serve it.
#
# That detection never fires here. It needs BOTH of:
#
#     [ -L /data/adb/metamodule ]          <- present, points at meta-nomount
#     [ -d /data/adb/modules/nomount ]     <- absent, we install as meta-nomount
#
# so it fails on a hardcoded directory name while the symlink it already checks
# points straight at the real one. The result is not breakage -- bindhosts falls
# through to a bind mount and absorb takes that over -- but it is a mount created
# and then removed on every boot for no reason.
#
# mode_override.sh is bindhosts' own documented extension point, so this is not
# a patch to another module; it is answering the question bindhosts asked with
# the answer it was looking for.
#
# The override is written CONDITIONAL rather than as a bare `mode=0`. If NoMount
# is later removed or disabled, a hardcoded mode 0 would leave bindhosts serving
# its hosts file through a metamodule that is no longer there -- adblocking would
# stop silently, which is exactly the failure class the rest of this work exists
# to remove. Evaluating the condition at bindhosts' runtime means the override
# no-ops the moment we are gone and it picks its own mode again.
#
# Takes effect from the NEXT boot: bindhosts sorts before meta-nomount, so its
# post-fs-data has already run by the time this does.
_bh_dir=/data/adb/bindhosts
_bh_ovr="$_bh_dir/mode_override.sh"
# `-L /data/adb/metamodule` also gates out Magisk, where that symlink does not
# exist at all (see post-fs-data.sh): the override could only ever be inert
# there, and writing one anyway would promise a mode 0 that never arrives.
if [ -d "$_bh_dir" ] && [ -d /data/adb/modules/bindhosts ] &&
   [ ! -f /data/adb/modules/bindhosts/remove ] && [ -L /data/adb/metamodule ]; then
    # Absent, or already ours. `grep -q` alone answers the same for "no file"
    # and "somebody else's file", and this is bindhosts' documented user-facing
    # extension point -- truncating a hand-written override would be silent data
    # loss, and unrecoverable, since our marker would then be present and this
    # block would never look at it again.
    if [ ! -e "$_bh_ovr" ] || grep -q 'NoMount Suite' "$_bh_ovr" 2>/dev/null; then
        # Temp file then rename, the same discipline as the ksud de-link above.
        # Writing straight onto the target means a short write (ENOSPC, killed
        # shell) leaves a truncated file whose first line already carries the
        # marker -- permanently unrepairable, and a syntax error in whatever
        # sources it.
        cat > "$_bh_ovr.nm_new" <<'BHEOF'
# Written by the NoMount Suite. Safe to delete.
#
# bindhosts mode 0 = ship system/etc/hosts as a normal module file and let the
# metamodule serve it, with no mount of its own. bindhosts already prefers this
# when it detects a nomount metamodule; its check looks for
# /data/adb/modules/nomount and this Suite installs as meta-nomount, so it does
# not match. Resolve the metamodule symlink instead.
#
# Conditional on OUR metamodule being live, not merely on one existing: the
# sha256sums manifest is ours. Without that test a leftover copy of this file
# would force mode 0 under a different metamodule after NoMount was removed.
_nm=$(readlink -f /data/adb/metamodule 2>/dev/null)
if [ -n "$_nm" ] && [ -d "$_nm" ] && [ -f "$_nm/nomount.sha256sums" ] &&
   [ ! -f "$_nm/disable" ] && [ ! -f "$_nm/remove" ] &&
   [ ! -f /data/adb/nomount/disabled ]; then
    mode=0
fi
unset _nm
BHEOF
        _bh_rc=$?
        if [ "$_bh_rc" -eq 0 ] && mv -f "$_bh_ovr.nm_new" "$_bh_ovr" 2>/dev/null; then
            chmod 0644 "$_bh_ovr" 2>/dev/null
            nmlog "bindhosts: wrote mode_override.sh — it will use its mountless mode 0 from the next boot"
        else
            rm -f "$_bh_ovr.nm_new"
            nmlog "⚠ bindhosts: could not write mode_override.sh (rc=$_bh_rc) — it keeps its own mount mode"
        fi
    fi
fi
unset _bh_dir _bh_ovr _bh_rc

# --- pick up content modules wrote after the mount pass ---
# The mount pass runs at post-fs-data. Measured across 576 module payloads, 56%
# build their payload tree at RUNTIME rather than shipping it in the zip -- and
# a module's own service.sh runs at late_start, after that pass has already
# walked it. Anything written there was invisible for the whole session: the
# file existed in the module directory and no rule named it.
#
# Verified on an OP15 with a module writing one file per lifecycle stage: the
# post-fs-data file was served on the same boot, the service.sh and
# boot-completed.sh files were not, and a single `reload` served all three with
# nothing else disturbed. That is this call.
#
# reload is a gap-free delta (it applies only what changed, never a clear), so
# on the common case of nothing new it is a cheap no-op. It runs BEFORE absorb
# so absorb sees the finished rule set.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    _rl_all=$(nmto 60 "$BIN" reload 2>&1)
    _rl_rc=$?
    _rl=$(printf '%s\n' "$_rl_all" | tail -1)
    if [ "$_rl_rc" -eq 124 ]; then
        nmlog "post-boot reload TIMED OUT after 60s - late module content may be unserved"
    elif [ "$_rl_rc" -ne 0 ]; then
        nmlog "⚠ post-boot reload FAILED (exit $_rl_rc) — content written by module service.sh is NOT served: $_rl"
    else
        nmlog "post-boot reload: $_rl"
    fi
fi

# --- absorb any bind mounts other modules made ---
# Module boot scripts have all run by now. Anything that bind-mounted its own
# content is visible in every app's mountinfo, which defeats the zero-mount
# posture no matter how mountless the Suite itself is. Re-serve each as an
# injection and drop the mount. No-op when nothing mounted anything.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    # Bounded. This is FOREGROUND and everything below it -- the whiteout
    # re-apply, the authoritative `uid apply`, the package watcher, the
    # selfcheck canary -- only runs once it returns. absorb now takes the
    # process-wide pass lock, so a concurrent WebUI reload can make it wait;
    # without a timeout here that wait would silently cost per-UID hiding for
    # the rest of the boot. 90s is well past a worst-case absorb (measured in
    # seconds) and still far short of stalling boot.
    # Capture the status BEFORE any pipe. `$?` after a command substitution that
    # contains a pipeline is the status of the LAST element -- `tail`, which
    # always succeeds -- so `_ab=$(timeout 90 ... | tail -1); [ $? -eq 124 ]`
    # could never be true and the timeout branch was dead code. Verified:
    # `x=$(sh -c "exit 124" | tail -1)` leaves $? at 0; without the pipe, 124.
    _ab_all=$(nmto 90 "$BIN" absorb 2>&1)
    _ab_rc=$?
    _ab=$(printf '%s\n' "$_ab_all" | tail -1)
    if [ "$_ab_rc" -eq 124 ]; then
        nmlog "absorb TIMED OUT after 90s - continuing boot"
    elif [ "$_ab_rc" -ne 0 ]; then
        # A non-zero, non-124 exit is a FAILED absorb: every mount it could not
        # take over stays in every app's mountinfo. The status was captured but
        # only 124 was acted on, so a plain failure was logged with its own
        # summary line -- written before absorb knew it would fail -- in exactly
        # the voice of a successful pass.
        nmlog "⚠ absorb FAILED (exit $_ab_rc) — foreign mounts may still be visible: $_ab"
    else
        nmlog "$_ab"
    fi
    # Second pass, later. Not every module binds by the time this runs: a
    # patched-APK module (ReVanced and friends, issue #14) waits for
    # sys.boot_completed, then for /sdcard, then polls `pm path` until
    # PackageManager answers, then sleeps before mounting its APK over the
    # installed one. That lands after the pass above on a slow boot, and a bind
    # that arrives after the only absorb pass stays mounted for the whole
    # session. Backgrounded so it cannot delay anything else here, and a plain
    # no-op when nothing new turned up.
    (
        sleep 45
        # Same reason as the late absorb pass below it: boot-completed.sh runs
        # after this script, and a module that writes its payload there lands
        # after the foreground reload. One more delta pass catches it.
        _rl2_all=$(nmto 60 "$BIN" reload 2>&1)
        _rl2_rc=$?
        if [ "$_rl2_rc" -eq 124 ]; then
            nmlog "late reload pass TIMED OUT after 60s"
        elif [ "$_rl2_rc" -ne 0 ]; then
            nmlog "⚠ late reload pass FAILED (exit $_rl2_rc): $(printf '%s\n' "$_rl2_all" | tail -1)"
        else
            nmlog "late reload pass: $(printf '%s\n' "$_rl2_all" | tail -1)"
        fi
        # Bounded and status-checked like the foreground pass. Backgrounded, so a
        # hang cannot delay boot -- but it CAN sit forever on the engine-wide pass
        # lock and hold it against uidwatch.sh, and a failed late pass reported by
        # its last line alone reads as a success. Status captured BEFORE any pipe.
        _ab2_all=$(nmto 90 "$BIN" absorb 2>&1)
        _ab2_rc=$?
        _ab2=$(printf '%s
' "$_ab2_all" | tail -1)
        if [ "$_ab2_rc" -eq 124 ]; then
            nmlog "late absorb pass TIMED OUT after 90s"
        elif [ "$_ab2_rc" -ne 0 ]; then
            nmlog "⚠ late absorb pass FAILED (exit $_ab2_rc): $_ab2"
        else
            nmlog "late absorb pass: $_ab2"
        fi
    ) &
fi

# --- re-apply persistent whiteouts ---
# Whiteouts live in kernel memory and are empty after every reboot; the list on
# disk is the durable record.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/whiteouts.txt" ]; then
    # Status BEFORE the pipe. `$(cmd | tail -1)` leaves $? as tail's, which always
    # succeeds -- the same trap documented for absorb above, still live here. A
    # failed whiteout apply means the stock paths the user asked to hide are
    # VISIBLE for the whole session, which is the one result that must not be
    # logged in the same voice as a success.
    _wo_all=$(nmto 30 "$BIN" whiteout apply 2>&1)
    _wo_rc=$?
    _wo=$(printf '%s
' "$_wo_all" | tail -1)
    if [ "$_wo_rc" -ne 0 ]; then
        nmlog "⚠ whiteout apply FAILED (exit $_wo_rc) — hidden paths are still VISIBLE: $_wo"
    else
        nmlog "$_wo"
    fi
fi

# --- re-apply the persistent per-app hide list (authoritative pass) ---
# Per-UID hiding lives in kernel memory and is empty after every reboot; the hide
# list on disk (package names / UIDs) is the durable record. The mount pass has
# already applied it from the cached appid mirror at post-fs-data, so apps are
# hidden from the moment the injections exist rather than from here — this later
# pass is the authoritative one: packages.list is now populated and app UIDs are
# stable, so it re-resolves, refreshes the mirror, and retires any appid an entry
# no longer maps to (appids get reused after an uninstall). Guard-gated.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/uidhide" ]; then
    _bl=$(nmto 60 "$BIN" uid apply 2>&1)
    if [ $? -eq 0 ]; then
        nmlog "hide list re-applied ($_bl)"
    else
        # A failed apply is the one thing here that must not pass quietly: it means
        # apps the user believes are hidden are not.
        nmlog "⚠ hide list apply FAILED ($_bl)"
    fi
fi

# --- watch the package map, so the hide list follows installs ---
# An entry saved for an app that wasn't installed yet used to sit inert until the
# next reboot — install the detector you meant to hide from and it saw everything
# until you rebooted. PackageManager rewrites packages.list on every install,
# uninstall and update, so watch its directory and re-apply.
#
# Deliberately NOT gated on the list being non-empty: hide your first app from the
# WebUI after boot and a list-gated watcher would not be running, leaving the gap
# open for the rest of the boot — the exact hole this closes. uidwatch.sh exits
# immediately when there is nothing to apply, so the idle cost is one blocked
# process. No event mask either: the mask letters differ between the busybox and
# toybox inotifyd, and an unknown letter makes inotifyd exit at startup, which
# would disable the watcher silently.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] \
   && command -v inotifyd >/dev/null 2>&1 && [ -f "$MODDIR/uidwatch.sh" ]; then
    inotifyd "$MODDIR/uidwatch.sh" /data/system >/dev/null 2>&1 &
    nmlog "hide-list package watcher started"
fi

# The missing `else`. Every block above is gated on [ -x "$BIN" ] and NONE of them
# had one, so a binary that is absent, not executable, or under an ABI directory
# this device does not have made absorb, the whiteout re-apply, the authoritative
# `uid apply`, the package watcher and the health canary ALL no-ops -- in silence,
# on a boot that otherwise completed. The card block below is gated the same way,
# so it would not even restate the post-fs-data text; the user simply sees their
# modules stop working. Say it once, where the WebUI already looks.
if [ ! -x "$BIN" ]; then
    nmlog "⛔ engine binary is missing or not executable ($BIN) — absorb, whiteouts, per-app hiding and the health canary were ALL skipped this boot"
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
        # Bounded, like every other engine call on this path. selfcheck runs the
        # per-UID probe, which takes the engine-wide pass lock and can wait behind
        # a concurrent WebUI reload; unbounded, a hung engine held the whole rest
        # of the boot pass (card refresh included) hostage AND left the stale
        # health.txt below to be read as if it were this boot's.
        timeout 20 "$BIN" selfcheck --write >/dev/null 2>&1
        _cons=$(_health_get consistency)
        if ! _health_fresh; then
            # No record from THIS boot: the write failed, or the probe never
            # finished. The settle window exists to smooth a transient *verdict*,
            # not to re-ask a question that produced no answer — so stop rather
            # than spend 6 x 15s of boot on it, and let the "unknown" state below
            # carry the result. (It is the state `doctor` already models
            # correctly; the canary just never used it.)
            break
        fi
        # "unchecked" and its qualified forms (unchecked:probe-uid-hidden, when
        # shell itself is on the hide list) are not-a-verdict, not a failure.
        case "$_cons" in
            ok|unchecked*|"") break ;;
        esac
        _try=$((_try + 1))
        sleep 15
    done
    if _health_fresh; then
        _hv=$(_health_get verdict)
        nmlog "selfcheck verdict=${_hv:-unknown} consistency=${_cons:-unknown} (settle tries=$_try)"
    else
        nmlog "⚠ selfcheck wrote no health record this boot — health is UNKNOWN, not healthy"
    fi
fi

# --- detection audit, cached for the WebUI --------------------------------------
# `selfcheck` has run at boot and persisted to health.txt since the beginning; the
# audit never did. So the Detection audit card opened with a dash and the first
# time a user saw a finding was also the first time they had heard of the tool --
# and only if they went looking for a button on the Diagnostics tab.
#
# Runs AFTER the selfcheck settle window on purpose: several checks read live
# per-UID state, and asking before the hide pass has settled is the same
# too-early measurement that produced the false "per-UID" warning the canary
# retries around.
#
# Bounded and best-effort in both directions: a failed run leaves no cache, and
# the WebUI treats a missing or stale file as "no cached verdict" -- which is
# exactly what it is. `audit --json --write` writes the file itself (0600, in the
# state dir) so nothing here has to know the format. Exit is non-zero whenever a
# finding is open, which is the normal case for some setups and must not read as
# an error here.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    if nmto 60 "$BIN" audit --json --write >/dev/null 2>&1; then
        nmlog "detection audit cached — nothing open"
    elif [ -s "$NMDIR/audit.json" ]; then
        # Distinguish "ran, found something" from "did not run at all". The first
        # is a normal, actionable state; the second means the card will show an
        # age with no verdict behind it.
        nmlog "detection audit cached — one or more findings are open (see the Detection audit card)"
    else
        rm -f "$NMDIR/audit.json"
        nmlog "⚠ detection audit did not complete — the WebUI will show no cached verdict"
    fi
fi

if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    # One dump, both counts (see metamount.sh): two `nm list` runs returning the
    # same answer is two full netlink dumps of the whole rule table.
    _NMLIST=$(nmto 15 "$NM_BIN" list 2>/dev/null)
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    # EXCLUDE the (virtual dir) rows. `grep -c .` counts every line of the dump,
    # which on this device is 260 while `selfcheck`, `audit` and health.txt all
    # say 257 -- the difference being 3 directories the engine materialises, which
    # are not rules. The card is the surface most users read, so having it
    # disagree with every other number the Suite prints made a real discrepancy
    # indistinguishable from a bug. Measured on OP15: 260 lines, 3 virtual dirs.
    _rules=$(_nmcount -vc '(virtual dir)')
    _rro=$(_nmcount '/overlay/[^ ]*\.apk')
    # Match on mountinfo FIELD 4, the mount's root within its own filesystem. A bind
    # out of a module reads "/adb/modules/<id>/..." there, because /data is its own
    # filesystem -- so the old `grep -c '/data/adb/modules'` matched nothing on any
    # device and the card reported "0 mounts" however many there really were.
    # (It also used `|| echo 0` after a grep that already prints 0 and exits 1 when
    # it does, appending a second line and making every later -gt test a bad number.)
    _mnt=$(awk '$4 ~ "/adb/modules/" {n++} END{print n+0}' /proc/self/mountinfo 2>/dev/null); _mnt=${_mnt:-0}
    # Distinguish "doctor found nothing" from "doctor never answered". Parsing an
    # EMPTY capture through awk yields 0 errors / 0 warnings, so a timeout or a
    # crash used to render the card as "healthy" -- the one word it must not say
    # when it does not know. _docok=0 means unknown, and the card says so.
    _doc=$(timeout 30 "$BIN" doctor 2>/dev/null | sed -n 's/^summary: \([0-9]*\) errors, \([0-9]*\) warnings.*$/\1 \2/p')
    if [ -n "$_doc" ]; then
        _docok=1
        _err=$(echo "$_doc" | awk '{print $1+0}')
        _wrn=$(echo "$_doc" | awk '{print $2+0}')
    else
        _docok=0
        _err=0
        _wrn=0
    fi
    # runtime consistency canary trumps plan-time doctor for card health: a
    # per-UID inconsistency is a live regression, not a plan hazard.
    # Same not-a-verdict rule as the canary loop, but read through _health_get so
    # a record left over from LAST boot cannot supply the answer. _hfresh keeps
    # "the canary said nothing bad" apart from "the canary never spoke" -- without
    # it, "" mapped to _consbad=0 and the ladder below fell through to "healthy"
    # off a file that was stale or absent.
    _health_fresh && _hfresh=1 || _hfresh=0
    _cons=$(_health_get consistency)
    case "$_cons" in
        ok|unchecked*|"") _consbad=0 ;;
        *) _consbad=1 ;;
    esac
    if [ "$_consbad" = 1 ]; then
        _health="⚠️ per-UID inconsistency — see WebUI › Tools"
    elif [ "${_err:-0}" -gt 0 ]; then
        _health="⚠️ $_err error(s) — see WebUI › Tools"
    elif [ "${_wrn:-0}" -gt 0 ]; then
        _health="$_wrn warning(s)"
    elif [ "${_docok:-0}" = 1 ] && [ "${_hfresh:-0}" = 1 ]; then
        _health="healthy"
    elif [ "${_docok:-0}" = 1 ]; then
        _health="health unknown — no selfcheck record this boot"
    else
        _health="health unknown — doctor did not finish"
    fi
    # Distinguish a LEAK from a mount absorb leaves on purpose (a Zygisk/Xposed
    # hook bind). Counting them the same made the card read
    # "⚠ 1 module mount(s) … fully mountless" in one breath, which is both
    # alarming and self-contradictory, and gave the reader no way to tell an
    # expected mount from a real one.
    # Through _health_get too: a stale record's foreign count describes last
    # boot's mount table, and here it would override the live one we just read.
    _fgn=$(_health_get mounts_foreign)
    # health.rs now writes `unknown` when it could not read the mount table, so it
    # can stop rendering a failed read as a measurement of zero. Anything
    # non-numeric here means "the record does not know", which is the same case as
    # a stale/absent record: fall back to the count we just took live.
    case "$_fgn" in ''|*[!0-9]*) _fgn=$_mnt ;; esac
    if [ "${_fgn:-0}" -gt 0 ]; then
        _mstate="⚠ $_fgn module mount(s)"
        _tail="Prism VFS + RRO injection is mountless; $_fgn foreign mount(s) present"
    elif [ "${_mnt:-0}" -gt 0 ]; then
        _mstate="$_mnt by design"
        _tail="fully mountless: Prism VFS + RRO, su via sucompat ($_mnt hook-framework mount left alone)"
    else
        _mstate="0 mounts"
        _tail="fully mountless: Prism VFS + RRO, su via sucompat"
    fi
    # The manager's kernel_umount rides along on the card. It can hide nothing
    # the Suite serves -- injections are VFS redirects, so the kernel umount list
    # is empty -- and enabling it on this hardware once cost ~8 reboots. Put it
    # where the user already looks (the module description in their root
    # manager), not only in dmesg. "unknown" means ksud could not be asked, so
    # say nothing rather than accuse a switch of being on.
    # Freshness-gated as well: accusing a switch of being ON off LAST boot's
    # record is exactly the "say nothing rather than accuse" case above.
    _mu=$(_health_get manager_umount | head -1)
    if [ "$_mu" = "on" ]; then
        # shellcheck disable=SC1111  # typographic quotes on purpose: this names
        # the manager's own label inside a sentence shown to the user.
        _muc=" · ⚠️ turn OFF “kernel umount” in your root manager (it hides nothing here)"
        _mul=", ⚠ manager kernel_umount is ON — turn it off"
    else
        _muc=""
        _mul=""
    fi
    # ✅ next to "0 rules" is a contradiction, and this card is the last word on
    # the boot -- it overwrites whatever metamount.sh wrote. Mirror the same
    # guard, so a boot that served nothing cannot end on a green tick here after
    # metamount.sh refused to give it one.
    if [ "${_rules:-0}" = 0 ]; then _mark="⚠️"; else _mark="✅"; fi
    KSU_MODULE=meta-nomount ksud module config set --temp override.description \
        "[NoMount $_mark $_rules rules · $_rro RRO · $_mstate] $_health$_muc — $_tail" \
        >/dev/null 2>&1
    nmlog "card refreshed ($_rules rules, $_mstate, $_health$_mul)"
fi
exit 0
