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
BIN="$MODDIR/bin/$ABI/nomount"
export NM_BIN="$MODDIR/bin/$ABI/nm"

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
case "$_now$_up" in *[!0-9]*|"") _now=0; _up=0 ;; esac
_bootepoch=$((_now - _up))
# 0 unless health.txt exists AND was stamped at or after this boot began.
_health_fresh() {
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
        while IFS= read -r _phr; do
            _phr=$(echo "$_phr" | tr -d '\r')
            [ -z "$_phr" ] && continue
            case "$_phr" in \#*) continue ;; esac
            "$NM_BIN" k p "+$_phr" >/dev/null 2>&1
        done < "$NMDIR/pathhide.conf"
        nmlog "pathhide cloak rules re-applied"
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
    _ab_all=$(timeout 90 "$BIN" absorb 2>&1)
    _ab_rc=$?
    if [ "$_ab_rc" -eq 124 ]; then
        nmlog "absorb TIMED OUT after 90s - continuing boot"
    else
        _ab=$(printf '%s\n' "$_ab_all" | tail -1)
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
        _ab2=$("$BIN" absorb 2>&1 | tail -1)
        nmlog "late absorb pass: $_ab2"
    ) &
fi

# --- re-apply persistent whiteouts ---
# Whiteouts live in kernel memory and are empty after every reboot; the list on
# disk is the durable record.
if [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ] && [ -s "$NMDIR/whiteouts.txt" ]; then
    _wo=$("$BIN" whiteout apply 2>&1 | tail -1)
    nmlog "$_wo"
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
    _bl=$("$BIN" uid apply 2>&1)
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

if command -v ksud >/dev/null 2>&1 && [ -x "$BIN" ] && [ ! -f "$NMDIR/disabled" ]; then
    # One dump, both counts (see metamount.sh): two `nm list` runs returning the
    # same answer is two full netlink dumps of the whole rule table.
    _NMLIST=$("$NM_BIN" list 2>/dev/null)
    _nmcount() { [ -z "$_NMLIST" ] && { echo 0; return; }; printf '%s\n' "$_NMLIST" | grep -c "$@"; }
    _rules=$(_nmcount .)
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
    _fgn=${_fgn:-$_mnt}
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
