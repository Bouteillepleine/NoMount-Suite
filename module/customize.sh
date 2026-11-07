#!/system/bin/sh
ui_print "- Installing NoMount metamodule"
ui_print "- version $(grep_prop version "$MODPATH/module.prop")"

SUMS="$MODPATH/nomount.sha256sums"
if [ -f "$SUMS" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        _sumout=$(cd "$MODPATH" && sha256sum -c "$SUMS" 2>&1)
        if [ $? -eq 0 ]; then
            ui_print "- Payload intact - $(wc -l < "$SUMS") files match the manifest"
        else
            ui_print "*********************************************************"
            ui_print "! Integrity check FAILED - a file does not match its hash."
            ui_print "! This zip is damaged or was repacked. Re-download it from"
            ui_print "! the official release page."
            ui_print "! What sha256sum -c reported:"
            printf '%s\n' "$_sumout" | grep -v ': OK$' | head -n 8 | while IFS= read -r _l; do
                ui_print "!   $_l"
            done
            ui_print "*********************************************************"
            abort "- Aborting install: integrity check failed"
        fi
        unset _sumout
    else
        ui_print "! sha256sum is missing from this recovery - the payload was NOT verified."
        ui_print "! Installing unverified. If this zip came from anywhere but the official"
        ui_print "! release page, cancel and re-flash from a full Android boot instead."
    fi
else
    ui_print "*********************************************************"
    ui_print "! No sha256 manifest in this zip - it cannot be verified."
    ui_print "! Every official build ships one, so this zip is corrupt,"
    ui_print "! truncated, or was repacked. Re-download it."
    ui_print "*********************************************************"
    abort "- Aborting install: no integrity manifest"
fi

for mp in /data/adb/modules/*/module.prop; do
    [ -f "$mp" ] || continue
    mdir="${mp%/module.prop}"
    id="${mdir##*/}"
    [ "$id" = "meta-nomount" ] && continue
    [ -f "$mdir/remove" ] && continue
    [ -f "$mdir/disable" ] && continue
    # Mirror ksud's is_metamodule() (trim, then "1" or a case-insensitive
    # "true") rather than prefix-matching "metamodule=1". maxsteeel/nomount
    # writes metamodule=true, so the one metamodule likely to sit beside ours
    # was the one this guard could not see - and two installed at once is
    # silent: ksud points /data/adb/metamodule at whichever was flashed last
    # and never calls the loser's metamount.sh. The old pattern also tripped
    # on metamodule=10, which ksud does not count as one.
    if grep -qiE '^metamodule[[:space:]]*=[[:space:]]*(1|true)[[:space:]]*$' "$mp"; then
        other="$(grep '^name=' "$mp" | head -n1 | cut -d= -f2-)"
        ui_print "*********************************************************"
        ui_print "! Another metamodule is already installed:"
        ui_print "!   $id${other:+  ($other)}"
        ui_print "! KernelSU/APatch allow only one metamodule."
        ui_print "! Remove or disable it first, then flash NoMount."
        ui_print "*********************************************************"
        abort "- Aborting install: metamodule conflict"
    fi
done

for abi in arm64-v8a armeabi-v7a x86_64 x86; do
    for b in nomount nm; do
        if [ -f "$MODPATH/bin/$abi/$b" ]; then
            set_perm "$MODPATH/bin/$abi/$b" 0 0 0755
        fi
    done
done

_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
[ -n "$_abi" ] || _abi=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$_abi" ] || _abi=arm64-v8a
_nm="$MODPATH/bin/${_abi}/nm"
if [ ! -d "$MODPATH/bin/${_abi}" ]; then
    ui_print "*********************************************************"
    ui_print "! This zip has no binaries for this device's ABI."
    ui_print "!   device ABI: ${_abi}"
    # shellcheck disable=SC2012  # listing the ABI directories the ZIP shipped, by
    ui_print "!   shipped:    $(ls "$MODPATH/bin" 2>/dev/null | tr '\n' ' ')"
    ui_print "! The module will install and then inject nothing, on every"
    ui_print "! boot, silently. NoMount is arm64-v8a only."
    ui_print "*********************************************************"
fi
NM_LKM_SAY=ui_print
NM_LKM_NM="$_nm"
NM_LKM_LOADER="$MODPATH/loader"
export NM_LKM_SAY NM_LKM_NM NM_LKM_LOADER
# shellcheck source=module/lkm-load.sh
[ -f "$MODPATH/lkm-load.sh" ] && . "$MODPATH/lkm-load.sh"
[ -f "$NM_LKM_LOADER" ] && chmod 0755 "$NM_LKM_LOADER" 2>/dev/null

# Read before the probe, not after: from recovery there is no running engine to
# answer, so "no answer" means something different there, and both the block
# below and the next step at the end of the file have to say so.
_booted=$(getprop sys.boot_completed 2>/dev/null)

# Whether this zip carries an engine module at all. The lite zip ships none by
# design, so "nothing loaded" there is not a fact about the kernel - it used to
# be printed as one, which reads as "your kernel is incompatible" and sends
# people to reflash a kernel instead of to the LKM zip.
_bundled=0
for _k in "$MODPATH"/lkm/nomount-*.ko; do
    [ -f "$_k" ] && { _bundled=1; break; }
done
unset _k

# _eng, not _ev: the engine can be up while its version is unreadable, and the
# messages at the end of this file are about whether anything will be injected,
# not about whether we could read a number.
_eng=0
_lrc=1
_denied=0
if [ -x "$_nm" ]; then
    _evl=$("$_nm" v 2>/dev/null | head -n 1)
    _ev=$(printf '%s' "${_evl%% *}" | tr -dc '0-9')
    _eb=""
    case "$_evl" in *" "*) _eb=${_evl#* }; _eb=${_eb%% *} ;; esac
    if [ -z "$_ev" ] && command -v nm_lkm_load_best >/dev/null 2>&1; then
        nm_lkm_load_best "$MODPATH/lkm"; _lrc=$?
        if [ "$_lrc" = 0 ] || [ "$_lrc" = 2 ]; then
            nm_lkm_prune "$MODPATH/lkm"
            _evl=$("$_nm" v 2>/dev/null | head -n 1)
            _ev=$(printf '%s' "${_evl%% *}" | tr -dc '0-9')
        fi
    fi
    if [ -n "$_ev" ]; then
        _eng=1
        if [ "$_lrc" = 0 ]; then
            ui_print "- Prism engine: v${_ev} (module loaded, no reboot needed)"
        else
            ui_print "- Prism engine: v${_ev} (${_eb:+build $_eb, }responding)"
        fi
        # The bundled modules are NOT dropped here any more. That used to happen
        # whenever lsmod showed no nomount line, read as "the engine is built
        # into the kernel" - but the module takes itself OUT of /proc/modules by
        # default, so a device already running the LKM looked built-in and had
        # its only fallback deleted. There is no sound lsmod test while the
        # module hides itself, and a few MB left in place costs nothing.
    elif [ "$_lrc" = 2 ]; then
        _eng=1
        ui_print "*********************************************************"
        ui_print "! The engine module LOADED (from ${NM_LKM_SOURCE:-?}) but the"
        ui_print "! probe did not answer, so its version is unknown."
        ui_print "! Your KERNEL is not the problem. bin/${_abi}/nm is missing,"
        ui_print "! built for another ABI, or lost its executable bit."
        ui_print "! Re-flash this zip; do not reflash the kernel."
        ui_print "*********************************************************"
    else
        # nm already tells the two failures apart (userspace/src/nm.c: errno
        # 1/13 = the socket was denied, so the engine may well be loaded; 93/97
        # = no such protocol = no engine). The probe above discards stderr, so
        # re-run it on this path only to read the errno back - telling someone
        # to reflash their kernel over an SELinux denial is the worst advice
        # this script can give.
        _nmerr=$("$_nm" v 2>&1 >/dev/null)
        _nmerrno=$(printf '%s' "$_nmerr" | sed -n 's/.*(errno \([0-9]*\)).*/\1/p' | head -n 1)
        case "$_nmerrno" in 1|13) _denied=1 ;; esac

        ui_print "*********************************************************"
        if [ "$_denied" = 1 ]; then
            ui_print "! The netlink socket was DENIED, not missing - this kernel"
            ui_print "! may well have NoMount. Do NOT reflash it. Look for a"
            ui_print "! denied netlink_socket create on the domain running nm,"
            ui_print "! then reinstall."
        elif [ "$_bundled" = 0 ]; then
            ui_print "! This zip bundles NO engine module - it is the lite zip,"
            ui_print "! for a kernel that already has NoMount built in. Nothing"
            ui_print "! here can load one, so this says nothing about whether"
            ui_print "! your kernel is capable."
            ui_print "! Flash 01_NoMount-Module-LKM from the same release - it"
            ui_print "! carries a module per KMI - or drop a matching one at"
            ui_print "! /data/adb/nomount/nomount.ko."
        else
            ui_print "! The kernel's NoMount engine did not answer, and no"
            ui_print "! bundled module loads on it either."
            ui_print "! Flash a NoMount-enabled kernel, or drop a matching"
            ui_print "! nomount.ko at /data/adb/nomount/nomount.ko."
        fi
        ui_print "!   kernel: $(uname -r)"
        ui_print "!   nm: netlink proto 29, errno ${_nmerrno:-unknown}"
        if [ "$_booted" != "1" ] && [ "$_denied" != 1 ]; then
            ui_print "! From recovery the engine cannot answer at all - reboot,"
            ui_print "! then reinstall to find out."
        fi
        ui_print "*********************************************************"
    fi
else
    ui_print "*********************************************************"
    ui_print "! Could not run the engine probe: no executable at"
    ui_print "!   bin/${_abi}/nm"
    ui_print "! The engine state is unknown and the module may inject"
    ui_print "! nothing. Re-flash the zip; a partial extraction or an"
    ui_print "! unsupported ABI is the usual cause."
    ui_print "*********************************************************"
fi

NMDIR=/data/adb/nomount
mkdir -p "$NMDIR"
set_perm "$NMDIR" 0 0 0700 u:object_r:adb_data_file:s0

_bak=/data/adb/nomount.bak
if [ -d "$_bak" ]; then
    _rn=0
    _fail=0
    # KEEP IN SYNC with the stash list in uninstall.sh and lib.sh's nm_consume_stash().
    for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
              absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
              uidconceal ghostpaths kmsg incident.log nomount.ko \
              absorbed.list binds.list absorbed-tmpfs.list apkstate.list; do
        [ -e "$_bak/$_f" ] || continue
        [ -e "$NMDIR/$_f" ] && continue
        if cp -p "$_bak/$_f" "$NMDIR/$_f" 2>/dev/null; then
            set_perm "$NMDIR/$_f" 0 0 0600 u:object_r:adb_data_file:s0
            _rn=$((_rn + 1))
        else
            rm -f "$NMDIR/$_f" 2>/dev/null
            _fail=$((_fail + 1))
        fi
    done
    unset _f
    [ "$_rn" -gt 0 ] && ui_print "- Restored $_rn setting(s) kept from your previous install"
    if [ "$_fail" -eq 0 ]; then
        rm -rf "$_bak"
    else
        ui_print "- ! $_fail setting(s) could not be restored; keeping $_bak"
        ui_print "  Free some space and reboot - they are recovered on the next boot."
    fi
    unset _rn _fail
fi
unset _bak
CONF="$NMDIR/spoof.conf"
[ -f "$CONF" ] && set_perm "$CONF" 0 0 0600 u:object_r:adb_data_file:s0

# Both inotifyd handlers need the exec bit: inotifyd execs them directly, and the
# manager's own set_permissions pass leaves every file 0644 regardless of the mode
# stored in the zip. Without this, inotifyd stays resident and silently fails to exec
# its handler on every event -- checkwatch.sh shipped that way and the WebUI's
# check-on-request never answered.
[ -f "$MODPATH/uidwatch.sh" ] && set_perm "$MODPATH/uidwatch.sh" 0 0 0755
[ -f "$MODPATH/checkwatch.sh" ] && set_perm "$MODPATH/checkwatch.sh" 0 0 0755

[ -f "$MODPATH/lib.sh" ] && set_perm "$MODPATH/lib.sh" 0 0 0644
[ -d "$MODPATH/webroot" ] && set_perm_recursive "$MODPATH/webroot" 0 0 0755 0644

[ -f "$MODPATH/uninstall.sh" ] && set_perm "$MODPATH/uninstall.sh" 0 0 0755

[ -f "$NMDIR/absorb-skip" ] && [ ! -f "$NMDIR/absorb-skip.txt" ] && \
    cp -f "$NMDIR/absorb-skip" "$NMDIR/absorb-skip.txt"
if [ ! -f "$NMDIR/absorb-skip.txt" ]; then
    {
        echo "# One per line: an absolute target path prefix, or a module id."
        echo "#"
        echo "# You rarely need to add a hook framework here: absorb already leaves"
        echo "# alone everything mounted by a module that ships zygisk/<abi>.so (any"
        echo "# Zygisk module, LSPosed and its forks included) or bin/zygisk* (the"
        echo "# providers - Zygisk Next, ReZygisk, NeoZygisk). This file is for"
        echo "# anything that marker does not cover."
        echo "#"
        echo "# Prefer a path: a hook framework's module id differs between forks"
        echo "# (zygisk_lsposed, zygisk_lsposed_next, lsposed, ...) so an id list"
        echo "# silently misses every fork it does not name, while the path being"
        echo "# hooked is the same for all of them."
        echo "#"
        echo "# Why these are skipped: the bind is installed by native daemon code"
        echo "# and the failure mode is silent and delayed - dex2oat runs during"
        echo "# dexopt on app install, not at boot, so a broken hook shows up hours"
        echo "# later as \"modules stopped applying to new apps\"."
        echo "#"
        echo "# How matching works:"
        echo "#  - A path is a plain string prefix, not a path-component match. That"
        echo "#    is deliberate: /apex/com.android.art/bin/dex2oat also covers"
        echo "#    dex2oat64. It also means /product/app/Foo covers FooBar - use the"
        echo "#    longest path that is unambiguous."
        echo "#  - If any one mount of a module matches a path here, ALL of that"
        echo "#    module's mounts are left alone, not just that one."
        echo "#  - A module id does NOT apply to a tmpfs mounted over the ROM: a"
        echo "#    tmpfs has no module source in the mount table, so use a path for"
        echo "#    those."
        echo "#"
        echo "# The four paths below are ALSO built into the binary. Deleting them"
        echo "# here does nothing; they stay skipped either way. Lines you add"
        echo "# yourself can be deleted normally."
        echo "/apex/com.android.art/bin/dex2oat"
        echo "/apex/com.android.runtime/bin/dex2oat"
        echo "/system/bin/dex2oat"
        echo "/system/bin/app_process"
        echo "zygisksu"
    } > "$NMDIR/absorb-skip.txt"
fi
set_perm "$NMDIR/absorb-skip.txt" 0 0 0600 u:object_r:adb_data_file:s0
rm -f "$NMDIR/bootcount"

if [ -e "$NMDIR/disabled" ]; then
    ui_print "- ℹ️  The Suite is disabled on this device - it will inject nothing at boot."
    ui_print "     Clear it in the WebUI, or: rm $NMDIR/disabled"
fi

if [ "$_eng" = 1 ] && [ ! -e "$NMDIR/disabled" ]; then
    ui_print "- Modules under /data/adb/modules are injected mountlessly at boot."
    ui_print "- next step: reboot. Nothing is served until you do."
elif [ ! -d "$MODPATH/bin/${_abi}" ]; then
    ui_print "- next step: none - this zip is arm64-v8a only and this device is ${_abi}."
    ui_print "  Re-flashing cannot help. Remove it from your manager."
elif [ ! -x "$_nm" ]; then
    ui_print "- next step: re-flash this zip. The engine could not be probed (see above),"
    ui_print "  so we cannot tell you whether your kernel has NoMount."
elif [ "$_denied" = 1 ]; then
    ui_print "- next step: clear the SELinux denial above, then reinstall. Reflashing"
    ui_print "  the kernel is the wrong move - the socket was refused, not absent."
elif [ "$_eng" != 1 ] && [ "$_booted" != "1" ]; then
    ui_print "- Installed from recovery, where the engine cannot answer."
    ui_print "- next step: reboot, then open the WebUI - it says whether your kernel has it."
elif [ "$_eng" != 1 ] && [ "$_bundled" = 0 ]; then
    ui_print "- next step: flash 01_NoMount-Module-LKM from the same release - this"
    ui_print "  lite zip carries no engine module - or a kernel built with CONFIG_NOMOUNT."
    ui_print "  OnePlus prebuilts: github.com/Bouteillepleine/OnePlus-BakaSu_NMS/releases"
    ui_print "  Until you do, this module is installed and doing nothing."
elif [ "$_eng" != 1 ]; then
    ui_print "- next step: flash a kernel built with CONFIG_NOMOUNT, then reboot."
    ui_print "  OnePlus prebuilts: github.com/Bouteillepleine/OnePlus-BakaSu_NMS/releases"
    ui_print "  Until you do, this module is installed and doing nothing."
else
    ui_print "- next step: clear the disable flag (see above), then reboot."
fi

# The manager prints "Module installed successfully!" after this, which is true of
# the files and says nothing about the engine. A reader who sees that under a green
# "Flash success" reasonably concludes NoMount is working. Make the real state the
# last thing we print, so the two cannot be read as agreeing.
if [ "$_eng" != 1 ]; then
    ui_print "*********************************************************"
    if [ "$_denied" = 1 ]; then
        ui_print "! INSTALLED BUT INACTIVE - the engine could not be reached."
        ui_print "! The kernel is not implicated. See the next step above."
    elif [ "$_booted" != "1" ]; then
        ui_print "! INSTALLED - engine state UNKNOWN (no running kernel to"
        ui_print "! ask). Reboot and re-check before relying on it."
    else
        ui_print "! INSTALLED BUT INACTIVE - nothing will be injected on"
        ui_print "! this kernel. See the next step above."
    fi
    ui_print "! Any success line below refers to the files, not the engine."
    ui_print "*********************************************************"
fi
unset _booted _eng _lrc _bundled _denied _nmerr _nmerrno
