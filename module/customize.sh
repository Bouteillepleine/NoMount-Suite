#!/system/bin/sh
ui_print "- Installing NoMount metamodule"
ui_print "- version $(grep_prop version "$MODPATH/module.prop")"

SUMS="$MODPATH/nomount.sha256sums"
if [ -f "$SUMS" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        _sumout=$(cd "$MODPATH" && sha256sum -c "$SUMS" 2>&1)
        if [ $? -eq 0 ]; then
            ui_print "- Integrity check passed ($(wc -l < "$SUMS") files)"
        else
            ui_print "*********************************************************"
            ui_print "! Integrity check FAILED - a file does not match its hash."
            ui_print "! This zip is corrupted or was modified. Re-download it."
            ui_print "! What sha256sum -c reported:"
            printf '%s\n' "$_sumout" | grep -v ': OK$' | head -n 8 | while IFS= read -r _l; do
                ui_print "!   $_l"
            done
            ui_print "*********************************************************"
            abort "- Aborting install: integrity check failed"
        fi
        unset _sumout
    else
        # Not a pass. Nothing was checked, and saying "skipping" invites reading that as
        # "fine". Name what is unverified so the line is a result, not a shrug.
        ui_print "! sha256sum is missing from this recovery - the payload was NOT verified."
        ui_print "! Installing unverified. If this zip came from anywhere but the official"
        ui_print "! release page, cancel and re-flash from a full Android boot instead."
    fi
else
    # package.sh always writes this manifest, so a zip without one did not come out of
    # the build pipeline intact. "Skipping" turned the one check that would have caught
    # a tampered or truncated payload into a line of text nobody reads, and then installed
    # it anyway. Absence of the manifest is itself the failure.
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
    if grep -q '^metamodule=1' "$mp"; then
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
if [ -x "$_nm" ]; then
    _ev=$("$_nm" v 2>/dev/null | tr -dc '0-9')
    if [ -n "$_ev" ]; then
        ui_print "- Prism engine: v${_ev} (responding)"
    else
        ui_print "*********************************************************"
        ui_print "! The kernel's NoMount engine did not answer."
        ui_print "! From recovery this is normal - it will work after boot."
        ui_print "! On a running system it means this kernel has no NoMount"
        ui_print "! support: the module installs but injects nothing."
        ui_print "! Flash a NoMount-enabled kernel, then reboot."
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
    for _f in uidhide uidhide.conf uidhide.cache blocklist my_hookless \
              absorb-skip.txt whiteouts.txt snapshot.txt spoof.conf \
              absorbed.list binds.list absorbed-tmpfs.list apkstate.list; do
        [ -e "$_bak/$_f" ] || continue
        [ -e "$NMDIR/$_f" ] && continue
        cp -p "$_bak/$_f" "$NMDIR/$_f" 2>/dev/null || { rm -f "$NMDIR/$_f" 2>/dev/null; continue; }
        set_perm "$NMDIR/$_f" 0 0 0600 u:object_r:adb_data_file:s0
        _rn=$((_rn + 1))
    done
    unset _f
    [ "$_rn" -gt 0 ] && ui_print "- Restored $_rn setting(s) kept from your previous install"
    rm -rf "$_bak"
    unset _rn
fi
unset _bak
CONF="$NMDIR/spoof.conf"
[ -f "$CONF" ] && set_perm "$CONF" 0 0 0600 u:object_r:adb_data_file:s0

[ -f "$MODPATH/uidwatch.sh" ] && set_perm "$MODPATH/uidwatch.sh" 0 0 0755

[ -f "$MODPATH/lib.sh" ] && set_perm "$MODPATH/lib.sh" 0 0 0644

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
        echo "# later as \"modules stopped applying to new apps\". Delete a line to"
        echo "# absorb it once you have tested your fork."
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
    ui_print "- ⚠️  The Suite is disabled on this device - it will inject nothing at boot."
    ui_print "     Clear it in the WebUI, or: rm $NMDIR/disabled"
fi

_booted=$(getprop sys.boot_completed 2>/dev/null)
if [ -n "$_ev" ] && [ ! -e "$NMDIR/disabled" ]; then
    ui_print "- Modules under /data/adb/modules are injected mountlessly at boot."
    ui_print "- next step: reboot. Nothing is served until you do."
elif [ ! -d "$MODPATH/bin/${_abi}" ]; then
    ui_print "- next step: none - this zip is arm64-v8a only and this device is ${_abi}."
    ui_print "  Re-flashing cannot help. Remove it from your manager."
elif [ ! -x "$_nm" ]; then
    ui_print "- next step: re-flash this zip. The engine could not be probed (see above),"
    ui_print "  so we cannot tell you whether your kernel has NoMount."
elif [ -z "$_ev" ] && [ "$_booted" != "1" ]; then
    ui_print "- Installed from recovery, where the engine cannot answer."
    ui_print "- next step: reboot, then open the WebUI - it says whether your kernel has it."
elif [ -z "$_ev" ]; then
    ui_print "- next step: flash a kernel built with CONFIG_NOMOUNT, then reboot."
    ui_print "  OnePlus prebuilts: github.com/Bouteillepleine/OnePlus-ReSukiSu_NMS/releases"
    ui_print "  Until you do, this module is installed and doing nothing."
else
    ui_print "- next step: clear the disable flag (see above), then reboot."
fi
unset _booted
