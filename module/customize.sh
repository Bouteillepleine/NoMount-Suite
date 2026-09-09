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
        ui_print "- sha256sum unavailable; skipping integrity check"
    fi
else
    ui_print "- No sha256 manifest bundled; skipping integrity check"
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
    ui_print "!   shipped:    $(ls "$MODPATH/bin" 2>/dev/null | tr '\n' ' ')"
    ui_print "! The module will install and then inject nothing, on every"
    ui_print "! boot, silently. NoMount is arm64-v8a only."
    ui_print "*********************************************************"
fi
NM_LKM_SAY=ui_print
NM_LKM_NM="$_nm"
NM_LKM_LOADER="$MODPATH/loader"
export NM_LKM_SAY NM_LKM_NM NM_LKM_LOADER
[ -f "$MODPATH/lkm-load.sh" ] && . "$MODPATH/lkm-load.sh"
[ -f "$NM_LKM_LOADER" ] && chmod 0755 "$NM_LKM_LOADER" 2>/dev/null

if [ -x "$_nm" ]; then
    _ev=$("$_nm" v 2>/dev/null | tr -dc '0-9')
    if [ -n "$_ev" ]; then
        if lsmod 2>/dev/null | grep -q "^nomount"; then
            ui_print "- Prism engine: v${_ev} (loaded as a module)"
            ui_print "- Keeping lkm/ so it can be re-inserted on every boot."
        else
            ui_print "- Prism engine: v${_ev} (built into the kernel)"
            ui_print "- Removing the bundled modules: this kernel does not need them."
            rm -rf "$MODPATH/lkm" "$MODPATH/loader"
        fi
    else
        ui_print "- No built-in NoMount engine. Trying the bundled modules..."
        ui_print "-   kernel: $(uname -r)"
        if command -v nm_lkm_load_best >/dev/null 2>&1 && nm_lkm_load_best "$MODPATH/lkm"; then
            _ev=$("$_nm" v 2>/dev/null | tr -dc '0-9')
            ui_print "- Prism engine: v${_ev} (module loaded)"
            nm_lkm_prune "$MODPATH/lkm"
        else
            ui_print "*********************************************************"
            ui_print "! No bundled module loads on this kernel, and it has no"
            ui_print "! built-in NoMount support: the module installs but"
            ui_print "! injects nothing."
            ui_print "!   kernel:    $(uname -r)"
            ui_print "!   available: $(ls "$MODPATH/lkm" 2>/dev/null | tr "\n" " ")"
            ui_print "! From recovery this is expected: there is no running"
            ui_print "! kernel to load into. Reboot, then reinstall to find out."
            ui_print "! Otherwise this kernel is not supported by this zip."
            ui_print "*********************************************************"
        fi
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
              absorbed.list binds.list; do
        [ -e "$_bak/$_f" ] || continue
        [ -e "$NMDIR/$_f" ] && continue
        cp -p "$_bak/$_f" "$NMDIR/$_f" 2>/dev/null || continue
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

if [ -f "$NMDIR/disabled" ]; then
    ui_print "- ⚠️  The Suite is disabled on this device - it will inject nothing at boot."
    ui_print "     Clear it in the WebUI, or: rm $NMDIR/disabled"
fi

ui_print "- Modules under /data/adb/modules are injected mountlessly at boot."
