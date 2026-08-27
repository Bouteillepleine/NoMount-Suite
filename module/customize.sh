#!/system/bin/sh
# NoMount metamodule installer. Requires a CONFIG_NOMOUNT kernel (the Prism
# engine, reached over private raw netlink -- there is no /dev/nomount node).
ui_print "- Installing NoMount metamodule"
ui_print "- version $(grep_prop version "$MODPATH/module.prop")"

# --- integrity check: verify bundled files against their sha256 manifest ---
# Catches a CORRUPTED DOWNLOAD (a truncated or bit-rotted zip) before we run a
# root binary. It is deliberately not an authenticity check and cannot be one:
# the manifest ships inside the same zip, so anyone who alters a file alters the
# manifest with it. Verifying provenance needs a signature over the zip against a
# key that is not in the zip.
SUMS="$MODPATH/nomount.sha256sums"
if [ -f "$SUMS" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        # KEEP the output. `>/dev/null 2>&1` threw away the one thing that tells a
        # corrupt download apart from a manifest this device cannot read at all --
        # and the second case really happened: a manifest written in BINARY mode
        # ("<hash> *./path") makes toybox read the asterisk as part of the
        # filename, so every entry fails to open and the install aborts with the
        # reason hidden. An abort with no reason is a bug report nobody can act on.
        _sumout=$(cd "$MODPATH" && sha256sum -c "$SUMS" 2>&1)
        if [ $? -eq 0 ]; then
            ui_print "- Integrity check passed ($(wc -l < "$SUMS") files)"
        else
            ui_print "*********************************************************"
            ui_print "! Integrity check FAILED — a file does not match its hash."
            ui_print "! This zip is corrupted or was modified. Re-download it."
            ui_print "! What sha256sum -c reported:"
            # Only the failing lines, and a bounded number of them: a manifest
            # this device cannot parse fails EVERY entry, and 250 identical
            # lines scrolled the actual message off the recovery screen.
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

# --- refuse to co-exist with another metamodule ---
# KSU/APatch allow only ONE metamodule to own module mounting; two will fight
# in post-fs-data (broken mounts / bootloop). Abort early with a clear message.
for mp in /data/adb/modules/*/module.prop; do
    [ -f "$mp" ] || continue
    mdir="${mp%/module.prop}"
    id="${mdir##*/}"
    [ "$id" = "meta-nomount" ] && continue          # our own (update/reinstall)
    [ -f "$mdir/remove" ] && continue               # pending uninstall
    [ -f "$mdir/disable" ] && continue              # disabled -> won't run
    if grep -q '^metamodule=1' "$mp"; then
        other="$(grep '^name=' "$mp" | head -n1 | cut -d= -f2-)"
        ui_print "*********************************************************"
        ui_print "! Another metamodule is already installed:"
        ui_print "!   $id${other:+  ($other)}"
        ui_print "! KernelSU/APatch allow only ONE metamodule."
        ui_print "! Remove or disable it first, then flash NoMount."
        ui_print "*********************************************************"
        abort "- Aborting install: metamodule conflict"
    fi
done

# Make the per-ABI binaries executable — BOTH the Suite driver (nomount) and the
# hookless netlink client (nm) it shells out to. Missing +x on nm makes the boot
# mount pass abort before it can inject.
for abi in arm64-v8a armeabi-v7a x86_64 x86; do
    for b in nomount nm; do
        if [ -f "$MODPATH/bin/$abi/$b" ]; then
            set_perm "$MODPATH/bin/$abi/$b" 0 0 0755
        fi
    done
done

# --- spoof add-on: dynamic vbmeta.digest ---
# Seed the persistent config (append-only so user edits survive an update), and
# make the add-on script executable. The work itself happens at boot in spoof.sh.
# --- does this kernel actually have the engine? ---------------------------
# The header above says this needs a CONFIG_NOMOUNT kernel, but nothing checked
# it: installing on a kernel without the hookless engine "succeeded" and then
# injected nothing, silently. `nm v` asks the engine its version over netlink and
# answers nothing if it is not there.
#
# A WARNING, never an abort: flashing from recovery is legitimate and the
# recovery kernel has no engine, so aborting would block a valid install.
_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
# Same fallback the boot scripts carry. An empty ABI builds "$MODPATH/bin//nm",
# which is never executable, so BOTH probes below ([ -x "$_nm" ]) fell through in
# silence: the install printed nothing about the engine at all, and then declared
# "kernel pathhide not present" on a kernel that has it. Neither is true; both
# read as a finding.
[ -n "$_abi" ] || _abi=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$_abi" ] || _abi=arm64-v8a
_nm="$MODPATH/bin/${_abi}/nm"
# ABI FIRST, and loudly. The zip ships arm64-v8a only, and the boot scripts load
# bin/$(getprop ro.product.cpu.abi)/nomount -- so on any other ABI every one of
# them takes an `[ -x "$BIN" ]` branch that is false and the module is a silent
# no-op from the first boot onward. The install said nothing about it, because
# the engine probe below is itself gated on [ -x "$_nm" ] with no else: no ABI
# directory means no nm, means no probe, means no output at all.
if [ ! -d "$MODPATH/bin/${_abi}" ]; then
    ui_print "*********************************************************"
    ui_print "! This zip has no binaries for this device's ABI."
    ui_print "!   device ABI: ${_abi}"
    ui_print "!   shipped:    $(ls "$MODPATH/bin" 2>/dev/null | tr '\n' ' ')"
    ui_print "! The module will install and then inject NOTHING, on every"
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
        ui_print "! From recovery this is normal — it will work after boot."
        ui_print "! On a running system it means this kernel has no NoMount"
        ui_print "! support: the module installs but injects NOTHING."
        ui_print "! Flash a NoMount-enabled kernel, then reboot."
        ui_print "*********************************************************"
    fi
else
    # The missing `else`. "The engine probe did not run" and "the engine did not
    # answer" are different problems with the same symptom (nothing is injected),
    # and this arm printed nothing at all -- so an install onto an unsupported ABI,
    # or from a partial extraction that dropped the exec bit, reported success and
    # then quietly did nothing forever.
    ui_print "*********************************************************"
    ui_print "! Could not run the engine probe: no executable at"
    ui_print "!   bin/${_abi}/nm"
    ui_print "! The engine state is UNKNOWN and the module may inject"
    ui_print "! nothing. Re-flash the zip; a partial extraction or an"
    ui_print "! unsupported ABI is the usual cause."
    ui_print "*********************************************************"
fi

NMDIR=/data/adb/nomount
mkdir -p "$NMDIR"
# The 5th argument is NOT optional here. set_perm() defaults its SELinux
# context to u:object_r:system_file:s0, and the live policy grants every app
# domain read+search on system_file (dir 0x11140053, file 0x2044412) while
# granting NOTHING on adb_data_file -- so omitting it relabelled the whole
# state directory on every install, and the only thing keeping spoof.conf,
# uidhide, pathhide.conf and blocklist away from an app was /data/adb refusing
# traversal one level up. Measured on OP15. Match the parent explicitly.
set_perm "$NMDIR" 0 0 0700 u:object_r:adb_data_file:s0
CONF="$NMDIR/spoof.conf"
[ -f "$CONF" ] || cat > "$CONF" <<'EOF'
# NoMount Suite — spoof add-on config
#
# ⚠️ DEFERRED / EXPERIMENTAL. Every knob below ships OFF. The vbmeta digest
# computation has two known unfixed defects (see the DEFECT comments in
# spoof.sh) that can produce a well-formed digest with the wrong value, which
# is a sharper tell than setting no digest at all. Turn one on only if you are
# going to verify the result yourself.
#
# vbmeta_digest: off (default) | auto (set only when the prop is missing) | force
# vbmeta_size:   off (default) | auto | force
EOF
seed_conf() { grep -q "^$1=" "$CONF" 2>/dev/null || echo "$1=$2" >> "$CONF"; }
# `off`, not `auto`. seed_conf only writes a key that is ABSENT, so a device that
# already chose a value keeps it -- this changes the default for a FRESH install,
# which is what "deferred for this release" has to mean in practice. It used to
# seed `auto`, so every new install silently opted in to an add-on with two
# unfixed defects in the value it computes.
seed_conf vbmeta_digest off
seed_conf vbmeta_size off
seed_conf spoof_props 0
seed_conf spoof_uname 0
seed_conf uname_tail ""
seed_conf uname_date ""
seed_conf fix_shell_tmp 1
# 0600 + the explicit context, like every other file in $NMDIR. Two problems in
# one line: 0644 made spoof.conf the only group/world-readable file in the state
# dir, and the MISSING 5th argument relabelled it to u:object_r:system_file:s0 --
# which the live policy grants every app domain read on (file 0x2044412), while
# granting nothing on adb_data_file. The 0700 parent was the only thing standing
# between an app and this file, which is exactly the reliance the $NMDIR fix
# above removed. spoof.conf records the boot-identity spoof settings; only root
# (spoof.sh at post-fs-data, and the WebUI through an exec) ever reads it.
set_perm "$CONF" 0 0 0600 u:object_r:adb_data_file:s0
[ -f "$MODPATH/spoof.sh" ] && set_perm "$MODPATH/spoof.sh" 0 0 0755
ui_print "- Spoof add-on: DEFERRED, off by default (experimental)"
ui_print "  config: $CONF"

# --- per-UID hiding ---
# The hide list used to share /data/adb/nomount/blocklist with the module-skip
# list, so hiding an app also told the mount pass to skip a module of that name,
# and the WebUI's unhide button could delete a module-skip entry. It has its own
# file (uidhide) now; an existing shared file is split on first read.
[ -f "$MODPATH/uidwatch.sh" ] && set_perm "$MODPATH/uidwatch.sh" 0 0 0755

# Executable, not just readable. `ksud module install` leaves the scripts it
# does not know about at 0644, and whether the manager runs this one as
# `sh uninstall.sh` or execs it directly is not something we can read off the
# binary -- so the difference is only discovered by uninstalling, which is
# exactly when nobody is watching. This file had never shipped in a zip at
# all until now, so it has never run anywhere: give it the bit and the
# question stops mattering.
[ -f "$MODPATH/uninstall.sh" ] && set_perm "$MODPATH/uninstall.sh" 0 0 0755

# --- Cloak (pathhide maps/fd) add-on ---
[ -f "$MODPATH/scan.sh" ] && set_perm "$MODPATH/scan.sh" 0 0 0755
[ -f "$NMDIR/pathhide.conf" ] || echo "# NoMount Cloak — pathhide rule list (managed by hand; see 'nomount check')" > "$NMDIR/pathhide.conf"

# --- absorb opt-out list -----------------------------------------------------
# `nomount absorb` converts other modules' bind mounts into injections. Safe for
# a plain file bind (exec through an injection is verified working), but a hook
# framework installs its bind from NATIVE daemon code that differs between forks
# and versions, and the failure mode is SILENT AND DELAYED: dex2oat runs during
# dexopt on app install, not at boot, so a broken hook surfaces hours later as
# "modules stopped applying to new apps" and is near-impossible to attribute.
# Skipped by default. The cost is one file keeping the bind's dev/ino/mtime
# tell, which `nomount check --plan` reports so it is not invisible. Delete a line to
# absorb that module once you have verified your fork.
# Migrate the pre-v1.2.1 extensionless name. COPY, never move: the outgoing
# binary is still live until the next reboot and reads the OLD name, so renaming
# here would silently drop its opt-outs for anything that runs absorb in that
# window. The new binary prefers .txt and falls back to the old name, so both
# work; the stale copy is simply ignored afterwards.
[ -f "$NMDIR/absorb-skip" ] && [ ! -f "$NMDIR/absorb-skip.txt" ] && \
    cp -f "$NMDIR/absorb-skip" "$NMDIR/absorb-skip.txt"
if [ ! -f "$NMDIR/absorb-skip.txt" ]; then
    {
        echo "# One per line: an absolute TARGET PATH PREFIX, or a module id."
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
# 0600, not 0644: this is the cloak rule list -- it names exactly which packages
# are being hidden from maps/fd -- and every other file in the 0700 $NMDIR is
# 0600. Only root reads it (service.sh at boot, the WebUI through an exec), so
# nothing needs the group/other bits.
set_perm "$NMDIR/pathhide.conf" 0 0 0600 u:object_r:adb_data_file:s0
# Probe over the netlink knob, not a /proc node: pathhide no longer creates one
# (any app could find it with a single readdir of /proc). `nm k p` with no value
# is side-effect-free and exits 0 only when the patch set is compiled in.
if [ -x "$_nm" ] && "$_nm" k p >/dev/null 2>&1; then
    ui_print "- Cloak add-on: kernel pathhide FOUND — inert by default (no rules); edit $NMDIR/pathhide.conf to use it"
else
    ui_print "- Cloak add-on: kernel pathhide not present (needs a pathhide-enabled kernel)"
fi

# A flash is an explicit user action, so the bootloop counter's premise -- "this
# device keeps failing to finish booting on its own" -- no longer holds. Without
# this, the classic recovery (flash the update that FIXES the bootloop) inherits
# a counter already at 2: the new code's first boot trips it, writes `disabled`,
# and skips the spoof and mount passes entirely -- before any of the new code has
# run once. The user sees the update "not help".
rm -f "$NMDIR/bootcount"

# `disabled` is NOT cleared here. The guard writes it, but a user can also write
# it by hand to park the Suite, and silently undoing that on every upgrade would
# be its own surprise. Say so instead -- loudly, because an install that reports
# success and then injects nothing, with no explanation, is the worse outcome.
if [ -f "$NMDIR/disabled" ]; then
    ui_print "- ⚠️  The Suite is DISABLED on this device — it will inject nothing at boot."
    ui_print "     Clear it in the WebUI, or: rm $NMDIR/disabled"
fi

ui_print "- Modules under /data/adb/modules are injected mountlessly at boot."
