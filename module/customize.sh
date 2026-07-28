#!/system/bin/sh
# NoMount metamodule installer. Requires the NoMount kernel patch (/dev/nomount).
ui_print "- Installing NoMount metamodule"
ui_print "- version $(grep_prop version "$MODPATH/module.prop")"

# --- integrity check: verify bundled files against their sha256 manifest ---
# Catches a corrupted download or a tampered zip before we run a root binary.
SUMS="$MODPATH/nomount.sha256sums"
if [ -f "$SUMS" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        if (cd "$MODPATH" && sha256sum -c "$SUMS" >/dev/null 2>&1); then
            ui_print "- Integrity check passed ($(wc -l < "$SUMS") files)"
        else
            ui_print "*********************************************************"
            ui_print "! Integrity check FAILED — a file does not match its hash."
            ui_print "! This zip is corrupted or was modified. Re-download it."
            ui_print "*********************************************************"
            abort "- Aborting install: integrity check failed"
        fi
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
NMDIR=/data/adb/nomount
mkdir -p "$NMDIR"
CONF="$NMDIR/spoof.conf"
[ -f "$CONF" ] || cat > "$CONF" <<'EOF'
# NoMount Suite — spoof add-on config
# vbmeta_digest: auto (set only when the prop is missing) | force | off
EOF
seed_conf() { grep -q "^$1=" "$CONF" 2>/dev/null || echo "$1=$2" >> "$CONF"; }
seed_conf vbmeta_digest auto
set_perm "$CONF" 0 0 0644
[ -f "$MODPATH/spoof.sh" ] && set_perm "$MODPATH/spoof.sh" 0 0 0755
ui_print "- Spoof add-on enabled: dynamic vbmeta.digest"
ui_print "  config: $CONF"

ui_print "- Modules under /data/adb/modules are injected mountlessly at boot."
