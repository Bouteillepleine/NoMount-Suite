#!/system/bin/sh
MODDIR="${0%/*}"
NMLOG_TAG=post-mount
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - the pre-zygote absorb did not run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR" 2>/dev/null

nm_set_bin

nm_early_absorb
