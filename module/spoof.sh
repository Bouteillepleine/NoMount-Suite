#!/system/bin/sh
# NoMount Suite — spoof add-on.
#
# Recomputes ro.boot.vbmeta.digest from the real AVB vbmeta chain on this device
# (no "paste it from the Key Attestation demo" step). Set only when the property
# is missing/empty, unless forced. Cached for boot-to-boot stability.
#
# Best-effort: a failure must never abort boot. Called from metamount.sh
# (KSU/APatch) and post-fs-data.sh (Magisk), in the post-fs-data stage so the
# property is in place before zygote/system_server start.

PATH=/data/adb/ksu/bin:/data/adb/magisk:/system/bin:/system/xbin:$PATH
NMDIR=/data/adb/nomount
CONF="$NMDIR/spoof.conf"
LOG="$NMDIR/spoof.log"

mkdir -p "$NMDIR" 2>/dev/null
# Trim the log so it can't grow unbounded across boots.
[ -f "$LOG" ] && tail -n 200 "$LOG" > "$LOG.tmp" 2>/dev/null && mv -f "$LOG.tmp" "$LOG" 2>/dev/null

log() {
    echo "nomount-spoof: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG" 2>/dev/null
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---- config (persistent, seeded by customize.sh) --------------------------
vbmeta_digest=auto     # auto = set only when missing | force = always | off
[ -f "$CONF" ] && . "$CONF"

# ---- resetprop locator ----------------------------------------------------
RESETPROP=""
find_resetprop() {
    local c
    for c in /data/adb/ksu/bin/resetprop /data/adb/magisk/resetprop resetprop; do
        if [ -x "$c" ] 2>/dev/null; then RESETPROP="$c"; return 0; fi
        if command -v "$c" >/dev/null 2>&1; then RESETPROP="$c"; return 0; fi
    done
    if command -v magisk >/dev/null 2>&1; then RESETPROP="magisk resetprop"; return 0; fi
    return 1
}

# ---- sha helper -----------------------------------------------------------
sha256_of() {
    local f=$1 out=""
    if have sha256sum; then out=$(sha256sum "$f" 2>/dev/null | awk '{print $1}'); fi
    [ -z "$out" ] && have busybox && out=$(busybox sha256sum "$f" 2>/dev/null | awk '{print $1}')
    echo "$out"
}
sha512_of() {
    local f=$1 out=""
    if have sha512sum; then out=$(sha512sum "$f" 2>/dev/null | awk '{print $1}'); fi
    [ -z "$out" ] && have busybox && out=$(busybox sha512sum "$f" 2>/dev/null | awk '{print $1}')
    echo "$out"
}

# ===========================================================================
#  vbmeta.digest — true AVB digest, computed from the vbmeta chain on-device
# ===========================================================================
# AvbVBMetaImageHeader is big-endian; struct length = 256 + auth_size + aux_size.
# The digest per avbtool calculate_vbmeta_digest() is:
#   sha( struct(vbmeta) [ + struct(<each chained vbmeta partition>) ... ] )
# walked depth-first in chain-descriptor order. We reproduce that here.

SLOT=""

# read a big-endian u32 at <file> <offset>
be_u32() {
    local f=$1 o=$2
    set -- $(dd if="$f" bs=1 skip="$o" count=4 2>/dev/null | od -An -tu1)
    echo $(( ${1:-0}*16777216 + ${2:-0}*65536 + ${3:-0}*256 + ${4:-0} ))
}
# read a big-endian u64 at <file> <offset> (values here are all small; a set
# high word means a corrupt/unexpected field, so we treat it as invalid -> 0)
be_u64() {
    local f=$1 o=$2 hi lo
    set -- $(dd if="$f" bs=1 skip="$o" count=8 2>/dev/null | od -An -tu1)
    hi=$(( ${1:-0}*16777216 + ${2:-0}*65536 + ${3:-0}*256 + ${4:-0} ))
    lo=$(( ${5:-0}*16777216 + ${6:-0}*65536 + ${7:-0}*256 + ${8:-0} ))
    [ "$hi" -ne 0 ] && { echo 0; return; }
    echo "$lo"
}

resolve_part() {
    local n=$1 cand
    for cand in "/dev/block/by-name/${n}${SLOT}" "/dev/block/by-name/${n}"; do
        [ -e "$cand" ] && { echo "$cand"; return 0; }
    done
    return 1
}

# append <partition-basename>'s vbmeta struct to $ACC, then recurse its chains.
ACC=""

# Where does this partition's vbmeta struct start? A pure vbmeta partition has the
# AVB0 header at offset 0; a signed image (boot, dtbo, recovery, …) instead carries
# a 64-byte AvbFooter at the very end whose vbmeta_offset points at it. Without this
# the chained image partitions are silently skipped and the digest comes out wrong.
#   AvbFooter: magic[4] "AVBf" | version_major u32 | version_minor u32 |
#              original_image_size u64 @12 | vbmeta_offset u64 @20 | vbmeta_size u64 @28
vbmeta_base() {
    local dev=$1 sz foot magic vo
    [ "$(dd if="$dev" bs=1 count=4 2>/dev/null)" = "AVB0" ] && { echo 0; return 0; }
    sz=$(blockdev --getsize64 "$dev" 2>/dev/null)
    [ -z "$sz" ] && sz=$(( $(cat "/sys/class/block/$(basename "$(readlink -f "$dev")")/size" 2>/dev/null || echo 0) * 512 ))
    [ "${sz:-0}" -gt 64 ] || return 1
    foot=$(( sz - 64 ))
    magic=$(dd if="$dev" bs=1 skip="$foot" count=4 2>/dev/null)
    [ "$magic" = "AVBf" ] || return 1
    vo=$(be_u64 "$dev" $(( foot + 20 )))
    [ "${vo:-0}" -gt 0 ] || return 1
    echo "$vo"
}

emit_struct() {
    local base=$1 depth=$2 dev magic auth aux len vo
    local desc_off desc_size aux_start p end tag nbf nlen nm
    [ "${depth:-0}" -gt 6 ] && return 0
    dev=$(resolve_part "$base") || { [ "$depth" = 0 ] && log "vbmeta: partition '$base$SLOT' not found"; return 1; }
    vo=$(vbmeta_base "$dev") || { [ "$depth" = 0 ] && log "vbmeta: '$dev' has no AVB header or footer"; return 1; }
    magic=$(dd if="$dev" bs=1 skip="$vo" count=4 2>/dev/null)
    [ "$magic" = "AVB0" ] || { [ "$depth" = 0 ] && log "vbmeta: '$dev' is not an AVB image"; return 1; }
    auth=$(be_u64 "$dev" $(( vo + 12 )))
    aux=$(be_u64 "$dev" $(( vo + 20 )))
    len=$(( 256 + auth + aux ))
    # sanity: a real vbmeta struct is between the bare header and ~1 MiB
    [ "$len" -ge 256 ] && [ "$len" -le 1048576 ] || { log "vbmeta: implausible struct len=$len for $base"; return 1; }
    dd if="$dev" bs=1 skip="$vo" count="$len" 2>/dev/null >> "$ACC"

    desc_off=$(be_u64 "$dev" $(( vo + 96 )))
    desc_size=$(be_u64 "$dev" $(( vo + 104 )))
    aux_start=$(( vo + 256 + auth ))
    p=$(( aux_start + desc_off ))
    end=$(( p + desc_size ))
    while [ "$p" -lt "$end" ]; do
        tag=$(be_u64 "$dev" "$p")
        nbf=$(be_u64 "$dev" $(( p + 8 )))
        [ "$nbf" -le 0 ] && break
        if [ "$tag" = "4" ]; then          # AVB_DESCRIPTOR_TAG_CHAIN_PARTITION
            # AVB tags: 0=property 1=hashtree 2=hash 3=kernel_cmdline 4=chain_partition.
            # AvbChainPartitionDescriptor: 16 hdr + 4 rollback_index_location +
            # 4 partition_name_len + 4 public_key_len + 64 reserved => name at +92.
            nlen=$(be_u32 "$dev" $(( p + 20 )))          # partition_name_len
            if [ "$nlen" -gt 0 ] && [ "$nlen" -le 64 ]; then
                nm=$(dd if="$dev" bs=1 skip=$(( p + 92 )) count="$nlen" 2>/dev/null)
                [ -n "$nm" ] && emit_struct "$nm" $(( depth + 1 ))
            fi
        fi
        p=$(( p + 16 + nbf ))
    done
    return 0
}

compute_vbmeta_digest() {
    ACC="$NMDIR/.vbacc"
    : > "$ACC" 2>/dev/null || return 1
    SLOT=$(getprop ro.boot.slot_suffix 2>/dev/null)
    if ! emit_struct vbmeta 0 || [ ! -s "$ACC" ]; then
        rm -f "$ACC" 2>/dev/null
        return 1
    fi
    local alg dg=""
    alg=$(getprop ro.boot.vbmeta.hash_alg 2>/dev/null)
    [ "$alg" = "sha512" ] && dg=$(sha512_of "$ACC")
    [ -z "$dg" ] && dg=$(sha256_of "$ACC")
    rm -f "$ACC" 2>/dev/null
    [ -n "$dg" ] && printf '%s' "$dg" | tr 'A-F' 'a-f'
}

do_vbmeta() {
    local mode=$1 cur cache="$NMDIR/vbmeta_digest.cache" dg=""
    [ "$mode" = "off" ] && { log "vbmeta.digest: off"; return 0; }
    cur=$(getprop ro.boot.vbmeta.digest 2>/dev/null)
    if [ -n "$cur" ] && [ "$mode" != "force" ]; then
        log "vbmeta.digest already present (len ${#cur}); leaving as-is"
        return 0
    fi
    if [ -s "$cache" ] && [ "$mode" != "force" ]; then
        dg=$(cat "$cache" 2>/dev/null)
    fi
    if [ -z "$dg" ]; then
        dg=$(compute_vbmeta_digest)
        [ -n "$dg" ] && echo "$dg" > "$cache" 2>/dev/null
    fi
    if [ -z "$dg" ]; then
        log "vbmeta.digest: could not compute (left unset)"
        return 0
    fi
    if [ -z "$RESETPROP" ]; then
        log "vbmeta.digest: resetprop unavailable, cannot set"
        return 0
    fi
    $RESETPROP -n ro.boot.vbmeta.digest "$dg" 2>/dev/null \
        && log "vbmeta.digest set = $dg ($mode)" \
        || log "vbmeta.digest: resetprop failed"
}

# ===========================================================================
main() {
    find_resetprop || log "resetprop not found (vbmeta.digest set will be skipped)"
    do_vbmeta "$vbmeta_digest"
}

# `verify` / `compute` inspect without changing anything, so the UI can show
# whether the current prop already matches the real chain before Apply is used.
#   compute -> the freshly computed digest, or empty on failure
#   verify  -> "match <d>" | "mismatch <d>" | "absent <d>" | "error"
case "${1:-}" in
    compute)
        compute_vbmeta_digest
        exit 0 ;;
    verify)
        cur=$(getprop ro.boot.vbmeta.digest 2>/dev/null)
        dg=$(compute_vbmeta_digest)
        if [ -z "$dg" ]; then echo "error";
        elif [ -z "$cur" ]; then echo "absent $dg";
        elif [ "$cur" = "$dg" ]; then echo "match $dg";
        else echo "mismatch $dg"; fi
        exit 0 ;;
esac

main
exit 0
