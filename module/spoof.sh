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
# The only script under module/ that did not set this, and it showed: every other
# file in $NMDIR is 0600 while spoof.log was 0644 on-device. The log rotation
# below is what does it -- `tail > $LOG.tmp` creates the temp under whatever umask
# is in force and `mv` carries that mode onto the log. The 0700 parent means this
# was never reachable by anything unprivileged, but the log records the spoof
# decisions (vbmeta digest, uname) and the invariant is "nothing here is group- or
# world-readable", so state it here rather than depend on the caller's umask.
umask 077
NMDIR=/data/adb/nomount
CONF="$NMDIR/spoof.conf"
LOG="$NMDIR/spoof.log"

mkdir -p "$NMDIR" 2>/dev/null && chmod 0700 "$NMDIR" 2>/dev/null
# Trim the log so it can't grow unbounded across boots.
[ -f "$LOG" ] && tail -n 200 "$LOG" > "$LOG.tmp" 2>/dev/null && mv -f "$LOG.tmp" "$LOG" 2>/dev/null
# Correct a log left 0644 by an older build; the rotation above only fixes the
# mode once it next rotates, and a fresh install never rotates at all.
[ -f "$LOG" ] && chmod 0600 "$LOG" 2>/dev/null

log() {
    echo "nomount-spoof: $*" > /dev/kmsg 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG" 2>/dev/null
    # ...and to stderr, so a CALLER can see what happened. This script is
    # best-effort by design and ALWAYS exits 0 -- a spoof failure must never abort
    # boot -- which left the WebUI's Apply button with nothing to judge: it awaited
    # the exec, discarded everything, and toasted green even when the run logged
    # "resetprop not found" and changed nothing. stderr, not stdout, because the
    # subcommands below (props / verify / compute / shell-tmp-status / reset-uname)
    # have machine-read stdout that must stay pristine. Every boot-time caller
    # already redirects fd 2 to /dev/null, so nothing changes there.
    echo "nomount-spoof: $*" >&2
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---- config (persistent, seeded by customize.sh) --------------------------
vbmeta_digest=auto     # auto = set only when missing | force = always | off
vbmeta_size=auto       # auto = set alongside digest | off
spoof_props=0          # 1 = normalize boot-state props (conditional writes only)
spoof_uname=0          # 1 = apply the uname override
# spoof_cmdline: sanitize /proc/cmdline + /proc/bootconfig. Unset = follow spoof_props
# (so Boot-state props covers procfs too); set 0 in spoof.conf to keep procfs untouched.
uname_tail=""          # blank = keep; a bare tail or a whole pasted uname -r
uname_date=""          # blank = keep; a bare date or a whole pasted uname -v
fix_shell_tmp=1        # 1 = restore AOSP owner/mode/context on /data/local/tmp
# Parse, do NOT source. `. "$CONF"` executes the file as root at post-fs-data,
# so a writable config was arbitrary root code execution. Only known keys are
# accepted and the value is never evaluated.
nm_load_conf() {
    [ -f "$CONF" ] || return 0
    while IFS= read -r _l; do
        # Never cut at the first "#": every pasted `uname -v` STARTS with
        # "#1 SMP ...", so a blanket ${_l%%#*} silently emptied uname_date and the
        # version override was skipped -- a spoofed release with a stock version,
        # exactly the half-spoof this add-on exists to avoid. A "#" opens a comment
        # only at the start of a line, or after a blank in an unquoted value.
        _t=$_l
        while :; do case "$_t" in " "*|"	"*) _t=${_t#?} ;; *) break ;; esac; done
        case "$_t" in ""|"#"*) continue ;; esac
        case "$_t" in *=*) ;; *) continue ;; esac
        _k=${_t%%=*}; _v=${_t#*=}
        _k=$(printf '%s' "$_k" | tr -d " \t")
        case "$_v" in
            \'*) _v=${_v#\'}; _v=${_v%%\'*} ;;
            \"*)  _v=${_v#\"};  _v=${_v%%\"*} ;;
            *)    _v=${_v%%[ 	]#*}
                  while :; do case "$_v" in *" "|*"	") _v=${_v%?} ;; *) break ;; esac; done ;;
        esac
        case "$_k" in
            vbmeta_digest) vbmeta_digest=$_v ;;
            vbmeta_size)   vbmeta_size=$_v ;;
            spoof_props)   spoof_props=$_v ;;
            spoof_uname)   spoof_uname=$_v ;;
            spoof_cmdline) spoof_cmdline=$_v ;;
            uname_tail)    uname_tail=$_v ;;
            uname_date)    uname_date=$_v ;;
            fix_shell_tmp) fix_shell_tmp=$_v ;;
        esac
    done < "$CONF"
}
nm_load_conf

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
    # shellcheck disable=SC2046  # the split IS the parse: od prints one decimal
    # byte per field and this turns them into $1..$4. Quoting would hand the
    # whole line to $1 and the arithmetic below would read 0.
    set -- $(dd if="$f" bs=1 skip="$o" count=4 2>/dev/null | od -An -tu1)
    echo $(( ${1:-0}*16777216 + ${2:-0}*65536 + ${3:-0}*256 + ${4:-0} ))
}
# read a big-endian u64 at <file> <offset> (values here are all small; a set
# high word means a corrupt/unexpected field, so we treat it as invalid -> 0)
be_u64() {
    local f=$1 o=$2 hi lo
    # shellcheck disable=SC2046  # same as be_u32: the split is the parse.
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
    # regular-file fallback (an extracted vbmeta image, or the test harness) —
    # block-device size ioctls above return nothing for a plain file.
    [ "${sz:-0}" -gt 0 ] || sz=$(stat -c %s "$dev" 2>/dev/null || wc -c < "$dev" 2>/dev/null)
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
    # Per-invocation: on a shared path two concurrent runs truncate and rm each
    # other's chain bytes, and the loser still returns a full-length wrong digest.
    ACC="$NMDIR/.vbacc.$$"
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
    VB_SIZE=$(wc -c < "$ACC" 2>/dev/null | tr -d ' \n')
    # Written here, not returned: every caller runs this in a $(...) subshell, so a
    # variable set now is gone the moment it returns. That is why ro.boot.vbmeta.size
    # was NEVER set -- do_vbmeta read an always-empty VB_SIZE, so it also never wrote
    # the size cache it then fell back to. A file crosses the subshell boundary.
    [ -n "$VB_SIZE" ] && echo "$VB_SIZE" > "$NMDIR/vbmeta_size.cache" 2>/dev/null
    rm -f "$ACC" 2>/dev/null
    [ -n "$dg" ] && printf '%s' "$dg" | tr 'A-F' 'a-f'
}

do_vbmeta() {
    local mode=$1 cur cache="$NMDIR/vbmeta_digest.cache" szcache="$NMDIR/vbmeta_size.cache" dg="" sz=""
    # digest=off must NOT skip the size half. These are two independent settings
    # (vbmeta_digest / vbmeta_size) and the early `return 0` here swallowed the
    # size block 30 lines below, so `vbmeta_digest=off` + `vbmeta_size=auto` --
    # the configuration on the author's own device -- silently never applied the
    # size on a bootloader that does not export ro.boot.vbmeta.size. Skip only
    # the digest work and fall through to the size block.
    if [ "$mode" = "off" ]; then
        log "vbmeta.digest: off"
        do_vbmeta_size "$mode"
        return 0
    fi

    cur=$(getprop ro.boot.vbmeta.digest 2>/dev/null)
    if [ -n "$cur" ] && [ "$mode" != "force" ]; then
        log "vbmeta.digest already present (len ${#cur}); leaving as-is"
    else
        [ -s "$cache" ] && [ "$mode" != "force" ] && dg=$(cat "$cache" 2>/dev/null)
        if [ -z "$dg" ]; then
            dg=$(compute_vbmeta_digest)
            # Shape check before it reaches the prop or the cache: a wrong digest
            # is worse than none, and the cache would keep serving it.
            case "$dg" in
                *[!0-9a-f]*) dg="" ;;
                ????????????????????????????????????????????????????????????????) ;;
                ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????) ;;
                *) dg="" ;;
            esac
            # compute_vbmeta_digest wrote $szcache itself (it runs in a subshell).
            [ -n "$dg" ] && echo "$dg" > "$cache" 2>/dev/null
        fi
        if [ -z "$dg" ]; then
            log "vbmeta.digest: could not compute (left unset)"
        elif [ -z "$RESETPROP" ]; then
            log "vbmeta.digest: resetprop unavailable, cannot set"
        else
            $RESETPROP -n ro.boot.vbmeta.digest "$dg" 2>/dev/null \
                && log "vbmeta.digest set = $dg ($mode)" || log "vbmeta.digest: resetprop failed"
        fi
    fi

    do_vbmeta_size "$mode"
}

# ro.boot.vbmeta.size — the same chain bytes the digest is computed over.
# Split out of do_vbmeta() so it is reachable when vbmeta_digest=off; the two
# knobs are independent and the caller decides.
do_vbmeta_size() {
    local mode=$1 cur="" sz="" szcache="$NMDIR/vbmeta_size.cache"

    # Set only when missing (unless forced). VALIDATE once against the real prop.
    [ "${vbmeta_size:-auto}" = "off" ] && return 0
    [ -n "$RESETPROP" ] || return 0
    # Decide whether there is anything to DO before doing any work. Walking the AVB
    # chain costs ~1.9s (dd bs=1 over every chained partition) and this runs at
    # post-fs-data, ahead of the mount pass -- so it must not happen on a device
    # whose ro.boot.vbmeta.size is already correct, which is the normal case.
    cur=$(getprop ro.boot.vbmeta.size 2>/dev/null)
    [ -n "$cur" ] && [ "$mode" != "force" ] && return 0
    [ -s "$szcache" ] && sz=$(cat "$szcache" 2>/dev/null)
    # No cache yet (digest already present, so nothing recomputed) -- measure the
    # chain now rather than leaving the size permanently unset.
    [ -n "$sz" ] || { compute_vbmeta_digest >/dev/null 2>&1
                      [ -s "$szcache" ] && sz=$(cat "$szcache" 2>/dev/null); }
    [ -n "$sz" ] || return 0
    if [ -z "$cur" ] || [ "$mode" = "force" ]; then
        $RESETPROP -n ro.boot.vbmeta.size "$sz" 2>/dev/null && log "vbmeta.size set = $sz ($mode)"
    fi
}

# ---- boot-state props — conditional writes only (never create a missing prop) --
rp_reset_if_present() {
    local name=$1 want=$2 cur
    cur=$(getprop "$name" 2>/dev/null)
    [ -n "$cur" ] && [ "$cur" != "$want" ] \
        && $RESETPROP -n "$name" "$want" 2>/dev/null && log "prop $name -> $want"
}
rp_del() { [ -n "$(getprop "$1" 2>/dev/null)" ] && $RESETPROP -d "$1" 2>/dev/null && log "prop $1 deleted"; }

do_props() {
    [ "${spoof_props:-0}" = "1" ] || return 0
    [ -n "$RESETPROP" ] || { log "props: resetprop unavailable"; return 0; }

    rp_reset_if_present ro.boot.vbmeta.device_state    locked
    rp_reset_if_present ro.boot.verifiedbootstate      green
    rp_reset_if_present ro.boot.flash.locked           1
    rp_reset_if_present ro.boot.veritymode             enforcing
    rp_reset_if_present ro.boot.warranty_bit           0
    rp_reset_if_present ro.warranty_bit                0
    rp_reset_if_present ro.vendor.boot.warranty_bit    0
    rp_reset_if_present ro.vendor.warranty_bit         0
    rp_reset_if_present vendor.boot.vbmeta.device_state locked
    rp_reset_if_present vendor.boot.verifiedbootstate  green
    rp_reset_if_present ro.debuggable                  0
    rp_reset_if_present ro.force.debuggable            0
    rp_reset_if_present ro.secure                      1
    rp_reset_if_present ro.adb.secure                  1
    rp_reset_if_present ro.build.type                  user
    rp_reset_if_present ro.build.tags                  release-keys
    rp_reset_if_present ro.crypto.state                encrypted
    rp_reset_if_present ro.secureboot.lockstate        locked
    rp_reset_if_present ro.boot.realmebootstate        green
    rp_reset_if_present ro.boot.realme.lockstate       1

    # No build.date.utc harmonization. On a QSSI split build the vendor-side
    # partitions are stamped in their own pass, so a vendor/odm/bootimage dated
    # after system is stock cadence; flattening them is what looks synthetic.

    # harmonize the build-type/tags tail on every fingerprint so it agrees with the
    # ro.build.type=user / ro.build.tags=release-keys set above. A custom ROM often
    # leaves :userdebug/test-keys inside the composite fingerprint (and in
    # description/flavor) — a classic tags-vs-fingerprint inconsistency a RASP checks.
    for fp in ro.build.fingerprint ro.system.build.fingerprint ro.vendor.build.fingerprint \
              ro.product.build.fingerprint ro.odm.build.fingerprint ro.system_ext.build.fingerprint \
              ro.bootimage.build.fingerprint ro.vendor_dlkm.build.fingerprint \
              ro.odm_dlkm.build.fingerprint ro.system_dlkm.build.fingerprint; do
        cur=$(getprop "$fp" 2>/dev/null)
        [ -n "$cur" ] || continue
        new=$(echo "$cur" | sed -E 's#:(user|userdebug|eng)/(release-keys|test-keys|dev-keys)$#:user/release-keys#')
        [ "$new" != "$cur" ] && rp_reset_if_present "$fp" "$new"
    done
    d_cur=$(getprop ro.build.description 2>/dev/null)
    if [ -n "$d_cur" ]; then
        d_new=$(echo "$d_cur" | sed -E 's#-userdebug #-user #; s#-eng #-user #; s# (test-keys|dev-keys)$# release-keys#')
        [ "$d_new" != "$d_cur" ] && rp_reset_if_present ro.build.description "$d_new"
    fi
    f_cur=$(getprop ro.build.flavor 2>/dev/null)
    if [ -n "$f_cur" ]; then
        f_new=$(echo "$f_cur" | sed -E 's#-(userdebug|eng)$#-user#')
        [ "$f_new" != "$f_cur" ] && rp_reset_if_present ro.build.flavor "$f_new"
    fi

    case "$(getprop ro.bootmode 2>/dev/null)" in
        *recovery*) $RESETPROP -n ro.bootmode unknown 2>/dev/null && log "prop ro.bootmode -> unknown" ;;
    esac
    [ -n "$(getprop ro.kernel.qemu 2>/dev/null)" ] \
        && $RESETPROP -n ro.kernel.qemu "" 2>/dev/null && log "prop ro.kernel.qemu cleared"

    rp_del ro.boot.verifiedbooterror
    # DELETE on SDK >= 36, rewrite to 0 below it -- and the delete is the correct
    # stock state on Android 16, not an oversight. This has been re-raised as a
    # "gap" twice on the assumption that stock answers 0; measured on a live OP15
    # (SDK 36) it does not answer at all:
    #   * sys.oem_unlock_allowed has NO entry in any property_contexts under
    #     /system/etc/selinux or /vendor/etc/selinux -- the property has no
    #     defined SELinux label on this platform;
    #   * nothing under /system/etc/init or /vendor/etc/init references it, so
    #     no stock boot path ever sets it;
    #   * ro.oem_unlock_supported=1 and `settings get global oem_unlock_disabled`
    #     returns null, i.e. the state lives in settings, not in a property.
    # So on SDK >= 36 "absent" IS stock, and writing 0 would be the divergence a
    # detector could read. Pre-36 platforms do define and set it, hence the
    # conditional rewrite on the other arm. props_status() mirrors both arms:
    # present counts as dirty here, present-and-differs counts as dirty there.
    if [ "$(getprop ro.build.version.sdk 2>/dev/null)" -ge 36 ] 2>/dev/null; then
        rp_del sys.oem_unlock_allowed
    else
        rp_reset_if_present sys.oem_unlock_allowed 0
    fi
}

# ---- /data/local/tmp — restore the AOSP owner/mode/context ------------------
# ksud (and anything else that stages files there) commonly leaves it 0777 and/or
# root/root; AOSP ships 0771 shell:shell u:object_r:shell_data_file:s0. The drift
# is a first-class detector probe. Restorative only: each field is touched solely
# when it already differs, so a clean device is a no-op.
SHELL_TMP=/data/local/tmp

# `stat -c %C` answers correctly from an interactive root shell but comes back as
# the bare letter "C" in the post-fs-data / ksud service context this actually runs
# in, so the label always compared unequal: every boot re-ran chcon and logged a
# change that had not happened, and the WebUI read /data/local/tmp as permanently
# "dirty ctx=C". Take the reading only when it looks like a context, and fall back
# to `ls -Zd`; an empty answer means "could not read", which is not "wrong".
selinux_ctx() {
    local c
    c=$(stat -c %C "$1" 2>/dev/null)
    case "$c" in *:*:*) echo "$c"; return 0 ;; esac
    c=$(ls -Zd "$1" 2>/dev/null | awk '{print $1}')
    case "$c" in *:*:*) echo "$c"; return 0 ;; esac
    echo ""
}

do_shell_tmp() {
    [ "${fix_shell_tmp:-1}" = "1" ] || return 0
    local mode own ctx changed=""

    if [ ! -d "$SHELL_TMP" ]; then
        mkdir -p "$SHELL_TMP" 2>/dev/null \
            || { log "shell-tmp: $SHELL_TMP absent and not creatable"; return 0; }
        changed="created"
    fi

    mode=$(stat -c %a "$SHELL_TMP" 2>/dev/null)
    own=$(stat -c %u:%g "$SHELL_TMP" 2>/dev/null)
    ctx=$(selinux_ctx "$SHELL_TMP")

    if [ "$mode" != "771" ]; then
        chmod 0771 "$SHELL_TMP" 2>/dev/null && changed="$changed mode:${mode:-?}->771"
    fi
    if [ "$own" != "2000:2000" ]; then
        chown 2000:2000 "$SHELL_TMP" 2>/dev/null && changed="$changed owner:${own:-?}->2000:2000"
    fi
    if [ -n "$ctx" ] && [ "$ctx" != "u:object_r:shell_data_file:s0" ]; then
        chcon u:object_r:shell_data_file:s0 "$SHELL_TMP" 2>/dev/null \
            && changed="$changed ctx:$ctx->shell_data_file"
    fi

    [ -n "$changed" ] && log "shell-tmp: ${changed# }"
    return 0
}

# Report-only, for `check`/the UI: "clean" or the fields that still differ. The
# inode is informational — lowering a real inode is the separate hijacker module,
# not something a chmod can fix.
shell_tmp_status() {
    local mode own ctx bad=""
    [ -d "$SHELL_TMP" ] || { echo "absent"; return 0; }
    mode=$(stat -c %a "$SHELL_TMP" 2>/dev/null)
    own=$(stat -c %u:%g "$SHELL_TMP" 2>/dev/null)
    ctx=$(selinux_ctx "$SHELL_TMP")
    [ "$mode" = "771" ] || bad="$bad mode=$mode"
    [ "$own" = "2000:2000" ] || bad="$bad owner=$own"
    [ -n "$ctx" ] && [ "$ctx" != "u:object_r:shell_data_file:s0" ] && bad="$bad ctx=$ctx"
    [ -z "$bad" ] && echo "clean ino=$(stat -c %i "$SHELL_TMP" 2>/dev/null)" \
                  || echo "dirty$bad ino=$(stat -c %i "$SHELL_TMP" 2>/dev/null)"
}

# ---- kernel knob interface --------------------------------------------------
# Current kernels carry the boot-identity knobs on the netlink control plane
# (CAP_NET_ADMIN-gated, not enumerable). Older ones exposed a /sys/kernel
# directory whose name AND attribute names any app could read. Prefer netlink,
# fall back to either legacy sysfs layout so kernel and module can be flashed
# out of step.
nm_sysd() {
    local d
    for d in /sys/kernel/boot_meta /sys/kernel/nomount; do
        [ -d "$d" ] && { echo "$d"; return 0; }
    done
    return 1
}
nm_bin() {
    local b
    [ -n "$NM_BIN" ] && [ -x "$NM_BIN" ] && { echo "$NM_BIN"; return 0; }
    for b in /data/adb/modules/meta-nomount/bin/*/nm; do
        [ -x "$b" ] && { echo "$b"; return 0; }
    done
    return 1
}
# nm_knob <r|v|c|b> <value>
nm_knob() {
    local b d a
    b=$(nm_bin) && "$b" k "$1" "$2" 2>/dev/null && return 0
    d=$(nm_sysd) || return 1
    case "$1" in
        r) a=release;    [ -e "$d/$a" ] || a=uname_release ;;
        v) a=version;    [ -e "$d/$a" ] || a=uname_version ;;
        c) a=cmdline ;;
        b) a=bootconfig ;;
        *) return 1 ;;
    esac
    [ -w "$d/$a" ] || return 1
    printf '%s' "$2" > "$d/$a" 2>/dev/null
}
nm_knob_ok() { nm_bin >/dev/null 2>&1 || nm_sysd >/dev/null 2>&1; }

# ---- uname override via the kernel knob dir (blank = keep) ------------------
do_uname() {
    [ "${spoof_uname:-0}" = "1" ] || return 0
    if ! nm_knob_ok; then
        log "uname: kernel interface absent (needs the nomount uname build)"
        return 0
    fi

    if [ -n "$uname_tail" ]; then
        local tail prefix rel
        tail=$(printf '%s' "$uname_tail" | sed -E 's/^[0-9][0-9.]*-android[0-9]+-//')
        prefix=$(uname -r | grep -oE '^[0-9][0-9.]*-android[0-9]+-')
        rel="${prefix}${tail}"
        nm_knob r "$rel" && log "uname release=$rel"
    fi

    if [ -n "$uname_date" ]; then
        local d head ver
        d=$(printf '%s' "$uname_date" | grep -oE '(Mon|Tue|Wed|Thu|Fri|Sat|Sun) .*$')
        [ -z "$d" ] && d=$uname_date
        head=$(uname -v | sed -E 's/^(#[0-9]+ SMP( [A-Z_]*PREEMPT[A-Z_]*)?).*/\1/')
        ver="$head $d"
        nm_knob v "$ver" && log "uname version=$ver"
    fi
}

# ---- /proc/cmdline + /proc/bootconfig spoof via the kernel knob dir ----------
# resetprop only moves the derived ro.boot.* props; the raw androidboot.* in
# /proc/cmdline (and /proc/bootconfig on GKI) still carry the real boot state, so
# a detector reading them sees the opposite of the props. The kernel serves a
# sanitized copy once we write it to these knobs (absent knob = feature not built,
# so this is a graceful no-op). The digest is taken from the prop do_vbmeta/do_props
# already set, so cmdline/bootconfig agree with the props.
do_cmdline() {
    # Rides on Boot-state props: follows spoof_props unless spoof_cmdline is set
    # explicitly in spoof.conf. Reuses the digest do_props set; the two must tell the
    # same story, so it also requires spoof_props (skips loudly otherwise).
    [ "${spoof_cmdline:-$spoof_props}" = "1" ] || return 0
    if [ "${spoof_props:-0}" != "1" ]; then
        log "cmdline: skipped (needs spoof_props=1 to stay consistent)"
        return 0
    fi
    # do_props already ran (main order). If the boot-state prop is not actually
    # green — resetprop missing, or a prop that could not be set — spoofing the
    # cmdline/bootconfig green would flip the inconsistency the other way (green
    # cmdline vs orange props). Confirm props landed before touching procfs.
    if [ "$(getprop ro.boot.verifiedbootstate 2>/dev/null)" != "green" ]; then
        log "cmdline: skipped (props not normalized to green; check resetprop)"
        return 0
    fi
    local dg
    dg=$(getprop ro.boot.vbmeta.digest 2>/dev/null)

    # /proc/cmdline: androidboot.key=value, space-separated
    if nm_knob_ok && [ -r /proc/cmdline ]; then
        local c
        # Prefix-agnostic: OnePlus/OEM boot state rides oplusboot.* (and others use
        # their own prefix), not just androidboot.*, in /proc/cmdline. Capture the
        # prefix and reuse it so the token keeps its original name.
        c=$(sed -E 's/([a-z]*boot\.verifiedbootstate)=[^ ]*/\1=green/g;
                    s/([a-z]*boot\.vbmeta\.device_state)=[^ ]*/\1=locked/g;
                    s/([a-z]*boot\.flash\.locked)=[^ ]*/\1=1/g;
                    s/([a-z]*boot\.warranty_bit)=[^ ]*/\1=0/g;
                    s/([a-z]*boot\.veritymode)=[^ ]*/\1=enforcing/g;
                    s/ [a-z]*boot\.verifiedbooterror=[^ ]*//g' /proc/cmdline)
        [ -n "$dg" ] && c=$(printf '%s' "$c" | sed -E "s/([a-z]*boot\.vbmeta\.digest)=[^ ]*/\1=$dg/g")
        nm_knob c "$c" && log "cmdline sanitized (green/locked)"
    fi

    # /proc/bootconfig: androidboot.key = "value" (GKI 5.10+); knob absent otherwise
    if nm_knob_ok && [ -r /proc/bootconfig ]; then
        local b
        # Prefix-agnostic like the cmdline branch: bootconfig is androidboot.* on GKI,
        # but keep symmetry so an OEM that namespaces it differently is still covered.
        b=$(sed -E '/[a-z]*boot\.verifiedbooterror[[:space:]]*=/d;
                    s/([a-z]*boot\.verifiedbootstate[[:space:]]*=[[:space:]]*")[^"]*/\1green/g;
                    s/([a-z]*boot\.vbmeta\.device_state[[:space:]]*=[[:space:]]*")[^"]*/\1locked/g;
                    s/([a-z]*boot\.flash\.locked[[:space:]]*=[[:space:]]*")[^"]*/\11/g;
                    s/([a-z]*boot\.warranty_bit[[:space:]]*=[[:space:]]*")[^"]*/\10/g;
                    s/([a-z]*boot\.veritymode[[:space:]]*=[[:space:]]*")[^"]*/\1enforcing/g' /proc/bootconfig)
        [ -n "$dg" ] && b=$(printf '%s' "$b" | sed -E "s/([a-z]*boot\.vbmeta\.digest[[:space:]]*=[[:space:]]*\")[^\"]*/\1$dg/g")
        nm_knob b "$b" && log "bootconfig sanitized (green/locked)"
    fi
}

# ===========================================================================
# dry-run for the UI: how many target props are present-and-wrong (i.e. would be
# changed by do_props)? Writes nothing. "clean" = nothing to fix. Same present-
# and-differs rule do_props uses, so absent OEM-specific props never count.
props_status() {
    local n=0 c _p _c
    _d() { c=$(getprop "$1" 2>/dev/null); [ -n "$c" ] && [ "$c" != "$2" ] && n=$((n + 1)); }
    _d ro.boot.vbmeta.device_state    locked
    _d ro.boot.verifiedbootstate      green
    _d ro.boot.flash.locked           1
    _d ro.boot.veritymode             enforcing
    _d ro.boot.warranty_bit           0
    _d ro.warranty_bit                0
    _d ro.vendor.boot.warranty_bit    0
    _d ro.vendor.warranty_bit         0
    _d vendor.boot.vbmeta.device_state locked
    _d vendor.boot.verifiedbootstate  green
    _d ro.debuggable                  0
    _d ro.force.debuggable            0
    _d ro.secure                      1
    _d ro.adb.secure                  1
    _d ro.build.type                  user
    _d ro.build.tags                  release-keys
    _d ro.crypto.state                encrypted
    _d ro.secureboot.lockstate        locked
    _d ro.boot.realmebootstate        green
    _d ro.boot.realme.lockstate       1
    [ -n "$(getprop ro.boot.verifiedbooterror 2>/dev/null)" ] && n=$((n + 1))
    case "$(getprop ro.bootmode 2>/dev/null)" in *recovery*) n=$((n + 1)) ;; esac
    [ -n "$(getprop ro.kernel.qemu 2>/dev/null)" ] && n=$((n + 1))
    # Both arms, because do_props has both: it DELETES this prop on SDK >= 36 and
    # REWRITES it to 0 below that. Counting only the delete case meant Android 15
    # and older were told "✓ all props already clean — nothing to fix" while Apply
    # still changed a prop — the UI disagreeing with the button next to it.
    if [ "$(getprop ro.build.version.sdk 2>/dev/null)" -ge 36 ] 2>/dev/null; then
        [ -n "$(getprop sys.oem_unlock_allowed 2>/dev/null)" ] && n=$((n + 1))
    else
        _d sys.oem_unlock_allowed 0
    fi
    # The harmonization pass do_props also runs -- the :type/keys tail on every
    # fingerprint, description and flavor. Without these the UI reported "clean"
    # while Apply still rewrote more props.
    for _p in ro.build.fingerprint ro.system.build.fingerprint ro.vendor.build.fingerprint \
              ro.product.build.fingerprint ro.odm.build.fingerprint ro.system_ext.build.fingerprint \
              ro.bootimage.build.fingerprint ro.vendor_dlkm.build.fingerprint \
              ro.odm_dlkm.build.fingerprint ro.system_dlkm.build.fingerprint; do
        _c=$(getprop "$_p" 2>/dev/null)
        [ -n "$_c" ] || continue
        [ "$(echo "$_c" | sed -E 's#:(user|userdebug|eng)/(release-keys|test-keys|dev-keys)$#:user/release-keys#')" != "$_c" ] \
            && n=$((n + 1))
    done
    _c=$(getprop ro.build.description 2>/dev/null)
    [ -n "$_c" ] && [ "$(echo "$_c" | sed -E 's#-userdebug #-user #; s#-eng #-user #; s# (test-keys|dev-keys)$# release-keys#')" != "$_c" ] \
        && n=$((n + 1))
    _c=$(getprop ro.build.flavor 2>/dev/null)
    [ -n "$_c" ] && [ "$(echo "$_c" | sed -E 's#-(userdebug|eng)$#-user#')" != "$_c" ] \
        && n=$((n + 1))
    [ "$n" = 0 ] && echo clean || echo "dirty $n"
}

# Capture the pristine kernel uname once per boot (before any override), so the
# WebUI "Reset to kernel default" can restore it without a reboot. boot-id guarded.
capture_uname_orig() {
    local cache=$NMDIR/uname_orig bid
    bid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
    [ -n "$bid" ] || return 0
    if [ ! -f "$cache" ] || [ "$(sed -n 1p "$cache" 2>/dev/null)" != "$bid" ]; then
        { echo "$bid"; uname -r; uname -v; } > "$cache" 2>/dev/null
    fi
}

main() {
    find_resetprop || log "resetprop not found (prop spoofing skipped)"
    capture_uname_orig
    do_vbmeta "$vbmeta_digest"
    do_props
    do_uname
    do_cmdline
    do_shell_tmp
}

# `verify` / `compute` inspect without changing anything, so the UI can show
# whether the current prop already matches the real chain before Apply is used.
#   compute -> the freshly computed digest, or empty on failure
#   verify  -> "match <d>" | "mismatch <d>" | "absent <d>" | "error"
# A test harness sources this to unit-test the AVB parser functions without
# running the pass or touching props. Return early when sourced with the flag.
[ -n "${NM_SPOOF_SOURCE:-}" ] && return 0 2>/dev/null

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
    props)
        props_status
        exit 0 ;;
    shell-tmp)
        do_shell_tmp
        exit 0 ;;
    shell-tmp-status)
        shell_tmp_status
        exit 0 ;;
    reset-uname)
        orig=$NMDIR/uname_orig
        [ -s "$orig" ] || { echo "no-baseline"; exit 0; }
        rel=$(sed -n 2p "$orig"); ver=$(sed -n 3p "$orig")
        [ -n "$rel" ] && nm_knob r "$rel"
        [ -n "$ver" ] && nm_knob v "$ver"
        # grep exits 1 when it selects NO lines -- a conf holding only these two
        # keys. That is a successful filter, not a failure; the old `if` skipped the
        # reset and left a stray spoof.conf.t behind.
        if grep -v -E '^(uname_tail|uname_date)=' "$CONF" > "$CONF.t" 2>/dev/null || [ -f "$CONF.t" ]; then
            printf "uname_tail=''\nuname_date=''\n" >> "$CONF.t" && mv -f "$CONF.t" "$CONF"
        fi
        rm -f "$CONF.t" 2>/dev/null
        echo "reset"
        exit 0 ;;
esac

main
exit 0
