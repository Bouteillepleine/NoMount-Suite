#!/system/bin/sh
MODDIR="${0%/*}"
NMLOG_TAG=uidscan
# shellcheck source=module/lib.sh
. "$MODDIR/lib.sh" 2>/dev/null || {
    echo "nomount: lib.sh missing or unreadable at $MODDIR - the hide-list scan cannot run; re-flash the zip" > /dev/kmsg 2>/dev/null
    exit 1
}
CACHE="$NMDIR/uidscan_cache"
mkdir -p "$NMDIR" && chmod 0700 "$NMDIR"

nm_set_bin

if [ -x "$BIN" ]; then
    INV=$("$BIN" uid preset --dry-run detectors 2>/dev/null | grep -v '^$' | grep -v 'entr(ies)')
else
    INV=""
fi
if [ -z "$INV" ]; then
    echo "nomount scan: no detector inventory (no executable at $BIN) - name matching is OFF, manifest signals only" >&2
    nmlog "⚠ scan ran with NO detector inventory (no executable at $BIN) - name matching was off"
fi

if command -v timeout >/dev/null 2>&1; then NM_TO="timeout 2"; else NM_TO=""; fi
export NM_TO

_J=$(nproc 2>/dev/null)
case "$_J" in ''|*[!0-9]*) _J=4 ;; esac
J=$((_J * 2))
unset _J
[ "$J" -gt 24 ] && J=24
[ "$J" -lt 4 ] && J=4

export INV
PKGS=$(pm list packages -3 -f 2>/dev/null | sed 's/^package://')
if [ -z "$PKGS" ]; then
    echo "nomount scan: pm listed no packages; keeping the previous cache" >&2
    nmlog "scan: pm listed no packages - kept the previous cache rather than publishing an empty one"
    cat "$CACHE" 2>/dev/null
    exit 0
fi

# shellcheck disable=SC2016  # single quotes are the point: this is the body of
printf '%s\n' "$PKGS" | tr '\n' '\0' | xargs -0 -P "$J" -n1 sh -c '
    apk="${1%=*}"; pkg="${1##*=}"
    [ -n "$pkg" ] || exit 0
    reasons=""

    set -f
    for rule in $INV; do
        case "$pkg" in
            $rule) reasons="detector"; break ;;
        esac
    done
    set +f

    if [ -f "$apk" ]; then
        # shellcheck disable=SC2086  # $NM_TO is a command prefix ("timeout 2" or
        man=$($NM_TO unzip -p "$apk" AndroidManifest.xml 2>/dev/null | tr -d "\000")
        case "$man" in
            *topjohnwu.magisk*|*me.weishu.kernelsu*|*eu.chainfire.supersu*|\
            *com.topjohnwu.*|*io.github.huskydg.magisk*|*me.bmax.apatch*|\
            *com.rifsxd.ksunext*|*zako.zako.zako*)
                reasons="${reasons:+$reasons,}queries-root" ;;
        esac
        case "$man" in
            *ACCESS_SUPERUSER*) reasons="${reasons:+$reasons,}su-perm" ;;
        esac
        if [ -n "$reasons" ]; then
            case "$man" in
                *QUERY_ALL_PACKAGES*) reasons="$reasons,queries-all" ;;
            esac
        fi
    fi

    [ -n "$reasons" ] && printf "%s\t%s\n" "$pkg" "$reasons"
' _ | sort -u > "$CACHE.tmp" && mv -f "$CACHE.tmp" "$CACHE"

cat "$CACHE"
