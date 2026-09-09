#!/system/bin/sh
CACHE=/data/adb/nomount/uidscan_cache
MODDIR="${0%/*}"
mkdir -p /data/adb/nomount && chmod 0700 /data/adb/nomount

ABI=$(getprop ro.product.cpu.abi)
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"

if [ -x "$BIN" ]; then
    INV=$("$BIN" uid preset --dry-run detectors 2>/dev/null | grep -v '^$' | grep -v 'entr(ies)')
else
    INV=""
fi
if [ -z "$INV" ]; then
    echo "nomount scan: no detector inventory (no executable at $BIN) - name matching is OFF, manifest signals only" >&2
fi

J=$(( $(nproc 2>/dev/null || echo 4) * 2 ))
[ "$J" -gt 24 ] && J=24
[ "$J" -lt 4 ] && J=4

export INV
PKGS=$(pm list packages -3 -f 2>/dev/null | sed 's/^package://')
if [ -z "$PKGS" ]; then
    echo "nomount scan: pm listed no packages; keeping the previous cache" >&2
    cat "$CACHE" 2>/dev/null
    exit 0
fi

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
        man=$(timeout 2 unzip -p "$apk" AndroidManifest.xml 2>/dev/null | tr -d "\000")
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
