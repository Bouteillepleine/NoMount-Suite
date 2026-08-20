#!/system/bin/sh
# Scan installed 3rd-party apps for ones worth hiding injections from, and say WHY.
# Emits "pkg<TAB>reason[,reason]"; cached to $CACHE. --cached prints the cache.
#
# Adding a whole preset to the hide list buries the handful of apps that are
# actually on THIS device under dozens of entries for apps that are not. A scan
# proposes only what is installed, the same shape as scan.sh + the Cloak picker.
#
# Reasons, strongest first:
#   detector     name matches the known-detector inventory (exact or glob)
#   queries-root manifest names a root manager in <queries> — it is looking for us
#   su-perm      requests ACCESS_SUPERUSER
#   queries-all  requests QUERY_ALL_PACKAGES — annotation only, never on its own
#
# The inventory comes from `nomount uid preset --dry-run`, so the package list has
# exactly one home (src/presets.rs) and the globs work verbatim as shell `case`
# patterns. tr -d '\000' collapses the manifest's UTF-16 string pool so grep matches.
CACHE=/data/adb/nomount/uidscan_cache
MODDIR="${0%/*}"
mkdir -p /data/adb/nomount && chmod 0700 /data/adb/nomount

if [ "$1" = "--cached" ]; then
    cat "$CACHE" 2>/dev/null
    exit 0
fi

ABI=$(getprop ro.product.cpu.abi)
BIN="$MODDIR/bin/$ABI/nomount"

# One source of truth for the inventory; empty if the binary is missing, in which
# case the manifest signals below still stand on their own.
INV=$("$BIN" uid preset --dry-run detectors 2>/dev/null | grep -v '^$' | grep -v 'entr(ies)')

# Manifest probe is I/O-bound -> ~2x cores, capped.
J=$(( $(nproc 2>/dev/null || echo 4) * 2 ))
[ "$J" -gt 24 ] && J=24
[ "$J" -lt 4 ] && J=4

export INV
pm list packages -3 -f 2>/dev/null | sed 's/^package://' | xargs -P "$J" -n1 sh -c '
    apk="${1%=*}"; pkg="${1##*=}"
    [ -n "$pkg" ] || exit 0
    reasons=""

    # Name match first: no APK read needed, and globs from the inventory are
    # already in shell `case` syntax.
    #
    # set -f is load-bearing: $INV must word-split (so it cannot be quoted) but its
    # entries are globs, and without noglob the shell PATHNAME-EXPANDS them against
    # the cwd first. A file named e.g. "x.duckdetector" in whatever directory the
    # caller happens to be in silently replaces the rule "*.duckdetector" with that
    # filename, and the rule stops matching anything -- a scan that looks like it
    # ran fine and quietly checks nothing. `case` patterns are unaffected by -f.
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
        # Never a reason on its own -- ~50 of 64 apps on a normal device request it,
        # from app stores to launchers, so a list led by it is noise rather than a
        # shortlist. It is kept only as an annotation on an app that already
        # qualified for another reason.
        if [ -n "$reasons" ]; then
            case "$man" in
                *QUERY_ALL_PACKAGES*) reasons="$reasons,queries-all" ;;
            esac
        fi
    fi

    [ -n "$reasons" ] && printf "%s\t%s\n" "$pkg" "$reasons"
' _ | sort -u > "$CACHE"

cat "$CACHE"
