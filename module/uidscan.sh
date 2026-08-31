#!/system/bin/sh
# Scan installed 3rd-party apps for ones worth hiding injections from, and say WHY.
# Emits "pkg<TAB>reason[,reason]"; cached to $CACHE.
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

ABI=$(getprop ro.product.cpu.abi)
# The SAME fallback metamount.sh, post-fs-data.sh, post-mount.sh, service.sh and
# uidwatch.sh all carry, and the one script that was missing it. An empty ABI
# builds "$MODDIR/bin//nomount", which can never be executable -- and the only
# consumer below swallows that with 2>/dev/null, so the detector inventory came
# back EMPTY and the scan silently degraded to the manifest heuristics alone. A
# scan that has quietly stopped checking the thing it is named for looks exactly
# like a scan that found nothing.
[ -n "$ABI" ] || ABI=$(getprop ro.product.cpu.abilist 2>/dev/null | cut -d, -f1)
[ -n "$ABI" ] || ABI=arm64-v8a
BIN="$MODDIR/bin/$ABI/nomount"

# One source of truth for the inventory; empty if the binary is missing, in which
# case the manifest signals below still stand on their own -- but SAY SO, because
# "no package matched the detector inventory" and "there was no inventory to
# match against" are different answers and only one of them is a scan result.
if [ -x "$BIN" ]; then
    INV=$("$BIN" uid preset --dry-run detectors 2>/dev/null | grep -v '^$' | grep -v 'entr(ies)')
else
    INV=""
fi
if [ -z "$INV" ]; then
    echo "nomount scan: no detector inventory (no executable at $BIN) -- name matching is OFF, manifest signals only" >&2
fi

# `timeout` is toybox's and is not guaranteed present, and without it a bare
# `timeout 2 unzip ...` does not run the command unbounded -- it does not run it
# at all, so every manifest signal silently disappears and the scan reports a
# shorter candidate list than it found. The probe runs inside `xargs sh -c`, where
# a shell FUNCTION cannot follow, so the bound travels as a command PREFIX in the
# environment instead: bounded where timeout exists, unbounded on one zip entry
# where it does not, never skipped.
if command -v timeout >/dev/null 2>&1; then NM_TO="timeout 2"; else NM_TO=""; fi
export NM_TO

# Manifest probe is I/O-bound -> ~2x cores, capped.
J=$(( $(nproc 2>/dev/null || echo 4) * 2 ))
[ "$J" -gt 24 ] && J=24
[ "$J" -lt 4 ] && J=4

export INV
# Publish a scan only when `pm` actually listed something. The redirect used to
# truncate $CACHE as the pipeline STARTED, so a `pm list` that came back empty --
# package service not up yet, or an interrupted scan -- replaced a good cache
# with an empty one. An empty list then reads as "nothing found" rather than
# "the scan failed", which is the wrong answer stated confidently. A genuinely
# empty RESULT still publishes: only an empty INPUT is treated as failure.
PKGS=$(pm list packages -3 -f 2>/dev/null | sed 's/^package://')
if [ -z "$PKGS" ]; then
    echo "nomount scan: pm listed no packages; keeping the previous cache" >&2
    cat "$CACHE" 2>/dev/null
    exit 0
fi

# NUL-delimited. Verified against toybox 0.8.12 on Android: unlike GNU xargs it
# does NOT do quote processing -- a single or double quote in a path passes
# through intact -- but it DOES split on whitespace, so a path containing a
# space becomes two arguments and the scan reads a truncated path plus a bogus
# one. -0 disables splitting entirely. Latent rather than live: 0 of 306
# third-party APK paths on an OP11 contain a space, quote or backslash, because
# the installer builds them from the package name plus base64 hashes.
# shellcheck disable=SC2016  # single quotes are the point: this is the BODY of
# the `sh -c` xargs runs per package, and $1/$INV must expand THERE, not here.
printf '%s\n' "$PKGS" | tr '\n' '\0' | xargs -0 -P "$J" -n1 sh -c '
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
        # shellcheck disable=SC2086  # $NM_TO is a COMMAND PREFIX ("timeout 2" or
        # empty) and must word-split; quoting it would exec a program named
        # "timeout 2", or an empty one.
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
' _ | sort -u > "$CACHE.tmp" && mv -f "$CACHE.tmp" "$CACHE"

cat "$CACHE"
