#!/system/bin/sh
# Scan installed 3rd-party apps for Xposed/LSPosed modules; cache to $CACHE.
# An xargs -P worker pool (no batch barrier) scaled to CPU count with a per-APK
# timeout keeps one slow/wedged APK from stalling the scan. --cached prints cache.
# tr -d '\000' collapses the manifest's UTF-16 string pool so grep matches.
CACHE=/data/adb/nomount/xposed_cache
mkdir -p /data/adb/nomount && chmod 0700 /data/adb/nomount

if [ "$1" = "--cached" ]; then
    cat "$CACHE" 2>/dev/null
    exit 0
fi

# Manifest probe is I/O-bound -> ~2x cores, capped.
J=$(( $(nproc 2>/dev/null || echo 4) * 2 ))
[ "$J" -gt 24 ] && J=24
[ "$J" -lt 4 ] && J=4

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

# NUL-delimited: plain `xargs` also applies QUOTE processing, so an APK path
# containing a quote is either mangled or aborts the whole scan with "unmatched
# quote" -- and a silently short scan here means the list is missing entries it
# should have offered. -0 disables both splitting and quoting.
printf '%s\n' "$PKGS" | tr '\n' '\0' | xargs -0 -P "$J" -n1 sh -c '
    apk="${1%=*}"; pkg="${1##*=}"
    [ -f "$apk" ] || exit 0
    timeout 2 unzip -p "$apk" AndroidManifest.xml 2>/dev/null | tr -d "\000" | grep -qa "xposedmodule" && echo "$pkg"
' _ | sort -u > "$CACHE.tmp" && mv -f "$CACHE.tmp" "$CACHE"

cat "$CACHE"
