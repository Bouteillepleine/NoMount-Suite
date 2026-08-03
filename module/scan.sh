#!/system/bin/sh
# Scan installed 3rd-party apps for Xposed/LSPosed modules; cache the result.
#
# Speed/robustness: the manifest probe runs in parallel (bounded to 8 at a time)
# with a per-APK `timeout`, so a large or wedged APK can never hang the whole
# scan. The result is cached to $CACHE so the WebUI can read it instantly
# instead of re-scanning on every open. Pass --cached to just print the cache.
#
# tr -d '\000' collapses the binary manifest's UTF-16 string pool to ASCII so the
# grep matches ("xposedmodule" is stored as x\0p\0o\0s\0... otherwise).

CACHE=/data/adb/nomount/xposed_cache
mkdir -p /data/adb/nomount

if [ "$1" = "--cached" ]; then
    cat "$CACHE" 2>/dev/null
    exit 0
fi

TMP="${CACHE}.tmp.$$"
LIST="${CACHE}.list.$$"
: > "$TMP"
pm list packages -3 -f 2>/dev/null | sed 's/^package://' > "$LIST"

probe() {
    apk="${1%=*}"; pkg="${1##*=}"
    [ -f "$apk" ] || return 0
    if timeout 3 unzip -p "$apk" AndroidManifest.xml 2>/dev/null | tr -d '\000' | grep -qa "xposedmodule"; then
        echo "$pkg" >> "$TMP"
    fi
}

n=0
while IFS= read -r line; do
    [ -z "$line" ] && continue
    probe "$line" &
    n=$((n + 1))
    [ $((n % 8)) -eq 0 ] && wait
done < "$LIST"
wait

sort -u "$TMP" > "$CACHE" 2>/dev/null
rm -f "$TMP" "$LIST"
cat "$CACHE"
