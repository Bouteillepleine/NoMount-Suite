#!/bin/sh
# module/checkwatch.sh, the WebUI's check-on-request handler, against a copy whose MODDIR and
# NMDIR point into a scratch dir. Nothing else is stubbed but the engine binary.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
check() {
	if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf '  ok   %s\n' "$1"
	else fail=$((fail + 1)); printf '  FAIL %s\n       want=%s got=%s\n' "$1" "$3" "$2"; fi
}
NM="$WORK/nm"; MOD="$WORK/mod"
mkdir -p "$MOD/bin/arm64-v8a"
sed "s|^NMDIR=/data/adb/nomount$|NMDIR=$NM|" "$HERE/module/lib.sh" > "$MOD/lib.sh"
grep -q "^NMDIR=$NM$" "$MOD/lib.sh" || { echo "lib.sh no longer sets NMDIR on one line"; exit 1; }
# $1 = the owner the handler accepts. A host test cannot make a root-owned file.
handler() {
	sed -e "s|^MODDIR=/data/adb/modules/meta-nomount$|MODDIR=$MOD|" -e "s|\"0:0\"|\"$1\"|" \
		"$HERE/module/checkwatch.sh" > "$MOD/checkwatch.sh"
	grep -q "^MODDIR=$MOD$" "$MOD/checkwatch.sh" || { echo "checkwatch.sh no longer sets MODDIR on one line"; exit 1; }
}
me="$(id -u):$(id -g)"
fresh() { rm -rf "$NM"; mkdir -p "$NM/request"; : > "$NM/request/check"; }
run() { sh "$MOD/checkwatch.sh" n "$NM/request" "${1:-check}" >/dev/null 2>&1; }
declined() { cat "$NM/request/declined" 2>/dev/null || echo none; }
consumed() { [ -e "$NM/request/check" ] && echo left || echo consumed; }

echo "a request the handler refuses says why"
handler "0:0"
fresh; [ "$(id -u)" = 0 ] && chown 1:1 "$NM/request/check"
run
check "a request not owned by root is consumed" "$(consumed)" "consumed"
check "  and declined, naming why" "$(declined)" "the request was not root's"

handler "$me"
fresh; touch "$NM/disabled"; run
check "a parked Suite declines" "$(declined)" "the Suite is parked by the bootloop guard"
fresh; run
check "no engine binary declines" "$(declined)" "the engine binary is missing or not executable"

printf '#!/bin/sh\necho verdict=clean > "%s/health.txt"\n' "$NM" > "$MOD/bin/arm64-v8a/nomount"
chmod 755 "$MOD/bin/arm64-v8a/nomount"
fresh; run
check "a request it runs leaves no refusal behind" "$(declined)" "none"
check "  and runs the check" "$(cat "$NM/health.txt" 2>/dev/null)" "verdict=clean"
fresh; run declined
check "its own refusal file is not a request" "$(consumed)" "left"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
