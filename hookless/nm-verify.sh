#!/system/bin/sh
NM=/data/adb/modules/meta-nomount/bin/arm64-v8a/nm
[ -x "$NM" ] || { echo "fatal: nm client not found at $NM"; exit 1; }

MIN_VER=14
VER=$("$NM" v 2>/dev/null)
echo "engine version : ${VER:-<no answer>}"
case "$VER" in
    ''|*[!0-9]*)
        echo "fatal: the engine did not answer a version - is this a CONFIG_NOMOUNT kernel?"
        exit 1 ;;
esac
[ "$VER" -ge "$MIN_VER" ] || echo "  NOTE: engine is older than v$MIN_VER, so the two tests below should fail - that is the bug."
B=$("$NM" l | wc -l); echo "rules before   : $B"
echo ""

fail=0
T=/data/local/tmp/nm-verify
rm -rf "$T"; mkdir -p "$T/dirA" "$T/dirB" "$T/srcB"
echo hi > "$T/srcA"; echo w > "$T/srcB/inner"

"$NM" add "$T/dirA/x" "$T/srcB" >/dev/null 2>&1
ctl=$(stat -c %h "$T/dirA")
"$NM" del "$T/dirA/x" >/dev/null 2>&1

"$NM" add "$T/dirB/x" "$T/srcA" >/dev/null 2>&1
"$NM" add "$T/dirB/x" "$T/srcB" >/dev/null 2>&1
case_t=$(stat -c %F "$T/dirB/x"); case_n=$(stat -c %h "$T/dirB")
"$NM" del "$T/dirB/x" >/dev/null 2>&1

mkdir -p "$T/real/sub"; real=$(stat -c %h "$T/real")

echo "A1  rule replacement refreshes d_type"
echo "      control (fresh dir rule)   nlink=$ctl      expect 3"
echo "      control (real on-disk dir) nlink=$real      expect 3"
echo "      case    (file->dir shadow) nlink=$case_n type=$case_t  expect 3 / directory"
if [ "$case_n" = "3" ] && [ "$case_t" = "directory" ] && [ "$ctl" = "3" ] && [ "$real" = "3" ]; then
    echo "      result: PASS"
else
    echo "      result: FAIL  (nlink $case_n != 3 means the child node is still stale)"; fail=1
fi
echo ""

mkdir -p "$T/g"
"$NM" add "$T/g/ghost" "$T/DOES_NOT_EXIST" >/dev/null 2>&1
rc=$?
live=$("$NM" l | grep -c "$T/g/ghost")
echo "A3  a rejected rule reaches the caller"
echo "      nm exit code=$rc  rules created=$live   expect non-zero / 0"
if [ "$rc" != "0" ] && [ "$live" = "0" ]; then
    echo "      result: PASS"
else
    echo "      result: FAIL  (exit 0 means the rejection is still swallowed)"; fail=1
fi
echo ""

rm -rf "$T"
A=$("$NM" l | wc -l)
echo "rules after    : $A"
[ "$A" = "$B" ] || { echo "WARNING: rule count changed ($B -> $A) - inspect with: $NM l"; fail=1; }
echo ""
[ "$fail" = "0" ] && echo "all checks PASSED" || echo "some checks FAILED (see above)"
exit $fail
