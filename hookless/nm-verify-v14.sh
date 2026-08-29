#!/system/bin/sh
# NoMount v14 post-flash verifier.
# Proves the two fixes that need a kernel to test: A1 (rule replacement leaves
# the parent child node half-updated) and A3 (batch add swallows rejections).
# Safe: rules live in kernel memory only and are rebuilt at boot, so anything
# this adds is removed again below and would vanish on reboot regardless.
NM=/data/adb/modules/meta-nomount/bin/arm64-v8a/nm
[ -x "$NM" ] || { echo "FATAL: nm client not found at $NM"; exit 1; }

VER=$("$NM" v 2>/dev/null)
echo "engine version : ${VER:-<no answer>}"
[ "$VER" = "14" ] || echo "  NOTE: expected 14. On 13 the two tests below SHOULD fail - that is the bug."
B=$("$NM" l | wc -l); echo "rules before   : $B"
echo ""

fail=0
T=/data/local/tmp/nmv14
rm -rf "$T"; mkdir -p "$T/dirA" "$T/dirB" "$T/srcB"
echo hi > "$T/srcA"; echo w > "$T/srcB/inner"

# ---- A1 -------------------------------------------------------------------
"$NM" a "$T/dirA/x" "$T/srcB" >/dev/null 2>&1
ctl=$(stat -c %h "$T/dirA")
"$NM" d "$T/dirA/x" >/dev/null 2>&1

"$NM" a "$T/dirB/x" "$T/srcA" >/dev/null 2>&1
"$NM" a "$T/dirB/x" "$T/srcB" >/dev/null 2>&1
case_t=$(stat -c %F "$T/dirB/x"); case_n=$(stat -c %h "$T/dirB")
"$NM" d "$T/dirB/x" >/dev/null 2>&1

mkdir -p "$T/real/sub"; real=$(stat -c %h "$T/real")

echo "A1  rule replacement refreshes d_type"
echo "      control (fresh dir rule)   nlink=$ctl      expect 3"
echo "      control (real on-disk dir) nlink=$real      expect 3"
echo "      CASE    (file->dir shadow) nlink=$case_n type=$case_t  expect 3 / directory"
if [ "$case_n" = "3" ] && [ "$case_t" = "directory" ] && [ "$ctl" = "3" ] && [ "$real" = "3" ]; then
    echo "      RESULT: PASS"
else
    echo "      RESULT: FAIL  (nlink $case_n != 3 means the child node is still stale)"; fail=1
fi
echo ""

# ---- A3 -------------------------------------------------------------------
mkdir -p "$T/g"
"$NM" a "$T/g/ghost" "$T/DOES_NOT_EXIST" >/dev/null 2>&1
rc=$?
live=$("$NM" l | grep -c "$T/g/ghost")
echo "A3  a rejected rule reaches the caller"
echo "      nm exit code=$rc  rules created=$live   expect non-zero / 0"
if [ "$rc" != "0" ] && [ "$live" = "0" ]; then
    echo "      RESULT: PASS"
else
    echo "      RESULT: FAIL  (exit 0 means the rejection is still swallowed)"; fail=1
fi
echo ""

rm -rf "$T"
A=$("$NM" l | wc -l)
echo "rules after    : $A"
[ "$A" = "$B" ] || { echo "WARNING: rule count changed ($B -> $A) - inspect with: $NM l"; fail=1; }
echo ""
[ "$fail" = "0" ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED (see above)"
exit $fail
