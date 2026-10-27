#!/system/bin/sh
# Does a mapping pathhide hides stay hidden from pagemap and mincore too?
#
# Unlike lkm-load.sh next to it, this one does not run on the host: the
# guards are kprobes, so the only place they can be observed is a device
# with the module loaded and a kernel that has no NoMount built in.
#
# The numbers it is checking against are not invented. Measured on CPH2745,
# 6.12.69, with the IN-TREE build serving as the reference - a 4-page mapping
# of a file under /data/adb, against an identical control under
# /data/local/tmp:
#
#              control    subject
#   maps       1          0
#   mincore    ok         Out of memory      <- bionic's spelling of ENOMEM
#   pagemap    4          0
#   vmsize     8668928    8668912            <- 16 kB, the 4 hidden pages
#   statm      2167232    2167228            <- 4 pages
#
# The first three are what this LKM build reproduces. The last two are the
# accounting arm it does not have, so the subject's vmsize and statm will read
# the same as the control here, and the script says so rather than failing.
#
# The shipped rule set covers /data/adb/, so this maps two identical files -
# a control under /data/local/tmp and a subject under /data/adb - and asks
# each of the three readers what it sees. Needs root, the module loaded, and
# tests/pathhide-probe built for the device:
#
#   clang --target=aarch64-linux-android31 -O2 -static tests/pathhide-probe.c -o pathhide-probe
#
# Run as:  sh lkm-pathhide.sh /data/local/tmp/pathhide-probe

PROBE=${1:-/data/local/tmp/pathhide-probe}
NM=${NM:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nm}
CTL=/data/local/tmp/ph-control.bin
SUBJ=/data/adb/ph-subject.bin
fail=0

[ "$(id -u)" = 0 ] || { echo "fatal: needs root"; exit 1; }
[ -x "$PROBE" ] || { echo "fatal: no probe at $PROBE (see header)"; exit 1; }
lsmod | grep -q '^nomount' || { echo "fatal: nomount not loaded"; exit 1; }

dmesg | grep -oE 'pathhide guard[s]?[:a-z ]*\(.*|pathhide guard: cannot probe .*' | tail -3

if [ -x "$NM" ]; then
	[ -n "$("$NM" pathhide list 2>/dev/null)" ] || "$NM" pathhide sync >/dev/null 2>&1
	rules=$("$NM" pathhide list 2>/dev/null)
	[ -n "$rules" ] || { echo "SKIP: no pathhide rules programmed (engine has no knob?)"; exit 0; }
	echo "rules    : $(echo "$rules" | tr '\n' ' ')"
else
	echo "SKIP: no nm client at $NM, cannot confirm rules are programmed"
	exit 0
fi

cleanup() { rm -f "$CTL" "$SUBJ"; }
trap cleanup EXIT

dd if=/dev/urandom of="$CTL" bs=4096 count=4 2>/dev/null
cp "$CTL" "$SUBJ" || { echo "fatal: cannot write $SUBJ"; exit 1; }

field() { echo "$1" | sed -n "s/^$2  *//p"; }

ctl=$("$PROBE" "$CTL" ph-control.bin)
subj=$("$PROBE" "$SUBJ" ph-subject.bin)
echo "-- control (not covered by a rule) --"; echo "$ctl"
echo "-- subject (under /data/adb) --"; echo "$subj"

[ "$(field "$ctl" maps)" = 1 ] || { echo "FAIL control: probe cannot see its own mapping"; exit 1; }
[ "$(field "$ctl" mincore)" = ok ] || { echo "FAIL control: mincore already failing"; exit 1; }
[ "$(field "$ctl" pagemap)" -gt 0 ] || { echo "FAIL control: pagemap already empty"; exit 1; }
echo "ok   control visible to all three readers"

[ "$(field "$subj" maps)" = 0 ] \
	&& echo "ok   maps   : path gone" \
	|| { echo "FAIL maps   : path still rendered"; fail=1; }

case "$(field "$subj" mincore)" in
*"annot allocate memory"*|*"ut of memory"*)
	echo "ok   mincore: ENOMEM" ;;
*)
	echo "FAIL mincore: got '$(field "$subj" mincore)', wanted ENOMEM"; fail=1 ;;
esac

if [ "$(field "$subj" pagemap)" = 0 ]; then
	echo "ok   pagemap: every entry reads as a hole"
else
	echo "FAIL pagemap: $(field "$subj" pagemap) non-zero entries remain"; fail=1
fi

echo "KNOWN accounting: VmSize/VmPeak/statm still count the hidden mapping."
echo "      The module reports this itself as 'accounting unavailable'."
echo "      The accounting guard is not shipped in the LKM build - lkm/README.md"
echo "      says why. control statm=$(field "$ctl" statm) subject statm=$(field "$subj" statm)"

dmesg | tail -40 | grep -qiE 'BUG:|Call trace:|Unable to handle kernel' && {
	echo "FAIL kernel complained while the guards ran"; fail=1; }

[ "$fail" = 0 ] && echo "PASS" || echo "FAILED"
exit "$fail"
