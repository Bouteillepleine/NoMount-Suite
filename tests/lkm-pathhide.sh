#!/system/bin/sh
# Does a mapping pathhide hides stay hidden from every reader, and do those
# readers agree with each other?
#
# Unlike lkm-load.sh next to it, this one does not run on the host: the guards
# are kprobes, so the only place they can be observed is a device with the
# module loaded and a kernel that has no NoMount built in.
#
# It maps two identical files - a control under /data/local/tmp and a subject
# under /data/adb, which the shipped rule set covers - and asks each reader
# about both. The control is what proves the probe works: if the control comes
# back hidden, the test is broken, not the cloak.
#
# The numbers it checks against are not invented. Measured on CPH2745, 6.12.69,
# with the IN-TREE build as the reference, on a 4-page mapping:
#
#              control    subject
#   maps       1          0
#   mincore    ok         Out of memory      <- bionic's spelling of ENOMEM
#   pagemap    4          0
#   vmsize     8668928    8668912            <- 16 kB, the 4 hidden pages
#   statm      2167232    2167228            <- 4 pages
#
# The first three are what this LKM build reproduces. The last two are the
# accounting arm it does not have, so the subject's vmsize and statm read the
# same as the control here and the script says so rather than failing.
#
# No nm client is needed: the rules are programmed by the Suite's own service
# at boot, and the module reports on load whether the knob exists at all.
#
# Build the probe for the device first:
#   clang --target=aarch64-linux-android31 -O2 -static \
#         tests/pathhide-probe.c -o pathhide-probe
#
# Run as:  sh lkm-pathhide.sh /data/local/tmp/pathhide-probe

PROBE=${1:-/data/local/tmp/pathhide-probe}
CTL=/data/local/tmp/ph-control.bin
SUBJ=/data/adb/ph-subject.bin
fail=0

[ "$(id -u)" = 0 ] || { echo "fatal: needs root"; exit 1; }
[ -x "$PROBE" ] || { echo "fatal: no probe at $PROBE (see header)"; exit 1; }

dmesg | grep -o 'pathhide guards active.*' | tail -1
dmesg | grep -o 'pathhide guard: cannot probe.*' | tail -3

if ! dmesg | grep -q 'pathhide guards active'; then
	echo "SKIP: this engine has no pathhide guards - nothing to test"
	exit 0
fi

cleanup() { rm -f "$CTL" "$SUBJ"; }
trap cleanup EXIT

dd if=/dev/urandom of="$CTL" bs=4096 count=4 2>/dev/null
cp "$CTL" "$SUBJ" 2>/dev/null || { echo "fatal: cannot write $SUBJ"; exit 1; }

field() { echo "$1" | sed -n "s/^$2  *//p"; }

ctl=$("$PROBE" "$CTL" ph-control.bin)
subj=$("$PROBE" "$SUBJ" ph-subject.bin)
echo "-- control (no rule covers it) --"; echo "$ctl"
echo "-- subject (under /data/adb) --"; echo "$subj"

[ "$(field "$ctl" maps)" = 1 ]    || { echo "FAIL control: cannot see its own mapping"; exit 1; }
[ "$(field "$ctl" mincore)" = ok ] || { echo "FAIL control: mincore already failing"; exit 1; }
[ "$(field "$ctl" pagemap)" -gt 0 ] || { echo "FAIL control: pagemap already empty"; exit 1; }
echo "ok   control is visible to all three readers"

[ "$(field "$subj" maps)" = 0 ] \
	&& echo "ok   maps   : line gone" \
	|| { echo "FAIL maps   : line still rendered"; fail=1; }

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

# The readers must agree with each other. A mapping that maps denies while
# map_files resolves it to a path is a louder signal than either leak alone.
echo "-- do the readers agree? --"
mf=0
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
	[ -r "/proc/$p/maps" ] || continue
	n=$(ls -l "/proc/$p/map_files" 2>/dev/null | grep -c '/data/adb')
	m=$(grep -c '/data/adb' "/proc/$p/maps" 2>/dev/null)
	if [ "${n:-0}" != "0" ] && [ "${m:-0}" = "0" ]; then
		echo "  contradiction: pid $p maps=0 map_files=$n"
		mf=$((mf + 1))
	fi
done
if [ "$mf" = 0 ]; then
	echo "ok   map_files: agrees with maps"
else
	echo "FAIL map_files: $mf process(es) where map_files resolves what maps denies"
	fail=1
fi

echo "KNOWN accounting: VmSize/VmPeak/statm still count the hidden mapping."
echo "      control statm=$(field "$ctl" statm) subject statm=$(field "$subj" statm)"
echo "KNOWN smaps_rollup totals and PROCMAP_QUERY still include it, and"
echo "      map_files still lists the address range even when the path is gone."

dmesg | tail -40 | grep -qiE 'BUG:|Call trace:|Unable to handle kernel' && {
	echo "FAIL kernel complained while the guards ran"; fail=1; }

[ "$fail" = 0 ] && echo "PASS" || echo "FAILED"
exit "$fail"
