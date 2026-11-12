#!/system/bin/sh
# The changes that exist ONLY in the LKM build, checked on a device.
#
# None of them can be observed on a kernel with NoMount built in. The module
# cannot load beside a built-in engine - nomount_init() binds netlink proto 29
# and the second copy's init fails - so every guard below is simply absent
# there. This needs a stock GKI kernel, with the Suite having loaded the module.
#
#   adb push tests/lkm-ondevice.sh tests/lkm-pathhide.sh /data/local/tmp/
#   clang --target=aarch64-linux-android31 -O2 -static \
#         tests/pathhide-probe.c -o pathhide-probe
#   adb push pathhide-probe /data/local/tmp/
#   adb shell su -c 'sh /data/local/tmp/lkm-ondevice.sh'
#
# One thing here is deliberately reported rather than asserted: a kretprobe's
# nmissed counter is only legible through /sys/kernel/debug/kprobes/list, which
# is usually not mounted. Where it is, the numbers are printed; where it is not,
# this says "unmeasured" rather than implying zero.

PROBE=${1:-/data/local/tmp/pathhide-probe}
BIN=${2:-/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount}
NMC=$(dirname "$BIN")/nm
fail=0
note() { echo "NOTE $*"; }
ok()   { echo "ok   $*"; }
bad()  { echo "FAIL $*"; fail=1; }

[ "$(id -u)" = 0 ] || { echo "fatal: needs root"; exit 1; }

echo "== variant =="
# There are THREE states here and the kallsyms test alone separates only two:
#
#   hidden LKM  not in kallsyms      not in /proc/modules
#   hide=0 LKM  IS in kallsyms       IS in /proc/modules
#   in-tree     IS in kallsyms       not in /proc/modules
#
# Keying on kallsyms alone put the hide=0 build in the in-tree bucket -- and that is
# precisely the build these tests get run against, because it is the only one you can
# rmmod. The run then printed SKIP and exited 0, which reads as a pass for a run that
# tested nothing. Ask whether the module is LOADED first; that answer is unambiguous.
if grep -q '^nomount ' /proc/modules 2>/dev/null || [ -d /sys/module/nomount ]; then
	echo "variant: LKM (hide=0 - the module is listed, so its symbols are visible)"
elif grep -qE ' (vfs_map_meta_override|nm_uid_blocked)$' /proc/kallsyms 2>/dev/null; then
	echo "SKIP: this kernel has NoMount built in, so the LKM's guards are not"
	echo "      present and nothing below can be observed. Boot a stock GKI"
	echo "      kernel and run this there."
	exit 0
fi
[ -n "$("$NMC" v 2>/dev/null | tr -dc 0-9)" ] || {
	echo "fatal: the engine does not answer - the module is not loaded"; exit 1; }
ok "engine answers and is not in kallsyms: this is the LKM build"

echo "== is the module actually hidden? =="
for probe in "grep -c '^nomount' /proc/modules" "ls -d /sys/module/nomount" \
             "grep -c 'nomount' /proc/kallsyms"; do
	n=$(eval "$probe" 2>/dev/null | tr -dc 0-9)
	[ -z "$n" ] && n=0
	if [ "$n" = 0 ]; then
		ok "clear: $probe"
	else
		bad "visible ($n): $probe"
	fi
done

echo "== does it name itself in the ring buffer? =="
# The guards print their "armed" lines only on hide=0 now, and lib.sh's nmlog
# writes to /dev/kmsg only when /data/adb/nomount/kmsg exists.
k=$(dmesg 2>/dev/null | grep -c 'nomount:')
if [ -e /data/adb/nomount/kmsg ]; then
	note "kmsg opt-in marker present, so $k line(s) is expected"
elif [ "${k:-0}" = 0 ]; then
	ok "no 'nomount:' line in dmesg"
else
	bad "$k 'nomount:' line(s) in dmesg with no opt-in marker"
	dmesg | grep 'nomount:' | head -4 | sed 's/^/     /'
fi

echo "== hammer the path and stat guards, then look for a sleep in atomic =="
# The deferred path_put and the kretprobe pool are what this exercises: every
# lookup by a hidden caller goes through user_path_at's and do_filp_open's
# return handlers. A kernel that still put a path from one of those complains.
HID=$("$BIN" uid list 2>/dev/null | sed -n 's/.*uid \([0-9]\{4,\}\).*/\1/p' | head -1)
if [ -z "$HID" ]; then
	note "no uid on the hide list, so the guards cannot be driven - unmeasured"
else
	before=$(dmesg 2>/dev/null | wc -l)
	i=0
	while [ "$i" -lt 12 ]; do
		# shellcheck disable=SC2016  # expanded by the inner shell, not this one
		su "$HID" -c 'for d in /data/adb /data/adb/modules /system/bin /system/etc; do
			ls "$d" >/dev/null 2>&1; stat "$d" >/dev/null 2>&1
			cat "$d/.nonexistent" >/dev/null 2>&1
		done' >/dev/null 2>&1 &
		i=$((i + 1))
	done
	wait
	# shellcheck disable=SC2010  # /proc entries are pids and names, and the
	# grep is how the pids are selected; no filename can be awkward here
	for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | head -60); do
		ls -l "/proc/$p/map_files" >/dev/null 2>&1
	done
	new=$(dmesg 2>/dev/null | tail -n "+$before")
	if echo "$new" | grep -qE 'sleeping function called from invalid context|scheduling while atomic|BUG: |Call trace:'; then
		bad "the kernel complained while the guards ran"
		echo "$new" | grep -E 'sleeping function|scheduling while atomic|BUG: ' | head -4 | sed 's/^/     /'
	else
		ok "12 concurrent hidden callers + 60 map_files reads: no atomic-context complaint"
	fi
fi

echo "== kretprobe misses (a miss is a guard that silently failed open) =="
KP=/sys/kernel/debug/kprobes/list
if [ -r "$KP" ]; then
	hot=$(grep -cE 'user_path_at|do_filp_open|vfs_getattr|vfs_getxattr|security_inode_getattr' "$KP" 2>/dev/null)
	ok "kprobes/list readable: $hot handler(s) on the hot symbols"
	note "per-probe nmissed is in $KP; any non-zero means a guard failed open"
	grep -E 'user_path_at|do_filp_open|vfs_getattr|vfs_getxattr' "$KP" 2>/dev/null | head -6 | sed 's/^/     /'
else
	note "$KP not readable (debugfs not mounted) - nmissed UNMEASURED."
	note "mount -t debugfs none /sys/kernel/debug to read it."
fi

echo "== maps spoof: an injected file must not report its backing dev:ino =="
APK=$("$NMC" list 2>/dev/null | sed 's/ (.*//; s/ \[UID.*//; s/ -> .*//' | grep -E '\.apk$' | head -1)
if [ -z "$APK" ] || [ ! -r "$APK" ] || [ ! -x "$PROBE" ]; then
	note "no readable injected .apk or no probe - maps spoof UNMEASURED"
else
	sdev=$(stat -c '%d' "$APK" 2>/dev/null); sino=$(stat -c '%i' "$APK" 2>/dev/null)
	ddev=$(stat -c '%d' /data 2>/dev/null)
	line=$("$PROBE" "$APK" "$(basename "$APK")" 2>/dev/null | sed -n 's/^maps  *//p')
	note "injected $APK stat dev=$sdev ino=$sino (/data dev=$ddev), maps rows=$line"
	if [ "$sdev" = "$ddev" ]; then
		bad "stat already reports the /data device - the rule is not spoofing dev"
	else
		ok "stat reports a non-/data device, so maps has the stock value to match"
	fi
fi

echo "== delegate the maps/pagemap/mincore/map_files set =="
if [ -r /data/local/tmp/lkm-pathhide.sh ]; then
	sh /data/local/tmp/lkm-pathhide.sh "$PROBE" "$BIN" || fail=1
else
	note "lkm-pathhide.sh not pushed - that set UNMEASURED"
fi

echo
[ "$fail" = 0 ] && echo "PASS" || echo "FAILED"
exit "$fail"
