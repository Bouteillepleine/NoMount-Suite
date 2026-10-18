#!/bin/sh
# Search order and fallthrough in module/lkm-load.sh.
# nm_lkm_insert is replaced so nothing is ever really insmod'ed: each case says
# which files are loadable, and the test asserts which one got picked.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

check() {
	if [ "$2" = "$3" ]; then
		pass=$((pass + 1)); printf '  ok   %s\n' "$1"
	else
		fail=$((fail + 1)); printf '  FAIL %s\n       want=%s got=%s\n' "$1" "$3" "$2"
	fi
}

# $1 = space-separated list of basenames that "load"; everything else fails.
setup() {
	rm -rf "$WORK/lkm" "$WORK/dev"; mkdir -p "$WORK/lkm" "$WORK/dev"
	LOADABLE=" $1 "
	NM_LKM_DEVICE_KO="$WORK/dev/nomount.ko"
	NM_LKM_SAY=:
	. "$HERE/module/lkm-load.sh"
	NM_LKM_DEVICE_KO="$WORK/dev/nomount.ko"   # re-assert: the file sets a default
	nm_lkm_kver()  { echo "6.12"; }
	nm_lkm_akver() { echo "android16"; }
	nm_lkm_probe() { return 1; }
	nm_lkm_insert() {
		PICKED=$(basename "$1")
		case "$LOADABLE" in *" $PICKED "*) return 0;; esac
		PICKED=; return 1
	}
	PICKED=; NM_LKM_SOURCE=
}

mk() { mkdir -p "$(dirname "$1")"; echo ko > "$1"; }

echo "nm_lkm_load_best search order"

setup "nomount.ko"
mk "$WORK/dev/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "kernel-supplied .ko wins over a bundled exact-KMI match" "$NM_LKM_SOURCE" "device"

setup "nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "unloadable kernel-supplied .ko falls through to bundled" "$NM_LKM_SOURCE" "bundled"

setup "nomount.ko"
mk "$WORK/lkm/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "cached pick from an earlier boot is reused" "$NM_LKM_SOURCE" "cached"

# The regression this change exists for: a kernel update makes the cached .ko
# stale, and the old elif-chain gave up instead of trying anything else.
setup "nomount-android16-6.12.ko"
mk "$WORK/lkm/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "STALE cached .ko falls through to the per-KMI set" "$NM_LKM_SOURCE" "bundled"
check "  and the chosen module is kept outside the module dir" \
	"$([ -f "$WORK/dev/nomount.ko" ] && echo persisted || echo lost)" "persisted"

setup "nomount-android14-6.12.ko"
mk "$WORK/lkm/nomount-android14-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "same kernel version, other KMI, is accepted" "$NM_LKM_SOURCE" "bundled"

setup "nomount-android16-5.15.ko"
mk "$WORK/lkm/nomount-android16-5.15.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null 2>&1
check "a different kernel version is NOT tried" "$NM_LKM_SOURCE" ""

setup ""
mk "$WORK/dev/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
if nm_lkm_load_best "$WORK/lkm" >/dev/null 2>&1; then r=0; else r=1; fi
check "nothing loadable returns non-zero" "$r" "1"

setup "nomount.ko"
mk "$WORK/dev/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
nm_lkm_prune "$WORK/lkm"
check "prune KEEPS the bundled set when the kernel supplied the .ko" \
	"$([ -f "$WORK/lkm/nomount-android16-6.12.ko" ] && echo kept || echo gone)" "kept"

setup "nomount-android16-6.12.ko"
mk "$WORK/lkm/nomount-android16-6.12.ko"; mk "$WORK/lkm/nomount-android14-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
nm_lkm_prune "$WORK/lkm"
check "prune DROPS the leftovers when a bundled .ko was used" \
	"$([ -f "$WORK/lkm/nomount-android14-6.12.ko" ] && echo kept || echo gone)" "gone"

# The whole point of persisting outside $MODDIR: the lite zip ships no lkm/ at
# all, so a user on a kernel with no built-in engine must not lose it on update.
setup "nomount-android16-6.12.ko"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
rm -rf "$WORK/lkm"                       # simulate the update replacing $MODDIR
setup2_loadable="nomount.ko"
LOADABLE=" nomount.ko "
NM_LKM_SOURCE=
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "survives a module update that removes lkm/" "$NM_LKM_SOURCE" "device"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
