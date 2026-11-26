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

# $1 = basenames that load and probe (rc 0).
# $2 = basenames that load but whose probe does not answer (rc 2).
# Anything else does not load (rc 1).
setup() {
	rm -rf "$WORK/lkm" "$WORK/dev"; mkdir -p "$WORK/lkm" "$WORK/dev"
	LOADABLE=" $1 "
	UNCONFIRMED=" ${2:-} "
	NM_LKM_DEVICE_KO="$WORK/dev/nomount.ko"
	NM_LKM_SAY=:
	. "$HERE/module/lkm-load.sh"
	NM_LKM_DEVICE_KO="$WORK/dev/nomount.ko"   # re-assert: the file sets a default
	nm_lkm_kver()  { echo "6.12"; }
	nm_lkm_akver() { echo "android16"; }
	nm_lkm_probe() { return 1; }
	# $2 is recorded too: whether a path asks for strict mode is the whole
	# protection against ko-loader rewriting vermagic for a module whose KMI was
	# guessed, and only the caller knows which path it is on.
	nm_lkm_insert() {
		PICKED=$(basename "$1")
		STRICT_OF="$STRICT_OF $PICKED=${2:-no}"
		case "$LOADABLE" in *" $PICKED "*) return 0;; esac
		case "$UNCONFIRMED" in *" $PICKED "*) return 2;; esac
		PICKED=; return 1
	}
	PICKED=; NM_LKM_SOURCE=; STRICT_OF=
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

# "It went in but the probe did not answer" is a different answer from "nothing
# went in", and the callers print different things for them: one says the engine
# is up and the nm binary is not, the other says to reflash the kernel.
setup "" "nomount.ko"
mk "$WORK/dev/nomount.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null 2>&1; r=$?
check "a load the probe cannot confirm returns 2, not 1" "$r" "2"
check "...and still records where it came from" "$NM_LKM_SOURCE" "device"

setup "" "nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null 2>&1; r=$?
check "an unloadable device .ko still falls through to a bundled one" "$r" "2"
check "...and names the bundled source" "$NM_LKM_SOURCE" "bundled"

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

# The kernel changing under a kept module is the one event the bundled set exists for, and
# it had no case at all: the suite pinned only the deletion. After a bundled load the pick
# is copied to NM_LKM_DEVICE_KO and the per-KMI set is pruned, so when a different KMI is
# flashed the device copy is tried, fails on vermagic, is removed - and the search has
# nothing left to offer. On the lite zip, which ships no lkm/ at all, that is an engineless
# boot until the full zip is reinstalled.
#
# Pinned as it behaves TODAY, deliberately: whether to narrow the prune so the set survives
# is a disk-space-versus-resilience call for the maintainer, not one this gate should make.
# What it must not be any more is invisible - this case fails if the prune changes either way.
setup "nomount-android16-6.12.ko"
mk "$WORK/lkm/nomount-android16-6.12.ko"; mk "$WORK/lkm/nomount-android13-5.15.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
nm_lkm_prune "$WORK/lkm"
check "after a bundled load + prune, no per-KMI candidate is left on disk" \
	"$(ls "$WORK/lkm"/nomount-*.ko 2>/dev/null | wc -l | tr -d ' ')" "0"
# Now the kernel changes under it and nothing it kept can load.
nm_lkm_kver()  { echo "5.15"; }
nm_lkm_akver() { echo "android13"; }
LOADABLE=" nomount-android13-5.15.ko "
UNCONFIRMED=" "
PICKED=; NM_LKM_SOURCE=
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "KNOWN: a KMI change after the prune finds nothing to load" "${PICKED:-none}" "none"

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

echo
echo "ko-loader is withheld from a guessed KMI"

# Only the "same version, other KMI" loop may pass `strict`, because it is the
# only path whose KMI is a guess off uname's major.minor. ko-loader rewrites
# vermagic AND pre-resolves symbols as SHN_ABS, which skips check_version() --
# so on that path the rewrite would force in a module built across a KABI
# boundary. On 5.10 and 5.15, the two versions shipping two KMIs each, that is
# reachable with the modules we actually ship.
setup "" ""
mk "$WORK/lkm/nomount-android16-6.12.ko"; mk "$WORK/lkm/nomount-android15-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "the exact KMI match is NOT strict - the rewrite is its intended use" \
	"$(echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount-android16-6.12.ko=' | head -1)" \
	"nomount-android16-6.12.ko=no"
check "a guessed KMI IS strict - the kernel's vermagic check is all that is left" \
	"$(echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount-android15-6.12.ko=' | head -1)" \
	"nomount-android15-6.12.ko=strict"

setup "" ""
mk "$WORK/dev/nomount.ko"; mk "$WORK/lkm/nomount.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "the kernel-supplied .ko is NOT strict" \
	"$(echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount.ko=' | head -1)" "nomount.ko=no"
check "the cached pick is NOT strict - it only loaded because something accepted it" \
	"$(echo "$STRICT_OF" | tr ' ' '\n' | grep -c '^nomount.ko=strict')" "0"

echo
echo "nm_lkm_insert honours strict"

# The cases above stub nm_lkm_insert wholesale, so they prove WHICH path asks for
# strict and nothing about what strict does. This runs the real body against a
# ko-loader stub that records being called.
insert_setup() {
	rm -rf "$WORK/ins"; mkdir -p "$WORK/ins"
	. "$HERE/module/lkm-load.sh"
	NM_LKM_SAY=:
	nm_lkm_probe() { return 1; }
	NM_LKM_LOADER="$WORK/ins/loader"
	printf '#!/bin/sh\necho called >> "%s"\nexit 1\n' "$WORK/ins/ran" > "$NM_LKM_LOADER"
	chmod 755 "$NM_LKM_LOADER"
	mk "$WORK/ins/nomount.ko"
	rm -f "$WORK/ins/ran"
}
loader_runs() { [ -s "$WORK/ins/ran" ] && echo ran || echo skipped; }

insert_setup
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1
check "without strict, ko-loader is used" "$(loader_runs)" "ran"

insert_setup
nm_lkm_insert "$WORK/ins/nomount.ko" strict >/dev/null 2>&1
check "with strict, ko-loader is NOT used" "$(loader_runs)" "skipped"

# Anything other than the exact word must not silently disable the loader: a
# caller passing a label, or a stray argument, would otherwise withhold the
# rewrite from a path that is entitled to it and the module would stop loading.
insert_setup
nm_lkm_insert "$WORK/ins/nomount.ko" "" >/dev/null 2>&1
check "an empty second argument is not strict" "$(loader_runs)" "ran"
insert_setup
nm_lkm_insert "$WORK/ins/nomount.ko" bundled >/dev/null 2>&1
check "an unrecognised second argument is not strict" "$(loader_runs)" "ran"

# The real mapping from "went in" to the return code: in and confirmed is 0, in but
# the probe is silent is 2. The stub above refuses, so these make each method succeed.
insert_setup; sed -i 's/^exit 1$/exit 0/' "$NM_LKM_LOADER"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1; _r=$?
check "ko-loader in, probe silent: returns 2" "$_r" "2"
insert_setup; sed -i 's/^exit 1$/exit 0/' "$NM_LKM_LOADER"; nm_lkm_probe() { return 0; }
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1; _r=$?
check "ko-loader in, probe answers: returns 0" "$_r" "0"
_op0=$PATH
insert_setup; rm -f "$NM_LKM_LOADER"; mkdir -p "$WORK/ins/bin"
printf '#!/bin/sh\nexit 0\n' > "$WORK/ins/bin/insmod"; chmod 755 "$WORK/ins/bin/insmod"
PATH="$WORK/ins/bin:$_op0"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1; _r=$?
check "insmod in, probe silent: returns 2" "$_r" "2"
nm_lkm_probe() { return 0; }
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1; _r=$?
PATH=$_op0
check "insmod in, probe answers: returns 0" "$_r" "0"

# ksud insmod rewrites vermagic and binds SHN_ABS as ko-loader does, so strict withholds it too.
ksud_setup() {
	insert_setup
	mkdir -p "$WORK/ins/bin"
	printf '#!/bin/sh\ncase "$1" in -h) echo "  insmod   Load a kernel module" ;; insmod) echo called >> "%s"; exit 1 ;; esac\n' \
		"$WORK/ins/ksud_ran" > "$WORK/ins/bin/ksud"
	chmod 755 "$WORK/ins/bin/ksud"
	rm -f "$WORK/ins/ksud_ran"
}
ksud_runs() { [ -s "$WORK/ins/ksud_ran" ] && echo ran || echo skipped; }
_op=$PATH
ksud_setup; PATH="$WORK/ins/bin:$_op"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1
PATH=$_op
check "without strict, ksud insmod is used" "$(ksud_runs)" "ran"
ksud_setup; PATH="$WORK/ins/bin:$_op"
nm_lkm_insert "$WORK/ins/nomount.ko" strict >/dev/null 2>&1
PATH=$_op
check "with strict, ksud insmod is NOT used" "$(ksud_runs)" "skipped"

# A load nm cannot confirm already put the engine in: a second load of the same file only
# runs another init that logs a netlink failure naming the module.
ksud_setup; sed -i 's/exit 1 ;; esac/exit 0 ;; esac/' "$WORK/ins/bin/ksud"; PATH="$WORK/ins/bin:$_op"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1; _r=$?
PATH=$_op
check "an unconfirmed load returns 2 at once" "$_r" "2"
check "  and no second method runs" "$(loader_runs)" "skipped"

echo
echo "a kept bundled copy does not shadow an update"

# modinfo-shaped file: NUL-separated key=value strings, as tr reads them on a device.
mkko() { mkdir -p "$(dirname "$1")"; printf 'nomount_variant=lkm\0vermagic=%s SMP preempt mod_unload aarch64\0' "$2" > "$1"; }
uname() { echo "6.12.69-android16-6-gdevice-4k"; }

setup "nomount-android16-6.12.ko"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a bundled pick is kept with a marker" \
	"$([ -f "$WORK/dev/nomount.ko.bundled" ] && echo marked || echo unmarked)" "marked"
check "  and the marker names the kernel it was picked for" \
	"$(sed -n 's/^kver=//p' "$WORK/dev/nomount.ko.bundled")" "6.12.69-android16-6-gdevice-4k"

# After an OTA or another kernel, the kept copy is a guess: the bundled set goes first.
setup "nomount-android16-6.12.ko nomount.ko"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a kept copy from another kernel does not go first" "$PICKED" "nomount-android16-6.12.ko"

setup "nomount.ko"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
rm -rf "$WORK/lkm"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "with nothing bundled, it is still tried, strict" \
	"$(echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount.ko=' | head -1)" "nomount.ko=strict"
check "  and re-stamped for this kernel once it loads" \
	"$(sed -n 's/^kver=//p' "$WORK/dev/nomount.ko.bundled")" "6.12.69-android16-6-gdevice-4k"

setup "nomount.ko"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.69-android16-6-gdevice-4k\nstrict=1\n' > "$WORK/dev/nomount.ko.bundled"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a kept guessed-KMI pick stays strict on the same kernel" \
	"$(echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount.ko=' | head -1)" "nomount.ko=strict"

setup "nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko"; : > "$WORK/dev/nomount.ko.bundled"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_retire_kept
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "after an update the new bundled module loads, not the kept copy" "$NM_LKM_SOURCE" "bundled"
check "  and the set-aside copy is dropped once the new one is kept" \
	"$([ -f "$WORK/dev/nomount.ko.prev" ] && echo left || echo dropped)" "dropped"

setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko"; : > "$WORK/dev/nomount.ko.bundled"; mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_retire_kept
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "if nothing newer loads, the copy from before the update still does" "$NM_LKM_SOURCE" "previous"

setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko.prev"; rm -rf "$WORK/lkm"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "the set-aside copy is reachable with no lkm/ at all" "$NM_LKM_SOURCE" "previous"

setup ""
mkko "$WORK/dev/nomount.ko" "6.12.52-4k"
nm_lkm_retire_kept
check "an unmarked copy with a stock GKI vermagic is ours: set aside" \
	"$([ -f "$WORK/dev/nomount.ko.prev" ] && echo aside || echo kept)" "aside"

setup ""
mkko "$WORK/dev/nomount.ko" "6.12.69-android16-6-gdevice-4k"
nm_lkm_retire_kept
check "a module built for this exact kernel is kernel-supplied: untouched" \
	"$([ -f "$WORK/dev/nomount.ko" ] && echo kept || echo aside)" "kept"

setup ""
mkko "$WORK/dev/nomount.ko" "6.12.52-4k"
nm_lkm_retire_kept recovery
check "from recovery an unmarked copy is left alone (wrong kernel to compare)" \
	"$([ -f "$WORK/dev/nomount.ko" ] && echo kept || echo aside)" "kept"

setup ""
mkdir -p "$WORK/dev"; printf 'vermagic=6.12.52-4k\0' > "$WORK/dev/nomount.ko"
nm_lkm_retire_kept
check "an unmarked file that is not a NoMount LKM is never touched" \
	"$([ -f "$WORK/dev/nomount.ko" ] && echo kept || echo aside)" "kept"
unset -f uname

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
