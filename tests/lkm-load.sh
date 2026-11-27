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
	NM_LKM_KALLSYMS="$WORK/ins/kallsyms"
	printf 'ffffffc080000000 T _text\n' > "$NM_LKM_KALLSYMS"
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

insert_setup
printf '0000000000000000 T _text\n' > "$NM_LKM_KALLSYMS"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1
check "kallsyms with zeroed addresses: ko-loader is NOT used" "$(loader_runs)" "skipped"
insert_setup
: > "$NM_LKM_KALLSYMS"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1
check "unreadable kallsyms: ko-loader is NOT used" "$(loader_runs)" "skipped"

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

# A monthly OTA changes the release string, not the KMI: the kept copy goes first, as before it.
setup "nomount.ko nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nkmi=android16-6.12\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "same KMI, new kernel: the kept copy is tried first" "$PICKED" "nomount.ko"
check "  without strict" "$(echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount.ko=' | head -1)" "nomount.ko=no"
check "  and re-stamped for this kernel" \
	"$(sed -n 's/^kver=//p' "$WORK/dev/nomount.ko.bundled")" "6.12.69-android16-6-gdevice-4k"
check "  keeping its KMI" "$(sed -n 's/^kmi=//p' "$WORK/dev/nomount.ko.bundled")" "android16-6.12"

setup "nomount.ko nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nkmi=android15-6.12\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "another KMI: the bundled set goes first" "$PICKED" "nomount-android16-6.12.ko"

setup "nomount.ko nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nkmi=android16-6.12\nstrict=1\n' > "$WORK/dev/nomount.ko.bundled"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a strict (guessed) pick is not trusted across kernels even on its KMI" "$PICKED" "nomount-android16-6.12.ko"

setup "nomount-android16-6.12.ko"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a new pick records its KMI" "$(sed -n 's/^kmi=//p' "$WORK/dev/nomount.ko.bundled")" "android16-6.12"

echo
echo "a kernel the zip has no module for says so"
setup ""
mk "$WORK/lkm/nomount-android15-6.6.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "no module for this KMI: NM_LKM_NOMATCH is set" "${NM_LKM_NOMATCH:-unset}" "1"
setup ""
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a module exists but does not load: NM_LKM_NOMATCH stays clear" "${NM_LKM_NOMATCH:-unset}" "unset"

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

prevstrict() { echo "$STRICT_OF" | tr ' ' '\n' | grep '^nomount.ko.prev=' | head -1; }
# A copy kept from the guessed-KMI loop is set aside with its marker, and loads strict.
setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.69-android16-6-gdevice-4k\nkmi=android16-6.12\nstrict=1\n' > "$WORK/dev/nomount.ko.bundled"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_retire_kept
check "the set-aside copy keeps its marker" "$(sed -n 's/^strict=//p' "$WORK/dev/nomount.ko.prev.bundled" 2>/dev/null)" "1"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a guessed-KMI copy from before the update loads strict" "$(prevstrict)" "nomount.ko.prev=strict"
nm_lkm_prune "$WORK/lkm"
check "  and the newer bundled set survives the prune" \
	"$([ -f "$WORK/lkm/nomount-android16-6.12.ko" ] && echo kept || echo gone)" "kept"

setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko.prev"; rm -rf "$WORK/lkm"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "an unmarked copy from before the update loads strict" "$(prevstrict)" "nomount.ko.prev=strict"

setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.69-android16-6-gdevice-4k\nkmi=android16-6.12\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
nm_lkm_retire_kept; rm -rf "$WORK/lkm"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "an exact pick for this kernel loads as it did" "$(prevstrict)" "nomount.ko.prev=no"

setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nkmi=android16-6.12\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
nm_lkm_retire_kept; rm -rf "$WORK/lkm"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "  and after an OTA on the same KMI" "$(prevstrict)" "nomount.ko.prev=no"

setup "nomount.ko.prev"
mk "$WORK/dev/nomount.ko"; printf 'kver=6.12.58-old\nkmi=android15-6.12\nstrict=0\n' > "$WORK/dev/nomount.ko.bundled"
nm_lkm_retire_kept; rm -rf "$WORK/lkm"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "an exact pick for another KMI loads strict" "$(prevstrict)" "nomount.ko.prev=strict"

setup "nomount-android16-6.12.ko"
mk "$WORK/dev/nomount.ko.prev"; printf 'strict=1\n' > "$WORK/dev/nomount.ko.prev.bundled"
mk "$WORK/lkm/nomount-android16-6.12.ko"
nm_lkm_load_best "$WORK/lkm" >/dev/null
check "a newer pick drops the set-aside copy's marker with it" \
	"$([ -f "$WORK/dev/nomount.ko.prev.bundled" ] && echo left || echo dropped)" "dropped"

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

echo
echo "the boot load runs the loaders once per boot"
mkdir -p "$WORK/bl/nm" "$WORK/bl/mod"
cat > "$WORK/bl/mod/lkm-load.sh" <<'EOF'
nm_lkm_probe() { return 1; }
nm_lkm_load_best() { echo load >> "$NMDIR/calls"; NM_LKM_SOURCE=bundled; return "${BL_RC:-2}"; }
nm_lkm_prune() { :; }
EOF
bootload() {
	(
		. "$HERE/module/lib.sh"
		NMDIR="$WORK/bl/nm"; BOOTLOG="$NMDIR/boot.log"; MODDIR="$WORK/bl/mod"
		NM_BOOT_ID="$WORK/bl/boot_id"
		nm_set_bin() { BIN=/bin/false; NM_BIN=/bin/false; }
		nm_lkm_boot_load
	)
}
calls() { grep -c load "$WORK/bl/nm/calls" 2>/dev/null || echo 0; }
echo "boot-a" > "$WORK/bl/boot_id"
bootload; bootload
check "loaded but unconfirmed: the second caller in that boot loads nothing" "$(calls)" "1"
check "  and does not log that nothing loads" \
	"$(grep -c 'no engine module loads' "$WORK/bl/nm/boot.log")" "0"
echo "boot-b" > "$WORK/bl/boot_id"
bootload
check "the next boot loads again" "$(calls)" "2"
# Three boots would trip the guard, which stops the load before it starts.
rm -f "$WORK/bl/nm/calls" "$WORK/bl/nm/.lkm.boot" "$WORK/bl/nm/bootcount" "$WORK/bl/nm/disabled"
echo "boot-c" > "$WORK/bl/boot_id"
BL_RC=1; export BL_RC
bootload; bootload
check "nothing went in: the second caller still tries" "$(calls)" "2"
unset BL_RC

# The cards tell an LKM user whose module did not load to flash a kernel unless this answers.
lkmzip() { ( . "$HERE/module/lib.sh"; MODDIR="$WORK/bl/mod"; nm_lkm_zip && echo lkm || echo lite ); }
echo 'updateJson=https://example.invalid/main/update-lkm.json' > "$WORK/bl/mod/module.prop"
check "the LKM zip is told apart for the cards" "$(lkmzip)" "lkm"
echo 'updateJson=https://example.invalid/main/update.json' > "$WORK/bl/mod/module.prop"
check "  and the lite zip is not" "$(lkmzip)" "lite"

echo
echo "a load that fails says why"

insert_setup
mkdir -p "$WORK/ins/bin"
printf '#!/bin/sh\ncase "$1" in -h) echo "  insmod   Load a kernel module" ;; insmod) echo "insmod: Exec format error"; exit 1 ;; esac\n' \
	> "$WORK/ins/bin/ksud"
chmod 755 "$WORK/ins/bin/ksud"
rm -f "$NM_LKM_LOADER"
: > "$WORK/ins/said"
say_to_file() { printf '%s\n' "$*" >> "$WORK/ins/said"; }
NM_LKM_SAY=say_to_file
PATH="$WORK/ins/bin:$_op"
nm_lkm_insert "$WORK/ins/nomount.ko" >/dev/null 2>&1
PATH=$_op
check "ksud insmod's own refusal is passed on, not thrown away" \
	"$(grep -c 'insmod: Exec format error' "$WORK/ins/said")" "1"

dmesg() {
	printf '[    1.000000][    T1] Booting Linux\n'
	printf '[    7.980145][   T62] nomount: disagrees about version of symbol module_layout\n'
	printf '[    8.100000][   T62] nomount: Unknown symbol d_lookup (err -2)\n'
}
check "the kernel's refusal lines, without their timestamps" "$(nm_lkm_kernel_reason | tr '\n' '|')" \
	"nomount: disagrees about version of symbol module_layout|nomount: Unknown symbol d_lookup (err -2)|"
unset -f dmesg
printf 'nomount_variant=lkm\000vermagic=6.12.52-4k SMP\0006.12.52\0001.36.7\000' > "$WORK/ins/built.ko"
check "a module's engine build is read off the file" "$(nm_lkm_build_of "$WORK/ins/built.ko")" "1.36.7"

# The boot path, through lib.sh's real nm_lkm_boot_load: only the device is stubbed.
boot_load() {
	(
		. "$HERE/module/lib.sh"
		NMDIR="$WORK/b/nm"; BOOTLOG="$NMDIR/boot.log"; MODDIR="$WORK/b/mod"; NM_BOOT_ID="$WORK/b/boot_id"
		NM_LKM_DEVICE_KO="$NMDIR/nomount.ko"
		getprop() { echo arm64-v8a; }
		uname() { if [ "${1:-}" = -r ]; then echo 6.12.69-android16-6-gdevice-4k; else echo Linux; fi; }
		dmesg() { printf '[    7.980145][   T62] nomount: disagrees about version of symbol module_layout\n'; }
		PATH="$WORK/b/bin:$_op"
		nm_lkm_boot_load
	)
}
boot_setup() {
	rm -rf "$WORK/b"; mkdir -p "$WORK/b/nm" "$WORK/b/mod/lkm" "$WORK/b/mod/bin/arm64-v8a" "$WORK/b/bin"
	echo "boot-$$" > "$WORK/b/boot_id"
	echo 'version=vtest' > "$WORK/b/mod/module.prop"
	cp "$HERE/module/lkm-load.sh" "$WORK/b/mod/lkm-load.sh"
	printf 'nomount_variant=lkm\000vermagic=6.12.52-4k SMP\0001.36.7\000' > "$WORK/b/mod/lkm/nomount-android16-6.12.ko"
	# insmod takes only a file named in LOADS; nm answers once something went in.
	printf '#!/bin/sh\ncase " %s " in *" $(basename "$1") "*) : > "%s"; exit 0 ;; esac\necho "insmod: ERROR: could not insert module $1: Exec format error" >&2\nexit 1\n' \
		"$1" "$WORK/b/loaded" > "$WORK/b/bin/insmod"
	printf '#!/bin/sh\nexit 1\n' > "$WORK/b/bin/rmmod"
	printf '#!/bin/sh\n[ -e "%s" ] && echo "36 1.36.2"\n' "$WORK/b/loaded" > "$WORK/b/mod/bin/arm64-v8a/nm"
	chmod 755 "$WORK/b/bin/insmod" "$WORK/b/bin/rmmod" "$WORK/b/mod/bin/arm64-v8a/nm"
}
blog() { grep -c -- "$1" "$WORK/b/nm/boot.log" 2>/dev/null || true; }

boot_setup ""
boot_load
check "boot: a failed load logs each candidate it tried" "$(blog 'trying android16-6.12 (exact KMI match)')" "1"
check "  and what insmod said" "$(blog 'insmod: ERROR: could not insert module')" "1"
check "  and the kernel's reason" "$(blog 'kernel: nomount: disagrees about version of symbol module_layout')" "1"

boot_setup "nomount.ko.prev"
printf 'nomount_variant=lkm\000vermagic=6.12.52-4k SMP\0001.36.2\000' > "$WORK/b/nm/nomount.ko.prev"
boot_load
check "boot: a load of the copy kept before the update is a warning, naming both builds" \
	"$(blog '⚠ engine module loaded from the copy kept before this update (engine 36 1.36.2), not this zip.s (1.36.7)')" "1"
check "  not the line a normal load logs" "$(blog 'engine module loaded from previous')" "0"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
