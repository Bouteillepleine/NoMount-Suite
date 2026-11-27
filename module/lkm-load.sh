#!/system/bin/sh

: "${NM_LKM_NM:=}"
: "${NM_LKM_DEVICE_KO:=/data/adb/nomount/nomount.ko}"
: "${NM_LKM_KALLSYMS:=/proc/kallsyms}"
NM_LKM_SOURCE=
NM_LKM_NOMATCH=

nm_lkm_probe() {
	[ -x "$NM_LKM_NM" ] || return 1
	[ -n "$("$NM_LKM_NM" v 2>/dev/null | tr -dc '0-9')" ]
}

nm_lkm_kver() { uname -r | cut -d. -f1,2; }
nm_lkm_akver() { uname -r | grep -oE 'android[0-9]+' | head -1; }
nm_lkm_kmi() { _ka=$(nm_lkm_akver); [ -n "$_ka" ] && echo "$_ka-$(nm_lkm_kver)"; }

# ko-loader resolves the module's imports out of kallsyms. With kptr_restrict hiding the
# addresses every one reads as 0, and the module's init calls through a null pointer.
nm_lkm_kallsyms_ok() {
	_ka=$(head -n 1 "$NM_LKM_KALLSYMS" 2>/dev/null | cut -d' ' -f1)
	case "$_ka" in ''|*[!0]*) [ -n "$_ka" ] ;; *) return 1 ;; esac
}

nm_lkm_echo() {
	[ -n "$1" ] || return 0
	printf '%s\n' "$1" | while IFS= read -r _line; do
		[ -n "$_line" ] && $NM_LKM_SAY "    $_line"
	done
}

# 0  it loaded and the engine answers.
# 2  it loaded, but nm_lkm_probe did not answer. A module only loads at all if
#    nomount_init() returned 0, which means the netlink socket is up - so the
#    ENGINE IS LIVE and what is broken is the probe: bin/<abi>/nm missing, built
#    for another ABI, or not executable after extraction. Reporting that as "no
#    module loads on this kernel" sent people to rebuild a kernel that was fine.
# 1  nothing went in. Try the next candidate.
#
# `rmmod nomount` between the attempts is kept for a dev build (`hide=0`) and is
# a no-op on a default one, which unlinks itself from the module list so rmmod
# cannot find it. It stays because removing it would change which attempts run,
# and the attempts after a successful load fail harmlessly either way: a second
# insmod of a live engine is refused on the netlink socket.
# $2 = "strict" -> do not use ko-loader for this module.
#
# ko-loader rewrites the module's vermagic to whatever the kernel asks for AND
# pre-resolves its undefined symbols out of /proc/kallsyms, writing each address
# in as SHN_ABS. simplify_symbols() only version-checks SHN_UNDEF symbols, so a
# pre-resolved one skips check_version() entirely. ksud insmod does the same two
# things. What is left is the module's own module_layout CRC and, on 6.6+, the
# size of struct module.
#
# That is the intended mechanism for a module whose KMI matches -- a stock
# android16-6.12 .ko can never match a specific device's 6.12.x-android16-ab...
# build string, and "same KMI => same layout" is the GKI contract. It is NOT
# intended for a module picked by guessing the KMI, which is what the "same
# version, other KMI" fallback in nm_lkm_load_best does, and only ever can on
# 5.10 and 5.15 -- the two versions shipping two KMIs each (android12/13 and
# android13/14). There the rewrite forces in a module built across a KABI
# boundary. Strict mode leaves that path with plain insmod, which checks every
# symbol CRC (a MODVERSIONS kernel skips the version in vermagic), so the fallback
# still works where it legitimately should (a custom kernel whose uname carries no
# androidNN, so no exact match exists, but whose KMI genuinely matches a shipped module).
nm_lkm_insert() {
	_ko="$1"
	_strict="${2:-}"
	[ -f "$_ko" ] || return 1
	_out=""

	if [ "$_strict" != strict ] && command -v ksud >/dev/null 2>&1 &&
	   ksud -h 2>&1 | grep -qE '(^|[[:space:]])insmod([[:space:]]|$)'; then
		if ksud insmod "$_ko" >/dev/null 2>&1; then
			nm_lkm_probe && return 0
			return 2
		fi
		rmmod nomount 2>/dev/null
	fi

	if [ "$_strict" = strict ]; then
		$NM_LKM_SAY "    not using ko-loader or ksud insmod here: this module's KMI was guessed"
		$NM_LKM_SAY "    from the kernel version alone, and both bypass the symbol CRC checks"
		$NM_LKM_SAY "    the kernel has against a module built for another struct layout"
	fi

	if [ "$_strict" != strict ] && [ -x "$NM_LKM_LOADER" ] && ! nm_lkm_kallsyms_ok; then
		$NM_LKM_SAY "    not using ko-loader: $NM_LKM_KALLSYMS shows no addresses here, and it would bind every import to 0"
	elif [ "$_strict" != strict ] && [ -x "$NM_LKM_LOADER" ]; then
		# ko-loader is the only step that can rewrite vermagic, so its output is
		# the one line that explains why a module did or did not go in. Throwing
		# it away left an install log with two "trying" lines and no reason.
		if _out=$("$NM_LKM_LOADER" "$_ko" 2>&1); then
			nm_lkm_echo "$_out"
			nm_lkm_probe && return 0
			return 2
		else
			nm_lkm_echo "$_out"
		fi
		rmmod nomount 2>/dev/null
	fi

	if command -v insmod >/dev/null 2>&1; then
		if _out=$(insmod "$_ko" 2>&1); then
			nm_lkm_probe && return 0
			return 2
		else
			nm_lkm_echo "$_out"
		fi
		rmmod nomount 2>/dev/null
	fi

	return 1
}

# Keep the module that worked OUTSIDE the module directory. Caching it inside
# $MODDIR looks tidier, but a module update replaces that directory: a user on
# a kernel with no built-in engine who updates to the lite zip would lose both
# the bundled set and the cached pick, and stop injecting with nothing to show
# for it. $NM_LKM_DEVICE_KO survives updates and is searched first anyway.
nm_lkm_keep() {
	_src="$1"; _dir="$2"; _kstrict="${3:-}"
	if [ -d "${NM_LKM_DEVICE_KO%/*}" ] || mkdir -p "${NM_LKM_DEVICE_KO%/*}" 2>/dev/null; then
		if cp -f "$_src" "$NM_LKM_DEVICE_KO" 2>/dev/null; then
			chmod 0600 "$NM_LKM_DEVICE_KO" 2>/dev/null
			# What it was picked for: after a kernel change, or for a guessed KMI, it must not
			# be the first candidate tried without the strict checks.
			printf 'kver=%s\nkmi=%s\nstrict=%s\n' "$(uname -r)" "$(nm_lkm_kmi)" \
				"$([ "$_kstrict" = strict ] && echo 1 || echo 0)" > "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null
			rm -f "$NM_LKM_DEVICE_KO.prev" 2>/dev/null
			$NM_LKM_SAY "  kept it at $NM_LKM_DEVICE_KO so an update cannot remove it"
			return 0
		fi
	fi
	# Could not write outside the module: fall back to the in-module cache.
	mv -f "$_src" "$_dir/nomount.ko" 2>/dev/null
}

# A kept bundled copy must not shadow a newer bundled set: an update sets it aside as
# .prev, tried last. Copies from before the marker existed carry a stock GKI vermagic,
# where a module built for this kernel carries its exact release; $1=recovery skips that test.
nm_lkm_retire_kept() {
	[ -f "$NM_LKM_DEVICE_KO" ] || return 0
	if [ ! -f "$NM_LKM_DEVICE_KO.bundled" ]; then
		[ "${1:-}" = recovery ] && return 0
		tr '\0' '\n' < "$NM_LKM_DEVICE_KO" 2>/dev/null | grep -aqx 'nomount_variant=lkm' || return 0
		_vm=$(tr '\0' '\n' < "$NM_LKM_DEVICE_KO" 2>/dev/null | grep -a -m1 '^vermagic=' | cut -d= -f2 | cut -d' ' -f1)
		[ -n "$_vm" ] && [ "$_vm" != "$(uname -r)" ] || return 0
	fi
	mv -f "$NM_LKM_DEVICE_KO" "$NM_LKM_DEVICE_KO.prev" 2>/dev/null || return 0
	rm -f "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null
	$NM_LKM_SAY "  set the engine module kept by the previous install aside; this one's loads first"
}

nm_lkm_load_best() {
	_dir="$1"
	_kver=$(nm_lkm_kver)
	_akver=$(nm_lkm_akver)
	_exact="$_dir/nomount-${_akver}-${_kver}.ko"

	# A kernel-supplied module outranks everything else. On a custom kernel the
	# bundled per-KMI builds carry a stock GKI vermagic and cannot load at all,
	# and after a kernel update a previously selected one is stale for the same
	# reason - so this is tried first, every boot, and never cached over.
	# A load that the probe could not confirm (2) is still a load: stop, and
	# hand the caller the code so it can say which of the two happened.
	_kept=""; _kstrict=""; _restamp=""
	if [ -f "$NM_LKM_DEVICE_KO" ]; then
		if [ -f "$NM_LKM_DEVICE_KO.bundled" ]; then
			_kk=$(sed -n 's/^kver=//p' "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null)
			_kkmi=$(sed -n 's/^kmi=//p' "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null)
			[ "$(sed -n 's/^strict=//p' "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null)" = 1 ] && _kstrict=strict
			# Same KMI, new point release (a monthly OTA): the GKI contract keeps the layout, and
			# module_layout refuses the copy if it did not. Only a KMI change makes it a guess.
			if [ "$_kk" != "$(uname -r)" ] && [ -n "$_kkmi" ] && [ "$_kkmi" = "$(nm_lkm_kmi)" ] && [ -z "$_kstrict" ]; then
				$NM_LKM_SAY "  trying $NM_LKM_DEVICE_KO (kept for $_kkmi, this kernel's KMI)"
				_restamp=1
			elif [ "$_kk" != "$(uname -r)" ]; then
				_kept=stale
				$NM_LKM_SAY "  the kept module was picked for ${_kk:-another kernel}: trying the bundled set first"
			else
				$NM_LKM_SAY "  trying $NM_LKM_DEVICE_KO (kept from an earlier install)"
			fi
		else
			$NM_LKM_SAY "  trying $NM_LKM_DEVICE_KO (kernel-supplied)"
		fi
		if [ "$_kept" != stale ]; then
			nm_lkm_insert "$NM_LKM_DEVICE_KO" $_kstrict; _rc=$?
			if [ "$_rc" != 1 ]; then
				NM_LKM_SOURCE=device
				[ "${_restamp:-}" = 1 ] && printf 'kver=%s\nkmi=%s\nstrict=0\n' "$(uname -r)" "$(nm_lkm_kmi)" \
					> "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null
				return "$_rc"
			fi
		fi
	fi

	if [ ! -d "$_dir" ]; then
		nm_lkm_try_kept_stale && return 0
		[ "$_rc" = 2 ] && return 2
		nm_lkm_try_prev
		return
	fi

	# The one picked on an earlier boot. Falling through when it fails is the
	# point: a kernel update invalidates it and the search has to carry on.
	if [ -f "$_dir/nomount.ko" ]; then
		$NM_LKM_SAY "  trying the module selected on an earlier boot"
		nm_lkm_insert "$_dir/nomount.ko"; _rc=$?
		if [ "$_rc" != 1 ]; then
			NM_LKM_SOURCE=cached
			return "$_rc"
		fi
		rm -f "$_dir/nomount.ko" 2>/dev/null
	fi

	if [ ! -f "$_exact" ] && ! ls "$_dir"/nomount-*-"${_kver}".ko >/dev/null 2>&1; then
		# shellcheck disable=SC2034  # read by lib.sh and customize.sh, which source this file
		NM_LKM_NOMATCH=1
		$NM_LKM_SAY "  this zip has no engine module for ${_akver:-this kernel}-${_kver}"
	fi
	if [ -n "$_akver" ] && [ -f "$_exact" ]; then
		$NM_LKM_SAY "  trying ${_akver}-${_kver} (exact KMI match)"
		nm_lkm_insert "$_exact"; _rc=$?
		if [ "$_rc" != 1 ]; then
			nm_lkm_keep "$_exact" "$_dir"
			NM_LKM_SOURCE=bundled
			return "$_rc"
		fi
	fi

	for _ko in "$_dir"/nomount-*-"${_kver}".ko; do
		[ -f "$_ko" ] || continue
		[ "$_ko" = "$_exact" ] && continue
		$NM_LKM_SAY "  trying $(basename "$_ko") (same version, other KMI)"
		# strict: the KMI here is a GUESS off uname's major.minor, so the kernel's
		# own vermagic check is the only thing standing between us and a module
		# built against a different task_struct. See nm_lkm_insert.
		nm_lkm_insert "$_ko" strict; _rc=$?
		if [ "$_rc" != 1 ]; then
			nm_lkm_keep "$_ko" "$_dir" strict
			NM_LKM_SOURCE=bundled
			return "$_rc"
		fi
	done

	nm_lkm_try_kept_stale && return 0
	[ "$_rc" = 2 ] && return 2
	nm_lkm_try_prev
}

# A kept module whose kernel has changed is a guess now: tried after the bundled set, strict.
nm_lkm_try_kept_stale() {
	_rc=1
	[ "$_kept" = stale ] && [ -f "$NM_LKM_DEVICE_KO" ] || return 1
	$NM_LKM_SAY "  trying $NM_LKM_DEVICE_KO, kept for another kernel (strict)"
	nm_lkm_insert "$NM_LKM_DEVICE_KO" strict; _rc=$?
	if [ "$_rc" != 1 ]; then
		NM_LKM_SOURCE=device
		printf 'kver=%s\nkmi=%s\nstrict=1\n' "$(uname -r)" "$(nm_lkm_kmi)" > "$NM_LKM_DEVICE_KO.bundled" 2>/dev/null
	fi
	[ "$_rc" = 0 ]
}

nm_lkm_try_prev() {
	[ -f "$NM_LKM_DEVICE_KO.prev" ] || return 1
	$NM_LKM_SAY "  trying the module kept before this update (nothing newer loads)"
	nm_lkm_insert "$NM_LKM_DEVICE_KO.prev"; _rc=$?
	[ "$_rc" != 1 ] && NM_LKM_SOURCE=previous
	return "$_rc"
}

nm_lkm_prune() {
	# Keep the bundled set when the kernel supplied the module: it is the only
	# fallback left if that file is gone after the next kernel.
	[ "$NM_LKM_SOURCE" = device ] && return 0
	rm -f "$1"/nomount-*.ko 2>/dev/null
}
