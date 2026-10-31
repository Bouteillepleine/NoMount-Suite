#!/system/bin/sh

: "${NM_LKM_NM:=}"
: "${NM_LKM_DEVICE_KO:=/data/adb/nomount/nomount.ko}"
NM_LKM_SOURCE=

nm_lkm_probe() {
	[ -x "$NM_LKM_NM" ] || return 1
	[ -n "$("$NM_LKM_NM" v 2>/dev/null | tr -dc '0-9')" ]
}

nm_lkm_kver() { uname -r | cut -d. -f1,2; }
nm_lkm_akver() { uname -r | grep -oE 'android[0-9]+' | head -1; }

nm_lkm_echo() {
	[ -n "$1" ] || return 0
	printf '%s\n' "$1" | while IFS= read -r _line; do
		[ -n "$_line" ] && $NM_LKM_SAY "    $_line"
	done
}

nm_lkm_insert() {
	_ko="$1"
	[ -f "$_ko" ] || return 1
	_out=""

	if command -v ksud >/dev/null 2>&1 &&
	   ksud -h 2>&1 | grep -qE '(^|[[:space:]])insmod([[:space:]]|$)'; then
		if ksud insmod "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	if [ -x "$NM_LKM_LOADER" ]; then
		# ko-loader is the only step that can rewrite vermagic, so its output is
		# the one line that explains why a module did or did not go in. Throwing
		# it away left an install log with two "trying" lines and no reason.
		if _out=$("$NM_LKM_LOADER" "$_ko" 2>&1) && nm_lkm_probe; then
			nm_lkm_echo "$_out"
			return 0
		fi
		nm_lkm_echo "$_out"
		rmmod nomount 2>/dev/null
	fi

	if command -v insmod >/dev/null 2>&1; then
		if _out=$(insmod "$_ko" 2>&1) && nm_lkm_probe; then
			return 0
		fi
		nm_lkm_echo "$_out"
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
	_src="$1"; _dir="$2"
	if [ -d "${NM_LKM_DEVICE_KO%/*}" ] || mkdir -p "${NM_LKM_DEVICE_KO%/*}" 2>/dev/null; then
		if cp -f "$_src" "$NM_LKM_DEVICE_KO" 2>/dev/null; then
			chmod 0600 "$NM_LKM_DEVICE_KO" 2>/dev/null
			$NM_LKM_SAY "  kept it at $NM_LKM_DEVICE_KO so an update cannot remove it"
			return 0
		fi
	fi
	# Could not write outside the module: fall back to the in-module cache.
	mv -f "$_src" "$_dir/nomount.ko" 2>/dev/null
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
	if [ -f "$NM_LKM_DEVICE_KO" ]; then
		$NM_LKM_SAY "  trying $NM_LKM_DEVICE_KO (kernel-supplied)"
		if nm_lkm_insert "$NM_LKM_DEVICE_KO"; then
			NM_LKM_SOURCE=device
			return 0
		fi
	fi

	[ -d "$_dir" ] || return 1

	# The one picked on an earlier boot. Falling through when it fails is the
	# point: a kernel update invalidates it and the search has to carry on.
	if [ -f "$_dir/nomount.ko" ]; then
		$NM_LKM_SAY "  trying the module selected on an earlier boot"
		if nm_lkm_insert "$_dir/nomount.ko"; then
			NM_LKM_SOURCE=cached
			return 0
		fi
		rm -f "$_dir/nomount.ko" 2>/dev/null
	fi

	if [ -n "$_akver" ] && [ -f "$_exact" ]; then
		$NM_LKM_SAY "  trying ${_akver}-${_kver} (exact KMI match)"
		if nm_lkm_insert "$_exact"; then
			nm_lkm_keep "$_exact" "$_dir"
			NM_LKM_SOURCE=bundled
			return 0
		fi
	fi

	for _ko in "$_dir"/nomount-*-"${_kver}".ko; do
		[ -f "$_ko" ] || continue
		[ "$_ko" = "$_exact" ] && continue
		$NM_LKM_SAY "  trying $(basename "$_ko") (same version, other KMI)"
		if nm_lkm_insert "$_ko"; then
			nm_lkm_keep "$_ko" "$_dir"
			NM_LKM_SOURCE=bundled
			return 0
		fi
	done

	return 1
}

nm_lkm_prune() {
	# Keep the bundled set when the kernel supplied the module: it is the only
	# fallback left if that file is gone after the next kernel.
	[ "$NM_LKM_SOURCE" = device ] && return 0
	rm -f "$1"/nomount-*.ko 2>/dev/null
}
