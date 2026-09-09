#!/system/bin/sh

: "${NM_LKM_NM:=}"

nm_lkm_probe() {
	[ -x "$NM_LKM_NM" ] || return 1
	[ -n "$("$NM_LKM_NM" v 2>/dev/null | tr -dc '0-9')" ]
}

nm_lkm_kver() { uname -r | cut -d. -f1,2; }
nm_lkm_akver() { uname -r | grep -oE 'android[0-9]+' | head -1; }

nm_lkm_insert() {
	_ko="$1"
	[ -f "$_ko" ] || return 1

	if command -v ksud >/dev/null 2>&1 &&
	   ksud -h 2>&1 | grep -qE '(^|[[:space:]])insmod([[:space:]]|$)'; then
		if ksud insmod "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	if [ -x "$NM_LKM_LOADER" ]; then
		if "$NM_LKM_LOADER" "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	if command -v insmod >/dev/null 2>&1; then
		if insmod "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	return 1
}

nm_lkm_load_best() {
	_dir="$1"
	_kver=$(nm_lkm_kver)
	_akver=$(nm_lkm_akver)
	_exact="$_dir/nomount-${_akver}-${_kver}.ko"

	[ -d "$_dir" ] || return 1

	if [ -n "$_akver" ] && [ -f "$_exact" ]; then
		$NM_LKM_SAY "  trying ${_akver}-${_kver} (exact KMI match)"
		if nm_lkm_insert "$_exact"; then
			mv -f "$_exact" "$_dir/nomount.ko" 2>/dev/null
			return 0
		fi
	fi

	for _ko in "$_dir"/nomount-*-"${_kver}".ko; do
		[ -f "$_ko" ] || continue
		[ "$_ko" = "$_exact" ] && continue
		$NM_LKM_SAY "  trying $(basename "$_ko") (same version, other KMI)"
		if nm_lkm_insert "$_ko"; then
			mv -f "$_ko" "$_dir/nomount.ko" 2>/dev/null
			return 0
		fi
	done

	return 1
}

nm_lkm_prune() {
	rm -f "$1"/nomount-*.ko 2>/dev/null
}
