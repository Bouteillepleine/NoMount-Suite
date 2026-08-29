#!/system/bin/sh
#
# Loading the engine as a kernel module. Sourced, never executed.
#
# THIS FILE EXISTS ONLY ON THE LKM BRANCH. The supported build compiles the
# engine into the kernel (CONFIG_NOMOUNT=y) and needs none of this; here the
# engine ships as a .ko per GKI KMI generation and has to be inserted at install
# and again on every boot, because a module does not survive a reboot.
#
# Both customize.sh and metamount.sh source this rather than carrying their own
# copy. They ask the same question in different contexts, and two copies of an
# insmod path that must agree on what "loaded" means is how they stop agreeing.
#
# WHAT COUNTS AS LOADED
#
# Not the exit status of insmod. A module can insert and fail its own init --
# and this one has an init that can legitimately refuse (see nomount_init). The
# only evidence that matters is the engine answering over netlink afterwards,
# which is what nm_lkm_probe checks. Every load path below is gated on it.

# Set by the caller before sourcing: the nm netlink client for this device's ABI.
: "${NM_LKM_NM:=}"

# Does the engine answer? True whether it is built into the kernel or inserted
# as a module -- the caller uses that to decide whether to try loading at all.
nm_lkm_probe() {
	[ -x "$NM_LKM_NM" ] || return 1
	[ -n "$("$NM_LKM_NM" v 2>/dev/null | tr -dc '0-9')" ]
}

# The KMI this kernel belongs to, e.g. "android15-6.6", and the bare version.
# A module is portable across a KMI GENERATION, not a version number:
# android12-5.10 and android13-5.10 are the same version and different KMIs.
nm_lkm_kver() { uname -r | cut -d. -f1,2; }
nm_lkm_akver() { uname -r | grep -oE 'android[0-9]+' | head -1; }

# Insert one .ko and verify the engine came up. Leaves nothing loaded on failure:
# a module that inserted but did not initialise still occupies the name, and the
# next candidate would fail with EEXIST for a reason that has nothing to do with
# whether it fits this kernel.
nm_lkm_insert() {
	_ko="$1"
	[ -f "$_ko" ] || return 1

	# ksud first where it exists. KernelSU's insmod runs in a context that is
	# allowed to call init_module; a bare insmod from a module script often is
	# not, and fails on SELinux rather than on anything about the module.
	if command -v ksud >/dev/null 2>&1 &&
	   ksud -h 2>&1 | grep -qE '(^|[[:space:]])insmod([[:space:]]|$)'; then
		if ksud insmod "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	# The bundled loader, which does the init_module syscall itself.
	if [ -x "$NM_LKM_LOADER" ]; then
		if "$NM_LKM_LOADER" "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	# Last resort. Present on most builds, allowed on few.
	if command -v insmod >/dev/null 2>&1; then
		if insmod "$_ko" >/dev/null 2>&1 && nm_lkm_probe; then
			return 0
		fi
		rmmod nomount 2>/dev/null
	fi

	return 1
}

# Pick a .ko for this kernel and load it. $1 is the directory holding them.
#
# Exact KMI match first, then any module built for the same kernel version. The
# fallback is deliberate but second: a module from a neighbouring generation
# usually fails the vermagic check, and when it does not it is because the
# generations genuinely share an interface. Trying it costs one failed insmod
# and occasionally saves an install; preferring it would be reckless.
#
# Prints what it tried through the caller's $NM_LKM_SAY, so the same function
# can talk to ui_print during install and to the boot log at boot.
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

# Drop every candidate that was not the one that worked. They are ~55 KB each
# and six of the seven can never load on this device.
nm_lkm_prune() {
	rm -f "$1"/nomount-*.ko 2>/dev/null
}
