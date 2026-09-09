// SPDX-License-Identifier: GPL-2.0
#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <ktypes.h>
#include <baselib.h>
#include <kputils.h>
#include <log.h>
#include <hook.h>

#include "nm_kpm_syms.h"

KPM_NAME("nomount");
KPM_VERSION("1.26.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("XxxY");
KPM_DESCRIPTION("NoMount Prism VFS engine (KernelPatch module build)");

void *nm_kpm_sym[NM_KPM_SYM_COUNT];

extern long nm_engine_init(void);
extern void nm_engine_exit(void);

extern void nm_maps_note_vma(void *vma);
extern int nm_maps_apply(unsigned long *dev, unsigned long *ino);
extern void nm_maps_reset(void);

struct nm_sym_ent {
	int idx;
	const char *name;
	const char *alt;
	int optional;
};

static const struct nm_sym_ent nm_syms[] = {
#include "nm_kpm_table.h"
};

static long nm_kpm_resolve(void)
{
	unsigned long i;
	long missing = 0;

	for (i = 0; i < sizeof(nm_syms) / sizeof(nm_syms[0]); i++) {
		const struct nm_sym_ent *e = &nm_syms[i];
		void *p = (void *)kallsyms_lookup_name(e->name);

		if (!p && e->alt)
			p = (void *)kallsyms_lookup_name(e->alt);

		if (!p && !e->optional) {
			logke("nomount: kpm: required symbol not found: %s\n", e->name);
			missing++;
		}
		nm_kpm_sym[e->idx] = p;
	}
	return missing;
}

static void *nm_hook_map_vma;
static void *nm_hook_hdr_prefix;

static void nm_before_map_vma(hook_fargs2_t *args, void *udata)
{
	nm_maps_note_vma((void *)args->arg1);
}

static void nm_before_hdr_prefix(hook_fargs7_t *args, void *udata)
{
	unsigned long dev = (unsigned long)args->arg5;
	unsigned long ino = (unsigned long)args->arg6;

	if (nm_maps_apply(&dev, &ino)) {
		args->arg5 = dev;
		args->arg6 = ino;
	}
}

static void nm_maps_hooks_install(void)
{
	hook_err_t err;

	nm_hook_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
	nm_hook_hdr_prefix = (void *)kallsyms_lookup_name("show_vma_header_prefix");

	if (!nm_hook_map_vma || !nm_hook_hdr_prefix) {
		logkw("nomount: maps spoof off: show_map_vma=%llx show_vma_header_prefix=%llx "
		      "(inlined on this kernel?)\n",
		      (unsigned long long)nm_hook_map_vma,
		      (unsigned long long)nm_hook_hdr_prefix);
		nm_hook_map_vma = nm_hook_hdr_prefix = 0;
		return;
	}

	err = hook_wrap2(nm_hook_map_vma, nm_before_map_vma, 0, 0);
	if (err) {
		logkw("nomount: maps spoof off: cannot wrap show_map_vma (%d)\n", err);
		nm_hook_map_vma = nm_hook_hdr_prefix = 0;
		return;
	}

	err = hook_wrap7(nm_hook_hdr_prefix, nm_before_hdr_prefix, 0, 0);
	if (err) {
		logkw("nomount: maps spoof off: cannot wrap show_vma_header_prefix (%d)\n", err);
		hook_unwrap(nm_hook_map_vma, nm_before_map_vma, 0);
		nm_hook_map_vma = nm_hook_hdr_prefix = 0;
		return;
	}

	logki("nomount: maps spoof active\n");
}

static void nm_maps_hooks_remove(void)
{
	if (nm_hook_hdr_prefix) {
		hook_unwrap(nm_hook_hdr_prefix, nm_before_hdr_prefix, 0);
		nm_hook_hdr_prefix = 0;
	}
	if (nm_hook_map_vma) {
		hook_unwrap(nm_hook_map_vma, nm_before_map_vma, 0);
		nm_hook_map_vma = 0;
	}
	nm_maps_reset();
}

static long nm_kpm_init(const char *args, const char *event, void *__user reserved)
{
	long missing, rc;

	missing = nm_kpm_resolve();
	if (missing) {
		logke("nomount: kpm: %ld required symbols missing, refusing to start\n", missing);
		return -1;
	}

	logki("nomount: kpm: %d symbols resolved\n", NM_KPM_SYM_COUNT);

	rc = nm_engine_init();
	if (rc)
		return rc;

	nm_maps_hooks_install();
	return 0;
}

static long nm_kpm_exit(void *__user reserved)
{
	nm_maps_hooks_remove();
	nm_engine_exit();
	return 0;
}

KPM_INIT(nm_kpm_init);
KPM_EXIT(nm_kpm_exit);
