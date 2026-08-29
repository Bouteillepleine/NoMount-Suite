// SPDX-License-Identifier: GPL-2.0
/*
 * KernelPatch module entry for NoMount.
 *
 * This half is compiled against the KernelPatch SDK headers ONLY (KP_FLAGS in
 * the Makefile). It must not include kernel headers: the SDK ships its own
 * ktypes and the two definitions of the same names do not agree.
 *
 * Its whole job is to populate nm_kpm_sym[] before the engine runs, because a
 * .kpm gets no relocation against the kernel's export table -- see the comment
 * on the `undefined` target in the Makefile.
 */
#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <ktypes.h>
#include <baselib.h>
#include <kputils.h>
#include <log.h>

#include "nm_kpm_syms.h"

KPM_NAME("nomount");
KPM_VERSION("1.26.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("XxxY");
KPM_DESCRIPTION("NoMount Prism VFS engine (KernelPatch module build)");

void *nm_kpm_sym[NM_KPM_SYM_COUNT];

/* Defined in nm_engine.c, which is the half that CAN see kernel headers. Kept to
 * plain types so this file never needs one. */
extern long nm_engine_init(void);
extern void nm_engine_exit(void);

struct nm_sym_ent {
	int idx;
	const char *name;
	const char *alt;	/* renamed on some KMIs; tried if name misses */
	int optional;		/* absent here is survivable, not fatal */
};

static const struct nm_sym_ent nm_syms[] = {
	/*
	 * Filled from `make -C kpm undefined`. Deliberately empty: see
	 * nm_kpm_syms.h. With no entries nm_kpm_init below resolves nothing and
	 * reports that plainly rather than pretending the module is ready.
	 */
};

/* Resolve every entry, and say exactly which ones failed. A KPM that loads with
 * half its symbols NULL faults later at a call site with no context; failing
 * here names the symbol instead. */
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
			pr_err("nomount: kpm: required symbol not found: %s\n", e->name);
			missing++;
		}
		nm_kpm_sym[e->idx] = p;
	}
	return missing;
}

static long nm_kpm_init(const char *args, const char *event, void *__user reserved)
{
	long missing;

	if (NM_KPM_SYM_COUNT == 0) {
		/* The port is not finished. Refuse rather than load an engine
		 * whose every external call goes through a NULL pointer. */
		pr_err("nomount: kpm: symbol table is empty; this build is scaffolding, not a module\n");
		return -1;
	}

	missing = nm_kpm_resolve();
	if (missing) {
		pr_err("nomount: kpm: %ld required symbols missing, refusing to start\n", missing);
		return -1;
	}

	pr_info("nomount: kpm: %d symbols resolved\n", NM_KPM_SYM_COUNT);
	return nm_engine_init();
}

static long nm_kpm_exit(void *__user reserved)
{
	nm_engine_exit();
	return 0;
}

KPM_INIT(nm_kpm_init);
KPM_EXIT(nm_kpm_exit);
