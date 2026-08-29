/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The symbol table shared by the two halves of the .kpm.
 *
 * nm_kpm_entry.c fills this array in at load time by asking KernelPatch to look
 * each name up in kallsyms; nm_kpm_shim.h turns the engine's calls into typed
 * calls through it. Both halves have to agree on the indices, which is the whole
 * reason this enum sits in its own header rather than in either .c file.
 *
 * The contents are DERIVED, not invented. Regenerate with:
 *
 *     make -C kpm undefined
 *
 * or read the artifact from the "KPM — symbol survey" workflow, which runs that
 * target against every supported kernel. The list is per-KMI: a symbol present
 * on 6.1 may be absent or renamed on 5.4, which is why entries carry an
 * alternate name and an optional flag rather than one spelling assumed to hold.
 */
#ifndef _NM_KPM_SYMS_H
#define _NM_KPM_SYMS_H

enum nm_kpm_sym {
	/*
	 * Populated from `make undefined`. Empty on purpose right now: an
	 * invented list would compile and then fault at load on the first
	 * symbol nobody checked. See kpm/README.md for what remains.
	 */
	NM_KPM_SYM_COUNT
};

extern void *nm_kpm_sym[NM_KPM_SYM_COUNT];

#endif /* _NM_KPM_SYMS_H */
