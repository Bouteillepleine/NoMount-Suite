/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Out-of-tree symbol shim for the NoMount engine.
 *
 * The engine is in-tree fs/ code, so it calls kernel functions that are never
 * EXPORT_SYMBOL'd. Built in-tree that is a direct call; built as a module the
 * link fails. Each such call is redirected here through a pointer resolved from
 * kallsyms at load time.
 *
 * INCLUDED BEFORE the engine, so these names are in scope at its call sites. It
 * must not be included anywhere else: it rewrites identifiers that mean
 * something different in any other translation unit.
 *
 * The engine is NOT forked. nomount_lkm.c includes ../hookless/src/nomount.c
 * verbatim, so there is one copy of it in this repository and this variant
 * cannot drift from the in-tree build without the drift being a compile error.
 *
 * WHAT NEEDS REDIRECTING, AND WHY IT IS NOT WHAT THE LINKER SAYS
 *
 * Against an untrimmed kernel the linker names nothing: every function the
 * engine calls is EXPORT_SYMBOL'd in source, which the ten-version compile gate
 * established. That answer is right for the kernel it was measured on and wrong
 * for the one people actually run.
 *
 * A released GKI kernel is built with CONFIG_TRIM_UNUSED_KSYMS against an
 * allow-list: only symbols named in android/abi_gki_aarch64* keep their exports.
 * Measured against the union of all 36 of those lists for android15-6.6 (9366
 * symbols), 89 of the engine's 98 are in the KMI; three of the remainder are not
 * kernel symbols at all, and six are genuinely trimmed. Those six are handled in
 * nm_oot_tramp.c, by trampoline rather than by NM_SYM -- see the note there for
 * why a signature-free redirect is worth having when three of the six changed
 * shape inside the supported range.
 *
 * NM_SYM below is kept for the case it was written for: a symbol that needs a
 * TYPED wrapper rather than a bare jump. Nothing uses it yet.
 */
#ifndef _NM_OOT_H
#define _NM_OOT_H

#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

/*
 * kallsyms_lookup_name() stopped being exported in 5.7. The supported way back
 * to it is a kprobe on the symbol itself: register, read .addr, unregister.
 *
 * A failure here is fatal to the load rather than something to limp past. A
 * half-resolved table means the engine calls a NULL pointer the first time it
 * touches the dcache, which is an oops -- not a degraded mode, and not
 * something the user could act on afterwards.
 */
unsigned long nm_oot_lookup(const char *name);

/* Resolve everything the redirect list needs. 0, or -ENOENT with the first
 * missing name in dmesg -- the one useful fact when a load fails on a kernel
 * nobody has tried yet. */
int nm_oot_resolve_all(void);

/*
 * One line per non-exported symbol, once the linker has told us which:
 *
 *   NM_SYM(kern_path, int, (const char *n, unsigned f, struct path *p), (n,f,p))
 *
 * expands to a static inline of the engine's own name, so its call sites need
 * no edit and the engine source stays untouched.
 */
#define NM_SYM(name, ret, params, args)                       \
    extern ret (*nm_p_##name) params;                         \
    static inline ret nm_s_##name params { return nm_p_##name args; } \
    /* redirect the engine's call sites at the real name */

/*
 * The trimmed six. Order is load-bearing: nm_oot_tramp.c spells these indices
 * as literals in asm, and asserts each one against this enum.
 */
enum nm_oot_sym {
	NM_OOT_vfs_getxattr,
	NM_OOT_vfs_setxattr,
	NM_OOT_free_inode_nonrcu,
	NM_OOT_netlink_rcv_skb,
	NM_OOT_security_inode_getsecctx,
	NM_OOT_security_inode_notifysecctx,
	NM_OOT_SYM_COUNT
};

extern void *nm_oot_sym[NM_OOT_SYM_COUNT];

#endif /* _NM_OOT_H */
