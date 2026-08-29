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
 * THE REDIRECT LIST IS EMPTY, AND THAT IS THE MEASURED ANSWER.
 *
 * Every function the engine calls is available to a module on every GKI KMI.
 * That was checked against the real thing: build-lkm-kmi.yml builds inside the
 * Android DDK containers, whose $KDIR carries the actual Module.symvers of a
 * released GKI kernel (14000-17000 symbols depending on generation), and the
 * module links against all seven with nothing undefined.
 *
 * TWO WRONG ANSWERS WERE REACHED FIRST. Both are recorded because each looks
 * convincing:
 *
 *   1. "The linker says nothing is missing." True, but the compile gate runs
 *      modpost under KBUILD_MODPOST_WARN=1, which downgrades every error
 *      including a missing namespace import. It cannot be used as evidence that
 *      a module would link, only that the engine still compiles.
 *
 *   2. "Six symbols are trimmed away by the GKI KMI." Reached by grepping the
 *      union of all 36 android/abi_gki_aarch64* lists (9366 symbols) and
 *      finding vfs_getxattr, vfs_setxattr, free_inode_nonrcu, netlink_rcv_skb
 *      and the two security_inode_*secctx absent. They are not absent; those
 *      lists are not the export table. The DDK's Module.symvers shows all six
 *      exported on every KMI -- several of them into a NAMESPACE
 *      (ANDROID_GKI_VFS_EXPORT_ONLY), which is exactly why a plain grep of the
 *      abi lists misses them. What they need is not a kallsyms redirect but a
 *      MODULE_IMPORT_NS, which nomount_lkm.c does.
 *
 * So NM_SYM below has no users. Keep it: if a future kernel does withhold a
 * symbol, the DDK build fails loudly with its name, and this is where the fix
 * goes. Do not populate it speculatively.
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

#endif /* _NM_OOT_H */
