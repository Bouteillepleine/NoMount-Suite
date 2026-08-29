// SPDX-License-Identifier: GPL-2.0
/*
 * kallsyms bootstrap for the out-of-tree build. See nm_oot.h.
 *
 * Deliberately a separate translation unit from nomount_lkm.c: that one
 * includes the engine wholesale, and the engine #defines and statics have no
 * business being in scope while this file talks to kprobes.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "nm_oot.h"

static unsigned long (*nm_kln)(const char *name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
/*
 * kallsyms_lookup_name() is no longer exported. Register a kprobe on it purely
 * to learn its address, then unregister -- the probe is never allowed to fire.
 *
 * CONFIG_KPROBES is not optional for this build. A kernel without it cannot
 * reach the symbol at all, and saying so at load time is better than a module
 * that inserts and then oopses on its first dcache call.
 */
static int nm_bootstrap_kln(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);

    if (ret < 0) {
        pr_err("nomount: cannot probe kallsyms_lookup_name (%d). "
               "This build needs CONFIG_KPROBES=y to resolve the kernel "
               "functions the engine calls but the kernel does not export.\n",
               ret);
        return ret;
    }
    nm_kln = (void *)kp.addr;
    unregister_kprobe(&kp);
    return nm_kln ? 0 : -ENOENT;
}
#else
static int nm_bootstrap_kln(void)
{
    nm_kln = (void *)kallsyms_lookup_name;   /* still exported before 5.7 */
    return 0;
}
#endif

unsigned long nm_oot_lookup(const char *name)
{
    unsigned long addr;

    if (!nm_kln && nm_bootstrap_kln() < 0)
        return 0;

    addr = nm_kln(name);
    if (!addr)
        pr_err("nomount: kernel symbol '%s' not found. The engine calls it and "
               "this kernel does not export it, so the module cannot load "
               "against this build.\n", name);
    return addr;
}

/* Names in the order of enum nm_oot_sym. */
static const char *const nm_oot_names[NM_OOT_SYM_COUNT] = {
    "vfs_getxattr",
    "vfs_setxattr",
    "free_inode_nonrcu",
    "netlink_rcv_skb",
    "security_inode_getsecctx",
    "security_inode_notifysecctx",
};

int nm_oot_resolve_all(void)
{
    int i;

    if (!nm_kln && nm_bootstrap_kln() < 0)
        return -ENOENT;

    /*
     * These six are EXPORT_SYMBOL'd in the kernel source but absent from every
     * android/abi_gki_aarch64* list, so a GKI kernel built with
     * CONFIG_TRIM_UNUSED_KSYMS drops their exports. kallsyms still knows them --
     * trimming removes the export, not the symbol -- which is what makes a
     * KMI-portable module possible at all.
     *
     * Resolving them here, before the engine's init runs, is the whole reason
     * nomount_lkm.c intercepts fs_initcall(). A NULL left in the table would
     * become a branch to zero the first time the engine touched an xattr.
     */
    for (i = 0; i < NM_OOT_SYM_COUNT; i++) {
        unsigned long addr = nm_oot_lookup(nm_oot_names[i]);

        if (!addr)
            return -ENOENT;
        nm_oot_sym[i] = (void *)addr;
    }
    return 0;
}
