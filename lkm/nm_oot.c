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

int nm_oot_resolve_all(void)
{
    if (!nm_kln && nm_bootstrap_kln() < 0)
        return -ENOENT;

    /*
     * Nothing to resolve yet. The redirect list in nm_oot.h is empty until the
     * linker has named the symbols that actually need one -- see the note there
     * and the `undefined symbols` step in the build workflow. Resolving a
     * guessed list would report success for a set nobody verified.
     */
    return 0;
}
