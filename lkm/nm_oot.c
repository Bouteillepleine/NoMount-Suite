#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "nm_oot.h"

static unsigned long (*nm_kln)(const char *name);

/* The kprobe route on every kernel, not only 5.7 and newer.
 *
 * There used to be a second arm below 5.7 that took the address of
 * kallsyms_lookup_name directly, on the grounds that the export was still there
 * - 5.7 is where upstream removed it. That is not true of every tree: on
 * android-4.19-stable the function is defined in kernel/kallsyms.c and carries
 * no EXPORT_SYMBOL at all, so the module referenced a symbol that tree does not
 * export and could never have linked against a fully built 4.19. It went
 * unnoticed because the symbol gate read the ten names modpost prints before it
 * suppresses the rest, and this was never among them.
 *
 * Nothing is lost by dropping that arm. Every guard in this module is a kprobe,
 * so CONFIG_KPROBES is already a hard requirement rather than a nicety, and the
 * message below is the one a kernel without it already got.
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

unsigned long nm_oot_lookup_opt(const char *name)
{
    if (!nm_kln && nm_bootstrap_kln() < 0)
        return 0;

    return nm_kln(name);
}

unsigned long nm_oot_lookup(const char *name)
{
    unsigned long addr = nm_oot_lookup_opt(name);

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

    return 0;
}
