/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Symbol redirects for the KernelPatch build.
 *
 * WHY THIS IS BIGGER THAN THE LKM'S SHIM (which is empty):
 *
 * A .kpm is not loaded by the kernel's module loader. It gets no relocation
 * against the kernel's export table, so EVERY external symbol the engine calls
 * has to be resolved by KernelPatch through kallsyms at load time -- not just
 * the ones the kernel declines to export. The LKM's finding that "no symbol
 * needs a redirect" is true for a module and does not transfer here.
 *
 * The authoritative list is produced by the build itself:
 *
 *     make -C kpm undefined
 *
 * which runs `nm -u` over the compiled engine object. That is exact, unlike
 * scraping modpost, which caps its output ("suppressed 90 unresolved symbol
 * warnings") and so under-reports.
 */
#ifndef _NM_KPM_SHIM_H
#define _NM_KPM_SHIM_H

#include "nm_kpm_syms.h"

/* KernelPatch does not come up on 6.12+ -- it hangs in its own pagetable
 * bring-up, so a module built for it could never load. Fail at compile time
 * rather than ship something that bootloops. See kpm/README.md. */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#error "KPM targets kernel 6.6 and older: KernelPatch does not boot on 6.12+."
#endif

#define NM_SYM(i, type) ((type)nm_kpm_sym[(i)])

/* One typed redirect per symbol, filled in from `make undefined`. Each needs a
 * signature that is correct for the TARGET KMI -- several changed inside the
 * supported range (vfs_getxattr and vfs_setxattr took a mnt_idmap/user_namespace
 * argument at 5.12 and again at 6.3), so these are per-version where required
 * rather than one spelling assumed to hold across five kernels. */

#endif /* _NM_KPM_SHIM_H */
