#ifndef _NM_KPM_SHIM_H
#define _NM_KPM_SHIM_H

#include "nm_kpm_syms.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#error "KPM targets kernel 6.6 and older: KernelPatch does not boot on 6.12+."
#endif

#define init_net (*(typeof(&init_net))nm_kpm_sym[NMS_init_net])

#undef kmalloc
#undef kzalloc
#undef kmalloc_array
#undef kcalloc
#define kmalloc(sz, fl)		__kmalloc((sz), (fl))
#define kzalloc(sz, fl)		__kmalloc((sz), (fl) | __GFP_ZERO)
#define kmalloc_array(n, sz, fl)	__kmalloc((n) * (sz), (fl))
#define kcalloc(n, sz, fl)	__kmalloc((n) * (sz), (fl) | __GFP_ZERO)

#define ghost_ctl (*nm_w_ghost_ctl)
#define ghost_get_rule (*nm_w_ghost_get_rule)

#endif
