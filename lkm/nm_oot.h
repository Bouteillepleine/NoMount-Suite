#ifndef _NM_OOT_H
#define _NM_OOT_H

#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

unsigned long nm_oot_lookup(const char *name);

int nm_oot_resolve_all(void);

#define NM_SYM(name, ret, params, args)                       \
    extern ret (*nm_p_##name) params;                         \
    static inline ret nm_s_##name params { return nm_p_##name args; } \

#endif
