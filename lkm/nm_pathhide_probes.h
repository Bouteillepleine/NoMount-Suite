#ifndef _NM_PATHHIDE_PROBES_H
#define _NM_PATHHIDE_PROBES_H

#include <linux/types.h>

int nm_pathhide_ctl_fwd(const char *buf, size_t count);
int nm_pathhide_get_rule_fwd(int idx, char *out, size_t outsz);

int nm_pathhide_probes_init(void);
void nm_pathhide_probes_exit(void);

#endif
