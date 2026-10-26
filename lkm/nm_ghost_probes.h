#ifndef _NM_GHOST_PROBES_H
#define _NM_GHOST_PROBES_H

#include <linux/types.h>

int nm_ghost_ctl_fwd(const char *buf, size_t count);
int nm_ghost_get_rule_fwd(int idx, char *out, size_t outsz);

int nm_ghost_probes_init(void);
void nm_ghost_probes_exit(void);

#endif
