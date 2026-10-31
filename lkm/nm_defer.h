/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NM_DEFER_H
#define _NM_DEFER_H

#include <linux/types.h>

struct path;

bool nm_path_put_deferred(struct path *path);
unsigned long nm_defer_overflows(void);
void nm_defer_exit(void);

#endif
