/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GHOST_H
#define _LINUX_GHOST_H

#include <linux/types.h>

struct path;
struct vfsmount;

bool ghost_hidden_path(const struct path *path);
/* ghost_name_ignorable() has no caller in THIS tree any more -- nm_gp_open_entry()
 * moved to ghost_hidden_name() below. Kept non-static and declared here on purpose:
 * ghost.c is also vendored into the kernel tree for the in-tree build, whose _ghost
 * patch set is not in this repository, so whether anything there calls it cannot be
 * checked from here. Making it static would be a silent bet on that answer. */
bool ghost_name_ignorable(const char *p);
bool ghost_hidden_name(const char *name);
bool ghost_hidden_mount(struct vfsmount *mnt);

bool ghost_abstract_hidden(const char *name, int len);
bool ghost_uid_concealed(u32 uid);
bool ghost_uid_task_hidden(u32 uid);

int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);

#endif
