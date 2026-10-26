/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GHOST_H
#define _LINUX_GHOST_H

#include <linux/types.h>

struct path;
struct vfsmount;

bool ghost_hidden_path(const struct path *path);
bool ghost_hidden_mount(struct vfsmount *mnt);

bool ghost_abstract_hidden(const char *name, int len);
bool ghost_uid_concealed(u32 uid);
bool ghost_uid_task_hidden(u32 uid);

int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);

#endif
