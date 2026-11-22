/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_GHOST_H
#define _LINUX_GHOST_H

#include <linux/types.h>

struct path;
struct vfsmount;

bool ghost_hidden_path(const struct path *path);
/* ghost_name_ignorable() has no caller in EITHER tree any more. nm_gp_open_entry()
 * moved to ghost_hidden_name() below, and the in-tree side was checked rather than
 * guessed at: no patch in Bouteillepleine/kernel_patches@main:common/_ghost references
 * it (ghost_hidden_mount(), by contrast, is called from ghost_mountinfo_5_10.patch,
 * ghost_mountinfo_6_12.patch and ghost_statmount_6_12.patch). Kept non-static only so
 * this file stays byte-identical to the in-tree copy; it can go in a later sweep of
 * both. */
bool ghost_name_ignorable(const char *p);
bool ghost_hidden_name(const char *name);
bool ghost_hidden_mount(struct vfsmount *mnt);

bool ghost_abstract_hidden(const char *name, int len);
bool ghost_uid_concealed(u32 uid);
bool ghost_uid_task_hidden(u32 uid);

int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);

#endif
