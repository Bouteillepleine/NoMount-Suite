/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PATHHIDE_H
#define _LINUX_PATHHIDE_H

#include <linux/types.h>

struct file;
struct mm_struct;

bool pathhide_match_file(struct file *file);
unsigned long pathhide_hidden_vm_pages(struct mm_struct *mm);

int pathhide_ctl(const char *buf, size_t count);
int pathhide_get_rule(int idx, char *out, size_t outsz);

#endif
