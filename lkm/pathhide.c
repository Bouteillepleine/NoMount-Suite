// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/percpu_counter.h>
#include <linux/cpumask.h>
#include "pathhide.h"

#ifndef PH_PROC_NAME
#define PH_PROC_NAME	"pathhide"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
#define PH_FILE_PATH(f)		file_user_path(f)
#else
#define PH_FILE_PATH(f)		(&(f)->f_path)
#endif

#define PH_MAX_RULES	64
#define PH_RULE_LEN	128

static char ph_rules[PH_MAX_RULES][PH_RULE_LEN];
static int  ph_nrules;
static DEFINE_SPINLOCK(ph_lock);

static bool ph_match_str(const char *path)
{
	bool hit = false;
	int i;

	spin_lock(&ph_lock);
	for (i = 0; i < ph_nrules; i++) {
		if (strstr(path, ph_rules[i])) {
			hit = true;
			break;
		}
	}
	spin_unlock(&ph_lock);
	return hit;
}

static DEFINE_PER_CPU(char [PATH_MAX], ph_pathbuf);

bool pathhide_match_file(struct file *file)
{
	char (*bufp)[PATH_MAX];
	char *p;
	bool hit = false;

	if (!file || !READ_ONCE(ph_nrules))
		return false;

	bufp = get_cpu_ptr(&ph_pathbuf);
	p = d_path(PH_FILE_PATH(file), *bufp, PATH_MAX);
	if (!IS_ERR(p))
		hit = ph_match_str(p);
	put_cpu_ptr(&ph_pathbuf);

	return hit;
}

static bool ph_rule_sane(const char *s)
{
	size_t len = strlen(s);
	size_t i;

	if (len < 3 || len >= PH_RULE_LEN)
		return false;
	for (i = 0; i < len; i++)
		if (s[i] != '/')
			return true;
	return false;
}

/* One entry is worth having: an ELF contributes several consecutive vmas from
 * one struct file, and each pathhide_match_file() is a d_path() render plus a
 * rule scan under a global lock. This runs for every reader of
 * /proc/<pid>/status and /proc/<pid>/statm, with mmap_read_lock held.
 */
struct ph_vm_memo {
	struct file *file;
	bool hit;
};

static bool ph_memo_match(struct ph_vm_memo *m, struct file *file)
{
	if (m->file != file) {
		m->file = file;
		m->hit = pathhide_match_file(file);
	}
	return m->hit;
}

unsigned long pathhide_hidden_vm_pages(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct ph_vm_memo memo = { NULL, false };
	unsigned long pages = 0;
	unsigned long rss, total, peak, peak_rss, room, peak_room, slack;

	if (!mm || !READ_ONCE(ph_nrules))
		return 0;
	if (mmap_read_lock_killable(mm))
		return 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	{
		VMA_ITERATOR(vmi, mm, 0);

		for_each_vma(vmi, vma)
			if (vma->vm_file && ph_memo_match(&memo, vma->vm_file))
				pages += vma_pages(vma);
	}
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next)
		if (vma->vm_file && ph_memo_match(&memo, vma->vm_file))
			pages += vma_pages(vma);
#endif
	rss = get_mm_counter(mm, MM_FILEPAGES) + get_mm_counter(mm, MM_SHMEMPAGES) +
	      get_mm_counter(mm, MM_ANONPAGES);
	total = mm->total_vm;
	peak = mm->hiwater_vm < total ? total : mm->hiwater_vm;
	peak_rss = mm->hiwater_rss < rss ? rss : mm->hiwater_rss;
	mmap_read_unlock(mm);

	/* The callers subtract this from VmSize, VmPeak and statm's size while
	 * leaving RSS alone on purpose -- but VmRSS <= VmSize and VmHWM <=
	 * VmPeak hold on every stock kernel and cost one read to check. Never
	 * report more than the headroom they leave, or closing a quantity
	 * oracle opens an impossible-value one, which is the louder of the two.
	 * Real PAGE_SIZE pages, so a page-size-compat tree converts after this
	 * and never before.
	 */
	/* get_mm_counter() reads the percpu counter without folding in the
	 * per-CPU deltas. Some trees -- every one that has get_mm_counter_sum()
	 * -- read RSS *with* them in task_mem()/task_statm(), so their figure is
	 * the larger one and this headroom would be an over-estimate: measured
	 * at 59 pages on OP15 6.12.58, which was enough to put VmSize under
	 * VmRSS and defeat the clamp. Subtract the bound on that drift rather
	 * than reach for an accessor this file cannot know the tree has:
	 * |sum - read| <= percpu_counter_batch per CPU per counter.
	 *
	 * It costs nothing where it does not matter. Headroom is ~95% of
	 * total_vm on a real process, so `pages` is still the smaller term and
	 * the deduction is exact; the margin only ever binds in the pathological
	 * case this guards, where erring low is the whole point.
	 */
	slack = 3UL * (unsigned long)percpu_counter_batch * num_online_cpus();

	room = total > rss ? total - rss : 0;
	peak_room = peak > peak_rss ? peak - peak_rss : 0;
	if (peak_room < room)
		room = peak_room;
	room = room > slack ? room - slack : 0;

	return min(pages, room);
}

static int ph_add_locked(const char *s)
{
	int i;

	if (!ph_rule_sane(s))
		return -EINVAL;

	for (i = 0; i < ph_nrules; i++)
		if (!strcmp(ph_rules[i], s))
			return 0;
	if (ph_nrules >= PH_MAX_RULES)
		return -ENOSPC;
	strscpy(ph_rules[ph_nrules], s, PH_RULE_LEN);
	if (!ph_rules[ph_nrules][0])
		return -EINVAL;
	WRITE_ONCE(ph_nrules, ph_nrules + 1);
	return 0;
}

static int ph_del_locked(const char *s)
{
	int i, n = ph_nrules;

	for (i = 0; i < n; i++) {
		if (!strcmp(ph_rules[i], s)) {
			memmove(&ph_rules[i], &ph_rules[i + 1],
				(n - i - 1) * PH_RULE_LEN);
			WRITE_ONCE(ph_nrules, n - 1);
			return 0;
		}
	}
	return -ENOENT;
}

int pathhide_ctl(const char *buf, size_t count)
{
	char line[PH_RULE_LEN + 1];
	const char *s;
	size_t n = count;
	int ret;

	if (n == 0)
		return -EINVAL;
	if (n > PH_RULE_LEN)
		return -ENAMETOOLONG;
	memcpy(line, buf, n);
	line[n] = '\0';
	while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		line[--n] = '\0';
	if (n == 0)
		return 0;

	if (line[0] == '-' && line[1] == '\0') {
		spin_lock(&ph_lock);
		WRITE_ONCE(ph_nrules, 0);
		spin_unlock(&ph_lock);
		return 0;
	}

	if (line[0] == '~' || line[0] == '+')
		s = line + 1;
	else
		s = line;
	if (!*s)
		return -EINVAL;
	if (strlen(s) >= PH_RULE_LEN)
		return -ENAMETOOLONG;

	spin_lock(&ph_lock);
	if (line[0] == '~')
		ret = ph_del_locked(s);
	else
		ret = ph_add_locked(s);
	spin_unlock(&ph_lock);
	return ret;
}

int pathhide_get_rule(int idx, char *out, size_t outsz)
{
	int len = 0;

	if (!out || outsz < PH_RULE_LEN || idx < 0)
		return -EINVAL;
	spin_lock(&ph_lock);
	if (idx < ph_nrules) {
		strscpy(out, ph_rules[idx], outsz);
		len = strlen(out);
	}
	spin_unlock(&ph_lock);
	return len;
}

#ifdef PH_ENABLE_PROC
static int ph_seq_show(struct seq_file *m, void *v)
{
	int i;

	spin_lock(&ph_lock);
	for (i = 0; i < ph_nrules; i++)
		seq_printf(m, "%s\n", ph_rules[i]);
	spin_unlock(&ph_lock);
	return 0;
}

static int ph_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -ENOENT;
	return single_open(file, ph_seq_show, NULL);
}

static ssize_t ph_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char line[PH_RULE_LEN + 1];
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (count == 0)
		return -EINVAL;
	if (count > PH_RULE_LEN)
		return -ENAMETOOLONG;
	if (copy_from_user(line, ubuf, count))
		return -EFAULT;

	ret = pathhide_ctl(line, count);
	return ret ? ret : count;
}

static const struct proc_ops ph_proc_ops = {
	.proc_open	= ph_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= ph_write,
};

static int __init pathhide_init(void)
{
	proc_create(PH_PROC_NAME, 0600, NULL, &ph_proc_ops);
	return 0;
}
late_initcall(pathhide_init);
#endif
