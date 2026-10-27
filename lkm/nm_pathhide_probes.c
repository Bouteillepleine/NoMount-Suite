/* The readers _pathhide closes in-tree beyond /proc/<pid>/maps, reproduced
 * out-of-tree.
 *
 * Dropping a mapping's line out of /proc/<pid>/maps is not the whole job. The
 * mapping is still there, so the same gap is readable three more ways, and
 * in-tree patches all three: pagemap_pmd_range() reports the vma as a hole,
 * pagemap_scan_test_walk() skips it, and do_mincore() answers -ENOMEM. A
 * module cannot edit any of those call sites, so each becomes a probe here.
 *
 * pathhide_match_file() already gates itself on an empty rule table, so there
 * is nothing to test before calling it. Two of the three guards run with
 * mmap_read_lock already held by the page walker and read one vma the kernel
 * has handed them, which is why they can afford to call it at all - see the
 * note on the accounting guard below for where that stops being true.
 *
 * __arm64_sys_mincore() rather than do_mincore(): do_mincore() is inlined into
 * the syscall on every kernel this module is built for, so there is nothing to
 * probe. The arm64 wrapper takes a single pt_regs pointer and unpacks the real
 * arguments from it, so the entry handler reads addr and len out of that inner
 * struct. Rewriting the syscall's return to -ENOMEM is what the in-tree patch
 * produces anyway: do_mincore() returns -ENOMEM, the syscall loop breaks on a
 * non-positive result and returns it unchanged. The range is walked under
 * mmap_read_trylock() rather than mmap_read_lock(), because a kprobe handler
 * cannot sleep; a failed trylock leaves the call answered normally, which
 * needs a concurrent writer on the same mm to happen at all.
 *
 * pagemap_pmd_range() is the one with no precedent in this module, because it
 * is the only guard that has to make a compiled-in function return early
 * rather than correct what it returned. add_to_pagemap() is inlined, so the
 * entries cannot be rewritten as they are emitted. What works instead is the
 * mechanism arm64 already has for exactly this shape: a pre-handler puts a
 * return value in x0, points pc at x30 and returns non-zero. That is
 * override_function_with_return() in arch/arm64/lib/error-inject.c verbatim,
 * and kprobe_breakpoint_handler() states the contract in a comment - a
 * pre-handler returning non-zero "will modify the execution path and not need
 * to single-step", after which it resets the current kprobe and resumes at the
 * modified pc. It holds on the BRK path and on the ftrace path too, because
 * arm64's `mov x9, x30` prologue means ftrace saves the original LR into
 * regs->regs[30], which is why the upstream helper reads it from there.
 *
 * The value left in x0 is the kernel's own pagemap_pte_hole() result, resolved
 * through kallsyms and called from a __nocfi trampoline, so the entries a
 * hidden vma emits are the ones the kernel would emit for a real hole rather
 * than a reimplementation of them. If that symbol is not resolvable the guard
 * does not arm, because a pagemap guard that emits some real entries is worse
 * than one that declares itself absent.
 *
 * Hugetlb is not covered, and neither is it in tree: pagemap_ops also carries
 * .hugetlb_entry, and the in-tree patch touches only .pmd_entry. A hidden file
 * mapped from hugetlbfs still reports its pages through that arm in both
 * builds.
 *
 * The accounting guard is NOT here, and cannot be. In tree, task_mem() and
 * task_statm() subtract pathhide_hidden_vm_pages(mm), which walks every vma in
 * the mm and renders d_path() for each distinct mapped file. That is fine in a
 * function running in process context. It is not fine in a kprobe handler: on
 * arm64 one is reached through el1_dbg(), which calls ct_nmi_enter() and never
 * restores DAIF_PROCCTX, so the handler runs with interrupts disabled in
 * RCU-NMI context, and kprobes_save_local_irqflag() is called from
 * setup_singlestep() only afterwards. A few thousand vmas with a few hundred
 * d_path() renders is a few hundred microseconds with interrupts off, on every
 * read of /proc/<pid>/status and /proc/<pid>/statm, which are read constantly.
 * That is a latency bug wearing a cloak's clothes, and a cached or bounded
 * version that corrects some reads and not others is a louder signal than no
 * guard at all. pathhide_hidden_vm_pages() is therefore compiled in with no
 * caller, waiting for a mechanism that lands in process context: either an
 * ftrace redirect on the two functions, whose replacement runs in the original
 * caller's context where sleeping is allowed, or a per-mm count maintained as
 * vmas come and go so the read path is O(1). Until one of those exists, an LKM
 * user's VmSize still counts what their maps does not.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/limits.h>
#include <linux/percpu.h>
#include <linux/string.h>

#include <asm/ptrace.h>

#include "nm_oot.h"
#include "pathhide.h"
#include "nm_pathhide_probes.h"

#ifndef untagged_addr
#define untagged_addr(addr)	(addr)
#endif

/* mmap_read_trylock() arrived with the mmap_lock wrappers in 5.8; before that
 * the same lock is reached as mm->mmap_sem directly. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define nm_ph_mm_trylock(mm)	down_read_trylock(&(mm)->mmap_sem)
#define nm_ph_mm_unlock(mm)	up_read(&(mm)->mmap_sem)
#else
#define nm_ph_mm_trylock(mm)	mmap_read_trylock(mm)
#define nm_ph_mm_unlock(mm)	mmap_read_unlock(mm)
#endif

/* nomount.c tests these as pointers (`if (!pathhide_ctl)`) because in-tree they
 * are weak symbols. Handing it the function directly would make that test a
 * constant and trip -Waddress under CONFIG_WERROR, so the engine is given a
 * pointer to a forwarder and the engine source stays untouched. */
int nm_pathhide_ctl_fwd(const char *buf, size_t count)
{
	return pathhide_ctl(buf, count);
}

int nm_pathhide_get_rule_fwd(int idx, char *out, size_t outsz)
{
	return pathhide_get_rule(idx, out, outsz);
}

struct nm_ph_ctx {
	bool hide;
};

static bool nm_ph_vma_hidden(struct vm_area_struct *vma)
{
	return vma && vma->vm_file && pathhide_match_file(vma->vm_file);
}

/* find_vma() rather than for_each_vma() or vm_next: it is exported on every
 * kernel this module is built for, and walking forward from vm_end covers the
 * range without depending on which vma container the tree happens to use. */
static bool nm_ph_range_hidden(unsigned long start, unsigned long len)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, end;
	bool hit = false;

	if (!mm)
		return false;

	start = untagged_addr(start) & PAGE_MASK;
	end = start + PAGE_ALIGN(len);
	if (end <= start)
		return false;
	if (!nm_ph_mm_trylock(mm))
		return false;

	for (addr = start; addr < end;) {
		struct vm_area_struct *vma = find_vma(mm, addr);

		if (!vma || vma->vm_start >= end)
			break;
		if (nm_ph_vma_hidden(vma)) {
			hit = true;
			break;
		}
		if (vma->vm_end <= addr)
			break;
		addr = vma->vm_end;
	}

	nm_ph_mm_unlock(mm);
	return hit;
}

static int nm_ph_mincore_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_ph_ctx *ctx = (struct nm_ph_ctx *)ri->data;
	struct pt_regs *args = (struct pt_regs *)regs->regs[0];

	ctx->hide = false;
	if (!args)
		return 0;

	ctx->hide = nm_ph_range_hidden(args->regs[0], args->regs[1]);
	return 0;
}

static int nm_ph_mincore_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_ph_ctx *ctx = (struct nm_ph_ctx *)ri->data;

	if (ctx->hide)
		regs->regs[0] = (unsigned long)(long)-ENOMEM;
	return 0;
}

/* pagemap_scan_test_walk(start, end, walk): the walk is in x2 and carries the
 * vma. In tree the added check returns 1 before the wp-async tests, which is
 * the same 1 this writes afterwards - the function sets nothing a skipped vma
 * then reads, and a 1 overrides even the -EPERM it can return, in the
 * direction of skipping rather than failing the whole scan. */
static int nm_ph_scan_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_ph_ctx *ctx = (struct nm_ph_ctx *)ri->data;
	struct mm_walk *walk = (struct mm_walk *)regs->regs[2];

	ctx->hide = walk && nm_ph_vma_hidden(walk->vma);
	return 0;
}

static int nm_ph_scan_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_ph_ctx *ctx = (struct nm_ph_ctx *)ri->data;

	if (ctx->hide)
		regs->regs[0] = 1;
	return 0;
}

static int (*nm_ph_pte_hole)(unsigned long start, unsigned long end, int depth,
			     struct mm_walk *walk);

/* Resolved through kallsyms, so the call is indirect and kCFI would check it
 * against a type id this module never emitted. __nocfi drops the check on this
 * one call rather than on the file. */
static noinline __nocfi int nm_ph_hole(unsigned long start, unsigned long end,
				       struct mm_walk *walk)
{
	return nm_ph_pte_hole(start, end, -1, walk);
}

/* pagemap_pmd_range(pmdp, addr, end, walk): addr in x1, end in x2, walk in x3. */
static int nm_ph_pmd_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long addr = regs->regs[1];
	unsigned long end = regs->regs[2];
	struct mm_walk *walk = (struct mm_walk *)regs->regs[3];

	if (!walk || !nm_ph_vma_hidden(walk->vma))
		return 0;

	regs->regs[0] = (unsigned long)(long)nm_ph_hole(addr, end, walk);
	instruction_pointer_set(regs, procedure_link_pointer(regs));
	return 1;
}

/* The maps line itself.
 *
 * Dropping the derived readers above is pointless on its own: in tree the
 * mapping's line never appears in the first place, because show_map(),
 * show_smap() and show_numa_map() each `return 0` for a hidden vma before
 * emitting anything. Measured on CPH2745 with only the three guards above
 * armed: a file under /data/adb read as a hole in pagemap and -ENOMEM to
 * mincore while its path was still right there in /proc/self/maps - the loud
 * surface open and the quiet ones closed, which is the wrong way round.
 *
 * All three have the same shape - (struct seq_file *m, void *v) returning int,
 * with the vma in x1 - so one handler covers them, and it is the same early
 * return the pagemap arm uses: 0 into x0, pc to x30, return non-zero. Their
 * addresses are taken by a seq_operations, so none of them can be inlined away.
 *
 * Not covered, because neither is a plain early return: show_smaps_rollup(),
 * which `continue`s inside its own vma loop, and query_matching_vma(), which
 * jumps to its skip label. The PROCMAP_QUERY ioctl and smaps_rollup therefore
 * still see a hidden mapping in this build. /proc/<pid>/map_files is untouched
 * too - in tree that is three edits in fs/proc/base.c.
 */
static int nm_ph_show_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];

	if (!nm_ph_vma_hidden(vma))
		return 0;

	regs->regs[0] = 0;
	instruction_pointer_set(regs, procedure_link_pointer(regs));
	return 1;
}

static struct kprobe nm_ph_kp_show[] = {
	{ .symbol_name = "show_map",      .pre_handler = nm_ph_show_pre },
	{ .symbol_name = "show_smap",     .pre_handler = nm_ph_show_pre },
	{ .symbol_name = "show_numa_map", .pre_handler = nm_ph_show_pre },
};

static const char * const nm_ph_show_surface[] = {
	"a hidden mapping still has its line in /proc/<pid>/maps",
	"a hidden mapping still has its line in /proc/<pid>/smaps",
	"a hidden mapping still has its line in /proc/<pid>/numa_maps",
};

static bool nm_ph_show_armed[ARRAY_SIZE(nm_ph_kp_show)];

/* /proc/<pid>/map_files, which is what makes hiding the maps line honest.
 *
 * Measured on CPH2745 with the maps arm above but nothing here: adbd read
 * maps=0 map_files=3, zygiskd64 read maps=0 map_files=6. Every process that
 * maps something under a rule had maps deny what map_files listed. A cloak
 * whose two views contradict each other is a worse signal than the leak it
 * replaced - the in-tree comment in pathhide.c makes exactly this point about
 * impossible values, and in tree the maps hunk and the three fs/proc/base.c
 * hunks land in the same change for this reason.
 *
 * map_files_get_link(dentry, path) is where the symlink's target is resolved:
 * it fills the caller's struct path from the vma's file and returns 0. The
 * same kretprobe shape nm_gp_upa_ret() uses applies - stash the path at entry,
 * and on a successful return drop the reference and answer -ENOENT instead.
 * The reference being dropped is one the function itself just took on a dentry
 * the vma pins, so this does not reach the iput() path that can sleep.
 *
 * It needs a path-based test rather than pathhide_match_file(), which takes a
 * struct file. Rather than reach into pathhide.c - vendored byte-identical and
 * not ours to edit - the rules are read back through its own
 * pathhide_get_rule() and matched here, which is the same substring test on
 * the same strings.
 *
 * What this does NOT do: the entries themselves still exist, named by address
 * range, because readdir emits them through proc_fill_cache() with no per-entry
 * hook a kretprobe can fail. So an address present in map_files and absent from
 * maps is still visible; the path behind it is not.
 */
/* pathhide_get_rule() refuses an outsz under its own PH_RULE_LEN, which the
 * header does not export, so 128 is a floor - the same constant and the same
 * reasoning as NM_PATHHIDE_RULE_MAX in the engine. */
#define NM_PH_RULE_MAX 128

static char __percpu *nm_ph_linkbuf;

static bool nm_ph_path_hidden(const struct path *path)
{
	char rule[NM_PH_RULE_MAX];
	char *buf, *p;
	bool hit = false;
	int i;

	if (!path || !path->dentry || !nm_ph_linkbuf)
		return false;

	buf = get_cpu_ptr(nm_ph_linkbuf);
	p = d_path(path, buf, PATH_MAX);
	if (!IS_ERR(p)) {
		for (i = 0; pathhide_get_rule(i, rule, sizeof(rule)) > 0; i++) {
			if (strstr(p, rule)) {
				hit = true;
				break;
			}
		}
	}
	put_cpu_ptr(nm_ph_linkbuf);

	return hit;
}

struct nm_ph_link_ctx {
	struct path *path;
};

static int nm_ph_link_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_ph_link_ctx *ctx = (struct nm_ph_link_ctx *)ri->data;

	ctx->path = (struct path *)regs->regs[1];
	return 0;
}

static int nm_ph_link_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct nm_ph_link_ctx *ctx = (struct nm_ph_link_ctx *)ri->data;

	if ((long)regs->regs[0] != 0 || !ctx->path)
		return 0;
	if (!nm_ph_path_hidden(ctx->path))
		return 0;

	path_put(ctx->path);
	regs->regs[0] = (unsigned long)(long)-ENOENT;
	return 0;
}

static struct kretprobe nm_ph_krp_link = {
	.kp.symbol_name = "map_files_get_link",
	.entry_handler  = nm_ph_link_entry,
	.handler        = nm_ph_link_ret,
	.data_size      = sizeof(struct nm_ph_link_ctx),
	.maxactive      = 64,
};

static bool nm_ph_link_armed;

static struct kretprobe nm_ph_krp[] = {
	{
		.kp.symbol_name = "__arm64_sys_mincore",
		.entry_handler  = nm_ph_mincore_entry,
		.handler        = nm_ph_mincore_ret,
		.data_size      = sizeof(struct nm_ph_ctx),
		.maxactive      = 64,
	},
	{
		.kp.symbol_name = "pagemap_scan_test_walk",
		.entry_handler  = nm_ph_scan_entry,
		.handler        = nm_ph_scan_ret,
		.data_size      = sizeof(struct nm_ph_ctx),
		.maxactive      = 64,
	},
};

static const char * const nm_ph_surface[] = {
	"a hidden mapping still answers mincore() instead of reporting nothing mapped",
	"a hidden mapping is still reported by the PAGEMAP_SCAN ioctl",
};

static bool nm_ph_armed[ARRAY_SIZE(nm_ph_krp)];

static struct kprobe nm_ph_kp_pmd = {
	.symbol_name = "pagemap_pmd_range",
	.pre_handler = nm_ph_pmd_pre,
};

static bool nm_ph_pmd_armed;

static void nm_ph_arm_pagemap(void)
{
	int rc;

	nm_ph_pte_hole = (void *)nm_oot_lookup_opt("pagemap_pte_hole");
	if (!nm_ph_pte_hole) {
		pr_warn("nomount: pathhide guard: pagemap_pte_hole is not in "
			"kallsyms. A hidden mapping is still readable through "
			"/proc/<pid>/pagemap.\n");
		return;
	}

	rc = register_kprobe(&nm_ph_kp_pmd);
	if (rc) {
		pr_warn("nomount: pathhide guard: cannot probe pagemap_pmd_range "
			"(%d). A hidden mapping is still readable through "
			"/proc/<pid>/pagemap.\n", rc);
		nm_ph_pte_hole = NULL;
		return;
	}
	nm_ph_pmd_armed = true;
}

/* Every surface this build could close, including the one it cannot: the
 * accounting arm has no mechanism here, so it is counted and never armed. */
#define NM_PH_SURFACES \
	(ARRAY_SIZE(nm_ph_krp) + ARRAY_SIZE(nm_ph_kp_show) + 3)

int nm_pathhide_probes_init(void)
{
	size_t i;
	int armed = 0;
	int rc;

	nm_ph_linkbuf = __alloc_percpu(PATH_MAX, __alignof__(char));
	if (!nm_ph_linkbuf) {
		pr_warn("nomount: pathhide guard: no percpu path buffer. "
			"/proc/<pid>/map_files still resolves a hidden mapping "
			"to its path.\n");
	} else {
		rc = register_kretprobe(&nm_ph_krp_link);
		if (rc) {
			pr_warn("nomount: pathhide guard: cannot probe "
				"map_files_get_link (%d). /proc/<pid>/map_files "
				"still resolves a hidden mapping to its path.\n", rc);
			free_percpu(nm_ph_linkbuf);
			nm_ph_linkbuf = NULL;
		} else {
			nm_ph_link_armed = true;
			armed++;
		}
	}

	for (i = 0; i < ARRAY_SIZE(nm_ph_kp_show); i++) {
		int rc = register_kprobe(&nm_ph_kp_show[i]);

		if (rc) {
			nm_ph_show_armed[i] = false;
			pr_warn("nomount: pathhide guard: cannot probe %s (%d). %s.\n",
				nm_ph_kp_show[i].symbol_name, rc,
				nm_ph_show_surface[i]);
			continue;
		}
		nm_ph_show_armed[i] = true;
		armed++;
	}

	for (i = 0; i < ARRAY_SIZE(nm_ph_krp); i++) {
		int rc = register_kretprobe(&nm_ph_krp[i]);

		if (rc) {
			nm_ph_armed[i] = false;
			pr_warn("nomount: pathhide guard: cannot probe %s (%d). %s.\n",
				nm_ph_krp[i].kp.symbol_name, rc, nm_ph_surface[i]);
			continue;
		}
		nm_ph_armed[i] = true;
		armed++;
	}

	nm_ph_arm_pagemap();
	if (nm_ph_pmd_armed)
		armed++;

	if (!armed) {
		pr_warn("nomount: pathhide guards off: the maps cloak has no "
			"companion call sites on this kernel.\n");
		return -ENOENT;
	}

	/* The count is deliberately out of a total that includes the arm this
	 * build does not have, so the line reads as short rather than complete. */
	pr_info("nomount: pathhide guards active (%d/%zu surfaces, accounting unavailable)\n",
		armed, (size_t)NM_PH_SURFACES);
	return 0;
}

void nm_pathhide_probes_exit(void)
{
	size_t i;

	if (nm_ph_link_armed) {
		nm_ph_link_armed = false;
		unregister_kretprobe(&nm_ph_krp_link);
	}
	if (nm_ph_linkbuf) {
		free_percpu(nm_ph_linkbuf);
		nm_ph_linkbuf = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(nm_ph_kp_show); i++) {
		if (!nm_ph_show_armed[i])
			continue;
		nm_ph_show_armed[i] = false;
		unregister_kprobe(&nm_ph_kp_show[i]);
	}

	if (nm_ph_pmd_armed) {
		nm_ph_pmd_armed = false;
		unregister_kprobe(&nm_ph_kp_pmd);
	}
	nm_ph_pte_hole = NULL;

	for (i = 0; i < ARRAY_SIZE(nm_ph_krp); i++) {
		if (!nm_ph_armed[i])
			continue;
		nm_ph_armed[i] = false;
		unregister_kretprobe(&nm_ph_krp[i]);
	}
}
