#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Local copies of the 6.12 procfs ioctl ABI.
 *
 * Deliberately NOT the uapi names: an NDK sysroot new enough to declare
 * struct procmap_query would collide, and one too old to declare it would make
 * the surface silently unprobeable. Local names compile on every sysroot and
 * the numbers are asserted against include/uapi/linux/fs.h ('f', 16, 17).
 */
#define PQ_MAGIC 'f'
#define PQ_IOCTL  _IOWR(PQ_MAGIC, 17, struct pq_local)
#define PMS_IOCTL _IOWR(PQ_MAGIC, 16, struct pms_local)

#define PQ_FILE_BACKED_VMA 0x20

#define PG_IS_PRESENT (1 << 3)

struct pq_local {
	uint64_t size;
	uint64_t query_flags;
	uint64_t query_addr;
	uint64_t vma_start;
	uint64_t vma_end;
	uint64_t vma_flags;
	uint64_t vma_page_size;
	uint64_t vma_offset;
	uint64_t inode;
	uint32_t dev_major;
	uint32_t dev_minor;
	uint32_t vma_name_size;
	uint32_t build_id_size;
	uint64_t vma_name_addr;
	uint64_t build_id_addr;
};

struct pms_local {
	uint64_t size;
	uint64_t flags;
	uint64_t start;
	uint64_t end;
	uint64_t walk_end;
	uint64_t vec;
	uint64_t vec_len;
	uint64_t max_pages;
	uint64_t category_inverted;
	uint64_t category_mask;
	uint64_t category_anyof_mask;
	uint64_t return_mask;
};

struct pr_local {
	uint64_t start;
	uint64_t end;
	uint64_t categories;
};

/* Every probe returns 1 = the hidden thing is visible, 0 = it is not,
 * -1 = could not be measured. -1 is never folded into 0 anywhere below;
 * a surface that could not be read is reported SKIP, not CLEAN.
 */
#define VIS_LEAK  1
#define VIS_CLEAN 0
#define VIS_NONE  (-1)

/* Also reports the dev and inode columns of the maps row covering `addr`.
 *
 * The gate's section is titled "an injected file must not report its backing dev:ino" and
 * nothing read them: the only thing asserted was that root's stat() of the path reported
 * some device other than /data's, which is a different claim. The caller compares these
 * against stat() on the same path.
 */
static int maps_names(unsigned long addr, const char *needle, char *dev, size_t devsz,
		      unsigned long *ino)
{
	char line[1024];
	FILE *f = fopen("/proc/self/maps", "r");
	int hit = 0;

	if (dev && devsz)
		snprintf(dev, devsz, "-");
	if (ino)
		*ino = 0;
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		unsigned long lo, hi, off, li = 0;
		char perms[8], d[32];

		if (sscanf(line, "%lx-%lx", &lo, &hi) != 2)
			continue;
		if (addr < lo || addr >= hi)
			continue;
		if (sscanf(line, "%lx-%lx %7s %lx %31s %lu", &lo, &hi, perms, &off, d, &li) == 6) {
			if (dev && devsz)
				snprintf(dev, devsz, "%s", d);
			if (ino)
				*ino = li;
		}
		if (needle && strstr(line, needle))
			hit = 1;
	}
	fclose(f);
	return hit;
}

/* Does a /proc/self/map_files entry covering `addr` still resolve to the needle?
 *
 * Measured IN the process that owns the mapping. The gate used to ask this in the shell,
 * after this probe - a command substitution - had already exited, so it scanned every
 * other process for incidental /data/adb mappings and called that agreement. It could not
 * fail for the property it was named after.
 *
 * The range remaining is expected and is not what this answers: on a build with no
 * accounting arm, map_files still lists the address range. The question is whether the
 * PATH is still reachable through it.
 */
static int map_files_names(unsigned long addr, const char *needle)
{
	DIR *d = opendir("/proc/self/map_files");
	struct dirent *e;
	int hit = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)) != NULL) {
		unsigned long lo, hi;
		char path[PATH_MAX], link[PATH_MAX];
		ssize_t n;

		if (sscanf(e->d_name, "%lx-%lx", &lo, &hi) != 2)
			continue;
		if (addr < lo || addr >= hi)
			continue;
		snprintf(path, sizeof(path), "/proc/self/map_files/%s", e->d_name);
		n = readlink(path, link, sizeof(link) - 1);
		if (n <= 0)
			continue;
		link[n] = '\0';
		if (needle && strstr(link, needle))
			hit = 1;
	}
	closedir(d);
	return hit;
}

/* /proc/self/smaps - show_smap().
 *
 * A separate seq_file show function from show_map_vma(), so a guard in one is not a
 * guard in the other. verify_pathhide() asserts both in source; only maps was ever
 * measured. Reports the needle hit and, as a byte-level payload rather than a verdict,
 * the Rss: of the entry covering addr.
 */
static int smaps_entry(unsigned long addr, const char *needle, unsigned long *rss_kb)
{
	char line[1024];
	FILE *f = fopen("/proc/self/smaps", "r");
	int hit = 0, in_entry = 0;

	if (rss_kb)
		*rss_kb = 0;
	if (!f)
		return VIS_NONE;
	while (fgets(line, sizeof(line), f)) {
		unsigned long lo, hi;

		if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
			in_entry = (addr >= lo && addr < hi);
			if (in_entry && needle && strstr(line, needle))
				hit = 1;
			continue;
		}
		if (in_entry && !strncmp(line, "Rss:", 4) && rss_kb)
			sscanf(line + 4, "%lu", rss_kb);
	}
	fclose(f);
	return hit;
}

/* /proc/self/smaps_rollup - show_smaps_rollup().
 *
 * Carries no paths, so a name probe cannot reach it; it is an aggregate, which makes it
 * an arithmetic surface. The caller samples Rss: before the mapping exists and again
 * with every page resident. A working guard leaves the delta at roughly zero; an
 * unguarded one shows the whole mapping.
 */
static long rollup_rss_kb(void)
{
	char line[256];
	FILE *f = fopen("/proc/self/smaps_rollup", "r");
	long v = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Rss:", 4)) {
			unsigned long u = 0;

			if (sscanf(line + 4, "%lu", &u) == 1)
				v = (long)u;
			break;
		}
	}
	fclose(f);
	return v;
}

/* /proc/self/numa_maps - show_numa_map().
 *
 * Third rendering of the same vma list, and the one that prints the path as
 * "file=<path>" rather than as a trailing column, so a parser written for maps does
 * not see it.
 */
static int numa_maps_names(unsigned long addr, const char *needle)
{
	char line[1024];
	FILE *f = fopen("/proc/self/numa_maps", "r");
	int hit = 0;

	(void)addr;
	if (!f)
		return VIS_NONE;
	/* No address filter on purpose. numa_maps prints the vma START only, with no
	 * range, so keying on "line address == our mmap address" reads CLEAN the moment
	 * the kernel merges our mapping into a neighbouring vma - a false pass produced
	 * by the parser, not by the cloak. The needle is a full path, so scanning every
	 * line is both simpler and strictly more sensitive, and it errs toward TELL.
	 */
	while (fgets(line, sizeof(line), f)) {
		if (needle && strstr(line, needle))
			hit = 1;
	}
	fclose(f);
	return hit;
}

/* PROCMAP_QUERY on /proc/self/maps - query_matching_vma(), 6.12+.
 *
 * Not a text surface at all: it answers about one address without rendering the list,
 * so every parser-shaped cloak misses it unless the guard is in the query path. Asks
 * for the name too, because inode and dev alone would under-report.
 */
static int procmap_query_probe(unsigned long addr, const char *needle,
			       unsigned long *inop, char *name, size_t namesz,
			       int *err)
{
	struct pq_local q;
	char buf[PATH_MAX];
	int fd, ret, hit = VIS_NONE;

	if (inop)
		*inop = 0;
	if (name && namesz)
		name[0] = '\0';
	if (err)
		*err = 0;

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0)
		return VIS_NONE;

	memset(&q, 0, sizeof(q));
	memset(buf, 0, sizeof(buf));
	q.size = sizeof(q);
	q.query_addr = (uint64_t)addr;
	q.query_flags = 0;
	q.vma_name_size = sizeof(buf);
	q.vma_name_addr = (uint64_t)(uintptr_t)buf;

	errno = 0;
	ret = ioctl(fd, PQ_IOCTL, &q);
	if (ret == 0) {
		hit = VIS_CLEAN;
		if (inop)
			*inop = (unsigned long)q.inode;
		if (name && namesz)
			snprintf(name, namesz, "%s", buf);
		if (needle && buf[0] && strstr(buf, needle))
			hit = VIS_LEAK;
		/* A covering vma reported with the right inode is a leak even with no
		 * name: the caller compares inode against stat(). */
		if (needle && !buf[0] && q.vma_start == (uint64_t)addr)
			hit = VIS_LEAK;
	} else {
		if (err)
			*err = errno;
		if (errno == ENOENT)
			hit = VIS_CLEAN;
		else
			hit = VIS_NONE; /* ENOTTY on <6.12, EINVAL on a size mismatch */
	}
	close(fd);
	return hit;
}

/* PAGEMAP_SCAN on /proc/self/pagemap - pagemap_scan_test_walk(), 6.7+.
 *
 * The second residency window onto the same vma. nm_pathhide_probes.c checks the guard
 * from inside the kernel; nothing asked the question the way an app would. Returns the
 * number of regions the ioctl reports, which is do_pagemap_scan()'s n_ranges_out.
 */
static long pagemap_scan_probe(unsigned long addr, size_t len, int *err)
{
	struct pms_local arg;
	struct pr_local regions[64];
	long page = sysconf(_SC_PAGESIZE);
	size_t end = ((addr + len) + (size_t)page - 1) & ~((size_t)page - 1);
	int fd, ret;

	if (err)
		*err = 0;
	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0)
		return -1;

	memset(&arg, 0, sizeof(arg));
	memset(regions, 0, sizeof(regions));
	arg.size = sizeof(arg);
	arg.start = (uint64_t)addr;
	arg.end = (uint64_t)end;
	arg.vec = (uint64_t)(uintptr_t)regions;
	arg.vec_len = sizeof(regions) / sizeof(regions[0]);
	arg.category_mask = PG_IS_PRESENT;
	arg.return_mask = PG_IS_PRESENT;

	errno = 0;
	ret = ioctl(fd, PMS_IOCTL, &arg);
	if (ret < 0) {
		if (err)
			*err = errno;
		close(fd);
		return -1;
	}
	close(fd);
	return (long)ret;
}

static long pagemap_nonzero(unsigned long addr, size_t pages)
{
	long page = sysconf(_SC_PAGESIZE);
	long nonzero = 0;
	size_t i;
	int fd = open("/proc/self/pagemap", O_RDONLY);

	if (fd < 0)
		return -1;
	for (i = 0; i < pages; i++) {
		unsigned long long e = 0;
		off_t off = (off_t)((addr / page) + i) * sizeof(e);

		if (pread(fd, &e, sizeof(e), off) != (ssize_t)sizeof(e)) {
			close(fd);
			return -2;
		}
		if (e)
			nonzero++;
	}
	close(fd);
	return nonzero;
}

static unsigned long statm_size(void)
{
	unsigned long v = 0;
	FILE *f = fopen("/proc/self/statm", "r");

	if (!f)
		return 0;
	if (fscanf(f, "%lu", &v) != 1)
		v = 0;
	fclose(f);
	return v;
}

static unsigned long status_field(const char *key)
{
	char line[256];
	unsigned long v = 0;
	FILE *f = fopen("/proc/self/status", "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, key, strlen(key))) {
			sscanf(line + strlen(key), "%lu", &v);
			break;
		}
	}
	fclose(f);
	return v;
}

struct surf {
	const char *path;
	const char *needle;
	int ok;

	unsigned long addr;
	size_t len, pages;
	unsigned long statino;

	int maps;
	char mapsdev[32];
	unsigned long mapsino;
	int mapfiles;

	int smaps;
	unsigned long smapsrss;
	long rollup_before, rollup_after;
	int numa;

	int pmquery, pmquery_err;
	unsigned long pmqino;
	char pmqname[PATH_MAX];

	long pmscan;
	int pmscan_err;

	int mincore_ok, mincore_err;
	long pagemap;

	unsigned long vmsize, vmpeak, vmrss, statm;
};

/* Maps `path`, makes every page resident, reads all eleven surfaces, unmaps.
 *
 * Residency matters: the original probe faulted the first page only, so pagemap and
 * mincore were asking about a mapping that was mostly not there. Touching the whole
 * range cannot turn a working guard into a failing one - a guard that zeroes the vma's
 * entries zeroes them however resident it is - and it is what gives rollup and
 * PAGEMAP_SCAN anything to report.
 */
static int measure(const char *path, const char *needle, struct surf *s)
{
	long page = sysconf(_SC_PAGESIZE);
	unsigned char *vec;
	struct stat st;
	size_t i;
	void *p;
	int fd;

	memset(s, 0, sizeof(*s));
	s->path = path;
	s->needle = needle ? needle : path;
	s->rollup_before = s->rollup_after = -1;
	s->pmscan = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) || st.st_size <= 0) {
		fprintf(stderr, "fstat %s: empty or failed\n", path);
		close(fd);
		return -1;
	}

	s->len = (size_t)st.st_size;
	s->pages = (s->len + (size_t)page - 1) / (size_t)page;
	s->statino = (unsigned long)st.st_ino;

	/* Sampled immediately around mmap + first touch and nothing else. Taken any
	 * wider, the window swallows the probe's own allocations: the first draft read
	 * it before open() and again after the calloc() below, and reported 536 KB of
	 * growth for a 256 KB mapping while the control - whose baseline fell after the
	 * first mapping was already torn down - reported 260 KB. Two runs, two different
	 * baselines, so the arithmetic was not comparable between them.
	 */
	s->rollup_before = rollup_rss_kb();

	p = mmap(NULL, s->len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap %s: %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	s->addr = (unsigned long)p;

	for (i = 0; i < s->pages; i++)
		(void)*(volatile unsigned char *)((char *)p + i * (size_t)page);

	s->rollup_after = rollup_rss_kb();

	s->maps = maps_names(s->addr, s->needle, s->mapsdev, sizeof(s->mapsdev),
			     &s->mapsino);
	s->mapfiles = map_files_names(s->addr, s->needle);
	s->smaps = smaps_entry(s->addr, s->needle, &s->smapsrss);
	s->numa = numa_maps_names(s->addr, s->needle);
	s->pmquery = procmap_query_probe(s->addr, s->needle, &s->pmqino,
					 s->pmqname, sizeof(s->pmqname),
					 &s->pmquery_err);
	s->pmscan = pagemap_scan_probe(s->addr, s->len, &s->pmscan_err);

	vec = calloc(s->pages, 1);
	errno = 0;
	s->mincore_ok = (vec && mincore(p, s->len, vec) == 0);
	s->mincore_err = errno;
	free(vec);

	s->pagemap = pagemap_nonzero(s->addr, s->pages);

	s->vmsize = status_field("VmSize:");
	s->vmpeak = status_field("VmPeak:");
	s->vmrss = status_field("VmRSS:");
	s->statm = statm_size();

	munmap(p, s->len);
	close(fd);
	s->ok = 1;
	return 0;
}

static long rollup_delta(const struct surf *s)
{
	if (s->rollup_before < 0 || s->rollup_after < 0)
		return -1;
	return s->rollup_after - s->rollup_before;
}

/* Rollup is arithmetic, so the question is not "did Rss move" but "did it move by
 * about the size of the mapping". A plain delta > 0 test grades scheduler noise and
 * the probe's own first-touch as a leak; half the mapping separates the two outcomes
 * with room to spare, since a working guard contributes nothing at all.
 */
static int rollup_vis(const struct surf *s)
{
	long d = rollup_delta(s);
	long half_kb = (long)(s->len / 1024) / 2;

	if (d < 0)
		return VIS_NONE;
	if (half_kb <= 0)
		return VIS_NONE;
	return d >= half_kb ? VIS_LEAK : VIS_CLEAN;
}

static void print_block(const struct surf *s, const char *tag)
{
	if (tag)
		printf("--- %s %s\n", tag, s->path);
	printf("addr      %lx\n", s->addr);
	printf("pages     %zu\n", s->pages);
	printf("maps      %d\n", s->maps);
	printf("mapsdev   %s\n", s->mapsdev);
	printf("mapsino   %lu\n", s->mapsino);
	printf("mapfiles  %d\n", s->mapfiles);
	printf("statino   %lu\n", s->statino);
	if (s->mincore_ok)
		printf("mincore   ok\n");
	else
		printf("mincore   %s\n", strerror(s->mincore_err));
	printf("pagemap   %ld\n", s->pagemap);
	printf("vmsize    %lu\n", s->vmsize);
	printf("vmpeak    %lu\n", s->vmpeak);
	printf("statm     %lu\n", s->statm);
	/* surfaces verify_pathhide() asserts in source and nothing measured */
	printf("smaps     %d\n", s->smaps);
	printf("smapsrss  %lu\n", s->smapsrss);
	printf("rollup    %ld\n", rollup_delta(s));
	printf("numa      %d\n", s->numa);
	if (s->pmquery == VIS_NONE && s->pmquery_err)
		printf("pmquery   %d (%s)\n", s->pmquery, strerror(s->pmquery_err));
	else
		printf("pmquery   %d\n", s->pmquery);
	printf("pmqino    %lu\n", s->pmqino);
	printf("pmqname   %s\n", s->pmqname[0] ? s->pmqname : "-");
	if (s->pmscan < 0 && s->pmscan_err)
		printf("pmscan    %ld (%s)\n", s->pmscan, strerror(s->pmscan_err));
	else
		printf("pmscan    %ld\n", s->pmscan);
	printf("vmrss     %lu\n", s->vmrss);
	printf("rssinv    %d\n", s->vmrss > s->vmsize ? 1 : 0);
}

/* hidden/control are 1 = visible, 0 = not, -1 = unmeasurable.
 *
 * control == 0 is INSTRUMENT, never CLEAN: if the surface cannot see an unhidden
 * mapping it says nothing about a hidden one, and calling that a pass is how a probe
 * reports success for the wrong reason.
 */
static const char *verdict(int hidden, int control)
{
	if (hidden < 0 || control < 0)
		return "SKIP";
	if (control == 0)
		return "INSTRUMENT";
	return hidden ? "TELL" : "CLEAN";
}

static int vis(long v)
{
	if (v < 0)
		return VIS_NONE;
	return v > 0 ? VIS_LEAK : VIS_CLEAN;
}

static int compare(const struct surf *h, const struct surf *c)
{
	struct row {
		const char *name;
		int hidden, control;
		const char *note;
	} rows[] = {
		{ "maps",     h->maps,            c->maps,            "show_map_vma()" },
		{ "mapfiles", h->mapfiles,        c->mapfiles,        "proc_map_files_*()" },
		{ "smaps",    h->smaps,           c->smaps,           "show_smap()" },
		{ "rollup",   rollup_vis(h),      rollup_vis(c),      "show_smaps_rollup()" },
		{ "numa",     h->numa,            c->numa,            "show_numa_map()" },
		{ "pmquery",  h->pmquery,         c->pmquery,         "query_matching_vma()" },
		{ "pmscan",   vis(h->pmscan),     vis(c->pmscan),     "pagemap_scan_test_walk()" },
		{ "pagemap",  vis(h->pagemap),    vis(c->pagemap),    "pagemap_pmd_range()" },
	};
	size_t i, n = sizeof(rows) / sizeof(rows[0]);
	int tells = 0;

	printf("--- verdict (hidden vs control, same process, same run)\n");
	/* Rows are v:-prefixed so lkm-pathhide.sh's field() can read them: that
	 * helper matches on a leading name, and "maps" already names a per-block
	 * line above. */
	for (i = 0; i < n; i++) {
		const char *v = verdict(rows[i].hidden, rows[i].control);

		printf("v:%-8s %-10s h=%-3d c=%-3d %s\n", rows[i].name, v,
		       rows[i].hidden, rows[i].control, rows[i].note);
		if (!strcmp(v, "TELL"))
			tells++;
	}

	/* Standalone: no control needed, because the arithmetic contradicts itself.
	 * RSS is deliberately not deducted while VmSize is, so a hidden mapping that
	 * dominates total_vm makes VmRSS exceed VmSize - an ordering no stock kernel
	 * can produce.
	 *
	 * But it only fires when the deduction can actually close the gap, and saying
	 * CLEAN when it cannot is a pass for the wrong reason. Measured on CPH2747,
	 * 6.12.69: a 256 kB subject against VmSize 8669376 kB and VmRSS 1164 kB. The
	 * deduction was a correct 256 kB and the inequality was still ~8.6 GB away, so
	 * a CLEAN there says nothing about the invariant. Reaching it needs
	 * total_vm - hidden_vm < rss, i.e. a large hidden mapping, resident, in a
	 * process whose other VA is small - and on this platform total_vm is ~8.3 GB
	 * before the subject is mapped at all, so it is not reachable here by any
	 * file size. UNREACHABLE is the honest verdict and is not counted as a pass.
	 */
	{
		const char *rv;

		if (h->vmrss > h->vmsize)
			rv = "TELL";
		else if (h->vmrss * 4 < h->vmsize)
			rv = "UNREACHABLE";
		else
			rv = "CLEAN";
		printf("v:%-8s %-10s VmRSS=%lu VmSize=%lu  %s\n", "rssinv", rv,
		       h->vmrss, h->vmsize,
		       "task_mem() deducts VmSize, not RSS");
		if (h->vmrss > h->vmsize)
			tells++;
	}

	if (h->len != c->len)
		printf("v:%-8s %-10s hidden=%zu control=%zu  %s\n", "size", "WARN",
		       h->len, c->len,
		       "control is not size-matched; rollup and pmscan are not comparable");

	printf("tells     %d\n", tells);
	return tells;
}

int main(int argc, char **argv)
{
	const char *control = NULL;
	const char *needle = NULL;
	const char *path;
	struct surf h, c;
	int i = 1;

	while (i < argc && argv[i][0] == '-') {
		if (!strcmp(argv[i], "-c") && i + 1 < argc) {
			control = argv[i + 1];
			i += 2;
			continue;
		}
		fprintf(stderr, "unknown option %s\n", argv[i]);
		return 2;
	}
	if (i >= argc) {
		fprintf(stderr,
			"usage: %s [-c <control-file>] <file-to-map> [maps-needle]\n"
			"\n"
			"  <file-to-map>   a path covered by a /proc/pathhide rule\n"
			"  -c <control>    an UNCOVERED file, same size, same filesystem.\n"
			"                  Without it every surface is reported raw and no\n"
			"                  verdict is possible: a surface that cannot see an\n"
			"                  unhidden mapping proves nothing about a hidden one.\n",
			argv[0]);
		return 2;
	}
	path = argv[i];
	if (i + 1 < argc)
		needle = argv[i + 1];
	if (!control)
		control = NULL;

	/* Discarded warm-up pass.
	 *
	 * Whichever mapping runs FIRST in the process pays one-time first-touch costs -
	 * page tables, lazily faulted libc and stack pages - and smaps_rollup charges
	 * them to that window. Measured here: a 256 KB control read exactly 256 KB of
	 * Rss growth while the identical 256 KB hidden file, measured first, read 432.
	 * On a kernel where the guard works the hidden mapping contributes nothing, so
	 * that 176 KB of ordering noise would clear the half-the-mapping threshold on
	 * its own and report a TELL for a cloak that is doing its job. One throwaway
	 * pass moves the cost out of both measured windows.
	 */
	{
		struct surf warm;
		const char *warmpath = control ? control : path;

		(void)measure(warmpath, warmpath, &warm);
	}

	if (measure(path, needle, &h))
		return 2;
	print_block(&h, control ? "hidden" : NULL);

	if (!control)
		return 0;

	if (measure(control, control, &c))
		return 2;
	print_block(&c, "control");

	return compare(&h, &c) ? 1 : 0;
}
