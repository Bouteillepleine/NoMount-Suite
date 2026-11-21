/* engine-conc-2: is a minted intermediate virtual dir readable before its
 * metadata exists, and does the bad inode survive in the dcache afterwards?
 *
 * nomount_generate_virtual_topology() makes an intermediate rule reachable to VFS
 * readers at __nomount_inject_child_locked() (nomount.c:4643 existing-ancestor,
 * 4746 real-ancestor) but computes v_ino/v_dino/times/secctx/blksize only after
 * the walk loop, at nomount.c:4802-4842. In between the rule carries what
 * 4768-4780 set: v_ino = (unsigned long)h_parent, a raw 32-bit full_name_hash of
 * the path; v_dino = v_pdino = 0; v_ctx_len = 0; v_blksize = 0; no
 * NM_FLAG_HAVE_TIMES, so nm_mirror_stat does not substitute times and they read
 * as 0. The child's readdir number is placeholder too - fake_ino = v_dino ?: v_ino
 * (nomount.c:3462), repaired later by nm_restamp_child_ino() at 4830-4831.
 *
 * So the window serves a directory with an inode number in the millions-to-
 * billions beside stock /product entries numbered in the tens, and an mtime of
 * 1970-01-01. No real directory on an erofs /product has either property.
 *
 * YOU DO NOT HAVE TO WIN THE RACE TWICE. One lookup landing in the window
 * materializes an inode that is then cached (engine-conc-3 keeps it blessed), so
 * the hash ino and the epoch times stay readable long after the add completed.
 * That is what `read` is for: `watch` races the add, `read` collects the residue.
 *
 * The window widens on a COLD nm_dev_ino_tab slot, where the writer also does a
 * subtree walk of up to NM_DMAX_DIRS=8192 dirs with cond_resched()
 * (nomount.c:4119-4203). First add after boot is the widest. On a warm slot the
 * window is the kern_path + iterate_dir only.
 *
 * Local struct statx: the uapi header is newer than some sysroots this is built
 * against, and bionic's struct stat truncates nothing here but hides stx_btime.
 *
 *   clang --target=aarch64-linux-android31 -O2 -static \
 *         tests/conc2-probe.c -o conc2-probe
 *
 * Modes (see tests/conc2-check.sh for the driver that sequences them):
 *   conc2-probe control <dir>          stock baseline: ino band + mtime of <dir>'s subdirs
 *   conc2-probe watch   <path> <ms>    tight statx loop; snapshots the first successes
 *   conc2-probe read    <path>         one full dump + parent's d_ino for that name
 *
 * Exit: 0 = ran, 2 = anomaly seen (watch/read), 1 = usage/fatal. A clean `watch`
 * is NOT a refutation - read the sample count and span it prints and decide
 * whether the window was covered at all.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#define STX_WANT 0x00000fffU /* BASIC_STATS | BTIME */

struct stx_ts {
	int64_t tv_sec;
	uint32_t tv_nsec;
	int32_t __res;
};

struct stx {
	uint32_t stx_mask, stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink, stx_uid, stx_gid;
	uint16_t stx_mode, __spare0[1];
	uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
	struct stx_ts stx_atime, stx_btime, stx_ctime, stx_mtime;
	uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
	uint64_t stx_mnt_id;
	uint32_t stx_dio_mem_align, stx_dio_offset_align;
	uint64_t __spare3[12];
};

struct dent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static int do_statx(const char *p, struct stx *s)
{
	memset(s, 0, sizeof(*s));
	return (int)syscall(SYS_statx, AT_FDCWD, p, AT_SYMLINK_NOFOLLOW, STX_WANT, s);
}

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* The parent's readdir number for one name. -1 = name absent, -2 = cannot read. */
static long long dent_ino(const char *dir, const char *name)
{
	char buf[32768];
	long long found = -1;
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -2;
	for (;;) {
		long n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		for (long off = 0; off < n;) {
			struct dent64 *d = (struct dent64 *)(buf + off);
			if (!strcmp(d->d_name, name)) {
				found = (long long)d->d_ino;
				close(fd);
				return found;
			}
			off += d->d_reclen;
		}
	}
	close(fd);
	return found;
}

static void split_path(const char *p, char *dir, size_t dsz, char *base, size_t bsz)
{
	const char *slash = strrchr(p, '/');
	if (!slash || slash == p) {
		snprintf(dir, dsz, "/");
		snprintf(base, bsz, "%s", slash ? slash + 1 : p);
		return;
	}
	size_t dl = (size_t)(slash - p);
	if (dl >= dsz)
		dl = dsz - 1;
	memcpy(dir, p, dl);
	dir[dl] = 0;
	snprintf(base, bsz, "%s", slash + 1);
}

/* Anomaly bits. Printed as values, never as a bare verdict. */
#define A_TIME 0x01 /* mtime 0 -> NM_FLAG_HAVE_TIMES was unset at the read */
#define A_INO 0x02  /* ino far above anything the control showed */
#define A_BLK 0x04  /* blksize 0 -> v_blksize placeholder */
#define A_CTX 0x08  /* no security.selinux -> v_ctx_len 0 */
#define A_DENT 0x10 /* parent's d_ino disagrees with stat's st_ino */

static uint64_t ino_ceiling = 100000; /* overridden by `control`; see conc2-check.sh */
/* A missing security.selinux is only a tell where the control showed labels at
 * all. Disarmed by default so a filesystem that labels nothing cannot false-PASS
 * this probe -- the same control-calibration the ino ceiling gets. */
static int expect_ctx;
static int expect_dent; /* d_ino==st_ino only where the control showed it holds */

static int flags_of(const struct stx *s)
{
	int f = 0;
	/* mtime alone, not an AND over the three: `control` reports whether stock
	 * on this parent ever shows mtime 0, so the baseline is measured. The
	 * window should zero all three; how many it actually zeroed is printed. */
	if (s->stx_mtime.tv_sec == 0)
		f |= A_TIME;
	if (s->stx_ino > ino_ceiling)
		f |= A_INO;
	if (s->stx_blksize == 0)
		f |= A_BLK;
	return f;
}

static void print_flags(int f)
{
	if (!f) {
		printf("none");
		return;
	}
	if (f & A_TIME)
		printf("TIME ");
	if (f & A_INO)
		printf("INO ");
	if (f & A_BLK)
		printf("BLKSIZE ");
	if (f & A_CTX)
		printf("NO_SECCTX ");
	if (f & A_DENT)
		printf("DENT_MISMATCH ");
}

static void dump(const char *tag, const char *path, const struct stx *s)
{
	char ctx[1024];
	long cl = syscall(SYS_getxattr, path, "security.selinux", ctx, sizeof(ctx) - 1);
	if (cl > 0)
		ctx[cl] = 0;

	printf("%s %s\n", tag, path);
	printf("  st_ino      %llu (0x%llx, %s)\n", (unsigned long long)s->stx_ino,
	       (unsigned long long)s->stx_ino,
	       s->stx_ino > 0xffffffffull ? ">32bit" : "fits 32bit");
	printf("  st_dev      %u:%u\n", s->stx_dev_major, s->stx_dev_minor);
	printf("  st_mode     0%o  uid %u  gid %u  nlink %u\n", s->stx_mode & 07777,
	       s->stx_uid, s->stx_gid, s->stx_nlink);
	printf("  st_blksize  %u\n", s->stx_blksize);
	printf("  st_size     %llu\n", (unsigned long long)s->stx_size);
	int nz = (s->stx_mtime.tv_sec == 0) + (s->stx_ctime.tv_sec == 0) +
		 (s->stx_atime.tv_sec == 0);
	printf("  mtime       %lld  ctime %lld  atime %lld  btime %lld\n",
	       (long long)s->stx_mtime.tv_sec, (long long)s->stx_ctime.tv_sec,
	       (long long)s->stx_atime.tv_sec, (long long)s->stx_btime.tv_sec);
	if (nz)
		printf("  1970        %d of 3 (m/c/a) are epoch 0%s\n", nz,
		       nz == 3 ? "  <- the full placeholder triple" :
				 "  <- partial, weaker than the claim");
	printf("  secctx      %s\n", cl > 0 ? ctx : (cl < 0 ? "ABSENT" : "empty"));
}

static int mode_control(const char *dir)
{
	char buf[32768], child[4096];
	uint64_t lo = ~0ull, hi = 0;
	long long tlo = -1, thi = -1;
	int n_dirs = 0, n_zero_time = 0, n_ctx = 0, n_dent = 0, n_btime0 = 0;
	uint32_t blk_lo = ~0u, blk_hi = 0;
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0) {
		fprintf(stderr, "control: open %s: %s\n", dir, strerror(errno));
		return 1;
	}
	printf("== control: subdirs of %s, same binary, same run ==\n", dir);
	for (;;) {
		long n = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		for (long off = 0; off < n;) {
			struct dent64 *d = (struct dent64 *)(buf + off);
			off += d->d_reclen;
			if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
				continue;
			snprintf(child, sizeof(child), "%s/%s", dir, d->d_name);
			struct stx s;
			if (do_statx(child, &s) < 0)
				continue;
			if ((s.stx_mode & 0170000) != 0040000)
				continue;
			n_dirs++;
			if (s.stx_ino < lo)
				lo = s.stx_ino;
			if (s.stx_ino > hi)
				hi = s.stx_ino;
			if (tlo < 0 || s.stx_mtime.tv_sec < tlo)
				tlo = s.stx_mtime.tv_sec;
			if (s.stx_mtime.tv_sec > thi)
				thi = s.stx_mtime.tv_sec;
			if (s.stx_mtime.tv_sec == 0)
				n_zero_time++;
			if (syscall(SYS_getxattr, child, "security.selinux", NULL, 0) >= 0)
				n_ctx++;
			if (s.stx_blksize < blk_lo)
				blk_lo = s.stx_blksize;
			if (s.stx_blksize > blk_hi)
				blk_hi = s.stx_blksize;
			if (s.stx_btime.tv_sec == 0)
				n_btime0++;
			if (d->d_ino != s.stx_ino)
				n_dent++;
		}
	}
	close(fd);
	if (!n_dirs) {
		printf("  no subdirs -- no baseline, do not run watch against this parent\n");
		return 1;
	}
	printf("  n_subdirs       %d\n", n_dirs);
	printf("  st_ino range    %llu .. %llu\n", (unsigned long long)lo,
	       (unsigned long long)hi);
	printf("  mtime range     %lld .. %lld\n", tlo, thi);
	printf("  mtime == 0      %d of %d\n", n_zero_time, n_dirs);
	printf("  has secctx      %d of %d%s\n", n_ctx, n_dirs,
	       n_ctx ? "" : "   <- this fs labels nothing; the secctx test stays off");
	printf("  st_blksize      %u .. %u\n", blk_lo, blk_hi);
	printf("  btime == 0      %d of %d\n", n_btime0, n_dirs);
	printf("  d_ino != st_ino %d of %d%s\n", n_dent, n_dirs,
	       n_dent ? "   <- STOCK already disagrees here (overlayfs); test stays off"
			: "");
	printf("INO_CEILING=%llu\n", (unsigned long long)hi);
	printf("ZERO_TIME_STOCK=%d\n", n_zero_time);
	printf("CTX_STOCK=%d\n", n_ctx);
	printf("DENT_STOCK=%d\n", n_dent);
	printf("BLKSIZE_STOCK=%u..%u\n", blk_lo, blk_hi);
	printf("BTIME_ZERO_STOCK=%d\n", n_btime0);
	return 0;
}

#define RING 64

static int mode_watch(const char *path, long ms)
{
	struct stx ring[RING], s;
	uint64_t t_ring[RING];
	int f_ring[RING];
	int got = 0, worst = 0;
	long long first_dent = -3;
	unsigned long long iters = 0, enoent = 0, ok = 0;
	uint64_t t0 = now_ns(), t_first = 0, deadline;
	char dir[4096], base[256];

	split_path(path, dir, sizeof(dir), base, sizeof(base));
	deadline = t0 + (uint64_t)ms * 1000000ull;

	while (now_ns() < deadline) {
		iters++;
		if (do_statx(path, &s) < 0) {
			enoent++;
			continue;
		}
		ok++;
		if (!t_first)
			t_first = now_ns();
		if (got < RING) {
			ring[got] = s;
			t_ring[got] = now_ns() - t_first;
			f_ring[got] = flags_of(&s);
			if (got == 0)
				first_dent = dent_ino(dir, base);
			got++;
		}
	}

	printf("== watch %s for %ld ms ==\n", path, ms);
	printf("  iterations      %llu  (absent %llu, present %llu)\n", iters, enoent, ok);
	printf("  appeared after  %s\n",
	       t_first ? "see below" : "never -- path stayed absent for the whole span");
	if (!ok) {
		printf("  NOTHING MEASURED. The add did not publish during the span, or the\n");
		printf("  path never materialized. Not a refutation -- re-run overlapping the add.\n");
		return 0;
	}
	printf("  first present   +%llu ns after loop start\n",
	       (unsigned long long)(t_first - t0));
	printf("  snapshots kept  %d of %llu present samples\n", got, ok);
	printf("  parent d_ino for \"%s\" at first sight: ", base);
	if (first_dent == -1)
		printf("name absent from parent's getdents64\n");
	else if (first_dent < 0)
		printf("could not read parent\n");
	else
		printf("%lld\n", first_dent);

	int suppressed = 0;
	for (int i = 0; i < got; i++) {
		int f = f_ring[i];
		if (expect_dent && first_dent >= 0 && (uint64_t)first_dent != ring[i].stx_ino)
			f |= A_DENT;
		if (f > worst)
			worst = f;
		/* Print the first sample, the last, and every one that DIFFERS in the
		 * fields that matter. Identical repeats are counted, not reprinted. */
		int same = i > 0 && !memcmp(&ring[i].stx_ino, &ring[i - 1].stx_ino,
					    sizeof(uint64_t)) &&
			   ring[i].stx_mtime.tv_sec == ring[i - 1].stx_mtime.tv_sec &&
			   ring[i].stx_blksize == ring[i - 1].stx_blksize && f == f_ring[i - 1];
		if (same && i != got - 1) {
			suppressed++;
			continue;
		}
		char tag[64];
		snprintf(tag, sizeof(tag), "  [+%lluus]", (unsigned long long)(t_ring[i] / 1000));
		dump(tag, path, &ring[i]);
		printf("  anomalies   ");
		print_flags(f);
		printf("\n");

	}
	if (suppressed)
		printf("  (%d further snapshot(s) byte-identical to the one above)\n",
		       suppressed);
	printf("WATCH_WORST=%d\n", worst);
	return worst ? 2 : 0;
}

static int mode_read(const char *path)
{
	struct stx s;
	char dir[4096], base[256];
	int f;
	long long di;

	if (do_statx(path, &s) < 0) {
		printf("== read %s ==\n  absent (%s)\n", path, strerror(errno));
		return 0;
	}
	split_path(path, dir, sizeof(dir), base, sizeof(base));
	di = dent_ino(dir, base);
	f = flags_of(&s);
	if (expect_ctx && syscall(SYS_getxattr, path, "security.selinux", NULL, 0) < 0)
		f |= A_CTX;
	if (expect_dent && di >= 0 && (uint64_t)di != s.stx_ino)
		f |= A_DENT;

	printf("== read (residue check) ==\n");
	dump("  ", path, &s);
	printf("  parent d_ino  ");
	if (di == -1)
		printf("name absent from parent's getdents64  <- readdir/stat contradiction\n");
	else if (di < 0)
		printf("could not read parent\n");
	else
		printf("%lld%s\n", di,
		       (uint64_t)di == s.stx_ino ? " (agrees)" : "  <- DISAGREES with st_ino");
	printf("  anomalies     ");
	print_flags(f);
	printf("\n");
	printf("READ_FLAGS=%d\n", f);
	return f ? 2 : 0;
}

int main(int argc, char **argv)
{
	const char *env = getenv("CONC2_INO_CEILING");
	if (env)
		ino_ceiling = strtoull(env, NULL, 10);
	env = getenv("CONC2_EXPECT_CTX");
	if (env)
		expect_ctx = atoi(env) != 0;
	env = getenv("CONC2_EXPECT_DENT");
	if (env)
		expect_dent = atoi(env) != 0;

	if (argc >= 3 && !strcmp(argv[1], "control"))
		return mode_control(argv[2]);
	if (argc >= 3 && !strcmp(argv[1], "read"))
		return mode_read(argv[2]);
	if (argc >= 4 && !strcmp(argv[1], "watch"))
		return mode_watch(argv[2], strtol(argv[3], NULL, 10));

	fprintf(stderr,
		"usage: %s control <dir>\n"
		"       %s watch   <path> <ms>\n"
		"       %s read    <path>\n"
		"env:   CONC2_INO_CEILING=<n>  ino above which to flag (from `control`)\n"
		"       CONC2_EXPECT_CTX=1     arm the missing-secctx test (from `control`)\n"
		"       CONC2_EXPECT_DENT=1    arm the d_ino/st_ino test (from `control`)\n",
		argv[0], argv[0], argv[0]);
	return 1;
}
