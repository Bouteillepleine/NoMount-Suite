/* PID 1 of the qemu engine smoke boot (tests/qemu/smoke.py builds the initramfs around it).
 *
 * Drives the engine with the repo's own nm client and prints one "NMSMOKE <verdict> <check>"
 * line per check on the serial port; smoke.py decides pass or fail from those lines and the
 * kernel log around them. nmsmoke.mode=lkm loads /nomount.ko with /bin/loader (ko-loader)
 * first, on a stock kernel. nmsmoke.xfail=a,b names known issues: those report XFAIL while
 * they fail and XPASS once they pass, which smoke.py treats as a failure until the name is
 * dropped from the list.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define HIDDEN_UID 10123

static char mode[32] = "builtin";
static char xfails[256];
static int n_pass, n_fail, n_xfail, n_xpass;

static void say(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(buf) - 2)
		n = sizeof(buf) - 2;
	buf[n++] = '\n';
	if (write(1, buf, n) < 0) {
		/* nowhere left to report to */
	}
}

static int listed(const char *list, const char *name)
{
	size_t len = strlen(name);
	const char *p = list;

	while (*p) {
		const char *e = strchr(p, ',');
		size_t l = e ? (size_t)(e - p) : strlen(p);

		if (l == len && !strncmp(p, name, len))
			return 1;
		if (!e)
			break;
		p = e + 1;
	}
	return 0;
}

static void check(const char *name, int ok, const char *fmt, ...)
{
	char detail[512] = "";
	va_list ap;
	int xf = listed(xfails, name);

	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);
	if (ok && !xf) {
		n_pass++;
		say("NMSMOKE PASS %s", name);
	} else if (ok) {
		n_xpass++;
		say("NMSMOKE XPASS %s: a known issue now passes - drop it from the xfail list", name);
	} else if (xf) {
		n_xfail++;
		say("NMSMOKE XFAIL %s: %s", name, detail);
	} else {
		n_fail++;
		say("NMSMOKE FAIL %s: %s", name, detail);
	}
}

/* Runs argv with stdout+stderr captured into out; returns the exit status, or -1. */
static int run(char *const argv[], char *out, size_t outsz)
{
	int p[2], st;
	size_t got = 0;
	pid_t pid;

	if (pipe(p))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		dup2(p[1], 1);
		dup2(p[1], 2);
		close(p[0]);
		close(p[1]);
		execv(argv[0], argv);
		_exit(127);
	}
	close(p[1]);
	for (;;) {
		ssize_t r = read(p[0], out + got, outsz - 1 - got);

		if (r <= 0)
			break;
		got += r;
		if (got >= outsz - 1)
			break;
	}
	out[got] = 0;
	close(p[0]);
	if (waitpid(pid, &st, 0) < 0)
		return -1;
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int nm(const char *a1, const char *a2, const char *a3)
{
	char *argv[] = { "/bin/nm", (char *)a1, (char *)a2, (char *)a3, NULL };
	char out[1024];
	int rc = run(argv, out, sizeof(out));

	if (rc != 0)
		say("NMSMOKE INFO nm %s %s %s -> rc %d: %s", a1, a2 ? a2 : "", a3 ? a3 : "", rc, out);
	return rc;
}

static long slurp(const char *path, char *buf, size_t sz)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	long got = 0;

	if (fd < 0)
		return -errno;
	for (;;) {
		ssize_t r = read(fd, buf + got, sz - 1 - got);

		if (r < 0) {
			got = -errno;
			break;
		}
		if (r == 0)
			break;
		got += r;
		if ((size_t)got >= sz - 1)
			break;
	}
	close(fd);
	if (got >= 0)
		buf[got] = 0;
	return got;
}

struct d64 {
	unsigned long long ino;
	long long off;
	unsigned short reclen;
	unsigned char type;
	char name[];
};

/* Entries other than . and .., and how many of them are named `name`. */
static int count_entries(const char *dir, const char *name, int *hits)
{
	char buf[8192];
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC), n = 0;

	*hits = 0;
	if (fd < 0)
		return -errno;
	for (;;) {
		long r = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		long o;

		if (r < 0) {
			n = -errno;
			break;
		}
		if (r == 0)
			break;
		for (o = 0; o < r;) {
			struct d64 *d = (struct d64 *)(buf + o);

			if (strcmp(d->name, ".") && strcmp(d->name, "..")) {
				n++;
				if (!strcmp(d->name, name))
					(*hits)++;
			}
			o += d->reclen;
		}
	}
	close(fd);
	return n;
}

static int loop_attach(const char *img, const char *dev_out_fmt, char *dev, size_t devsz)
{
	int ctl, back, lfd, n;

	ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (ctl < 0)
		return -errno;
	n = ioctl(ctl, LOOP_CTL_GET_FREE);
	close(ctl);
	if (n < 0)
		return -errno;
	snprintf(dev, devsz, dev_out_fmt, n);
	if (mknod(dev, S_IFBLK | 0600, makedev(7, n)) && errno != EEXIST)
		return -errno;
	back = open(img, O_RDONLY | O_CLOEXEC);
	if (back < 0)
		return -errno;
	lfd = open(dev, O_RDONLY | O_CLOEXEC);
	if (lfd < 0) {
		close(back);
		return -errno;
	}
	if (ioctl(lfd, LOOP_SET_FD, back)) {
		int e = errno;

		close(lfd);
		close(back);
		return -e;
	}
	close(back);
	close(lfd);
	return 0;
}

static int mount_victim(const char *img, const char *fstype, const char *at)
{
	char dev[64];
	int rc = loop_attach(img, "/dev/loop%d", dev, sizeof(dev));

	if (rc) {
		say("NMSMOKE INFO loop for %s: %s", img, strerror(-rc));
		return rc;
	}
	if (mount(dev, at, fstype, MS_RDONLY, NULL)) {
		rc = -errno;
		say("NMSMOKE INFO mount %s on %s (%s): %s", dev, at, fstype, strerror(errno));
		return rc;
	}
	return 0;
}

static void cmdline(void)
{
	char buf[2048], *t, *save = NULL;

	if (slurp("/proc/cmdline", buf, sizeof(buf)) <= 0)
		return;
	for (t = strtok_r(buf, " \n", &save); t; t = strtok_r(NULL, " \n", &save)) {
		if (!strncmp(t, "nmsmoke.mode=", 13))
			snprintf(mode, sizeof(mode), "%s", t + 13);
		else if (!strncmp(t, "nmsmoke.xfail=", 14))
			snprintf(xfails, sizeof(xfails), "%s", t + 14);
	}
}

static int same(const char *a, long alen, const char *b)
{
	return alen == (long)strlen(b) && !memcmp(a, b, alen);
}

static const char *stock_hosts = "127.0.0.1 localhost\n::1 ip6-localhost\n";
static const char *module_hosts = "# NoMount smoke: served from the module\n127.0.0.1 localhost\n0.0.0.0 ads.example\n";
static const char *module_injected = "injected by the smoke module\n";

/* The served/injected checks for one victim mount: rules under /<root>/etc. */
static void victim_checks(const char *root, const char *fs, int stock_entries)
{
	char vh[128], vi[128], ve[128], mh[128], mi[128], name[64], buf[512];
	struct stat st;
	long got;
	int n, hits;

	snprintf(ve, sizeof(ve), "%s/etc", root);
	snprintf(vh, sizeof(vh), "%s/etc/hosts", root);
	snprintf(vi, sizeof(vi), "%s/etc/injected.conf", root);
	snprintf(mh, sizeof(mh), "/m%s/etc/hosts", root);
	snprintf(mi, sizeof(mi), "/m%s/etc/injected.conf", root);

	n = nm("add", vh, mh);
	n |= nm("add", vi, mi);
	snprintf(name, sizeof(name), "rules_added_%s", fs);
	check(name, n == 0, "nm add returned non-zero");

	got = slurp(vh, buf, sizeof(buf));
	snprintf(name, sizeof(name), "served_bytes_%s", fs);
	check(name, same(buf, got, module_hosts), "read %ld bytes: %.60s", got, got > 0 ? buf : "");

	snprintf(name, sizeof(name), "served_stat_%s", fs);
	n = stat(vh, &st);
	check(name, !n && st.st_size == (off_t)strlen(module_hosts), "stat rc %d size %lld, module file %zu",
	      n, n ? -1LL : (long long)st.st_size, strlen(module_hosts));

	n = count_entries(ve, "injected.conf", &hits);
	snprintf(name, sizeof(name), "injected_listed_%s", fs);
	check(name, hits == 1 && n == stock_entries + 1, "%d entries, injected.conf listed %d times, stock %d",
	      n, hits, stock_entries);

	got = slurp(vi, buf, sizeof(buf));
	snprintf(name, sizeof(name), "injected_bytes_%s", fs);
	check(name, same(buf, got, module_injected), "read %ld bytes", got);
}

/* The one known divergence the engine fixer is closing (engine-oracles-1): SEEK_END on a
 * hijacked erofs directory answers the stock size while stat answers the merged one. */
static void seek_end_check(const char *dir, const char *name)
{
	struct stat st;
	off_t end;
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0) {
		check(name, 0, "open %s: %s", dir, strerror(errno));
		return;
	}
	if (fstat(fd, &st)) {
		check(name, 0, "fstat: %s", strerror(errno));
		close(fd);
		return;
	}
	end = lseek(fd, 0, SEEK_END);
	check(name, end == st.st_size, "st_size %lld, lseek(SEEK_END) %lld", (long long)st.st_size,
	      (long long)end);
	close(fd);
}

/* What a uid on the hide list sees, from a child that has dropped to it. */
static void hidden_checks(int builtin)
{
	int p[2], st;
	pid_t pid;
	char res[2048];
	size_t got = 0;

	if (nm("block", "10123", NULL)) {
		check("hidden_block", 0, "nm block %d failed", HIDDEN_UID);
		return;
	}
	if (pipe(p))
		return;
	pid = fork();
	if (pid == 0) {
		char buf[512];
		struct stat s;
		long n;
		int e, hits, fd, avail = -1;

		close(p[0]);
		dup2(p[1], 1);
		if (setresgid(HIDDEN_UID, HIDDEN_UID, HIDDEN_UID) || setresuid(HIDDEN_UID, HIDDEN_UID, HIDDEN_UID)) {
			say("NMSMOKE FAIL hidden_setuid: %s", strerror(errno));
			_exit(1);
		}
		n = slurp("/v/etc/hosts", buf, sizeof(buf));
		say("%s hidden_stock_bytes read %ld bytes", same(buf, n, stock_hosts) ? "ok" : "bad", n);
		e = stat("/v/etc/hosts", &s) ? errno : 0;
		say("%s hidden_stat_stock size %lld errno %d", !e && s.st_size == (off_t)strlen(stock_hosts) ? "ok" : "bad",
		    e ? -1LL : (long long)s.st_size, e);
		n = count_entries("/v/etc", "injected.conf", &hits);
		e = stat("/v/etc/injected.conf", &s) ? errno : 0;
		say("%s hidden_no_injected %ld entries, listed %d times, stat errno %d",
		    hits == 0 && e == ENOENT ? "ok" : "bad", n, hits, e);
		fd = open("/v/etc/hosts", O_RDONLY | O_CLOEXEC);
		if (fd >= 0 && ioctl(fd, FIONREAD, &avail))
			avail = -errno;
		if (fd >= 0)
			close(fd);
		if (builtin)
			say("%s fionread_hidden %d, stock %zu", avail == (int)strlen(stock_hosts) ? "ok" : "bad", avail,
			    strlen(stock_hosts));
		_exit(0);
	}
	close(p[1]);
	for (;;) {
		ssize_t r = read(p[0], res + got, sizeof(res) - 1 - got);

		if (r <= 0)
			break;
		got += r;
	}
	res[got] = 0;
	close(p[0]);
	waitpid(pid, &st, 0);
	{
		const char *names[] = { "hidden_stock_bytes", "hidden_stat_stock", "hidden_no_injected",
					builtin ? "fionread_hidden" : NULL };
		unsigned int i;

		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			char *line;

			if (!names[i])
				continue;
			line = strstr(res, names[i]);
			if (!line) {
				check(names[i], 0, "the hidden child did not report it (status %d): %s", st, res);
				continue;
			}
			{
				char *bol = line, *eol = strchr(line, '\n');

				while (bol > res && bol[-1] != '\n')
					bol--;
				if (eol)
					*eol = 0;
				check(names[i], !strncmp(bol, "ok ", 3), "%s", bol);
				if (eol)
					*eol = '\n';
			}
		}
	}
	check("hidden_unblock", nm("unblock", "10123", NULL) == 0, "nm unblock failed");
}

static int load_module(void)
{
	char *argv[] = { "/bin/loader", "/nomount.ko", NULL };
	char out[4096], *l, *save = NULL;
	int rc = run(argv, out, sizeof(out));

	for (l = strtok_r(out, "\n", &save); l; l = strtok_r(NULL, "\n", &save))
		say("NMSMOKE INFO loader: %s", l);
	return rc;
}

int main(void)
{
	int con, builtin;
	char ver[256], buf[512], uts[256];
	char *vargv[] = { "/bin/nm", "v", NULL };
	long got;
	int rc, hits, n;

	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	/* GKI appends console=ttynull to the command line, which takes /dev/console. */
	con = open("/dev/ttyAMA0", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (con < 0)
		con = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (con >= 0) {
		dup2(con, 1);
		dup2(con, 2);
	}
	cmdline();
	builtin = strcmp(mode, "lkm") != 0;
	got = slurp("/proc/sys/kernel/osrelease", uts, sizeof(uts));
	if (got > 0 && uts[got - 1] == '\n')
		uts[got - 1] = 0;
	say("NMSMOKE BEGIN mode=%s kernel=%s xfail=%s", mode, got > 0 ? uts : "?", xfails[0] ? xfails : "-");

	if (!builtin) {
		rc = load_module();
		check("module_loaded", rc == 0, "ko-loader exited %d", rc);
	}
	rc = run(vargv, ver, sizeof(ver));
	check("engine_answers", rc == 0 && atoi(ver) >= 36, "nm v rc %d: %s", rc, ver);
	if (rc != 0)
		goto out;
	say("NMSMOKE INFO engine %s", strtok(ver, "\n"));

	if (mount_victim("/victim.erofs", "erofs", "/v") || mount_victim("/victim.ext4", "ext4", "/x")) {
		check("victims_mounted", 0, "see the INFO line above");
		goto out;
	}
	n = count_entries("/v/etc", "injected.conf", &hits);
	victim_checks("/v", "erofs", n);
	victim_checks("/x", "ext4", count_entries("/x/etc", "injected.conf", &hits));
	seek_end_check("/v/etc", "seek_end_erofs");
	hidden_checks(builtin);

	rc = nm("del", "/v/etc/hosts", NULL);
	got = slurp("/v/etc/hosts", buf, sizeof(buf));
	check("del_restores", rc == 0 && same(buf, got, stock_hosts), "nm del rc %d, read %ld bytes", rc, got);
	rc = nm("clear", NULL, NULL);
	count_entries("/v/etc", "injected.conf", &hits);
	check("clear_restores_listing", rc == 0 && hits == 0, "nm clear rc %d, injected.conf listed %d times", rc,
	      hits);
out:
	say("NMSMOKE END pass=%d fail=%d xfail=%d xpass=%d", n_pass, n_fail, n_xfail, n_xpass);
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}
