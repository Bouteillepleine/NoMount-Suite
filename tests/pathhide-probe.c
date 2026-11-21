#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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

int main(int argc, char **argv)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t pages, len;
	unsigned char *vec;
	struct stat st;
	void *p;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <file-to-map> [maps-needle]\n", argv[0]);
		return 2;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", argv[1], strerror(errno));
		return 2;
	}
	if (fstat(fd, &st) || st.st_size <= 0) {
		fprintf(stderr, "fstat %s: empty or failed\n", argv[1]);
		return 2;
	}

	len = (size_t)st.st_size;
	pages = (len + page - 1) / page;
	p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap: %s\n", strerror(errno));
		return 2;
	}
	*(volatile unsigned char *)p;

	printf("addr      %lx\n", (unsigned long)p);
	printf("pages     %zu\n", pages);
	{
		const char *needle = argc > 2 ? argv[2] : argv[1];
		char mdev[32];
		unsigned long mino = 0;

		printf("maps      %d\n",
		       maps_names((unsigned long)p, needle, mdev, sizeof(mdev), &mino));
		printf("mapsdev   %s\n", mdev);
		printf("mapsino   %lu\n", mino);
		printf("mapfiles  %d\n", map_files_names((unsigned long)p, needle));
		printf("statino   %lu\n", (unsigned long)st.st_ino);
	}

	vec = calloc(pages, 1);
	errno = 0;
	if (mincore(p, len, vec) == 0)
		printf("mincore   ok\n");
	else
		printf("mincore   %s\n", strerror(errno));
	free(vec);

	printf("pagemap   %ld\n", pagemap_nonzero((unsigned long)p, pages));
	printf("vmsize    %lu\n", status_field("VmSize:"));
	printf("vmpeak    %lu\n", status_field("VmPeak:"));
	printf("statm     %lu\n", statm_size());

	munmap(p, len);
	close(fd);
	return 0;
}
