/* Does statmount/listmount leak a mount that /proc/<pid>/mountinfo no longer shows?
 *
 * The LKM's mount filter kretprobes show_mountinfo, show_vfsmnt and show_vfsstat,
 * and the in-tree engine patches the same three handlers. All three are procfs.
 * statmount(2) and listmount(2) landed in 6.8 and read the mount tree directly, so
 * neither guard is on their path. This measures whether that matters on a device:
 * it enumerates the namespace with listmount, asks statmount for each mount's root
 * and mountpoint, and prints the ones that name a module -- then says whether
 * mountinfo agrees. A mount that listmount reports and mountinfo does not is a
 * contradiction between two views, which is a stronger tell than either alone.
 *
 * Raw syscalls and local struct copies: bionic has no wrapper for either call, and
 * the NDK headers that carry the uapi structs are newer than some of the sysroots
 * this gets built against.
 *
 *   clang --target=aarch64-linux-android31 -O2 -static \
 *         tests/statmount-probe.c -o statmount-probe
 *
 * Run as any uid. The interesting run is as a hide-listed app uid, because that is
 * the only caller the guards act for:
 *   adb shell su -c 'sh /data/local/tmp/statmount-check.sh'
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_statmount
#define __NR_statmount 457
#endif
#ifndef __NR_listmount
#define __NR_listmount 458
#endif

#define LSMT_ROOT 0xffffffffffffffffULL

#define SM_SB_BASIC   0x00000001U
#define SM_MNT_BASIC  0x00000002U
#define SM_MNT_ROOT   0x00000008U
#define SM_MNT_POINT  0x00000010U
#define SM_FS_TYPE    0x00000020U

struct mnt_id_req {
	uint32_t size;
	uint32_t spare;
	uint64_t mnt_id;
	uint64_t param;
	uint64_t mnt_ns_id;
};
#define MNT_ID_REQ_SIZE_VER0 24

struct statmount {
	uint32_t size;
	uint32_t mnt_opts;
	uint64_t mask;
	uint32_t sb_dev_major;
	uint32_t sb_dev_minor;
	uint64_t sb_magic;
	uint32_t sb_flags;
	uint32_t fs_type;
	uint64_t mnt_id;
	uint64_t mnt_parent_id;
	uint32_t mnt_id_old;
	uint32_t mnt_parent_id_old;
	uint64_t mnt_attr;
	uint64_t mnt_propagation;
	uint64_t mnt_peer_group;
	uint64_t mnt_master;
	uint64_t propagate_from;
	uint32_t mnt_root;
	uint32_t mnt_point;
	uint64_t mnt_ns_id;
	uint64_t __spare2[49];
	char str[];
};

static long sys_listmount(const struct mnt_id_req *req, uint64_t *ids,
			  size_t nr, unsigned int flags)
{
	return syscall(__NR_listmount, req, ids, nr, flags);
}

static long sys_statmount(const struct mnt_id_req *req, struct statmount *buf,
			  size_t bufsize, unsigned int flags)
{
	return syscall(__NR_statmount, req, buf, bufsize, flags);
}

/* The needle is the one real mount a mountless posture keeps: a hook framework's
 * bind, whose root renders as /adb/modules/<id> out of the userdata fs, or in
 * full where that fs is presented at /. */
static int names_a_module(const char *s)
{
	return s && (strstr(s, "/adb/modules/") != NULL);
}

static int mountinfo_has(const char *needle)
{
	char line[4096];
	FILE *f = fopen("/proc/self/mountinfo", "re");
	int hit = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { hit = 1; break; }
	}
	fclose(f);
	return hit;
}

int main(void)
{
	static uint64_t ids[4096];
	struct mnt_id_req req = { .size = MNT_ID_REQ_SIZE_VER0, .mnt_id = LSMT_ROOT };
	long n, i;
	int leaked = 0, contradictions = 0;
	size_t bufsz = 8192;
	struct statmount *sm = malloc(bufsz);

	if (!sm) { fprintf(stderr, "oom\n"); return 2; }

	n = sys_listmount(&req, ids, sizeof(ids) / sizeof(ids[0]), 0);
	if (n < 0) {
		if (errno == ENOSYS) {
			printf("listmount: ENOSYS - this kernel predates the syscall, nothing to measure\n");
			printf("verdict: not applicable\n");
			return 0;
		}
		printf("listmount: failed (%s)\n", strerror(errno));
		printf("verdict: unmeasured\n");
		return 0;
	}
	printf("listmount: %ld mount(s) in this namespace\n", n);

	for (i = 0; i < n; i++) {
		struct mnt_id_req s = {
			.size = MNT_ID_REQ_SIZE_VER0,
			.mnt_id = ids[i],
			.param = SM_MNT_ROOT | SM_MNT_POINT | SM_FS_TYPE | SM_SB_BASIC,
		};
		const char *root, *point, *fst;
		long r = sys_statmount(&s, sm, bufsz, 0);

		if (r < 0) {
			/* Only worth a line when listmount offered the id and statmount
			 * then denied it: that pairing is itself the contradiction. */
			printf("  id %llu: listmount listed it, statmount says %s\n",
			       (unsigned long long)ids[i], strerror(errno));
			contradictions++;
			continue;
		}
		root  = sm->mnt_root  ? sm->str + sm->mnt_root  : "";
		point = sm->mnt_point ? sm->str + sm->mnt_point : "";
		fst   = sm->fs_type   ? sm->str + sm->fs_type   : "";

		if (names_a_module(root) || names_a_module(point)) {
			int mi = mountinfo_has(names_a_module(root) ? root : point);

			leaked++;
			printf("  LEAK id %llu  root=%s  point=%s  fs=%s\n",
			       (unsigned long long)ids[i], root, point, fst);
			if (mi == 0) {
				printf("       mountinfo does NOT show it: the two views disagree\n");
				contradictions++;
			} else if (mi == 1) {
				printf("       mountinfo shows it too: one uncovered surface, not a contradiction\n");
			}
		}
	}

	free(sm);
	printf("statmount/listmount: %d module-rooted mount(s), %d contradiction(s)\n",
	       leaked, contradictions);
	if (leaked == 0)
		printf("verdict: clean\n");
	else
		printf("verdict: %d leak(s)%s\n", leaked,
		       contradictions ? " and a disagreement with mountinfo" : "");
	return leaked ? 1 : 0;
}
