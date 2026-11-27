/* nm_ovl_layout_ok() (hookless/src/nomount.c) against struct ovl_fs layouts it was not built
 * for: tests/ovl-layout-check.sh extracts the function and compiles it here with a
 * copy_from_kernel_nofault that faults outside the fake objects. Every shifted layout, with
 * the inserted field non-zero and then zero, must be refused; the build's own must pass. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
typedef uint64_t u64;
typedef struct { long counter; } atomic_long_t;
/* Build-time view: the 6.12 field order up to last_ino (gki-6.12.81 fs/overlayfs/ovl_entry.h). */
struct ovl_layer { void *mnt; void *trap; void *fs; int idx; int fsid; bool has_xwhiteouts; };
#define OVL_FS_FIELDS(EXTRA_A, EXTRA_B, EXTRA_C, EXTRA_D) \
	EXTRA_A unsigned int numlayer; unsigned int numfs; unsigned int numdatalayer; \
	EXTRA_B struct ovl_layer *layers; void *fs; void *workbasedir; void *workdir; long namelen; \
	char config[64]; const void *creator_cred; bool tmpfile, noxattr, nofh, ul, wl; \
	void *wbt; void *wt; EXTRA_C int xino_mode; EXTRA_D atomic_long_t last_ino; void *whiteout;
struct ovl_fs { OVL_FS_FIELDS(,,,) };
struct live_a { OVL_FS_FIELDS(long added;,,,) };
struct live_b { OVL_FS_FIELDS(,long added;,,) };
struct live_c { OVL_FS_FIELDS(,,long added;,) };
struct live_d { OVL_FS_FIELDS(,,,long added;) };
static const char *lo, *hi; static const char *lo2, *hi2;
static long copy_from_kernel_nofault(void *dst, const void *src, size_t n)
{
	const char *s = src;
	if (!((s >= lo && s + n <= hi) || (s >= lo2 && s + n <= hi2))) return -14;
	memcpy(dst, src, n); return 0;
}
#include NM_OVL_FN
static struct ovl_layer L[4];
#define FILL(o) do { memset(&(o), 0, sizeof(o)); (o).numlayer = 4; (o).numfs = 2; (o).layers = L; \
	(o).creator_cred = (void *)0xffffff8012345678UL; (o).xino_mode = -1; (o).last_ino.counter = 40; } while (0)
static int pass, fail;
static void check(const char *what, bool got, bool want) {
	if (got == want) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s (got %d)\n", what, got); }
}

int main(void)
{
	for (int i = 0; i < 4; i++) { L[i].idx = i; L[i].fsid = i ? 1 : 0; }
	lo2 = (const char *)L; hi2 = lo2 + sizeof(L);
	struct ovl_fs o; FILL(o); lo = (const char *)&o; hi = lo + sizeof(o);
	check("the build's own layout is accepted", nm_ovl_layout_ok(&o, 28), true);
	check("a counter below the scanned maximum is refused", nm_ovl_layout_ok(&o, 41), false);
	L[2].idx = 7; check("a layer whose idx is not its index is refused", nm_ovl_layout_ok(&o, 28), false); L[2].idx = 2;
	L[3].fsid = 5; check("a fsid outside numfs is refused", nm_ovl_layout_ok(&o, 28), false); L[3].fsid = 1;
	o.layers = (struct ovl_layer *)0x10; check("an unmapped layers pointer is refused, not faulted on", nm_ovl_layout_ok(&o, 28), false); o.layers = L;
	o.xino_mode = 40; check("xino_mode out of range is refused", nm_ovl_layout_ok(&o, 28), false); o.xino_mode = -1;
	for (long fill = 0x4141414141414141L, round = 0; round < 2; round++, fill = 0) {
	struct live_a a; FILL(a); a.added = fill; lo = (const char *)&a; hi = lo + sizeof(a);
	check("a field inserted before numlayer is refused", nm_ovl_layout_ok((struct ovl_fs *)&a, 28), false);
	struct live_b b; FILL(b); b.added = fill; lo = (const char *)&b; hi = lo + sizeof(b);
	check("a field inserted before layers is refused", nm_ovl_layout_ok((struct ovl_fs *)&b, 28), false);
	struct live_c c; FILL(c); c.added = fill; lo = (const char *)&c; hi = lo + sizeof(c);
	check("a field inserted before xino_mode is refused", nm_ovl_layout_ok((struct ovl_fs *)&c, 28), false);
	struct live_d d; FILL(d); d.added = fill; lo = (const char *)&d; hi = lo + sizeof(d);
	check("a field inserted before last_ino is refused", nm_ovl_layout_ok((struct ovl_fs *)&d, 28), false);
	}
	printf("\n%d passed, %d failed\n", pass, fail);
	return fail != 0;
}
