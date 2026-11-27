/* nm_emit_tail() and nm_tail_gap() (hookless/src/nomount.c) driven as a merged overlay
 * directory and as an erofs one: tests/tail-gap-check.sh extracts both and compiles them
 * here. A stock overlay cursor is an index, so a listing of E entries must end at d_off E,
 * every getdents buffer size must resume without a duplicate or a skip, and a child hidden
 * from the reader must not leave a hole (engine-oracles-5). */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef long long loff_t;
typedef uint64_t u64;
typedef uint32_t u32;
#define NAME_MAX 255
#define NM_POS_HEADROOM 65536
#define NM_FLAG_WHITEOUT 0x1
#define NM_FLAG_SHADOWS_STOCK 0x2
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define rcu_read_lock() do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define READ_ONCE(x) (x)
struct super_block { int overlay; };
struct nomount_child_node { const char *name; int name_len; u64 fake_ino; unsigned char d_type; u32 flags; int visible; };
struct idr { struct nomount_child_node *slot[32]; };
struct nomount_dir_node { int refcount; struct idr children_idr; };
struct dir_context { loff_t pos; };
static bool nm_victim_is_overlay(const struct super_block *sb) { return sb->overlay; }
static bool nm_child_visible(const struct nomount_child_node *c) { return c->visible; }
static int atomic_inc_not_zero(int *r) { return *r ? ++*r : 0; }
static void nm_dir_node_put(struct nomount_dir_node *d) { d->refcount--; }
static struct nomount_child_node *idr_get_next(struct idr *idr, int *id)
{
	for (; *id < 32; ++*id)
		if (idr->slot[*id]) return idr->slot[*id];
	return NULL;
}
/* One getdents buffer: room for `cap` entries, each recorded with the position it was
 * emitted at; the previous entry's d_off is that position, the last one's is ctx->pos. */
static struct { char name[16]; loff_t at; } buf[64];
static int nbuf, cap;
static bool dir_emit(struct dir_context *ctx, const char *name, int len, u64 ino, unsigned char dt)
{
	(void)ino; (void)dt;
	if (nbuf >= cap) return false;
	memcpy(buf[nbuf].name, name, len); buf[nbuf].name[len] = 0; buf[nbuf].at = ctx->pos; nbuf++;
	return true;
}
#include NM_TAIL_FN

static int pass, fail;
static void check(const char *what, bool ok) { if (ok) pass++; else { fail++; printf("  FAIL %s\n", what); } }

/* The hijacked iterate, cut down: N real entries at positions 0..N-1 (overlay) or at 12-byte
 * dirent offsets (erofs), EOF at real_eof, then the tail. */
static loff_t getdents(struct super_block *sb, struct nomount_dir_node *d, int n_real,
                       loff_t real_eof, loff_t max_real_pos, loff_t (*real_pos)(int), loff_t pos)
{
	struct dir_context ctx = { .pos = pos };
	loff_t gap = nm_tail_gap(sb, real_eof, max_real_pos);
	nbuf = 0;
	if (pos <= max_real_pos || pos == real_eof) {
		for (int i = 0; i < n_real; i++) {
			if (real_pos(i) < ctx.pos) continue;
			ctx.pos = real_pos(i);
			char nm[8]; snprintf(nm, sizeof(nm), "r%d", i);
			if (!dir_emit(&ctx, nm, (int)strlen(nm), 0, 0)) return ctx.pos;
			ctx.pos = i + 1 < n_real ? real_pos(i + 1) : real_eof;
		}
		ctx.pos = real_eof;
	}
	nm_emit_tail(&ctx, d, real_eof, true, gap);
	return ctx.pos;
}
static loff_t ovl_pos(int i) { return i; }
static loff_t erofs_pos(int i) { return 12LL * i; }

static void run(const char *label, int overlay, int n_real, loff_t (*real_pos)(int), loff_t real_eof,
                int hide, loff_t want_terminal)
{
	struct super_block sb = { .overlay = overlay };
	static struct nomount_child_node kids[5] = {
		{ "t0", 2, 900, 4, 0, 1 }, { "t1", 2, 901, 4, 0, 1 }, { "t2", 2, 902, 4, 0, 1 },
		{ "t3", 2, 903, 4, 0, 1 }, { "t4", 2, 904, 4, 0, 1 } };
	struct nomount_dir_node d = { .refcount = 1 };
	char full[64][16]; int nfull = 0, ntail = 0;
	char what[160];

	for (int i = 0; i < 5; i++) { kids[i].visible = i != hide; d.children_idr.slot[i * 3] = &kids[i]; }
	for (int i = 0; i < n_real; i++) snprintf(full[nfull++], 16, "r%d", i);
	for (int i = 0; i < 5; i++) if (i != hide) { snprintf(full[nfull++], 16, "t%d", i); ntail++; }

	cap = 64;
	loff_t end = getdents(&sb, &d, n_real, real_eof, real_pos(n_real - 1), real_pos, 0);
	snprintf(what, sizeof(what), "%s: one read lists all %d entries", label, nfull);
	check(what, nbuf == nfull);
	snprintf(what, sizeof(what), "%s: terminal d_off %lld, want %lld", label, end, want_terminal);
	check(what, end == want_terminal);
	bool dense = true;
	for (int i = 1; i < nbuf; i++) if (buf[i].at <= buf[i - 1].at) dense = false;
	for (int i = n_real + 1; i < nbuf; i++) if (buf[i].at != buf[i - 1].at + 1) dense = false;
	snprintf(what, sizeof(what), "%s: tail positions rise by one with no hole", label);
	check(what, dense);

	for (cap = 1; cap <= nfull; cap++) {
		char got[64][16]; int ng = 0; loff_t pos = 0;
		for (int guard = 0; guard < 200; guard++) {
			loff_t np = getdents(&sb, &d, n_real, real_eof, real_pos(n_real - 1), real_pos, pos);
			if (!nbuf) break;
			for (int i = 0; i < nbuf && ng < 64; i++) strcpy(got[ng++], buf[i].name);
			pos = np;
		}
		bool same = ng == nfull;
		for (int i = 0; same && i < ng; i++) same = !strcmp(got[i], full[i]);
		snprintf(what, sizeof(what), "%s: %d-entry buffers resume without a duplicate or a skip", label, cap);
		check(what, same);
		snprintf(what, sizeof(what), "%s: %d-entry buffers end at d_off %lld", label, cap, want_terminal);
		check(what, pos == want_terminal);
	}
	check("the dir node reference is dropped on every pass", d.refcount == 1);
	(void)ntail;
}

int main(void)
{
	/* overlay: 7 real (dots included) at 0..6, EOF 7; five tail entries end at 12 = E. */
	run("overlay", 1, 7, ovl_pos, 7, -1, 12);
	run("overlay, t2 hidden", 1, 7, ovl_pos, 7, 2, 11);
	/* overlay passed through to one erofs layer: byte offsets, the tail keeps its gap. */
	run("overlay over sparse positions", 1, 7, erofs_pos, 84, -1, 84 + 1 + 5);
	/* erofs: byte offsets, EOF at 84, tail from 85. */
	run("erofs", 0, 7, erofs_pos, 84, -1, 84 + 1 + 5);
	run("erofs, t0 hidden", 0, 7, erofs_pos, 84, 0, 84 + 1 + 4);
	printf("tail-gap-check: %d passed, %d failed\n", pass, fail);
	return fail != 0;
}
