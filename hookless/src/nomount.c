#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/hash.h>
#include <linux/sort.h>
#include "nomount.h"

/* Android packs (user_id, appid) into a uid: uid = user_id*NM_PER_USER_RANGE + appid.
 * Matching a blocklist entry on the appid (uid % NM_PER_USER_RANGE) therefore covers
 * the same app across every user, work profile and clone with a single entry. Isolated
 * processes carry a pool-allocated appid that is not tied to the parent app:
 * [NM_APPZYGOTE_START, NM_APPZYGOTE_END] for an app's own zygote children and
 * [NM_ISOLATED_START, NM_ISOLATED_END] for the platform pool.
 *
 * Hiding from those pools protects a blocked app that farms its probing out to an
 * isolated helper, and it is not free: while it is on, an UNBLOCKED app can compare
 * its own view against its own isolated child's view and find the injection that way.
 * (The blocked app itself sees no such divergence -- both of its views are stock.)
 * Which side of that trade to take is a policy call, so it is nm_hide_isolated rather
 * than a hardcoded range. Default = both pools, i.e. the historical behaviour. */
#define NM_PER_USER_RANGE   100000
#define NM_APPZYGOTE_START  90000
#define NM_APPZYGOTE_END    98999
#define NM_ISOLATED_START   99000
#define NM_ISOLATED_END     99999

/* An app's SDK-runtime sandbox process, by contrast, runs at a uid that DOES name
 * its owner: Process.toSdkSandboxUid() is appid + 10000. So a blocked app could
 * simply read through its own sandbox process. That one maps back exactly, with no
 * collateral, so it is followed rather than pooled. */
#define NM_SDKSANDBOX_START 20000
#define NM_SDKSANDBOX_END   29999
#define NM_SDKSANDBOX_OFF   10000

/* Same weak-extern arrangement for _ghost. NM_GHOST_RULE_MAX must be >=
 * ghost.c's GH_RULE_LEN (192) plus its two-character command prefix; if it ever
 * drifts, ghost_get_rule() rejects the undersized buffer and the dump comes back
 * empty rather than truncated. */
#define NM_GHOST_RULE_MAX 200
extern int ghost_ctl(const char *buf, size_t count) __attribute__((weak));
extern int ghost_get_rule(int idx, char *out, size_t outsz) __attribute__((weak));

static atomic_t nm_rule_gen = ATOMIC_INIT(0);
static struct kmem_cache *nm_dir_cachep __read_mostly, *nm_inode_cachep __read_mostly;
static struct kmem_cache *nm_iop_cachep __read_mostly, *nm_fop_cachep __read_mostly;
static const struct cred *nm_root_cred;

/* dir_node lifetime: refcounted so a synthetic inode that cached info->dir_node
 * (pinned by an open fd) keeps the node alive across nm del/clear, which would
 * otherwise call_rcu-free it and leave the pinned reader walking a freed idr. */
static void nm_dir_node_put(struct nomount_dir_node *dir_node);
static DEFINE_STATIC_KEY_FALSE(nomount_active_uids);

/*** Helpers ***/

/* Read/apply an inode's LSM context. A synthesized directory has no backing
 * inode to inherit from, so without this it stays UNLABELED -- ls -Z prints '?'
 * where every stock sibling prints a context, which is a one-syscall tell any
 * app can make. */
static int nm_read_secctx(struct inode *in, char *dst, u16 *dlen)
{
/* 6.14, not 6.13: v6.13 include/linux/security.h still declares
 * security_inode_getsecctx(struct inode *, void **, u32 *) and
 * security_release_secctx(char *, u32); both took struct lsm_context * at v6.14. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    struct lsm_context lc;

    if (security_inode_getsecctx(in, &lc)) return -ENODATA;
    *dlen = min_t(u16, lc.len, NM_CTX_MAX - 1);
    memcpy(dst, lc.context, *dlen);
    security_release_secctx(&lc);
#else
    void *ctx = NULL;
    u32 clen = 0;

    if (security_inode_getsecctx(in, &ctx, &clen)) return -ENODATA;
    *dlen = min_t(u16, clen, NM_CTX_MAX - 1);
    memcpy(dst, ctx, *dlen);
    security_release_secctx(ctx, clen);
#endif
    dst[*dlen] = '\0';
    return 0;
}


/* Which isolated pools to hide from once anything is blocked. Bit 0 = the app
 * zygote pool, bit 1 = the platform isolated pool; NM_KNOB_HIDE_ISOLATED sets it.
 * See the range comment above for the trade this expresses. */
#define NM_HIDE_APPZYGOTE   0x1
#define NM_HIDE_ISOLATED    0x2
static unsigned int nm_hide_isolated __read_mostly = NM_HIDE_APPZYGOTE | NM_HIDE_ISOLATED;

static __always_inline bool nomount_is_uid_blocked(uid_t uid)
{
    unsigned int appid, pools;
    bool is_blocked;
    if (!static_branch_unlikely(&nomount_active_uids)) return false;
    /* Reaching here means the static branch is on, i.e. at least one appid is blocked. */
    appid = uid % NM_PER_USER_RANGE;
    pools = READ_ONCE(nm_hide_isolated);
    if ((pools & NM_HIDE_APPZYGOTE) &&
        appid >= NM_APPZYGOTE_START && appid <= NM_APPZYGOTE_END)
        return true; /* app-zygote isolated child: not attributable, hide from all */
    if ((pools & NM_HIDE_ISOLATED) &&
        appid >= NM_ISOLATED_START && appid <= NM_ISOLATED_END)
        return true; /* platform isolated pool: same */
    if (appid >= NM_SDKSANDBOX_START && appid <= NM_SDKSANDBOX_END)
        appid -= NM_SDKSANDBOX_OFF;  /* follow the sandbox back to the app that owns it */
    rcu_read_lock();
    is_blocked = (idr_find(&nomount_uid_idr, appid) != NULL);
    rcu_read_unlock();
    return is_blocked;
}

/* Is a rule visible to the CALLER? A rule scoped with --uid follows the app across
 * users, work profiles and clones, because it compares the appid -- the same
 * normalisation the block list uses. Comparing raw uids here (as this did) made a
 * uid-scoped rule silently miss the cloned instance of the very app it named.
 * target_uid 0 = every caller. */
static __always_inline bool nm_rule_visible(const struct nomount_rule *rule)
{
    unsigned int target;

    if (!rule) return false;
    target = rule->target_uid;
    return target == 0 ||
           (target % NM_PER_USER_RANGE) == (current_uid().val % NM_PER_USER_RANGE);
}

/* Does the block list hide a rule carrying these flags from THIS caller?
 *
 * The block list is otherwise all-or-nothing per UID, which is wrong for a rule
 * the system already advertises to that UID by other means -- see NM_FLAG_PUBLIC
 * for the PackageManager case that motivates it. Everything that used to test
 * nomount_is_uid_blocked() to decide whether to serve an injection asks this
 * instead; the raw test survives only where the question really is about the UID
 * and not about a rule (the coarse gates, which are additionally guarded by
 * dir_node->has_public, and nm_reval_stale). */
static __always_inline bool nm_uid_hidden(u32 flags)
{
    return !(flags & NM_FLAG_PUBLIC) &&
           nomount_is_uid_blocked(current_uid().val);
}

/* Is this listing entry visible to the caller: right audience for a --uid-scoped
 * rule, and not hidden by the block list. Every by-child walk (readdir emit, the
 * real-dirent proxy, the parent's nlink/size deltas) filters on this, so all
 * three agree about what the caller can see. */
static __always_inline bool nm_child_visible(const struct nomount_child_node *child)
{
    return child && nm_rule_visible(child->rule) && !nm_uid_hidden(child->flags);
}

#define __get_nm(ptr, type, member, field, hook_func) ({ \
    typeof(ptr) __p = (ptr); \
    (likely(__p) && __p->field == (hook_func)) ? container_of(__p, type, member) : NULL; \
})

/* forward decls: the __get_nm identity checks below reference these hijack ops
 * before their definitions (identity is now by function pointer, not magic sig) */
static struct dentry *nomount_hijacked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags);
static int nomount_hijacked_iterate_dir(struct file *file, struct dir_context *ctx);
/* Userspace-measured: this device's ROM directories are dirent-packed, so a
 * synthesized dir must report the erofs-shaped size instead of 4096. See
 * NM_KNOB_VDIR_EROFS_SIZE for why this cannot be inferred in-kernel. */
static bool nm_vdir_erofs_size __read_mostly;
/* linux/magic.h only grew this in 5.4; nm_llseek below needs it, so the
 * fallback has to sit above the FIRST use, not next to nm_vdir_size. */
#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xE0F5E1E2
#endif
/* Defined below; nm_llseek needs it so SEEK_END on a synthesized directory
 * reports the same size getattr does. */
static loff_t nm_vdir_size(struct nomount_dir_node *d, unsigned int blocksize);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static int nomount_hijacked_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat);
#else
static int nomount_hijacked_getattr(IDMAP_ARG const struct path *path, struct kstat *stat,
                                    u32 request_mask, unsigned int query_flags);
#endif
static u64 nm_child_dotdot_of(const char *dirpath);
/* Defined with the dir-target snapshot below; nomount_hijacked_destroy_inode()
 * sits above it and has to release the cache's reference, and nm_llseek() has to
 * answer SEEK_END with the size the snapshot dictates. */
static void nm_dsnap_drop(struct nm_inode_info *info);
static loff_t nm_dsnap_dir_size(struct inode *v_inode, struct nm_inode_info *info);

/* Returns the raw (unpinned) dir_node behind a hijacked inode. Safe ONLY under
 * nomount_write_mutex, which excludes the del/clear paths that call_rcu-free a
 * dir_node -- its sole caller (nomount_generate_virtual_topology) holds it. Any
 * lockless/RCU-walk caller must instead pin via atomic_inc_not_zero (see
 * nm_d_revalidate / the hijacked handlers). */
static __always_inline struct nomount_dir_node *nomount_get_dir_node(struct inode *inode)
{
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;

    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    /* ACQUIRE, not a plain load. The re-arm in nomount_hijack_* stores a
     * dir_node allocated microseconds earlier into a vtable that was ALREADY
     * published, so the reader's smp_load_acquire(&inode->i_op) pairs with the
     * FIRST publish and orders nothing about the new node. __nomount_alloc_dir_node
     * uses kmem_cache_alloc (not zalloc) and its idr_init/hash_init/atomic_set are
     * plain stores in another function, so on arm64 a reader could see the pointer
     * before the init and then atomic_inc_not_zero a recycled slab word. */
    {
        struct nomount_dir_node *d = nm_iop ? smp_load_acquire(&nm_iop->dir_node) : NULL;

        if (d) return d;
    }

    nm_fop = nm_get_fop(smp_load_acquire(&inode->i_fop));
    {
        struct nomount_dir_node *d = nm_fop ? smp_load_acquire(&nm_fop->dir_node) : NULL;

        if (d) return d;
    }
    
    return NULL;
}

/* Does `name` carry a rule here that this reader is NOT the audience for?
 * nomount_get_rule_info() applies nm_rule_visible() internally, so a UID-scoped
 * rule that does not match reports "no rule" and the caller falls through to the
 * real fs. That is correct for this reader, but the dentry the real lookup caches
 * is shared: whichever UID resolves the path first wins, and the UID the rule IS
 * for then gets the stock view until drop_caches. Measured on OP15 against a rule
 * scoped to uid 2000: 2000 read the injection, root's lookup cached the real
 * dentry, and every later read by 2000 returned the real file. Same shape as the
 * blocked-reader case below, one lookup away. */
static __always_inline bool nm_name_has_hidden_uid_rule(struct nomount_dir_node *dir_node,
                                                        const char *name, size_t len, u32 hash)
{
    struct nomount_child_node *child;
    bool found = false;

    if (unlikely(!dir_node)) return false;
    if (!(READ_ONCE(dir_node->bloom_mask) & (1ULL << (hash & 63)))) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            /* One child node per name (get_rule_info breaks on the first name
             * match too), so this decides the name outright. */
            found = child->rule && !nm_child_visible(child);
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

/* Lockless read path: snapshot the needed fields under RCU and path_get() the
 * backing path, so callers never dereference the rule after rcu_read_unlock().
 * Returns true if a rule visible to the current UID was found; on true the caller
 * owns rule_info->r_path and must path_put() it (when r_path.dentry != NULL). */
static __always_inline bool nomount_get_rule_info(struct nomount_dir_node *dir_node, const char *name, size_t len, u32 hash, struct nm_rule_info *rule_info, bool get_path)
{
    struct nomount_child_node *child;
    bool found = false;

    if (unlikely(!dir_node)) return false;
    /* Bloom fast-reject: a name whose hash bit is clear is definitely not an
     * injected child here, so skip the lookup entirely. On a hit we resolve via
     * the per-dir hash table (O(bucket)) rather than a full O(children) scan, so
     * large-fanout dirs stay fast even once the 64-bit bloom filter saturates. */
    if (!(READ_ONCE(dir_node->bloom_mask) & (1ULL << (hash & 63)))) return false;
    /* Sample the rule generation BEFORE reading the table, never after.
     * nm_inode_info.gen is what nm_d_revalidate()'s RCU fast path compares
     * against, so a stamp taken afterwards can carry a generation this snapshot
     * was never validated against: an add/del landing in between bumps the
     * counter, the inode is stamped with the NEW value, and the fast path then
     * keeps answering 1 for a dentry the topology change should have pushed
     * through the ref-walk. Sampling first can only ever record a STALER
     * generation, which costs one ref-walk and re-stamps there. */
    rule_info->gen = (u32)atomic_read(&nm_rule_gen);
    rule_info->r_path.dentry = NULL;
    rule_info->r_path.mnt = NULL;
    rule_info->s_path.dentry = NULL;
    rule_info->s_path.mnt = NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            struct nomount_rule *rule = child->rule;
            if (nm_rule_visible(rule)) {
                rule_info->flags = rule->flags;
                rule_info->v_ino = rule->v_ino;
                rule_info->v_dino = rule->v_dino;
                rule_info->v_pdino = rule->v_pdino;
                rule_info->v_dev = rule->v_dev;
                rule_info->v_mapdev = rule->v_mapdev;
                rule_info->v_atime = rule->v_atime;
                rule_info->v_mtime = rule->v_mtime;
                rule_info->v_ctime = rule->v_ctime;
                rule_info->v_attributes = rule->v_attributes;
                rule_info->v_attr_mask = rule->v_attr_mask;
                rule_info->v_blksize = rule->v_blksize;
                rule_info->v_cratio = rule->v_cratio;
                rule_info->v_result_mask = rule->v_result_mask;
                rule_info->v_cap = rule->v_cap;
                rule_info->v_uid = rule->v_uid;
                rule_info->v_gid = rule->v_gid;
                rule_info->v_mode = rule->v_mode;
                rule_info->v_ctx_len = rule->v_ctx_len;
                if (rule->v_ctx_len) memcpy(rule_info->v_ctx, rule->v_ctx, rule->v_ctx_len + 1);
                /* Acquire a ref while still under rcu_read_lock so the node
                 * survives create_new_inode's sleeping alloc; a node already being
                 * freed (refcount hit 0, call_rcu pending) fails not_zero -> treat
                 * as absent. The caller releases this ref via nm_put_rule_info(). */
                rule_info->this_dir = rule->this_dir;
                if (rule_info->this_dir && !atomic_inc_not_zero(&rule_info->this_dir->refcount))
                    rule_info->this_dir = NULL;
                if (get_path && rule->r_path.dentry) {
                    rule_info->r_path = rule->r_path;
                    path_get(&rule_info->r_path);
                }
                if (get_path && rule->s_path.dentry) {
                    rule_info->s_path = rule->s_path;
                    path_get(&rule_info->s_path);
                }
                found = true;
            }
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

/* Release the refs a successful nomount_get_rule_info() handed out (this_dir ref
 * + r_path). create_new_inode() takes its OWN refs, so the caller always releases
 * the rule_info copy on every exit path -- exactly mirroring the existing r_path
 * discipline. Idempotent: NULLs the fields after releasing. */
static inline void nm_put_rule_info(struct nm_rule_info *ri)
{
    if (ri->this_dir) { nm_dir_node_put(ri->this_dir); ri->this_dir = NULL; }
    if (ri->r_path.dentry) { path_put(&ri->r_path); ri->r_path.dentry = NULL; ri->r_path.mnt = NULL; }
    if (ri->s_path.dentry) { path_put(&ri->s_path); ri->s_path.dentry = NULL; ri->s_path.mnt = NULL; }
}

struct nomount_proxy_ctx {
    struct dir_context ctx;
    struct dir_context *orig_ctx;
    struct nomount_dir_node *dir_node;
    /* Set ONLY when the directory being listed is one whose rule TARGETS a real
     * directory, i.e. its entries come off the backing filesystem (/data, f2fs)
     * rather than off a stock ROM directory. NULL for a hijacked stock dir, where
     * the real dirents are the stock ones and must pass through untouched. See
     * nm_dirent_ino(). */
    const struct nm_inode_info *dir_info;
    int emitted;
};

/* A stable, mirrored st_ino for a child that has no rule of its own -- the
 * contents of a directory a rule TARGETS (NM_FLAG_IS_DIR with a real backing
 * dir). Those children are served straight off the backing fs, so without this
 * they report /data's f2fs inode numbers among ROM siblings.
 *
 * Same band shape nm_alloc_rule uses when it has no sampled sibling population to
 * place into (see the "last resort" branch there): keep the parent's magnitude,
 * step one 20-bit band up, and spread inside it. It must be a PURE function of
 * (parent ino, name) because readdir and stat compute it independently and have
 * to agree -- there is no child_node to cache it in, which is exactly the
 * difference between these children and a rule's.
 *
 * @dirent salts a SECOND number for the readdir side. On an overlay-backed parent
 * a real child's dirent ino and its st_ino differ (NM_FLAG_OVL_INO); emitting one
 * number for both is the tell that flag exists to avoid.
 *
 * Collisions are bounded the same way nm_alloc_rule's are: 20 bits per band
 * against one directory's population. */
static inline unsigned long nm_child_ino(unsigned long base, const char *name, int len, bool dirent)
{
    u64 h = (u64)full_name_hash(NULL, name, len) | (dirent ? (1ULL << 32) : 0);
    unsigned int bits, w;

    /* The fixed 1 MB step only preserves magnitude when the parent's ino is
     * ALREADY above 1 MB. Below that, `base & ~0xFFFFF` is 0 and every child
     * lands at 1..2M regardless of the parent -- two orders of magnitude above
     * its siblings on a small-ino filesystem. Measured on OP15: a dir-target at
     * /product/etc (erofs, dir ino 15018, stock siblings 7166..20309) minted
     * children at 1226252..2181515. One stat separates them from the whole
     * directory. So scale the band to the parent instead of assuming it. */
    if ((u64)base >= 0x100000ULL)
        return (unsigned long)(((u64)base & ~0xFFFFFULL) + 0x100000ULL +
                               hash_64(h ^ ((u64)base << 32), 20));

    /* Next power of two above the parent, spread over a quarter of that width:
     * for base 15018 -> band 32768, children in 32768..36863. Same digit count
     * as the siblings and clear of the sampled population, which is what the
     * 1 MB step was buying on large-ino filesystems. The 12-bit floor keeps a
     * tiny parent ino from collapsing the spread to nothing. */
    bits = fls64((u64)base | 0xFFFULL);
    w = bits - 2;
    return (unsigned long)((1ULL << (bits + 1)) +
                           hash_64(h ^ ((u64)base << 32), w));
}

/* The d_ino a dirent of a dir-target rule's backing directory should carry.
 * "." and ".." follow nm_emit_dots() exactly, so a synthesized dir and a
 * real-backed one answer the same way; everything else goes through
 * nm_child_ino() with the readdir salt when the parent is overlay-backed.
 *
 * Known gap: ".." falls back to the directory's OWN ino when v_pdino is unset,
 * which is what nm_emit_dots does and is only right for a dir whose parent was
 * itself synthesized. It is still strictly closer than the f2fs number this
 * replaces. */
static inline u64 nm_dirent_ino(const struct nm_inode_info *d, const char *name, int len)
{
    if (len == 1 && name[0] == '.')
        return d->v_dino ? d->v_dino : d->v_ino;
    if (len == 2 && name[0] == '.' && name[1] == '.')
        return d->v_pdino ? d->v_pdino : d->v_ino;
    return nm_child_ino(d->v_ino, name, len, !!(d->flags & NM_FLAG_OVL_INO));
}

static NM_ACTOR_RET nomount_actor_proxy(struct dir_context *ctx, const char *name, int namelen,
                                        loff_t offset, u64 ino, unsigned int d_type)
{
    struct nomount_proxy_ctx *proxy = container_of(ctx, struct nomount_proxy_ctx, ctx);
    struct nomount_child_node *child;
    NM_ACTOR_RET ret;
    u32 hash;

    if (!proxy->dir_node) goto do_real_actor;
    hash = full_name_hash(NULL, name, namelen);
    if (!(READ_ONCE(proxy->dir_node->bloom_mask) & (1ULL << (hash & 63))))
        goto do_real_actor;

    /* By-name lookup: use the per-dir hash table, not an O(children) idr scan.
     * This is the hottest by-name path -- called once per real dirent during a
     * readdir of a hijacked large dir -- so the O(bucket) table is what keeps the
     * "at any fanout" property on the dir that motivates it (/product/overlay). */
    rcu_read_lock();
    hash_for_each_possible_rcu(proxy->dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == namelen && memcmp(child->name, name, namelen) == 0) {
            if (nm_child_visible(child)) {
                /* A REPLACEMENT is emitted HERE, at the stock entry's own offset,
                 * instead of being suppressed and re-appended after real EOF.
                 *
                 * erofs stores dirents sorted by name and its cookies are byte
                 * offsets, so an appended entry was the only name out of order in
                 * the whole directory AND pushed the final d_off past
                 * stat().st_size -- both readable with one getdents64 plus one
                 * stat, no baseline needed. Measured on OP15 before this:
                 * /system/etc/permissions listed 25 entries, st_size 986, last
                 * d_off 988, one name out of order; every rule-free erofs dir on
                 * the same device ended exactly ON st_size and was fully sorted.
                 *
                 * Safe precisely for SHADOWS_STOCK: the flag means kern_path()
                 * resolved the vpath when the rule was made, so a real dirent for
                 * this name provably exists -- which is what gives us a correctly
                 * ordered slot to emit into. It also keeps the size books
                 * balanced, because nm_dir_deltas() already treats a shadowing
                 * child as size-neutral. nomount_emit_virtual_children() skips
                 * the same class so it is emitted exactly once.
                 *
                 * A WHITEOUT still falls through to suppression below: hiding the
                 * stock name is the entire point of that rule. */
                if ((child->flags & NM_FLAG_SHADOWS_STOCK) &&
                    !(child->flags & NM_FLAG_WHITEOUT)) {
                    u64 fino = child->fake_ino;
                    unsigned char dt = child->d_type;

                    rcu_read_unlock();
                    nm_note_real_pos(proxy->dir_node, offset);
                    proxy->orig_ctx->pos = proxy->ctx.pos;
                    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen,
                                                 offset, fino, dt);
                    proxy->ctx.pos = proxy->orig_ctx->pos;
                    if (ret == NM_ACTOR_CONTINUE) proxy->emitted++;
                    return ret;
                }
                rcu_read_unlock();
                proxy->ctx.pos = offset;
                return NM_ACTOR_CONTINUE;
            }
            break;
        }
    }
    rcu_read_unlock();

do_real_actor:
    /* A dirent of a dir-target rule's BACKING directory carries an ino from
     * /data, not from the ROM path the caller thinks it is reading. Mirror it,
     * with the same number nm_dir_child_lookup() will hand stat() for that name --
     * getdents64 d_ino and st_ino have to tell one story. */
    if (proxy->dir_info)
        ino = nm_dirent_ino(proxy->dir_info, name, namelen);
    nm_note_real_pos(proxy->dir_node, offset);
    proxy->orig_ctx->pos = proxy->ctx.pos;
    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino, d_type);
    proxy->ctx.pos = proxy->orig_ctx->pos;
    if (ret == NM_ACTOR_CONTINUE) proxy->emitted++;

    return ret;
}

/* dir_emit_dots() serves i_ino for "." and the parent's i_ino for "..", i.e. the
 * exact numbers stat returns. That is right on a normal fs and wrong under
 * overlayfs, where a real dir's dirent carries the lower fs's ino and stat the
 * one overlayfs allocated -- so a synthesized dir was the only one on the device
 * where getdents64(".") agreed with stat("."). Serve the dirent inos here. */
static bool nm_emit_dots(struct file *file, struct dir_context *ctx,
                         const struct nm_inode_info *info)
{
    if (!(info->flags & NM_FLAG_OVL_INO))
        return dir_emit_dots(file, ctx);

    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, info->v_dino ? info->v_dino : info->v_ino, DT_DIR))
            return false;
        ctx->pos = 1;
    }
    if (ctx->pos == 1) {
        if (!dir_emit(ctx, "..", 2, info->v_pdino ? info->v_pdino : info->v_ino, DT_DIR))
            return false;
        ctx->pos = 2;
    }
    return true;
}

/* @real_pass_done: this directory has a real backing listing that already ran, so
 * SHADOWS_STOCK children were emitted in place there and must NOT be emitted
 * again here. False for a directory NoMount synthesized whole -- it has no real
 * pass, so anything skipped here would simply never appear. (A synthesized dir's
 * children cannot normally shadow stock, since its own path does not exist in
 * stock; the flag is passed explicitly rather than assumed.) */
static inline void nomount_emit_virtual_children(struct dir_context *ctx, struct nomount_dir_node *dir_node,
                                                 bool real_pass_done)
{
    struct nomount_child_node *child;
    int id;

    if (!dir_node) return;
    if (!nm_is_virtual_pos(dir_node, ctx->pos)) ctx->pos = nm_pack_pos(dir_node, 0);
    id = nm_unpack_pos(dir_node, ctx->pos);
    if (id < 0) id = 0;

    /* Keep the node alive across the dir_emit sleeps below without holding RCU. */
    if (!atomic_inc_not_zero(&dir_node->refcount)) return;

    for (;;) {
        char name[NAME_MAX + 1];
        int found = -1, nlen = 0;
        u64 fino = 0;
        unsigned char dt = 0;

        /* Pick the next emittable child and SNAPSHOT it under RCU. dir_emit ->
         * filldir -> copy_to_user can fault and SLEEP; doing that under
         * rcu_read_lock is illegal (grace-period stall / mmap_lock inversion),
         * so the emit below runs with RCU dropped and only the stack snapshot. */
        rcu_read_lock();
        while ((child = idr_get_next(&dir_node->children_idr, &id)) != NULL) {
            /* SHADOWS_STOCK children were already emitted in the real pass, at
             * the stock entry's own (correctly ordered) offset -- see the
             * in-place branch in nomount_actor_proxy. Emitting them again here
             * would duplicate the name and re-introduce the ordering tell. */
            if (nm_child_visible(child) &&
                !(child->flags & NM_FLAG_WHITEOUT) &&
                !(real_pass_done && (child->flags & NM_FLAG_SHADOWS_STOCK))) {
                found = id;
                nlen = min_t(int, (int)child->name_len, NAME_MAX);
                memcpy(name, child->name, nlen);
                fino = child->fake_ino;
                dt = child->d_type;
                break;
            }
            id++;
        }
        rcu_read_unlock();

        if (found < 0)
            break;
        ctx->pos = nm_pack_pos(dir_node, found);
        if (!dir_emit(ctx, name, nlen, fino, dt))
            break;
        id = found + 1;
        ctx->pos = nm_pack_pos(dir_node, id);
    }

    nm_dir_node_put(dir_node);
}

static struct inode *nomount_create_new_inode(struct super_block *virtual_sb, struct nm_rule_info *rule_info)
{
    struct inode *inode;
    struct nm_inode_info *info;

    inode = new_inode(virtual_sb);
    if (unlikely(!inode)) return NULL;

    info = kmem_cache_alloc(nm_inode_cachep, GFP_KERNEL);
    if (unlikely(!info)) {
        iput(inode);
        return NULL;
    }

    info->flags = rule_info->flags;
    /* Stamped BEFORE the inode goes live, and re-stamped by nm_d_revalidate()
     * whenever the slow path confirms it. Read lockless -- see nm_inode_info.gen.
     * The value comes from the SNAPSHOT (sampled before the rule table was read)
     * rather than from a fresh atomic_read here, so it can never be newer than
     * the topology this inode was actually built from. */
    info->gen = rule_info->gen;
    info->v_ctx_len = rule_info->v_ctx_len;
    if (rule_info->v_ctx_len) memcpy(info->v_ctx, rule_info->v_ctx, rule_info->v_ctx_len + 1);
    /* Own ref for the inode's cached copy: the caller still holds its get_rule_info
     * ref (so the node is live here), and releases it via nm_put_rule_info(). This
     * ref is dropped in nomount_hijacked_destroy_inode(). */
    info->dir_node = rule_info->this_dir;
    if (info->dir_node) atomic_inc(&info->dir_node->refcount);
    /* Lazily filled on the first stat()/readdir() that qualifies -- see the
     * dir-target snapshot header. */
    info->dsnap = NULL;
    spin_lock_init(&info->dsnap_lock);
    if (rule_info->flags & NM_FLAG_VIRTUAL_DIR) {
        info->r_path.dentry = NULL;
        info->r_path.mnt = NULL;
    } else {
        info->r_path = rule_info->r_path;
        path_get(&info->r_path);
    }
    /* Own ref on the shadowed stock file, same discipline as r_path: it is what a
     * hidden reader gets served from the ops, so it must outlive the rule_info. */
    info->s_path.dentry = NULL;
    info->s_path.mnt = NULL;
    if (rule_info->s_path.dentry) {
        info->s_path = rule_info->s_path;
        path_get(&info->s_path);
    }

    info->v_ino = rule_info->v_ino;
    info->v_dino = rule_info->v_dino;
    info->v_pdino = rule_info->v_pdino;
    info->v_dev = rule_info->v_dev;
    info->v_mapdev = rule_info->v_mapdev;
    info->v_atime = rule_info->v_atime;
    info->v_mtime = rule_info->v_mtime;
    info->v_ctime = rule_info->v_ctime;
    info->v_attributes = rule_info->v_attributes;
    info->v_attr_mask = rule_info->v_attr_mask;
    info->v_blksize = rule_info->v_blksize;
    info->v_cratio = rule_info->v_cratio;
    info->v_result_mask = rule_info->v_result_mask;
    info->v_cap = rule_info->v_cap;

    inode->i_private = info;
    inode->i_ino = rule_info->v_ino;
    if (rule_info->flags & NM_FLAG_VIRTUAL_DIR) {
        /* Mirror the nearest real ancestor's owner/mode (captured at rule build)
         * instead of a hardcoded root:root 0755, which is an outlier under any
         * tree whose dirs are not 0755 root. v_mode == 0 => ancestor unknown,
         * fall back to the 0755 default. */
        inode->i_mode = S_IFDIR | (rule_info->v_mode ? rule_info->v_mode : 0755);
        inode->i_size = 4096;
        inode->i_blocks = 8;
        inode->i_uid = rule_info->v_uid;
        inode->i_gid = rule_info->v_gid;
        /* Initial value only -- getattr recounts, since children arrive in batches. */
        /* Real dirs report 2 + one per subdirectory. A synthesized dir that
         * contains subdirectories but reports a flat 2 is impossible on any
         * normal fs, so count the injected children that are dirs. */
        {
            unsigned int links = 2;

            if (rule_info->this_dir) {
                struct nomount_child_node *ch;
                int cid = 0;

                rcu_read_lock();
                idr_for_each_entry(&rule_info->this_dir->children_idr, ch, cid)
                    if (ch->d_type == DT_DIR && !(ch->flags & NM_FLAG_WHITEOUT))
                        links++;
                rcu_read_unlock();
            }
            set_nlink(inode, links);
        }
        /* Label it like its nearest real ancestor. If that context was
         * unreadable we deliberately do NOT fall back to S_PRIVATE: that would
         * reinstate the very LSM bypass this inode is meant to lose. An
         * unlabelled inode then gets whatever SELinux assigns any unlabelled
         * inode on this sb, and is enforced like one. */
        if (rule_info->v_ctx_len)
            security_inode_notifysecctx(inode, rule_info->v_ctx, rule_info->v_ctx_len);
        inode->i_op = &nm_dir_iops;
        inode->i_fop = &nm_dir_fops;
    } else {
        struct inode *real_inode = d_backing_inode(rule_info->r_path.dentry);
        inode->i_mode = real_inode->i_mode;
        inode->i_size = i_size_read(real_inode);
        inode->i_blocks = real_inode->i_blocks;
        inode->i_uid = real_inode->i_uid;
        inode->i_gid = real_inode->i_gid;
        nm_sync_inode_times(inode, real_inode);
       if (S_ISDIR(real_inode->i_mode)) {
            /* new_inode() leaves i_nlink at 1; a directory reporting 1 link is
             * impossible. Mirror the backing directory's count. */
            set_nlink(inode, real_inode->i_nlink);
            inode->i_op = &nm_dir_iops;
            inode->i_fop = &nm_dir_fops;
        } else {
            inode->i_op = &nm_file_iops;
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
            if (!S_ISLNK(real_inode->i_mode) && real_inode->i_fop && real_inode->i_fop->mmap_prepare)
                inode->i_fop = &nm_file_fops_mmap_prepare;
            else
        #endif
                inode->i_fop = &nm_file_fops;
        }
        inode->i_mapping = real_inode->i_mapping;
        /* Mirror the backing file's SELinux context onto the synthetic inode.
         * ls -Z reads the SID assigned at new_inode time, not our xattr proxy;
         * on plain erofs that SID is unlabeled ('?'). */
        {
            char ctx[NM_CTX_MAX];
            u16 ctxlen = 0;

            if (rule_info->v_ctx_len) {                 /* stock file's label */
                security_inode_notifysecctx(inode, rule_info->v_ctx, rule_info->v_ctx_len);
            } else if (nm_read_secctx(real_inode, ctx, &ctxlen) == 0) {
                security_inode_notifysecctx(inode, ctx, ctxlen);
                memcpy(info->v_ctx, ctx, ctxlen + 1);
                info->v_ctx_len = ctxlen;
            }
        }
    }

    /* No S_PRIVATE: IS_PRIVATE() makes selinux_inode_permission() and
     * inode_has_perm() return early, so the caller's domain was never checked
     * against an injected path -- both a policy hole and a probe (a read that
     * policy should deny but succeeds proves injection). Contexts are mirrored
     * above, so normal enforcement now applies and matches the stock file. */
    inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
    inode->i_opflags |= IOP_XATTR;
    if (!S_ISLNK(inode->i_mode)) inode->i_opflags |= IOP_NOFOLLOW;

    return inode;
}

/*** i_op / s_op / f_op Hijacking Hooks ***/

static struct dentry *nomount_hijacked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct nm_iop *nm_iop;
    struct nomount_dir_node *pdir;
    const struct inode_operations *orig_iop;
    struct nm_rule_info rule_info;
    const char *name = dentry->d_name.name;
    size_t len = dentry->d_name.len;
    struct dentry *ret = ERR_PTR(-EOPNOTSUPP);
    u32 v_hash;

    /* Recover our vtable and pin the parent dir_node under RCU, then copy out
     * everything we need: a concurrent del/clear can store_release the inode's
     * i_op back and call_rcu-free nm_iop while this (sleeping) handler runs, so
     * nm_iop must NOT be dereferenced past here. orig_iop points into the real
     * fs's const ops (alive for the whole mount), so the copy is safe; the
     * dir_node needs an explicit ref to outlive create_new_inode's sleeping
     * alloc. A node already being freed fails inc_not_zero -> treat as unhijacked. */
    rcu_read_lock();
    nm_iop = __get_nm(smp_load_acquire(&dir->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    orig_iop = nm_iop ? nm_iop->orig_iop : NULL;
    pdir = nm_iop ? smp_load_acquire(&nm_iop->dir_node) : NULL;
    if (pdir && !atomic_inc_not_zero(&pdir->refcount)) pdir = NULL;
    rcu_read_unlock();

    /* A blocked reader used to bail out here for the whole directory. It still
     * does when nothing in this one is public -- the common case, and the shape
     * the audit matrix measures -- but a directory that holds a public rule has
     * to be walked, because that rule stays visible to it. nm_uid_hidden() below
     * makes the call per rule, so only the public name is served. */
    if (unlikely(!pdir || (nomount_is_uid_blocked(current_uid().val) &&
                           !READ_ONCE(pdir->has_public))))
        goto fallback;

    v_hash = full_name_hash(NULL, name, len);
    if (nomount_get_rule_info(pdir, name, len, v_hash, &rule_info, true)) {
        if (unlikely(nm_uid_hidden(rule_info.flags))) {
            nm_put_rule_info(&rule_info);
            goto fallback;
        }
        if (rule_info.flags & NM_FLAG_WHITEOUT) {
            nm_install_dentry_ops(dentry);
            d_add(dentry, NULL);
            nm_put_rule_info(&rule_info);
            ret = NULL;
            goto out;
        }

        if ((rule_info.flags & NM_FLAG_VIRTUAL_DIR) || rule_info.r_path.dentry) {
            struct inode *new_inode = nomount_create_new_inode(dir->i_sb, &rule_info);
            if (likely(new_inode)) {
                struct dentry *res;
                nm_install_dentry_ops(dentry);
                nm_debug("Lookup hijacked! Splicing inode %lu into dentry '%s'\n", new_inode->i_ino, name);
                nm_put_rule_info(&rule_info);
                /* d_splice_alias may return a DIFFERENT (existing) alias dentry; our
                 * ops must ride on THAT one too, else d_revalidate never runs on the
                 * spliced dentry and the per-UID / ghost-dentry verdict is lost for
                 * it. (Ported from upstream c4fcdac; the DONTCACHE fallback below is
                 * deliberately kept -- upstream's rewrite dropped it.) */
                res = d_splice_alias(new_inode, dentry);
                if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
                ret = res;
                goto out;
            }
        }
        nm_put_rule_info(&rule_info);
    }

fallback:
    /* We bailed to the real fs because THIS reader's UID is blocked (not because
     * there's no rule). The dentry the real lookup is about to cache is the STOCK
     * view for a path that IS injected -- if it persists in the shared dcache it
     * hides the injection from every other UID (root included) until drop_caches.
     * Relying on nm_d_revalidate to re-resolve it later is not enough: the VFS's
     * d_invalidate() is a no-op on a negative, so the stale negative just stays.
     * So do not let it persist at all: DCACHE_DONTCACHE evicts the dentry on the
     * last dput, so the blocked reader gets its stock/negative view for this call
     * and the next lookup by anyone re-resolves cleanly. Still tag it with nm_dops
     * so d_revalidate keeps the per-UID verdict for the window it is alive.
     * DCACHE_DONTCACHE exists from 5.13; on older trees nm_reval_stale() in
     * d_revalidate is the fallback. Gate on a rule existing, else a normal real
     * file (no rule) would be needlessly uncached.
     *
     * nm_tag_passthrough_dentry(), not nm_install_dentry_ops(): the real fs is
     * about to populate this dentry and keeps its own d_op. See the note there --
     * replacing d_op here leaked an ovl_entry per lookup on 4.9..6.4. */
    if (pdir && nomount_is_uid_blocked(current_uid().val) &&
        nomount_get_rule_info(pdir, name, len,
                              full_name_hash(NULL, name, len), &rule_info, false)) {
        nm_tag_passthrough_dentry(dentry);
        nm_put_rule_info(&rule_info);
    } else if (pdir && nm_name_has_hidden_uid_rule(pdir, name, len,
                                                   full_name_hash(NULL, name, len))) {
        /* Mirror of the above for a UID-scoped rule this reader is not the
         * audience for: it legitimately sees the stock file, but that view must
         * not outlive the call or it becomes the cached answer for the UID the
         * rule names. */
        nm_tag_passthrough_dentry(dentry);
    }

    if (orig_iop && orig_iop->lookup)
        ret = orig_iop->lookup(dir, dentry, flags);

out:
    if (pdir) nm_dir_node_put(pdir);
    return ret;
}
static int nomount_hijacked_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_fop *nm_fop;
    struct nomount_dir_node *pdir;
    const struct file_operations *orig_fop;
    struct nomount_proxy_ctx proxy_ctx = {
        .ctx.actor = nomount_actor_proxy,
    };
    int res = 0;

    /* Same lifetime discipline as nomount_hijacked_lookup: recover + pin under
     * RCU, copy orig_fop (real fs const ops), never deref nm_fop after -- a
     * concurrent del/clear can call_rcu-free it across nm_call_iterate's sleep. */
    rcu_read_lock();
    nm_fop = nm_get_fop(smp_load_acquire(&file->f_op));
    orig_fop = nm_fop ? nm_fop->orig_fop : NULL;
    pdir = nm_fop ? smp_load_acquire(&nm_fop->dir_node) : NULL;
    if (pdir && !atomic_inc_not_zero(&pdir->refcount)) pdir = NULL;
    rcu_read_unlock();

    /* Same gate as nomount_hijacked_lookup: a blocked reader skips the whole
     * directory unless something in it is public, in which case it runs the
     * normal path and the per-child filter (nm_child_visible) decides what the
     * proxy suppresses and what the virtual pass emits. */
    if (unlikely(!orig_fop || !pdir ||
                 (nomount_is_uid_blocked(current_uid().val) &&
                  !READ_ONCE(pdir->has_public))))
        goto do_real_iterate;

    if (unlikely(nm_is_virtual_pos(pdir, ctx->pos))) {
        nomount_emit_virtual_children(ctx, pdir, true);
        goto out;
    }

    proxy_ctx.ctx.pos = ctx->pos;
    proxy_ctx.orig_ctx = ctx;
    proxy_ctx.dir_node = pdir;
    proxy_ctx.emitted = 0;

    res = nm_call_iterate(file, &proxy_ctx.ctx, orig_fop);
    ctx->pos = proxy_ctx.ctx.pos;
    if (res < 0 || proxy_ctx.emitted > 0) goto out;

    nm_publish_real_eof(pdir, ctx->pos);
    ctx->pos = nm_pack_pos(pdir, 0);
    nomount_emit_virtual_children(ctx, pdir, true);
    goto out;

do_real_iterate:
    res = orig_fop ? nm_call_iterate(file, ctx, orig_fop) : -ENOTDIR;
out:
    if (pdir) nm_dir_node_put(pdir);
    return res;
}

static void nm_inode_info_rcu_free(struct rcu_head *head)
{
    kmem_cache_free(nm_inode_cachep, container_of(head, struct nm_inode_info, rcu));
}

static void nomount_hijacked_destroy_inode(struct inode *inode)
{
    struct nm_sop *nm_sop;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        if (inode->i_private) {
            struct nm_inode_info *info = inode->i_private;

            /* UNPUBLISH FIRST, free last.
             *
             * call_rcu() only promises to wait for read-side sections that were
             * ALREADY IN PROGRESS when it was armed. A reader entering after
             * that point and still finding the pointer in i_private is not
             * covered by that grace period -- so arming the callback before
             * clearing i_private (which is what this did) left a window in which
             * nm_d_revalidate()'s RCU fast path could load the payload and then
             * dereference it after the callback had already freed it. Clearing
             * the pointer first means no reader can acquire it from here on, and
             * the call_rcu below covers exactly the ones that already had it. */
            WRITE_ONCE(inode->i_private, NULL);
            if (info->r_path.dentry) path_put(&info->r_path);
            if (info->s_path.dentry) path_put(&info->s_path);
            if (info->dir_node) nm_dir_node_put(info->dir_node);
            /* Release the CACHE's reference. An in-flight readdir/stat holds
             * its own, so the buffers survive until that reader puts it. */
            nm_dsnap_drop(info);
            /* The puts stay SYNCHRONOUS -- dput() can sleep and an RCU callback
             * runs in softirq -- but the struct itself must outlive any reader
             * that loaded i_private before the store above, so only the free is
             * deferred. Null the two path dentries: nm_d_revalidate()'s RCU fast
             * path tests s_path.dentry for NULL, and after the put above that
             * pointer is dangling. It is never dereferenced there, but leaving a
             * freed pointer behind to be compared is not worth the argument. */
            info->r_path.dentry = NULL;
            info->s_path.dentry = NULL;
            info->dir_node = NULL;
            call_rcu(&info->rcu, nm_inode_info_rcu_free);
        }
    }
    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode);
    if (nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->destroy_inode) {
        nm_sop->orig_sop->destroy_inode(inode);
    }
}

static int nomount_hijacked_drop_inode(struct inode *inode)
{
    struct nm_sop *nm_sop;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        return !inode->i_nlink || inode_unhashed(inode);
    }

    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode);
    if (nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->drop_inode) {
        return nm_sop->orig_sop->drop_inode(inode);
    }
    
    return !inode->i_nlink || inode_unhashed(inode);
}

static void nomount_hijacked_evict_inode(struct inode *inode)
{
    struct nm_sop *nm_sop;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        truncate_inode_pages_final(&inode->i_data);
        clear_inode(inode);
        return;
    }
    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode);
    if (nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->evict_inode) {
        nm_sop->orig_sop->evict_inode(inode);
    } else {
        truncate_inode_pages_final(&inode->i_data);
        clear_inode(inode);
    }
}

/*** file / inode / superblock operations ***/

/* A blocked (hidden) reader must not see an injected name that stock does not
 * have. The historic way to arrange that was to fail d_revalidate, which makes
 * the VFS d_invalidate() the dentry -- but the dcache holds ONE dentry per
 * (parent, name), so unhashing it for this reader unhashes it for everyone, and
 * every process that already MAPPED the file then reads
 * "…/file (deleted)" out of /proc/<pid>/maps for the life of that mapping.
 * Measured on OP15: six app-uid processes, every injected mapping in each of
 * them flagged, readable by any app from its OWN maps with no permission at all.
 *
 * So for an ADDED name, keep the dentry hashed for everyone and refuse it in the
 * ops instead: stat and open return -ENOENT, and readdir already filters per UID,
 * which is what "not there" means to a caller. A SHADOWING rule still takes the
 * old path: a stock file exists underneath and the reader is entitled to see it,
 * so re-resolving to the real fs is both correct and the only way to serve it. */
static __always_inline bool nm_hidden_from_caller(const struct nm_inode_info *info)
{
    return info && !(info->flags & NM_FLAG_SHADOWS_STOCK) &&
           nm_uid_hidden(info->flags);
}

/* The stock file to serve THIS caller, or NULL to serve the injection.
 * A hidden reader of a SHADOWING rule is entitled to the file underneath, and
 * handing it back from here is what removes the last reason to invalidate the
 * shared dentry (see nm_hidden_from_caller). NULL when the rule adds a new name
 * (nothing underneath -- that path returns -ENOENT instead) or when the stock
 * file could not be pinned at rule creation. */
/* Non-const on purpose: vfs_getattr() takes a writable `struct path *` on 4.9
 * (it gained the const in a later series), and a const return here fails that
 * build with -Wdiscarded-qualifiers. */
static __always_inline struct path *nm_stock_for_caller(struct nm_inode_info *info)
{
    if (!info || !info->s_path.dentry) return NULL;
    if (!(info->flags & NM_FLAG_SHADOWS_STOCK)) return NULL;
    /* Per-rule question, so ask nm_uid_hidden (which honours NM_FLAG_PUBLIC),
     * not the raw uid: a PUBLIC rule shadowing a stock file the PackageManager
     * has already parsed as ours must serve OUR bytes to a blocked reader, or
     * read()/stat() disagree with the version and signature PM published for
     * that path. nomount_is_uid_blocked here made NM_FLAG_PUBLIC a no-op for
     * open/getattr/xattr -- the reader still got the stock file. */
    return nm_uid_hidden(info->flags) ? &info->s_path : NULL;
}

static int nm_open(struct inode *inode, struct file *file)
{
    struct nm_inode_info *info = inode->i_private;
    struct file *real_file;

    if (unlikely(!info)) return -ENODEV;
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
        file->private_data = NULL;
        return 0;
    }
    if (unlikely(!info->r_path.dentry)) return -ENODEV;

    /* A hidden reader gets the file this rule shadows, opened from the pinned
     * stock path -- same view it used to get by having the dentry invalidated
     * underneath it, minus the collateral on everyone else's mappings. */
    {
        struct path *stock = nm_stock_for_caller(info);
        if (unlikely(stock)) {
            real_file = dentry_open(stock, file->f_flags, current_cred());
            if (IS_ERR(real_file)) return PTR_ERR(real_file);
            file->private_data = real_file;
            /* The MAPPING has to follow the file we just chose to serve.
             *
             * do_dentry_open() set f->f_mapping from inode->i_mapping, and this
             * inode borrows the MODULE file's address_space (see
             * nomount_create_new_inode). filemap_fault() resolves pages through
             * vmf->vma->vm_file->f_mapping, and nm_mmap deliberately restores
             * vma->vm_file to OUR file -- so without this a blocked reader got
             * stock bytes from read()/stat() and MODULE bytes from every mapped
             * page. On Android that is the dominant path (the linker mmaps .so,
             * AssetManager mmaps APKs), so per-UID hiding was defeated for
             * exactly the readers it targets, and read-vs-mmap disagreement is
             * its own oracle. Overriding f_mapping in ->open is the normal way
             * to express this (blkdev_open does the same). */
            file->f_mapping = real_file->f_mapping;
            return 0;
        }
    }

    /* The caller's own creds are authoritative: an injected path is authorised
     * exactly like a stock one. There is no privileged retry -- that fallback
     * let any caller reach a backing file its own domain could not open. A
     * module tree whose files are not labelled for the reader is a packaging
     * bug to fix with a relabel, not something to paper over in the kernel. */
    real_file = dentry_open(&info->r_path, file->f_flags, current_cred());
    if (IS_ERR(real_file)) {
        /* _once, and without the uid: an unprivileged open() of an injected path
         * whose backing file the caller cannot read drives this, so an app could
         * loop it -- emitting the tag (which names the project in .rodata AND at
         * runtime) once per attempt and evicting the rest of the ring buffer.
         * The relabel hint is what the operator needs; the uid is not. */
        nm_warn_once("open of backing file denied (relabel the module tree)\n");
        return PTR_ERR(real_file);
    }

    file->private_data = real_file;
    /* Mirror the stock answer for O_DIRECT, by SETTING f_mode -- never by
     * touching the caller's f_flags.
     *
     * do_dentry_open() ORs FMODE_CAN_ODIRECT in after ->open returns and then
     * rejects the open when the caller asked for O_DIRECT and the bit is clear
     * (fs/open.c:974 and :981). It only ever ORs, so a bit set here survives --
     * an earlier version of this comment claimed otherwise and stripped O_DIRECT
     * from f_flags instead, which made the open succeed while F_GETFL reported a
     * flag the caller had asked for and been told it had.
     *
     * v_cap carries the answer a REAL open of the stock path gave at rule build,
     * so both directions come out right without guessing: stock accepts and we
     * set the bit, or stock refuses and we leave it clear so the VFS refuses us
     * exactly as it refuses stock.
     *
     * 6.0+ only: FMODE_CAN_ODIRECT was introduced there. Before it, the VFS
     * tested f_mapping->a_ops->direct_IO directly in do_dentry_open, which a
     * ->open hook cannot influence without swapping the inode's mapping -- so on
     * 4.9..5.15 the mirror is simply not applied and behaviour is unchanged.
     * Those kernels are not an injection target for this oracle today; closing it
     * there needs a different lever and its own measurement. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    if (unlikely(info->v_cap & NM_CAP_ODIRECT))
        file->f_mode |= FMODE_CAN_ODIRECT;
#endif
    return 0;
}

static int nm_release(struct inode *inode, struct file *file)
{
    struct file *real_file = file->private_data;
    if (real_file) {
        fput(real_file);
        file->private_data = NULL;
    }
    return 0;
}

static loff_t nm_llseek(struct file *file, loff_t offset, int whence)
{
    struct file *real_file = file->private_data;
    loff_t res;
    if (!real_file) {
        /* Virtual (purely synthesized) directory: no backing file to seek.
         * Returning -EINVAL breaks rewinddir()/seekdir() (glibc rewinddir is
         * lseek(fd,0,SEEK_SET)), a behavioural tell vs a real directory.
         * Handle the directory-cookie seek on our own f_pos instead. */
        switch (whence) {
        case SEEK_END: {
            /* The size getattr REPORTS, not the raw i_size. A synthesized dir's
             * inode keeps the 4096 placeholder from nomount_create_new_inode
             * while nm_file_getattr recomputes the erofs-shaped size, so
             * stat().st_size and lseek(fd,0,SEEK_END) disagreed on the same fd --
             * something no filesystem does, and one syscall pair to spot.
             * Measured on OP15: /product/priv-app/Mms st_size=61 vs SEEK_END
             * 4096, 3 of 3 synthesized dirs diverging, 0 of 89 real ones. */
            struct nm_inode_info *vi = file_inode(file)->i_private;
            struct super_block *sb = file_inode(file)->i_sb;
            loff_t sz = i_size_read(file_inode(file));

            if (vi && vi->dir_node &&
                (sb->s_magic == EROFS_SUPER_MAGIC_V1 || nm_vdir_erofs_size))
                sz = nm_vdir_size(vi->dir_node, sb->s_blocksize);
            offset += sz;
            break;
        }
        case SEEK_CUR: offset += file->f_pos; break;
        case SEEK_SET: break;
        default:       return -EINVAL;
        }
        if (offset < 0) return -EINVAL;
        file->f_pos = offset;
        return offset;
    }

    /* A dir-target directory whose listing comes from the cached snapshot lives
     * in OUR cookie space and reports OUR size, so SEEK_END has to land on that
     * size rather than on the backing f2fs directory's. Forwarding it would
     * recreate, one arm over, exactly the stat-vs-lseek divergence the
     * synthesized-dir arm above exists to remove. Gated on real_file being the
     * backing dir, like every other dir-target decision: a hidden reader holding
     * the pinned STOCK directory seeks in the stock file's own space. */
    if (whence == SEEK_END && S_ISDIR(file_inode(file)->i_mode)) {
        struct nm_inode_info *di = file_inode(file)->i_private;

        if (di && di->r_path.dentry &&
            real_file->f_path.dentry == di->r_path.dentry) {
            loff_t sz = nm_dsnap_dir_size(file_inode(file), di);

            if (sz > 0) {
                offset += sz;
                if (offset < 0) return -EINVAL;
                file->f_pos = offset;
                return offset;
            }
        }
    }

    real_file->f_pos = file->f_pos;
    res = vfs_llseek(real_file, offset, whence);
    file->f_pos = real_file->f_pos;

    return res;
}

/* Run the caller's read/write against the backing file on a PRIVATE kiocb.
 *
 * The caller's kiocb is never touched. That is the whole point: the previous
 * shape borrowed it -- point ki_filp at the backing file, call down, restore --
 * and could not restore an op that came back -EIOCBQUEUED, because the backing
 * filesystem's completion still dereferences ki_filp (kiocb_end_write and the
 * iomap/dio completions all do) and would have been handed a file belonging to a
 * different inode. Leaving the backing file there is what the completion needs,
 * and is exactly what breaks the reference accounting one layer up:
 *
 *   struct aio_kiocb's leading ki_filp UNIONS with rw.ki_filp, and iocb_destroy()
 *   fputs iocb->ki_filp. So a queued AIO read of an injected file dropped a
 *   reference on the BACKING file that nobody had taken -- while the reference
 *   AIO holds on OUR file, the one iocb_destroy() meant to release, leaked. Our
 *   file->private_data is usually the only thing pinning real_file, so that
 *   stray fput frees it out from under a still-live nm_file, and every later
 *   read/mmap of the same fd walks a freed struct file.
 *
 * Balancing it in place is not available to us: whether ki_filp owns the
 * reference the completion will drop is a property of the SUBMITTER, not of the
 * file. AIO owns it there; io_uring keeps its reference on req->file and would
 * underflow if we adjusted ki_filp's. A filesystem cannot tell the two apart --
 * which is why mainline gave stacking filesystems fs/backing-file.c, where
 * overlayfs clones the kiocb (with its own get_file) instead of borrowing it.
 *
 * We clone without the async half: ki_complete NULL makes is_sync_kiocb() true,
 * and every direct-I/O path keys its "queue and return -EIOCBQUEUED" behaviour
 * off exactly that (dio->is_async, iomap's wait_for_completion), so the backing
 * fs completes inline and returns a byte count. Both async submitters handle a
 * non-(-EIOCBQUEUED) return by completing the request themselves -- that is the
 * ordinary path for any buffered read, which is what nearly every read of an
 * injected file already is. IOCB_NOWAIT rides along in ki_flags, so an io_uring
 * NOWAIT probe still gets -EAGAIN and retries from its worker rather than
 * blocking the submitter.
 *
 * Cost, stated: an O_DIRECT io_submit()/io_uring read of an INJECTED file now
 * completes synchronously instead of being queued. Everything else -- ki_pos,
 * ki_flags, ioprio, the readahead state on real_file->f_ra -- is carried across
 * unchanged, and the sync read(2)/write(2) path behaves as it always did. */
static ssize_t nm_forward_iter(struct kiocb *iocb, struct iov_iter *iter,
                               struct file *real_file, bool is_write)
{
    struct kiocb kio = *iocb;
    ssize_t ret;

    kio.ki_filp = real_file;
    kio.ki_complete = NULL;   /* -> is_sync_kiocb(): the op cannot be queued */
    kio.private = NULL;

    ret = is_write ? real_file->f_op->write_iter(&kio, iter)
                   : real_file->f_op->read_iter(&kio, iter);
    /* The backing fs advances its own copy; hand the position back. On an error
     * return it is unchanged, so this is a copy of what the caller already had. */
    iocb->ki_pos = kio.ki_pos;

    return ret;
}

static ssize_t nm_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct file *real_file = iocb->ki_filp->private_data;

    if (!real_file || !real_file->f_op->read_iter) return -EINVAL;
    return nm_forward_iter(iocb, to, real_file, false);
}

static ssize_t nm_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *real_file = iocb->ki_filp->private_data;

    if (!real_file || !real_file->f_op->write_iter) return -EINVAL;
    return nm_forward_iter(iocb, from, real_file, true);
}

/* Map through the GENERIC path, never the backing filesystem's ->mmap.
 *
 * The old shape -- point vma->vm_file at the backing file, call its ->mmap,
 * then restore vma->vm_file to ours -- left the backing fs's vm_ops installed
 * over OUR file. f2fs_file_mmap() sets vma->vm_ops = &f2fs_file_vm_ops, whose
 * .fault and .page_mkwrite both start with F2FS_I_SB(file_inode(vma->vm_file)),
 * i.e. inode->i_sb->s_fs_info reinterpreted as a struct f2fs_sb_info *. After
 * the restore that inode is ours, on erofs or overlayfs. Read from the device's
 * own BTF: f2fs_sb_info.iostat_enable sits at offset 4376 and iostat_lock at
 * 3676, while erofs_sb_info is 472 bytes and ovl_fs is 176 -- so every faulted
 * page of every injected mapping read ~4KB past a live slab object, and a
 * non-zero byte there would have taken a spinlock and written counters into
 * whatever allocation follows. CONFIG_F2FS_IOSTAT=y on OP15, and the linker
 * mmaps every injected .so, so this was the hot path, surviving on the stray
 * byte happening to read zero -- a property of struct layout, not of anything
 * we control.
 *
 * The generic path is also what STOCK does here: erofs_file_mmap is literally
 * generic_file_readonly_mmap, so an injected file now gets the same
 * generic_file_vm_ops as its stock siblings instead of f2fs's. filemap_fault()
 * resolves pages through vmf->vma->vm_file->f_mapping, and nm_open() already
 * points our f_mapping at whichever file we serve (the module file, or the
 * stock one for a hidden reader), so page contents are unchanged and f2fs's
 * a_ops still do the decryption/decompression.
 *
 * READONLY rather than plain generic_file_mmap, deliberately: it rejects a
 * shared+maywrite mapping with -EINVAL exactly as stock erofs does. Forwarding
 * to f2fs used to ALLOW that, which is its own one-syscall divergence -- and no
 * legitimate consumer can depend on it, because the same mmap fails on a stock
 * device. MAP_PRIVATE (what the linker and AssetManager use) is unaffected. */
static int nm_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct file *real_file = file->private_data;

    if (!real_file) return -ENODEV;
    return generic_file_readonly_mmap(file, vma);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
/* Same reasoning as nm_mmap(), on the 6.16+ ->mmap_prepare path: forwarding to
 * the backing fs installed ITS vm_ops over our file. generic_file_readonly_mmap_prepare
 * landed in 6.17 (absent in 6.16), and erofs's own erofs_file_mmap_prepare is
 * exactly that call, so this matches stock on every version that has the hook.
 * On 6.16 there is no generic _prepare to call, so fall back to reporting no
 * support: the VFS then uses ->mmap, which is nm_mmap() above and already
 * correct. nm_file_fops_mmap_prepare is only installed when the backing inode
 * advertises ->mmap_prepare (see nomount_create_new_inode). */
static int nm_mmap_prepare(struct vm_area_desc *desc)
{
    struct file *file = desc->file;
    struct file *real_file = file->private_data;

    if (!real_file) return -ENODEV;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
    return generic_file_readonly_mmap_prepare(desc);
#else
    return -ENOSYS;
#endif
}
#endif

/* Answer ioctls like the STOCK filesystem, never like the donor.
 *
 * Forwarding to the backing file exposed the DONOR fs's ioctl surface: the module
 * tree lives on /data (f2fs), whose ->unlocked_ioctl serves the ext4-family
 * commands, while erofs_file_fops has NO ->unlocked_ioctl and no ->compat_ioctl
 * at all -- every stock ROM file answers -ENOTTY. So one unprivileged
 * `ioctl(fd, FS_IOC_GETVERSION)` separated injected from stock perfectly.
 * Measured on OP15 over 2616 files in eight ROM directories: 117 returned 0 and
 * all 117 were rule paths; the other 2499 returned -ENOTTY and none were. Two
 * independent commands (GETVERSION, GETFSLABEL) agreed file-for-file.
 *
 * Route to the shadowed stock file when there is one, so the answer is literally
 * the stock answer on any filesystem; a pure addition has nothing underneath, and
 * its siblings are on that same ROM fs, so -ENOTTY is what they would say.
 *
 * Generic-VFS ioctls (FS_IOC_GETFSUUID, FS_IOC_GETFSSYSFSPATH) never reach here
 * -- do_vfs_ioctl answers them from the superblock -- and they were measured
 * identical on both, which is why only the f_op-dispatched ones leaked. FIEMAP
 * likewise goes through i_op->fiemap (see nm_fiemap). */
static long nm_ioctl_as_stock(struct file *file, unsigned int cmd, unsigned long arg, bool compat)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    struct file *sf;
    long ret;

    if (unlikely(!info) || !info->s_path.dentry)
        return -ENOTTY;

    /* Answer WITHOUT the open when the stock file could not have answered
     * anything else. dentry_open() would hand the new file that inode's own
     * i_fop, so if the inode carries neither ioctl op the dispatch below is
     * guaranteed to fall through to -ENOTTY -- and the open, dispatch and fput
     * exist only to arrive at a value we already know.
     *
     * That round trip was measurable. On OP15, ioctl() with an unknown cmd on
     * erofs-backed paths (n=12 each side, 3000 reps per file, per-file median):
     * injected 938..1823ns vs stock siblings 521..781ns -- DISJOINT, so a single
     * threshold classified every file, unprivileged, with each file its own
     * baseline. Skipping the open collapses the injected cost onto the stock
     * path for exactly the filesystems where stock has no ioctl (plain erofs:
     * /system, /my_*). Overlay-backed paths keep the open, because
     * ovl_file_operations DOES implement ->unlocked_ioctl and forwarding is the
     * correct answer there. */
    {
        struct inode *si = d_backing_inode(info->s_path.dentry);

        if (si && si->i_fop && !si->i_fop->unlocked_ioctl
#ifdef CONFIG_COMPAT
            && !si->i_fop->compat_ioctl
#endif
           )
            return -ENOTTY;
    }

    sf = dentry_open(&info->s_path, O_RDONLY | O_LARGEFILE, current_cred());
    if (IS_ERR(sf))
        return -ENOTTY;

    ret = -ENOTTY;
#ifdef CONFIG_COMPAT
    if (compat) {
        if (sf->f_op->compat_ioctl)
            ret = sf->f_op->compat_ioctl(sf, cmd, arg);
    } else
#endif
    {
        if (sf->f_op->unlocked_ioctl)
            ret = sf->f_op->unlocked_ioctl(sf, cmd, arg);
    }
    fput(sf);
    return ret;
}

static long nm_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    return nm_ioctl_as_stock(file, cmd, arg, false);
}

#ifdef CONFIG_COMPAT
static long nm_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    return nm_ioctl_as_stock(file, cmd, arg, true);
}
#endif

static ssize_t nm_splice_read(struct file *in, loff_t *ppos, struct pipe_inode_info *pipe,
                              size_t len, unsigned int flags)
{
    struct file *real_file = in->private_data;
    if (!real_file || !real_file->f_op->splice_read) return -EINVAL;
    return real_file->f_op->splice_read(real_file, ppos, pipe, len, flags);
}

static ssize_t nm_splice_write(struct pipe_inode_info *pipe, struct file *out,
                               loff_t *ppos, size_t len, unsigned int flags)
{
    struct file *real_file = out->private_data;
    if (!real_file || !real_file->f_op->splice_write) return -EINVAL;
    return real_file->f_op->splice_write(pipe, real_file, ppos, len, flags);
}

/* Forward fallocate to the backing file: without this an injected file returns
 * -EOPNOTSUPP where a stock file returns whatever the backing fs does (usually
 * -EOPNOTSUPP/-EPERM on read-only ROM libs) -- either way, matching the backing
 * removes the "missing op" divergence a detector can probe. */
static long nm_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->fallocate) return -EOPNOTSUPP;
    return real_file->f_op->fallocate(real_file, mode, offset, len);
}

/* Which filesystem-dependent file-op answers does THIS inode give?
 *
 * Sampled from a stock file (the one a rule shadows, or a sibling on the same
 * partition) so the ops can replay them for the injected file, whose backing
 * lives on a different filesystem. See NM_CAP_*. */
/* Turn a sampled (size, blocks) pair into the 1/1024 ratio v_cratio stores.
 *
 * Only meaningful above one block: erofs compresses whole blocks, so a file
 * under 4 KiB occupies one block whether or not it compressed, and the
 * st_blocks*512 >= st_size predicate is true for stock and injected alike
 * there -- correctly no signal. Measured on OP15 /product/etc: build_flags.json
 * 77887 bytes in 16 sectors (ratio ~108), NOTICE.xml.gz 159485 in 312 (~1025,
 * already gzipped so incompressible), build.prop 2647 in 8 (single block).
 *
 * Clamped to 1/8..7/8. An unclamped sample lets one atypical neighbour make us
 * claim absurd compression, and a file whose CONTENT a detector can read while
 * st_blocks says it compressed 10x is a louder tell than the one being closed. */
static u16 nm_size_ratio(loff_t size, blkcnt_t blocks)
{
    u64 alloc = (u64)blocks << 9;
    u64 r;

    if (size < 8192 || alloc == 0)
        return 0;
    r = div64_u64(alloc << 10, (u64)size);
    if (r < 128) r = 128;
    if (r > 896) r = 896;
    return (u16)r;
}

/* Replay it. Rounds UP to a whole filesystem block, because a partially used
 * block is still allocated -- reporting a non-block-multiple st_blocks would
 * itself be an outlier no erofs file produces. */
static void nm_mirror_blocks(const struct nm_inode_info *info, struct kstat *stat)
{
    u64 want;

    if (!info->v_cratio || stat->size < 8192)
        return;
    want = div64_u64((u64)stat->size * info->v_cratio, 1024);
    want = (want + 4095) & ~4095ULL;
    if (want >= (u64)stat->size)                 /* never claim MORE than stock would */
        want = ((u64)stat->size) & ~4095ULL;
    if (!want)
        return;
    stat->blocks = (blkcnt_t)(want >> 9);
}

/* Two existence oracles that the ops layer CAN answer, unlike the four that need
 * a VFS or LSM patch (O_PATH, getxattr(security.*), the d_can_lookup ENOTDIR and
 * link()'s EXDEV). Both were measured on OP15 against a hidden pure-addition for
 * all 24 blocked uids, with a 7020-path genuinely-absent control that produced
 * zero false positives:
 *
 *   readlink(path)  hidden -> EINVAL   absent -> ENOENT
 *   statfs(path)    hidden -> succeeds absent -> ENOENT
 *
 * A hidden reader must not be able to tell "not there" from "there but refused",
 * so both now answer ENOENT for it and behave normally for everyone else.
 *
 * readlink: nm_alloc_rule resolves with LOOKUP_FOLLOW, so an injected inode
 * mirrors the symlink TARGET and S_ISLNK is never true -- a non-hidden caller
 * therefore gets -EINVAL, exactly what vfs_readlink() produces on its own for a
 * non-symlink, so nothing changes for them. */
static int nm_readlink(struct dentry *dentry, char __user *buf, int buflen)
{
    struct inode *inode = d_backing_inode(dentry);

    if (inode && unlikely(nm_hidden_from_caller(inode->i_private)))
        return -ENOENT;
    return -EINVAL;
}

/* statfs: our inodes live on the PARENT's superblock, so statfs_by_dentry()
 * reached the real fs and succeeded for a path we tell the same caller does not
 * exist. Forward everything else untouched -- this is the whole partition's
 * statfs, and every other file on it depends on the real answer. */
static int nomount_hijacked_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct inode *inode = d_backing_inode(dentry);
    struct nm_sop *nm_sop;

    if (inode && (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) &&
        unlikely(nm_hidden_from_caller(inode->i_private)))
        return -ENOENT;

    nm_sop = __get_nm(smp_load_acquire(&dentry->d_sb->s_op), struct nm_sop, fake_sop,
                      destroy_inode, nomount_hijacked_destroy_inode);
    if (nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->statfs)
        return nm_sop->orig_sop->statfs(dentry, buf);
    return -ENOSYS;
}

static u8 nm_stock_caps(struct inode *ino)
{
    u8 cap = NM_CAP_KNOWN;   /* reaching here IS the sample; see NM_CAP_KNOWN */

    if (!ino) return 0;
    if (ino->i_fop && ino->i_fop->fsync) cap |= NM_CAP_FSYNC;
    return cap;
}

/* Does a stock file at this path accept O_DIRECT? ASK IT -- do not infer.
 *
 * The obvious predicate, a_ops->direct_IO, is wrong on both sides here:
 *   - d_backing_inode() of an overlayfs dentry is the OVL inode, and ovl_aops
 *     sets .direct_IO = noop_direct_IO -- so every stock file on /product looks
 *     like it accepts, while the real open is forwarded by ovl_open_realfile()
 *     to a lower layer that on this device is COMPRESSED erofs and rejects it.
 *   - f2fs (our donor) has no .direct_IO in its aops at all, yet f2fs_file_open()
 *     sets FMODE_CAN_ODIRECT directly -- so the donor looks like it rejects when
 *     it accepts.
 * Both errors point the same way, and a guard built on them preserved exactly the
 * divergence it was meant to erase (measured: 139/139 injected accepted on
 * /product/overlay, 53/53 stock siblings refused).
 *
 * One real open at rule build settles it for any filesystem stacking. */
static bool nm_stock_takes_odirect(struct path *p)
{
    struct file *f;

    if (!p || !p->dentry) return false;
    f = dentry_open(p, O_RDONLY | O_DIRECT | O_LARGEFILE, current_cred());
    if (IS_ERR(f)) return false;
    fput(f);
    return true;
}

static int nm_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct file *real_file = file->private_data;
    struct nm_inode_info *info = file_inode(file)->i_private;

    /* Answer what a STOCK file here would answer.
     *
     * The backing file is on /data (f2fs, which has ->fsync); its neighbours are
     * on erofs, which has none, so vfs_fsync_range() gives them -EINVAL. Simply
     * forwarding therefore made the injected file the ONLY one in its directory
     * that returned 0 -- one syscall per file, no reference device, no timing.
     * Measured on OP15: all 24 stock files in /system/etc/permissions returned
     * EINVAL and the single injected one returned 0.
     *
     * v_cap is captured from the shadowed file (or the sampled sibling) at rule
     * build. Gate on NM_CAP_KNOWN, not on v_cap being non-zero: "sampled, and
     * stock has no ->fsync" is the COMMON case on erofs and its correct answer
     * is -EINVAL, but it also encodes as v_cap == 0 and so used to be read as
     * "never sampled" and fall through to the f2fs backing file, which answers
     * 0. That silently reopened this very oracle for every erofs-backed rule
     * whose caps came from a sibling scan. */
    if (info && (info->v_cap & NM_CAP_KNOWN) && !(info->v_cap & NM_CAP_FSYNC))
        return -EINVAL;
    if (!real_file || !real_file->f_op->fsync) return -EINVAL;
    return real_file->f_op->fsync(real_file, start, end, datasync);
}

/* The directory half of the same oracle nm_fsync() closes.
 *
 * nm_dir_fops carried no .fsync at all, so vfs_fsync_range() answered -EINVAL
 * for every directory we serve. Whether a real directory answers that depends
 * entirely on what it sits on: erofs has no ->fsync (-EINVAL), overlayfs has
 * ovl_dir_fsync (0). On OP15 /product/priv-app is an overlay, so the synthesized
 * dirs stood out against their neighbours with one syscall and no baseline --
 * measured 3/3 EINVAL (Mms, Mms/lib, Mms/lib/arm64) against 6/6 zero for the
 * stock package dirs beside them, at every depth.
 *
 * v_cap is sampled from the nearest real ancestor DIRECTORY for a synthesized
 * dir (nomount_generate_virtual_topology) and from the shadowed dir or a sampled
 * sibling otherwise. NM_CAP_KNOWN, not a non-zero v_cap, is what says we have an
 * answer -- on erofs the right answer is "no ->fsync", which encodes as zero.
 * Only a rule whose sampling found nothing at all falls through. Nothing here is
 * dirty -- the caller cannot have written to a read-only ROM view -- so the
 * capable answer is a plain 0, exactly what ovl_dir_fsync returns for a clean
 * dir. This also covers the children of a dir-target rule, which inherit the
 * parent's v_cap through nm_dir_child_lookup. */
static int nm_dir_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    struct file *real_file = file->private_data;

    if (info && (info->v_cap & NM_CAP_KNOWN))
        return (info->v_cap & NM_CAP_FSYNC) ? 0 : -EINVAL;
    if (real_file && real_file->f_op->fsync)
        return real_file->f_op->fsync(real_file, start, end, datasync);
    return -EINVAL;
}

static ssize_t nm_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
    static const char nm_selinux_name[] = "security.selinux";
    struct nm_inode_info *info = d_backing_inode(dentry)->i_private;
    struct path *stock;

    if (unlikely(!info)) return -EOPNOTSUPP;
    /* Tell the same story as the rest of the ops.
     *
     * xattr_permission() returns 0 for security.* and system.* WITHOUT calling
     * inode_permission(), so nm_inode_permission()'s -ENOENT never runs on the
     * xattr path: an ADDED name that stat(), open() and access() all refuse was
     * still listing security.selinux to the very reader it is hidden from.
     * Measured on OP15 as blocked uid 10438 against
     * /product/etc/permissions/privapp-permissions-oplus-product.xml -- 10/10
     * once any unblocked UID had warmed the shared dentry. That is a louder
     * loophole than the access() one this mirrors, because it hands back the
     * injected file's LABEL at a path stat() says is not there.
     *
     * Reach is an ADDED rule whose parent is a REAL directory; a rule under a
     * synthesized parent is unreachable anyway (the blocked reader cannot
     * resolve the parent), which is why 25 of 26 hidden paths on that device
     * never showed it. */
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    /* A hidden reader of a SHADOWING rule is entitled to the stock file, exactly
     * as in nm_open()/nm_file_getattr(). Forward to the backing inode's op
     * rather than vfs_listxattr(), which would re-run the LSM hook the caller
     * has already passed for the path it named -- the same reason every getattr
     * here uses the _nosec form. */
    stock = nm_stock_for_caller(info);
    if (unlikely(stock)) {
        struct inode *si = d_backing_inode(stock->dentry);

        if (!si || !si->i_op || !si->i_op->listxattr) return -EOPNOTSUPP;
        return si->i_op->listxattr(stock->dentry, buffer, size);
    }
    /* A synthesized dir has no backing dentry to forward to. Returning
     * -EOPNOTSUPP where every real dir lists security.selinux is a tell, so
     * report the one attribute we actually serve. */
    if (info->flags & NM_FLAG_VIRTUAL_DIR) {
        if (!info->v_ctx_len) return -EOPNOTSUPP;
        if (!size) return sizeof(nm_selinux_name);
        if (size < sizeof(nm_selinux_name)) return -ERANGE;
        memcpy(buffer, nm_selinux_name, sizeof(nm_selinux_name));
        return sizeof(nm_selinux_name);
    }
    if (unlikely(!d_backing_inode(info->r_path.dentry)->i_op->listxattr))
        return -EOPNOTSUPP;

    return d_backing_inode(info->r_path.dentry)->i_op->listxattr(info->r_path.dentry, buffer, size);
}

/* A directory reports 2 + one link per subdirectory. Counted live rather than at
 * inode creation: the children of a synthesized dir are injected in batches, so
 * an inode created part-way through would bake in a count that never updates.
 *
 * Filtered by nm_child_visible, exactly as nm_dir_deltas does for a real
 * hijacked parent: a uid-scoped or per-UID-hidden child the caller's readdir
 * cannot emit must not move the caller's nlink either, or stat() and getdents()
 * disagree -- a blocked reader would see nlink 3 on a dir whose listing shows no
 * subdirectory, which no filesystem produces. */
static unsigned int nm_vdir_nlink(struct nomount_dir_node *d)
{
    struct nomount_child_node *ch;
    unsigned int links = 2;
    int cid = 0;

    if (!d) return links;
    rcu_read_lock();
    idr_for_each_entry(&d->children_idr, ch, cid)
        if (ch->d_type == DT_DIR && !(ch->flags & NM_FLAG_WHITEOUT) &&
            nm_child_visible(ch))
            links++;
    rcu_read_unlock();
    return links;
}

/* sizeof(struct erofs_dirent); fs/erofs/erofs_fs.h asserts it with a
 * BUILD_BUG_ON, so it is part of the on-disk format, not a guess. */
#define NM_EROFS_DIRENT_SZ 12

/* erofs stores a directory as a run of blocks, each holding a packed array of
 * 12-byte erofs_dirent followed by the entry names -- unpadded, not
 * NUL-terminated. So a directory that fits in one block reports
 * i_size == 12 * N + sum(namelen) over all N entries including "." and "..",
 * and is block-quantised beyond that. It is never PAGE_SIZE.
 *
 * A synthesized dir left at i_size 4096 is therefore an outlier no real erofs
 * directory produces, and one stat() on it is enough to prove injection. Every
 * stock dir sampled on /product and /vendor matches the formula exactly.
 *
 * ext4/f2fs *do* quantise directories to a block, where 4096 is correct, so
 * callers gate this on the superblock magic rather than applying it blindly.
 */
static loff_t nm_vdir_size(struct nomount_dir_node *d, unsigned int blocksize)
{
    struct nomount_child_node *ch;
    loff_t full = 0;                 /* bytes already committed to whole blocks */
    unsigned int used;               /* bytes used in the block being filled */
    int cid = 0;

    /* "." and ".." are always emitted */
    used = 2 * NM_EROFS_DIRENT_SZ + 1 + 2;

    if (d) {
        rcu_read_lock();
        idr_for_each_entry(&d->children_idr, ch, cid) {
            unsigned int need;

            /* Same visibility filter as nm_vdir_nlink and nm_dir_deltas: a child
             * the caller cannot list must not add to the size it reads, or the
             * erofs formula an app recomputes from its own getdents() disagrees
             * with stat().st_size by exactly the hidden entry's bytes. */
            if ((ch->flags & NM_FLAG_WHITEOUT) || !nm_child_visible(ch))
                continue;
            need = NM_EROFS_DIRENT_SZ + ch->name_len;
            /* An entry never straddles a block; the tail of the previous one
             * is padding, which is why multi-block dirs are not a flat sum. */
            if (blocksize && used + need > blocksize) {
                full += blocksize;
                used = 0;
            }
            used += need;
        }
        rcu_read_unlock();
    }
    return full + used;
}

/* parent_ino() was a static inline in include/linux/fs.h through v6.10 and was
 * replaced by the out-of-line d_parent_ino() in include/linux/dcache.h at
 * v6.11 -- checked against the trees, not from memory: v6.10 fs.h:3439 defines
 * `static inline ino_t parent_ino(struct dentry *)` and dir_emit_dotdot() at
 * fs.h:3577 calls it, while v6.11 fs.h:3610 calls d_parent_ino() and
 * dcache.h:286 declares it. Mirror whichever one the building tree's own
 * dir_emit_dotdot() uses. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
# define NM_PARENT_INO(dentry) d_parent_ino(dentry)
#else
# define NM_PARENT_INO(dentry) parent_ino(dentry)
#endif

/* ---- erofs directory-cookie replay -----------------------------------------
 *
 * getdents64() never hands userspace the offset an entry was emitted AT. It
 * fills each entry's d_off from the offset of the entry AFTER it, and the LAST
 * entry's d_off from the final ctx->pos (v6.6 fs/readdir.c: filldir64() does
 * unsafe_put_user(offset, &prev->d_off), and SYSCALL_DEFINE3(getdents64) does
 * put_user(buf.ctx.pos, &lastdirent->d_off)).
 *
 * erofs emits dirent j of block b with ctx->pos == b*blocksize + 12*j, stepping
 * ctx->pos by sizeof(struct erofs_dirent) per entry, and closes the final block
 * with ctx->pos = erofs_pos(sb,i) + maxsize -- which on the last block is
 * exactly i_size (v6.6 fs/erofs/dir.c erofs_readdir/erofs_fill_dentries). So a
 * stock single-block erofs directory shows d_off = 12, 24, ... and a last d_off
 * equal to st_size. Measured on OP15, /system/etc/init, 66 entries, no rules:
 * 12, 24, 36 ... 1610 with i_size == 1610.
 *
 * A dir NoMount synthesizes whole used to emit a plain per-child counter --
 * measured 1, 3, 4 ... 28 on a 27-entry dir whose i_size was already the
 * correct 780. One getdents64() separated it from every stock directory on the
 * device: interior cookies that are not multiples of 12, and a final d_off that
 * misses st_size. (Hijacked REAL erofs dirs were never affected -- their
 * cookies come from erofs itself; /my_product/etc/extension, 167 entries with
 * 81 injected, measured 12, 24 ... 3671 == i_size.)
 *
 * This replays erofs's packing with the SAME block walk nm_vdir_size() uses, so
 * the terminal cookie and the size getattr reports are the same number by
 * construction rather than by two calculations that happen to agree.
 */
struct nm_epack {
    unsigned int blocksize;
    loff_t full;         /* bytes already committed to whole blocks */
    unsigned int used;   /* bytes used in the block being filled */
    unsigned int slot;   /* dirents already placed in that block */
};

/* Account one entry and return the file offset erofs would emit it at. */
static loff_t nm_epack_step(struct nm_epack *p, unsigned int namelen)
{
    unsigned int need = NM_EROFS_DIRENT_SZ + namelen;
    loff_t off;

    /* An entry never straddles a block -- the same rule nm_vdir_size() replays,
     * and the reason a multi-block dir is not a flat sum. */
    if (p->blocksize && p->used + need > p->blocksize) {
        p->full += p->blocksize;
        p->used = 0;
        p->slot = 0;
    }
    /* Dirents are packed at the head of the block, names after it, so the j'th
     * dirent of a block sits at block_base + 12*j. */
    off = p->full + (loff_t)NM_EROFS_DIRENT_SZ * p->slot;
    p->used += need;
    p->slot++;
    return off;
}

/* The EOF cookie: identical to nm_vdir_size() over the same entry sequence.
 *
 * It can never collide with an entry offset, which is what makes a resume from
 * it decode as EOF without a special case: within the final block the used
 * count is 12*slots + sum(namelen) >= 12*slots, strictly greater than the last
 * dirent's in-block offset 12*(slots-1); and every earlier block's offsets are
 * below this block's base. */
static inline loff_t nm_epack_end(const struct nm_epack *p)
{
    return p->full + p->used;
}

/* Emit a FULLY SYNTHESIZED directory with erofs-shaped cookies.
 *
 * Ordinal k is the k'th entry of the listing: 0 -> ".", 1 -> "..", k >= 2 -> the
 * (k-2)'th VISIBLE child in idr order. That is the same order and the same
 * visibility filter nomount_emit_virtual_children() emits with and
 * nm_vdir_size() measures, so listing, size and cookies cannot disagree about
 * what is in the directory.
 *
 * Positions are ORDINAL-derived, not idr-id-derived (nm_pack_pos), because an
 * erofs cookie is a byte offset and therefore a function of every entry BEFORE
 * it -- an id cannot produce it. Resuming a paginated read costs one walk from
 * ordinal 0 to the resume point, O(k). Synthesized dirs hold tens of entries and
 * a continuation only happens when the caller's buffer filled, so this is a few
 * hundred pointer derefs on a path that already sleeps in copy_to_user.
 *
 * TRADE-OFF, deliberate and stated rather than left implicit: an id-keyed
 * position is stable across a concurrent insertion into the same directory, an
 * ordinal-keyed one is not. An `nm add` landing here BETWEEN two getdents64()
 * calls on the same fd shifts the remaining ordinals and can make that fd skip
 * or repeat one entry. Accepted because injections happen at boot and at an
 * explicit reload, readdir-concurrent-with-add is rare, and the alternative is a
 * permanent one-syscall tell on every synthesized directory for every caller.
 */
static int nm_vdir_iterate_erofs(struct file *file, struct dir_context *ctx,
                                 struct nm_inode_info *info,
                                 struct nomount_dir_node *d,
                                 unsigned int blocksize)
{
    struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
    struct inode *v_inode = file_inode(file);
    loff_t start = ctx->pos;
    bool emitting = false, full = false;
    int id = 0, k;

    if (start < 0) start = 0;

    /* Keep the node alive across the dir_emit sleeps below without holding RCU,
     * exactly as nomount_emit_virtual_children() does. */
    if (d && !atomic_inc_not_zero(&d->refcount)) d = NULL;

    for (k = 0; ; k++) {
        char name[NAME_MAX + 1];
        int nlen;
        u64 eino;
        unsigned char dt;
        loff_t off;

        if (k == 0) {
            /* Same ino choice nm_emit_dots() makes -- see the note there on why
             * an overlay-backed dir must serve the DIRENT ino, not stat's. */
            name[0] = '.'; nlen = 1; dt = DT_DIR;
            eino = (info->flags & NM_FLAG_OVL_INO)
                 ? (info->v_dino ? info->v_dino : info->v_ino)
                 : v_inode->i_ino;
        } else if (k == 1) {
            name[0] = '.'; name[1] = '.'; nlen = 2; dt = DT_DIR;
            eino = (info->flags & NM_FLAG_OVL_INO)
                 ? (info->v_pdino ? info->v_pdino : info->v_ino)
                 : NM_PARENT_INO(file->f_path.dentry);
        } else {
            struct nomount_child_node *child;
            int found = -1;

            if (!d) break;
            /* SNAPSHOT under RCU: dir_emit -> filldir64 -> copy_to_user can
             * fault and SLEEP, which rcu_read_lock() forbids. */
            rcu_read_lock();
            nlen = 0; eino = 0; dt = 0;
            while ((child = idr_get_next(&d->children_idr, &id)) != NULL) {
                if (nm_child_visible(child) && !(child->flags & NM_FLAG_WHITEOUT)) {
                    found = id;
                    nlen = min_t(int, (int)child->name_len, NAME_MAX);
                    memcpy(name, child->name, nlen);
                    eino = child->fake_ino;
                    dt = child->d_type;
                    break;
                }
                id++;
            }
            rcu_read_unlock();
            if (found < 0) break;
            id = found + 1;
        }

        off = nm_epack_step(&pk, (unsigned int)nlen);
        if (!emitting) {
            /* Resume at the first entry AT OR AFTER the requested cookie.
             * seekdir()/telldir() and getdents64 pagination always hand back a
             * cookie that is exactly some entry's offset, so the common case is
             * an exact hit; erofs itself rounds a mid-dirent position up to the
             * next dirent slot rather than failing (the `initial` branch of
             * erofs_readdir), so rounding up is both closer to stock and safer
             * than treating a non-exact position as EOF -- a sloppy seek loses
             * nothing. A cookie at or past nm_epack_end() matches no entry and
             * falls out of the loop as EOF. */
            if (off < start) continue;
            emitting = true;
        }
        ctx->pos = off;
        if (!dir_emit(ctx, name, nlen, eino, dt)) {
            /* Buffer full. ctx->pos is THIS entry's own offset, so the next
             * getdents64() resumes here and re-emits it; the entry already
             * written before it takes this offset as its d_off, which is what
             * erofs would have produced at the same cut point. */
            full = true;
            break;
        }
    }

    /* Walked to the end: leave the EOF cookie, which getdents64() copies into
     * the last emitted entry's d_off and which equals the size getattr and
     * SEEK_END report. */
    if (!full)
        ctx->pos = nm_epack_end(&pk);

    if (d) nm_dir_node_put(d);
    return 0;
}

/* ---- dir-target backing-directory snapshot ---------------------------------
 *
 * A rule whose TARGET is a directory serves that directory's children straight
 * out of the backing tree on /data, so two facts about it come from f2fs rather
 * than from the erofs directory it is impersonating. Both were measured on OP15
 * with a test dir-target rule:
 *
 *   SIZE. The injected directory reported size=3452 blocks=7 -- the f2fs values
 *   -- where every stock erofs dir on the same partition reports the closed form
 *   12*N + sum(namelen) (/product/etc = 417) and st_blocks rounded up from it.
 *   nm_dir_size_fix() cannot help: it bails on its first check because the
 *   backing sb is f2fs, and all it knows how to do is apply a DELTA to a size the
 *   backing filesystem already computed the erofs way.
 *
 *   ORDER. The same rule listed its children in f2fs hash order -- measured
 *   out-of-order=3 on 4 entries -- where erofs stores dirents sorted by name and
 *   every rule-free ROM directory sampled came out fully sorted.
 *
 * Both need the same thing, the backing directory's entry NAMES, and enumerating
 * those per stat() is far too expensive. So one bounded, sorted snapshot is
 * cached per injected inode and both answers are derived from it -- which is also
 * what keeps them consistent: the listing's terminal cookie is nm_epack_end()
 * over the same sequence stat() reports as st_size, by construction.
 *
 * NARROW ON PURPOSE. Used only when the directory's dir_node holds no injected
 * children at all -- the pure "serve this /data directory as a ROM directory"
 * shape, which is the shape that was measured. The moment a rule injects into
 * the same directory the listing becomes a MERGE (in-place shadowing of a stock
 * name, whiteouts, per-uid filtering, appended names) whose ordering and size
 * semantics belong to nomount_actor_proxy() and nm_dir_deltas(); those are left
 * exactly as they are, and that case keeps today's behaviour unchanged.
 *
 * INVALIDATION. The snapshot carries the backing directory's (i_size, mtime) as
 * sampled BEFORE the walk, and is rebuilt whenever either moves. A create,
 * unlink or rename in a directory updates that directory's mtime on every
 * filesystem a module tree can live on, so a tree edited underneath a live rule
 * is picked up on the next stat() or readdir(). Sampling the stamp before the
 * walk rather than after means a directory changed DURING the walk carries the
 * older stamp and rebuilds next time, instead of certifying a listing that is
 * already stale. Residual: two changes that leave i_size untouched inside a
 * single nanosecond-resolution timestamp tick.
 *
 * BOUNDED. At most NM_DSNAP_MAX_ENTS names and NM_DSNAP_MAX_BYTES of name bytes.
 * A backing directory larger than either gets a snapshot marked NOT ok, which is
 * still cached (so the walk is not retried on every stat) and which sends both
 * callers back to the unmodified paths. So neither readdir nor stat can be made
 * to allocate more than a fixed ~48 KiB transient / ~40 KiB resident per injected
 * directory no matter how large the backing directory is, and every allocation
 * carries __GFP_NOWARN -- an order-3 failure splat in dmesg would itself be a
 * tell. Plain kmalloc, not kvmalloc: kvmalloc does not exist before 4.12 and the
 * caps are chosen to stay inside what kmalloc serves. GFP_NOFS, not GFP_KERNEL:
 * the readdir caller reaches here holding the injected inode's i_rwsem, so
 * direct reclaim must not be allowed to re-enter a filesystem from under it.
 */
#define NM_DSNAP_MAX_ENTS  1024
#define NM_DSNAP_MAX_BYTES (32 * 1024)

struct nm_dsnap_ent {
    u32 noff;        /* byte offset of the name within nm_dsnap.names */
    u16 len;
    u8  d_type;
};

struct nm_dsnap {
    atomic_t refcount;   /* cache's ref + one per in-flight reader */
    bool ok;             /* false: too large / unreadable -- cached negative */
    loff_t stamp_size;   /* backing dir i_size + mtime at build time */
    s64 stamp_sec;
    long stamp_nsec;
    loff_t size;         /* erofs closed form over ".", ".." and every entry */
    unsigned int n;
    unsigned int nbytes;
    struct nm_dsnap_ent *ent;   /* n entries, sorted by name */
    char *names;                /* nbytes of names, in that same order */
};

/* Build-time scratch: name POINTERS, so the sort comparator needs no context
 * argument and plain sort() is enough (sort_r's cmp signature is not stable
 * across the supported range). */
struct nm_dsnap_bent {
    const char *p;
    u16 len;
    u8  d_type;
};

struct nm_dsnap_walk {
    struct dir_context ctx;
    struct nm_dsnap_bent *ent;
    char *names;
    unsigned int n;
    unsigned int nbytes;
    bool overflow;
};

/* mkfs.erofs orders dirents by strcmp() over NUL-terminated names, so a shared
 * prefix puts the shorter name first. Reproduce that, not memcmp over the
 * shorter length alone. */
static int nm_dsnap_cmp(const void *a, const void *b)
{
    const struct nm_dsnap_bent *x = a, *y = b;
    unsigned int m = min(x->len, y->len);
    int r = memcmp(x->p, y->p, m);

    if (r) return r;
    return (int)x->len - (int)y->len;
}

static NM_ACTOR_RET nm_dsnap_actor(struct dir_context *ctx, const char *name, int namelen,
                                   loff_t off, u64 ino, unsigned int dt)
{
    struct nm_dsnap_walk *b = container_of(ctx, struct nm_dsnap_walk, ctx);

    /* "." and ".." are ordinals 0 and 1 of the emitted listing and are accounted
     * separately, exactly as they are for a synthesized directory. */
    if (namelen == 1 && name[0] == '.') return NM_ACTOR_CONTINUE;
    if (namelen == 2 && name[0] == '.' && name[1] == '.') return NM_ACTOR_CONTINUE;
    if (namelen <= 0 || namelen > NAME_MAX ||
        b->n >= NM_DSNAP_MAX_ENTS ||
        b->nbytes + (unsigned int)namelen > NM_DSNAP_MAX_BYTES) {
        b->overflow = true;
        return !NM_ACTOR_CONTINUE;      /* stop: bool actors want false, int ones nonzero */
    }
    b->ent[b->n].p = b->names + b->nbytes;
    b->ent[b->n].len = (u16)namelen;
    b->ent[b->n].d_type = (u8)dt;
    memcpy(b->names + b->nbytes, name, namelen);
    b->nbytes += (unsigned int)namelen;
    b->n++;
    return NM_ACTOR_CONTINUE;
}

static void nm_dsnap_free(struct nm_dsnap *s)
{
    if (!s) return;
    kfree(s->ent);
    kfree(s->names);
    kfree(s);
}

static void nm_dsnap_put(struct nm_dsnap *s)
{
    if (s && atomic_dec_and_test(&s->refcount))
        nm_dsnap_free(s);
}

static bool nm_dsnap_fresh(const struct nm_dsnap *s, struct inode *bi)
{
    struct timespec64 mt = nm_inode_mtime(bi);

    return s->stamp_size == i_size_read(bi) &&
           s->stamp_sec == mt.tv_sec && s->stamp_nsec == mt.tv_nsec;
}

/* Enumerate the backing directory once. Always returns a STAMPED snapshot (or
 * NULL only if even the descriptor could not be allocated), so a directory that
 * does not qualify caches its own negative instead of re-walking on every
 * stat(). Privileged (nm_root_cred) and read-only, like every other backing-tree
 * scan in this file: the answer must not depend on which uid happened to stat
 * the directory first, and st_size is readable without read permission anyway. */
static struct nm_dsnap *nm_dsnap_make(struct nm_inode_info *info, struct inode *bi,
                                      unsigned int blocksize)
{
    struct nm_dsnap_walk b = { .ctx.actor = nm_dsnap_actor };
    struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
    const struct cred *old;
    struct file *dir;
    struct nm_dsnap *s;
    struct timespec64 mt;
    unsigned int i, off = 0;
    /* "COULD NOT BUILD" IS NOT A VERDICT -- and `ok = false` is one.
     *
     * v29 split those apart for the dentry_open arm below and left every other
     * exit sharing one `goto out`, which publishes a snapshot with ok = false --
     * the encoding for "walked it, it does not qualify". nm_dsnap_get() caches
     * that, and nm_dsnap_fresh() keeps it valid until the backing directory's
     * SIZE or MTIME moves, so a single GFP_NOFS failure (or a walk that returned
     * an error) froze the v25 dir-target size correction off for that rule
     * indefinitely, and silently -- exactly the failure v29 was cut for, reached
     * through the allocator instead of through SELinux.
     *
     * b.overflow is the one honest negative here: the actor sets it when the
     * directory has more entries or name bytes than the model can carry, which is
     * a property OF THAT DIRECTORY and will not change until its contents do --
     * which is precisely when the freshness stamp expires the entry anyway. */
    bool cannot_build = false;

    s = kzalloc(sizeof(*s), GFP_NOFS | __GFP_NOWARN);
    if (!s) return NULL;
    atomic_set(&s->refcount, 1);
    mt = nm_inode_mtime(bi);
    s->stamp_size = i_size_read(bi);
    s->stamp_sec = mt.tv_sec;
    s->stamp_nsec = mt.tv_nsec;

    b.ent = kmalloc_array(NM_DSNAP_MAX_ENTS, sizeof(*b.ent), GFP_NOFS | __GFP_NOWARN);
    b.names = kmalloc(NM_DSNAP_MAX_BYTES, GFP_NOFS | __GFP_NOWARN);
    if (!b.ent || !b.names) { cannot_build = true; goto out; }

    /* iterate_dir(), not a hand dispatch: it takes the backing directory's
     * i_rwsem, runs the LSM hook and the IS_DEADDIR check. The backing dir lives
     * on a WRITABLE filesystem, so that rwsem is exactly what keeps a concurrent
     * create/unlink out of this walk. Lock order is our inode's i_rwsem (held by
     * the VFS on the readdir path) then the backing dir's -- the same order
     * nm_dir_child_lookup()'s lookup_one_len_unlocked() already establishes. */
    old = override_creds(nm_root_cred);
    dir = dentry_open(&info->r_path, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);
    if (!IS_ERR(dir)) {
        /* A failed or truncated walk must NOT become a snapshot: a listing that
         * is short by one name would move st_size, the cookie sequence and the
         * emitted set together, i.e. produce a self-consistent LIE about the
         * directory. Fall back to the untouched proxy path instead.
         *
         * `cannot_build`, not `b.overflow`. An iterate_dir() ERROR is transient
         * (-EIO, -ENOMEM from the filesystem) and describes this attempt, not the
         * directory -- publishing it as ok = false cached a not-answer as an
         * answer, which is the whole defect this function has now been cut for
         * twice. Overflow stays a verdict; a failure does not. */
        if (iterate_dir(dir, &b.ctx) < 0)
            cannot_build = true;
        fput(dir);
    } else {
        /* COULD NOT ASK is not a verdict, and must not be cached as one.
         *
         * This is the one nm_root_cred user in the file that does NOT scan a ROM
         * path: r_path is the rule's backing directory, i.e. /data. nm_root_cred
         * comes from prepare_creds() at fs_initcall, so it carries the KERNEL SID,
         * and dentry_open() ends in the LSM -- measured on OP15, kernel_t is
         * allowed dir:search on system_file and system_data_file and DENIED on
         * shell_data_file and adb_data_file, with the denial dontaudit'd. On such
         * a label the open fails, and caching that as a snapshot froze the v25
         * dir-target correction OFF for the rule with nothing said, until the
         * backing directory's size or mtime happened to move.
         *
         * The caller's creds are not the answer either: an app that legitimately
         * reads an injected ROM directory cannot search a module tree, so using
         * them would disable the correction for exactly the readers it is for.
         * So keep the privileged open, and simply do not publish a failure:
         * return NULL, retry on the next qualifying stat. The cost is one failed
         * dentry_open per stat on a directory we cannot read -- an error path, on
         * a rule shape the Suite never builds. */
        nm_warn_once("cannot open a dir-target's backing directory (relabel the module tree); serving it unmodified\n");
        cannot_build = true;
    }
    revert_creds(old);
    if (cannot_build) goto out;
    if (b.overflow) goto out;

    sort(b.ent, b.n, sizeof(*b.ent), nm_dsnap_cmp, NULL);

    s->ent = kmalloc_array(b.n + 1, sizeof(*s->ent), GFP_NOFS | __GFP_NOWARN);
    s->names = kmalloc(b.nbytes + 1, GFP_NOFS | __GFP_NOWARN);
    if (!s->ent || !s->names) { cannot_build = true; goto out; }

    /* Copy the names down in SORTED order, so the resident copy is both smaller
     * than the scratch and walked sequentially by the emitter. */
    nm_epack_step(&pk, 1);      /* "."  */
    nm_epack_step(&pk, 2);      /* ".." */
    for (i = 0; i < b.n; i++) {
        memcpy(s->names + off, b.ent[i].p, b.ent[i].len);
        s->ent[i].noff = off;
        s->ent[i].len = b.ent[i].len;
        s->ent[i].d_type = b.ent[i].d_type;
        off += b.ent[i].len;
        nm_epack_step(&pk, b.ent[i].len);
    }
    s->n = b.n;
    s->nbytes = b.nbytes;
    s->size = nm_epack_end(&pk);
    s->ok = true;

out:
    kfree(b.ent);
    kfree(b.names);
    /* Publish nothing rather than a not-answer: the caller treats NULL as "no
     * snapshot applies THIS TIME" and re-asks on the next qualifying stat, which
     * is what the failures above deserve. Only b.overflow leaves here as a
     * cacheable ok = false. */
    if (cannot_build) {
        nm_dsnap_free(s);
        return NULL;
    }
    return s;
}

/* A usable snapshot for this injected directory, with a reference, or NULL. */
static struct nm_dsnap *nm_dsnap_get(struct nm_inode_info *info, unsigned int blocksize)
{
    struct nm_dsnap *s, *stale;
    struct inode *bi;

    if (!info || !info->r_path.dentry) return NULL;
    if (info->flags & NM_FLAG_VIRTUAL_DIR) return NULL;
    /* Merged listings keep nomount_actor_proxy()'s semantics -- see the header. */
    if (info->dir_node && !idr_is_empty(&info->dir_node->children_idr)) return NULL;
    bi = d_backing_inode(info->r_path.dentry);
    if (!bi || !S_ISDIR(bi->i_mode)) return NULL;

    spin_lock(&info->dsnap_lock);
    s = info->dsnap;
    if (s && nm_dsnap_fresh(s, bi)) {
        if (!s->ok) { spin_unlock(&info->dsnap_lock); return NULL; }
        atomic_inc(&s->refcount);
        spin_unlock(&info->dsnap_lock);
        return s;
    }
    spin_unlock(&info->dsnap_lock);

    s = nm_dsnap_make(info, bi, blocksize);
    if (!s) return NULL;

    /* Two threads can race here and both build; the loser's snapshot is simply
     * dropped by its own put. Both describe the same directory. */
    spin_lock(&info->dsnap_lock);
    stale = info->dsnap;
    info->dsnap = s;
    atomic_inc(&s->refcount);          /* cache ref; the build ref is the caller's */
    spin_unlock(&info->dsnap_lock);
    nm_dsnap_put(stale);

    if (!s->ok) { nm_dsnap_put(s); return NULL; }
    return s;
}

/* Dropped when the injected inode goes away. Readers hold their own reference,
 * so this only releases the cache's. */
static void nm_dsnap_drop(struct nm_inode_info *info)
{
    struct nm_dsnap *s;

    spin_lock(&info->dsnap_lock);
    s = info->dsnap;
    info->dsnap = NULL;
    spin_unlock(&info->dsnap_lock);
    nm_dsnap_put(s);
}

/* FIX 2: report the erofs closed form over the backing directory's own children
 * instead of f2fs's block-quantised size. Returns true if it answered.
 *
 * st_blocks has to move with it or the pair becomes its own tell: erofs sets
 * i_blocks = round_up(i_size, blocksize) >> 9 for an uncompressed inode, and a
 * directory is always uncompressed (v6.6 fs/erofs/inode.c, the !nblks arm). */
/* The size a dir-target directory has to REPORT everywhere -- stat(), SEEK_END,
 * and the terminal readdir cookie all read it from here so they cannot drift
 * apart. 0 means the snapshot does not apply and nothing should be overridden
 * (a real answer is never 0: "." and ".." alone are 27 bytes). */
static loff_t nm_dsnap_dir_size(struct inode *v_inode, struct nm_inode_info *info)
{
    struct super_block *sb = v_inode->i_sb;
    unsigned int bs = sb->s_blocksize ? sb->s_blocksize : 4096;
    struct nm_dsnap *s;
    loff_t sz;

    /* Same gate as the synthesized-dir size in nm_file_getattr(): the closed form
     * is an erofs fact, and on a filesystem that really does quantise directories
     * to a block, applying it would MANUFACTURE the divergence it removes. */
    if (sb->s_magic != EROFS_SUPER_MAGIC_V1 && !READ_ONCE(nm_vdir_erofs_size))
        return 0;
    s = nm_dsnap_get(info, bs);
    if (!s) return 0;
    sz = s->size;
    nm_dsnap_put(s);
    return sz;
}

static bool nm_dsnap_size_fix(struct nm_inode_info *info, struct inode *v_inode,
                              struct kstat *stat)
{
    unsigned int bs = v_inode->i_sb->s_blocksize ? v_inode->i_sb->s_blocksize : 4096;
    loff_t sz = nm_dsnap_dir_size(v_inode, info);

    if (sz <= 0) return false;
    stat->size = sz;
    stat->blocks = (blkcnt_t)(round_up(sz, (loff_t)bs) >> 9);
    return true;
}

/* FIX 3: emit the backing directory's children SORTED, with erofs cookies.
 *
 * Structurally identical to nm_vdir_iterate_erofs() -- ordinal 0 is ".", 1 is
 * "..", k >= 2 is snapshot entry k-2 -- and it inherits that function's position
 * contract wholesale: cookies are byte offsets replayed by nm_epack_step(), a
 * resume walks from ordinal 0, and the terminal cookie is nm_epack_end(), which
 * is the same number nm_dsnap_size_fix() reports as st_size.
 *
 * The stability trade-off is BETTER here than for a synthesized dir: the ordinals
 * come from a snapshot that is immutable once built and pinned by the caller's
 * reference, so a change to the backing directory cannot renumber the ordinals of
 * a read already in progress. It is only seen by the NEXT open or the next resume,
 * which rebuilds against the new stamp -- the same window every cached readdir has.
 *
 * d_ino comes from nm_dirent_ino(), exactly as the proxy path derives it, so
 * getdents64 and a following stat() on the same name keep telling one story. */
static int nm_dsnap_iterate(struct file *file, struct dir_context *ctx,
                            struct nm_inode_info *info, struct nm_dsnap *s,
                            unsigned int blocksize)
{
    struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
    loff_t start = ctx->pos;
    bool emitting = false, full = false;
    int k;

    if (start < 0) start = 0;

    for (k = 0; ; k++) {
        const char *name;
        int nlen;
        u64 eino;
        unsigned char dt;
        loff_t off;

        if (k == 0) {
            name = "."; nlen = 1; dt = DT_DIR;
        } else if (k == 1) {
            name = ".."; nlen = 2; dt = DT_DIR;
        } else {
            unsigned int i = (unsigned int)(k - 2);

            if (i >= s->n) break;
            name = s->names + s->ent[i].noff;
            nlen = s->ent[i].len;
            dt = s->ent[i].d_type;
        }
        eino = nm_dirent_ino(info, name, nlen);
        off = nm_epack_step(&pk, (unsigned int)nlen);
        if (!emitting) {
            if (off < start) continue;
            emitting = true;
        }
        ctx->pos = off;
        if (!dir_emit(ctx, name, nlen, eino, dt)) { full = true; break; }
    }
    if (!full)
        ctx->pos = nm_epack_end(&pk);
    return 0;
}

/* Reported (getattr-level) stat of a path — i.e. what a userspace detector
 * sees, not the raw backing inode->i_sb->s_dev. On an overlay mount this yields
 * the underlying layer's dev; on plain erofs it equals the sb dev. We mirror
 * this dev onto injected inodes so they don't stand out as an st_dev outlier
 * against their stock siblings (OnePlus /product is overlay-backed). */
static int nm_path_stat(const struct path *p, struct kstat *st)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    return vfs_getattr_nosec((struct path *)p, st);
#else
    return vfs_getattr_nosec(p, st, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#endif
}


/* erofs packs a directory as 12 bytes per dirent plus the name, unpadded, and
 * counts "." and "..". So its i_size encodes the entry set exactly, and serving
 * a listing that differs from the backing one without moving the size leaves a
 * directory whose stat() and readdir() disagree -- measured at -28 bytes for a
 * single added name. Apply the bookkeeping the dir_node has been keeping.
 *
 * Deliberately narrow. Only erofs has this closed form: f2fs reports block
 * multiples (3452, 20480) unrelated to the entries, and overlayfs reports a size
 * unrelated to either -- "correcting" those would manufacture the divergence
 * this removes. And only single-block directories, because past 4096 bytes erofs
 * pads each block by an amount that depends on where the names fall; measured
 * exact on every single-block dir and off by 18..208 bytes on multi-block ones,
 * so beyond one block a computed size would be confidently wrong, which is a
 * sharper oracle than a stale one.
 *
 * nm_vdir_size() solves the same problem for a dir NoMount synthesizes whole,
 * where every entry is known and the block packing can be replayed exactly. Here
 * the stock entries are NOT known -- this is a real erofs dir we are adding to
 * or hiding from -- so only the delta is computable, and only within one block. */
/* Both corrections a managed directory needs, from ONE walk of its children.
 *
 * nlink: a directory reports 2 + one link per subdirectory, so hiding one must
 * decrement and adding one must increment.
 * size: one erofs dirent is NM_EROFS_DIRENT_SZ + the name, unpadded, so an
 * addition grows the parent, a whiteout shrinks it, and a replacement (the name
 * is already counted) moves nothing.
 *
 * Both are filtered by nm_rule_visible(). The size half used to come from a
 * dir_node->size_delta counter maintained at add/delete time, which could not be
 * -- a single cached number cannot answer "how much does THIS caller see". So a
 * --uid-scoped rule shifted the reported SIZE for every caller while moving the
 * link count only for the targeted one: stat() on an untargeted process showed a
 * directory whose size had been corrected for entries it cannot see, which is the
 * same stat-vs-readdir divergence the correction exists to remove, just relocated.
 * Computing it here costs nothing extra -- the nlink walk was already O(children)
 * on this exact path -- and it is always in step with the current flags, so the
 * counter's staleness on rule replacement stops being expressible too. */
/* How this child moves the parent's on-disk directory size. One erofs dirent is
 * an NM_EROFS_DIRENT_SZ header plus the name, unpadded. A whiteout removes a
 * stock entry, an addition introduces one, and a replacement reuses the name
 * that is already counted. */
static s32 nm_child_size_contrib(const struct nomount_child_node *child)
{
    s32 bytes = (s32)(NM_EROFS_DIRENT_SZ + child->name_len);

    if (child->flags & NM_FLAG_WHITEOUT)
        return -bytes;
    if (child->flags & NM_FLAG_SHADOWS_STOCK)
        return 0;
    return bytes;
}

static void nm_dir_deltas(struct nomount_dir_node *d, int *nlink_d, s32 *size_d)
{
    struct nomount_child_node *ch;
    int nld = 0, cid = 0;
    s32 szd = 0;

    *nlink_d = 0;
    *size_d = 0;
    if (!d) return;
    rcu_read_lock();
    idr_for_each_entry(&d->children_idr, ch, cid) {
        /* Only children this caller can actually see: a uid-scoped rule must not
         * move the parent's metadata for everyone else. */
        if (!nm_child_visible(ch)) continue;
        szd += nm_child_size_contrib(ch);
        if (ch->d_type != DT_DIR) continue;
        if (ch->flags & NM_FLAG_WHITEOUT)            nld--;
        else if (!(ch->flags & NM_FLAG_SHADOWS_STOCK)) nld++;
    }
    rcu_read_unlock();
    *nlink_d = nld;
    *size_d = szd;
}

static void nm_dir_size_fix(struct nm_inode_info *info, struct kstat *stat)
{
    int nld;
    s32 delta;
    loff_t fixed;

    if (!info->dir_node || !info->r_path.dentry)
        return;
    /* O(1) rejects BEFORE the O(children) walk: the delta is only ever applied to
     * a single-block erofs directory, so on every other filesystem -- and on any
     * dir already past one block -- computing it would be wasted work on a stat
     * path. (The counter this replaced was a free read, so the old order did not
     * matter; now it does.) */
    if (d_backing_inode(info->r_path.dentry)->i_sb->s_magic != EROFS_SUPER_MAGIC_V1)
        return;
    if (stat->size <= 0 || stat->size >= 4096)
        return;
    nm_dir_deltas(info->dir_node, &nld, &delta);
    if (!delta)
        return;
    fixed = stat->size + delta;
    if (fixed <= 0 || fixed >= 4096)
        return;
    stat->size = fixed;
}

/* getattr for a REAL directory we manage.
 *
 * nomount_hijack_dir_inode used to swap only ->lookup, so a stock directory kept
 * its filesystem's own getattr and every metadata correction here was
 * unreachable: a hidden entry left the parent reporting a size and link count
 * that still counted it. This is that missing consumer -- the same RCU-pin
 * discipline as nomount_hijacked_lookup, because a concurrent del/clear can
 * restore i_op and call_rcu-free nm_iop underneath us.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static int nomount_hijacked_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
#else
static int nomount_hijacked_getattr(IDMAP_ARG const struct path *path, struct kstat *stat,
                                    u32 request_mask, unsigned int query_flags)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    struct inode *inode = d_backing_inode(dentry);
#else
    struct inode *inode = d_backing_inode(path->dentry);
#endif
    const struct inode_operations *orig_iop;
    struct nomount_dir_node *d;
    struct nm_iop *nm_iop;
    int res, nld;
    s32 delta;

    rcu_read_lock();
    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    orig_iop = nm_iop ? nm_iop->orig_iop : NULL;
    d = nm_iop ? smp_load_acquire(&nm_iop->dir_node) : NULL;
    if (d && !atomic_inc_not_zero(&d->refcount)) d = NULL;
    rcu_read_unlock();

    /* Always answer with the real filesystem's values first. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    if (orig_iop && orig_iop->getattr)
        res = orig_iop->getattr(mnt, dentry, stat);
    else { generic_fillattr(inode, stat); res = 0; }
#else
    if (orig_iop && orig_iop->getattr)
        res = orig_iop->getattr(IDMAP_CALL path, stat, request_mask, query_flags);
    else {
/* The request_mask argument arrived at 6.6, NOT with the mnt_idmap conversion at
 * 6.3. v6.5 include/linux/fs.h: generic_fillattr(struct mnt_idmap *, struct
 * inode *, struct kstat *); v6.6: (struct mnt_idmap *, u32, struct inode *,
 * struct kstat *). IDMAP_CALL is right from 6.3 either way -- only the extra
 * argument moved, and passing it on 6.3..6.5 is a hard build failure there. */
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        generic_fillattr(IDMAP_CALL request_mask, inode, stat);
# else
        generic_fillattr(IDMAP_CALL inode, stat);
# endif
        res = 0;
    }
#endif
    /* A blocked reader is being served the stock filesystem, so it must get the
     * stock METADATA too. Correcting nlink/size for it would leave stat() counting
     * children its own readdir() and lookup() refuse to show -- the exact
     * stat-vs-readdir divergence nm_dir_size_fix() exists to remove, handed to the
     * one caller most likely to be measuring for it, with the delta spelling out
     * how many entries are being hidden. Unless this directory holds a public
     * rule: that one IS in its listing, so its metadata has to count it, and
     * nm_dir_deltas() -- which filters per child on the same predicate readdir
     * uses -- returns exactly the public entries' contribution and nothing else. */
    if (res || !d)
        goto out;
    if (nomount_is_uid_blocked(current_uid().val) && !READ_ONCE(d->has_public))
        goto out;

    nm_dir_deltas(d, &nld, &delta);

    if (nld) {
        if ((int)stat->nlink + nld >= 2)
            stat->nlink = (unsigned int)((int)stat->nlink + nld);
    }
    /* erofs only, single block only -- see nm_dir_size_fix's reasoning. */
    if (delta && inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1 &&
        stat->size > 0 && stat->size < 4096) {
        loff_t fixed = stat->size + delta;
        if (fixed > 0 && fixed < 4096)
            stat->size = fixed;
    }
out:
    if (d) nm_dir_node_put(d);
    return res;
}

/* The stock facts every injected inode mirrors onto a stat: the device and inode
 * number a stock file at this path reports, the ROM build's timestamps, and the
 * st_blksize / statx attributes / result_mask a stock sibling answers with.
 *
 * Both arms of the getattr below need exactly this set, and it used to be written
 * out twice per arm and once per signature -- four copies of one paragraph, in a
 * function edited in nearly every version bump from 19 to 28. */
static void nm_mirror_stat(const struct nm_inode_info *info, struct inode *v_inode,
                           struct kstat *stat)
{
    stat->ino = info->v_ino;
    stat->dev = info->v_dev ? info->v_dev : v_inode->i_sb->s_dev;
    if (info->flags & NM_FLAG_HAVE_TIMES) {   /* mtime 0 is real (apex/erofs), so gate on the flag */
        stat->atime = info->v_atime;
        stat->mtime = info->v_mtime;
        stat->ctime = info->v_ctime;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    if (info->v_attr_mask) {      /* replay the stock/sibling statx attributes (guarded: 0 for virtual dirs) */
        stat->attributes = info->v_attributes;
        stat->attributes_mask = info->v_attr_mask;
    }
#endif
    if (info->v_blksize) stat->blksize = info->v_blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    /* A stock erofs file reports atime UNSUPPORTED in statx's result_mask;
     * forwarding getattr to the backing file on /data (which does track atime)
     * sets that bit, so injected files answered statx with a mask no stock
     * sibling produces. Narrow to the stock mask -- never widen. */
    if (info->v_result_mask) stat->result_mask &= info->v_result_mask;
#endif
}

/* getattr for an injected inode. ONE body, two signatures.
 *
 * ->getattr changed shape twice in the supported range: 4.11 replaced
 * (vfsmount, dentry, kstat) with (path, kstat, request_mask, query_flags), and
 * 5.12/6.3 prefixed an idmap. That was carried as two whole copies of this
 * function, 81 of 83 lines identical, differing only in the generic_fillattr
 * arity and the vfs_getattr_nosec argument count -- both of which are #if-guarded
 * inside this file anyway. The duplicated copy was the pre-4.11 one, i.e. the 4.9
 * build, which the compile matrix builds and nobody boots: a fix landing on one
 * arm and not the other could not be caught by CI and would not be caught on a
 * phone either. request_mask/query_flags are simply unused on the older arm.
 */
static int nm_file_getattr_common(IDMAP_ARG struct inode *v_inode, struct kstat *stat,
                                  u32 request_mask, unsigned int query_flags)
{
    struct nm_inode_info *info = v_inode->i_private;
    int res;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    (void)request_mask;
    (void)query_flags;
#endif
    if (unlikely(!info)) return -EIO;
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    /* Hidden reader of a shadowing rule: report the stock file it is entitled to,
     * so stat() agrees with the open() and no dcache invalidation is needed. */
    {
        struct path *stock = nm_stock_for_caller(info);
        if (unlikely(stock)) {
            /* _nosec, like every other getattr in this file: the caller has
             * already passed the security check for the path it named, and
             * re-running the LSM hook against the pinned stock path returned
             * -EPERM on OP15 (no AVC -- a non-SELinux hook), so a hidden reader
             * could read the file but not stat it. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            return vfs_getattr_nosec(stock, stat, request_mask, query_flags);
#else
            return vfs_getattr_nosec(stock, stat);
#endif
        }
    }

    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
/* The request_mask argument arrived at 6.6, NOT with the mnt_idmap conversion at
 * 6.3 -- see the note on the other generic_fillattr call site. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        generic_fillattr(IDMAP_CALL request_mask, v_inode, stat);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        generic_fillattr(IDMAP_CALL v_inode, stat);
#else
        generic_fillattr(v_inode, stat);
#endif
        nm_mirror_stat(info, v_inode, stat);
        stat->nlink = nm_vdir_nlink(info->dir_node);
        /* i_size stays at its 4096 placeholder otherwise; on erofs that is a
         * value no stock directory reports. Recount like nlink. */
        /* The sb here is the PARENT's -- overlayfs on an overlay-backed ROM path,
         * which is why this guard alone left those dirs at 4096. The knob is
         * userspace's measured answer for this device. */
        if (v_inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1 || READ_ONCE(nm_vdir_erofs_size)) {
            unsigned long vbs = v_inode->i_sb->s_blocksize;

            stat->size = nm_vdir_size(info->dir_node, vbs);
            /* st_blocks has to follow st_size, or fixing one half just moves the
             * tell. nomount_create_new_inode() stamps i_blocks = 8 (one 4K block)
             * and nothing updated it, so a synthesized dir whose size is now the
             * exact erofs closed form still reported 8 sectors -- correct only
             * while that size fits in one block, and visibly wrong the moment it
             * does not. erofs computes an uncompressed inode's blocks as the size
             * rounded up to a block (fs/erofs/inode.c), so do the same. */
            if (vbs)
                stat->blocks = (blkcnt_t)((((u64)stat->size + vbs - 1) & ~((u64)vbs - 1)) >> 9);
        }
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    res = vfs_getattr_nosec(&info->r_path, stat, request_mask, query_flags);
#else
    res = vfs_getattr_nosec(&info->r_path, stat);
#endif
    if (likely(res == 0)) {
        nm_mirror_stat(info, v_inode, stat);
        if (S_ISDIR(stat->mode)) {
            /* Fix 2 first: a dir-target directory's size comes from the
             * backing f2fs dir, which nm_dir_size_fix() cannot correct at
             * all. It falls through to the delta correction whenever the
             * snapshot does not apply (merged listing, non-erofs shape,
             * backing dir too large). */
            if (!nm_dsnap_size_fix(info, v_inode, stat))
                nm_dir_size_fix(info, stat);
        } else {
            nm_mirror_blocks(info, stat);   /* see nm_size_ratio() */
        }
    }
    return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
/* Pre-4.11 inode_operations->getattr signature: (vfsmount, dentry, kstat). */
static int nm_file_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
    (void)mnt;
    return nm_file_getattr_common(d_backing_inode(dentry), stat, 0, 0);
}
#else
static int nm_file_getattr(IDMAP_ARG const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    return nm_file_getattr_common(IDMAP_CALL d_backing_inode(path->dentry), stat,
                                  request_mask, query_flags);
}
#endif

static int nm_setattr(IDMAP_ARG struct dentry *dentry, struct iattr *attr)
{
    struct inode *v_inode = d_inode(dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int err;

    if (unlikely(!info)) return -EIO;
    /* Hidden reader: same -ENOENT the other ops give. notify_change() would
     * otherwise act on the backing file for a name this caller is told does not
     * exist. */
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    if (info->flags & NM_FLAG_VIRTUAL_DIR) return 0;

    /* Forward a COPY with ATTR_FILE stripped, never the caller's iattr verbatim.
     * do_truncate() sets ATTR_FILE with ia_file pointing at the file the caller
     * opened -- which is OURS, an nm_file_fops file whose payload lives in
     * ->private_data. Handing that to the backing filesystem gives it a struct
     * file belonging to a different inode and a vtable it knows nothing about;
     * a filesystem that consults attr->ia_file (fuse and friends do) then acts on
     * the wrong object. Dropping the bit makes the backing fs take its inode
     * path, which is the correct one for a stacked caller. Same reason overlayfs
     * does not pass its own file down. The copy also keeps notify_change's
     * ia_valid mutations off the caller's struct.
     * ATTR_MODE/UID/GID/SIZE and the times all survive -- only the file handle
     * is removed, so no permission or size semantics change. */
    {
        struct iattr battr = *attr;

        battr.ia_valid &= ~ATTR_FILE;
        battr.ia_file = NULL;

        inode_lock(d_backing_inode(info->r_path.dentry));
        err = notify_change(IDMAP_CALL info->r_path.dentry, &battr, NULL);
        inode_unlock(d_backing_inode(info->r_path.dentry));
    }

    if (likely(!err)) {
        if (attr->ia_valid & ATTR_MODE) v_inode->i_mode = d_backing_inode(info->r_path.dentry)->i_mode;
        if (attr->ia_valid & ATTR_UID)  v_inode->i_uid = d_backing_inode(info->r_path.dentry)->i_uid;
        if (attr->ia_valid & ATTR_GID)  v_inode->i_gid = d_backing_inode(info->r_path.dentry)->i_gid;
        nm_sync_inode_times(v_inode, d_backing_inode(info->r_path.dentry));
    }
    return err;
}

static const char *nm_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *done)
{
    struct nm_inode_info *info = inode->i_private;
    struct inode *real_inode;
    struct dentry *target_dentry;
    /* -ECHILD is a REQUEST to the VFS ("retry me in ref-walk"), not an error, and
     * it is only meaningful on the RCU-walk call -- which is the one the VFS makes
     * with dentry == NULL. Returning it on the ref-walk call instead propagates
     * all the way out, so a caller resolving a broken injected symlink got
     * ECHILD ("No child processes") from a path operation: an errno no filesystem
     * produces there, and therefore a tell. Answer -EIO on that side.
     * (Unreachable as written -- nm_alloc_rule resolves r_path with LOOKUP_FOLLOW
     * so S_ISLNK never holds -- but the whole point of keeping nm_get_link is
     * that resolution may change; see the note on nm_file_iops.get_link.) */
    if (unlikely(!info || !info->r_path.dentry))
        return ERR_PTR(dentry ? -EIO : -ECHILD);

    real_inode = d_backing_inode(info->r_path.dentry);
    target_dentry = dentry ? info->r_path.dentry : NULL;
    if (real_inode && real_inode->i_op && real_inode->i_op->get_link) {
        return real_inode->i_op->get_link(target_dentry, real_inode, done);
    }

    return ERR_PTR(-EINVAL);
}

/* Forward FS_IOC_FIEMAP to the backing inode. ioctl_fiemap() dispatches on
 * inode->i_op->fiemap before reaching f_op->unlocked_ioctl, so without this an
 * injected .so returns -EOPNOTSUPP where every real erofs/ext4 lib returns
 * extents -- a cheap, app-reachable detection tell. */
static int nm_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
                     u64 start, u64 len)
{
    struct nm_inode_info *info = inode->i_private;
    struct inode *real_inode;

    if (unlikely(!info)) return -EOPNOTSUPP;
    /* Normally unreachable for a hidden reader -- ioctl(FS_IOC_FIEMAP) needs an
     * fd and nm_open() answers first -- but ->fiemap is dispatched off the
     * inode, so keep the per-UID answer here rather than relying on that. */
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    if (unlikely((info->flags & NM_FLAG_VIRTUAL_DIR) || !info->r_path.dentry))
        return -EOPNOTSUPP;
    /* Describe the file this caller is actually SERVED, not always the module's.
     * read()/stat() already follow nm_stock_for_caller(); leaving fiemap on the
     * backing file meant a blocked reader got a 1484-byte stock file from read()
     * and the module file's physical extents from FS_IOC_FIEMAP -- one ioctl plus
     * one stat, measured on OP15 as an identical extent across three UIDs that
     * were being served two different files. */
    {
        struct path *stock = nm_stock_for_caller(info);

        real_inode = d_backing_inode(stock ? stock->dentry : info->r_path.dentry);
    }
    if (!real_inode || !real_inode->i_op || !real_inode->i_op->fiemap)
        return -EOPNOTSUPP;
    return real_inode->i_op->fiemap(real_inode, fieinfo, start, len);
}

static int nm_dir_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    struct nomount_dir_node *dir_node = info ? info->dir_node : NULL;
    struct file *real_file = file->private_data;
    int res = 0;

    /* Both erofs-cookie emitters own their listing from ordinal 0, so they are
     * decided BEFORE nm_is_virtual_pos() -- that test only means anything for a
     * dir whose cookies SIT ABOVE a real backing pass, and letting it run first
     * would short-circuit a resume into the counter-based emitter.
     *
     * Gated exactly like the erofs SIZE in nm_file_getattr() and nm_llseek():
     * the terminal cookie IS the reported size, so the two are on or off
     * together. Off (non-erofs sb, knob clear) keeps the previous behaviour byte
     * for byte, as does every case either emitter declines. */
    if (likely(info)) {
        struct super_block *sb = file_inode(file)->i_sb;

        if (sb->s_magic == EROFS_SUPER_MAGIC_V1 || READ_ONCE(nm_vdir_erofs_size)) {
            /* Fully synthesized: no real pass exists at all. */
            if (!real_file && (info->flags & NM_FLAG_VIRTUAL_DIR))
                return nm_vdir_iterate_erofs(file, ctx, info, dir_node,
                                             sb->s_blocksize);
            /* Dir-target rule serving its OWN backing directory. Gated on
             * real_file being that directory: a hidden reader is handed the
             * pinned STOCK dir by nm_open(), and that one's order and cookies
             * are already genuine erofs. */
            if (real_file && !(info->flags & NM_FLAG_VIRTUAL_DIR) &&
                info->r_path.dentry &&
                real_file->f_path.dentry == info->r_path.dentry) {
                struct nm_dsnap *snap = nm_dsnap_get(info, sb->s_blocksize);

                if (snap) {
                    res = nm_dsnap_iterate(file, ctx, info, snap, sb->s_blocksize);
                    nm_dsnap_put(snap);
                    return res;
                }
            }
        }
    }

    if (unlikely(nm_is_virtual_pos(dir_node, ctx->pos))) {
        nomount_emit_virtual_children(ctx, dir_node,
                                      !(info && (info->flags & NM_FLAG_VIRTUAL_DIR)));
        return 0;
    }

    if (real_file) {
        struct nomount_proxy_ctx proxy_ctx = {
            .ctx.actor = nomount_actor_proxy, .ctx.pos = ctx->pos,
            .orig_ctx = ctx, .dir_node = dir_node,
            /* These real dirents are the BACKING directory's, not a stock ROM
             * directory's -- so unlike the hijacked-dir proxy, their inos have to
             * be mirrored. See nm_dirent_ino().
             *
             * Gated on real_file actually being the backing dir: nm_open() hands a
             * reader that this rule hides the pinned STOCK directory instead, and
             * that one's dirents are genuine ROM entries whose inos must pass
             * through untouched. Compare the dentry rather than re-asking
             * nm_stock_for_caller(), so the answer is the one this fd was opened
             * with even if the fd is later read by a different uid. */
            .dir_info = (info && real_file->f_path.dentry == info->r_path.dentry)
                        ? info : NULL,
            .emitted = 0
        };
        /* iterate_dir(), not a hand dispatch of ->iterate_shared: the VFS took
         * i_rwsem on OUR synthetic inode, which is a different inode on a
         * different superblock from the backing directory. Calling the backing
         * fs's readdir directly left it unserialised -- and the backing dir lives
         * on /data (f2fs/ext4), a writable fs where concurrent modification
         * during ->iterate_shared is exactly what that rwsem excludes. It also
         * skipped security_file_permission(), fsnotify and the IS_DEADDIR check,
         * and never synced real_file->f_pos. The scan helpers in this file
         * (nm_dir_ino_pop, nm_iter_dotdot, nm_scan_dir_for_file) already go
         * through iterate_dir for the same reason. */
        res = iterate_dir(real_file, &proxy_ctx.ctx);
        ctx->pos = proxy_ctx.ctx.pos;
        if (res < 0 || proxy_ctx.emitted > 0) return res;
        if (!dir_node) return res;
        nm_publish_real_eof(dir_node, ctx->pos);
        ctx->pos = nm_pack_pos(dir_node, 0);
    } else if (info && (info->flags & NM_FLAG_VIRTUAL_DIR)) {
        if (ctx->pos < 2 && !nm_emit_dots(file, ctx, info)) return 0;
        if (!dir_node) return 0;
        nm_publish_real_eof(dir_node, 2);
        ctx->pos = nm_pack_pos(dir_node, 0);
    } else {
        return -ENOTDIR;
    }

    nomount_emit_virtual_children(ctx, dir_node,
                                  !(info && (info->flags & NM_FLAG_VIRTUAL_DIR)));
    return res;
}

/* Resolve a child of a directory a rule TARGETS -- a name with no rule of its
 * own, living in the backing directory on /data.
 *
 * This used to be `r_dir->i_op->lookup(r_dir, dentry, flags)`: a raw dispatch of
 * the BACKING filesystem's lookup, which spliced an f2fs inode onto a dentry
 * hanging off the ROM superblock. Everything the engine mirrors for a rule --
 * st_dev, st_ino, the timestamps, st_blksize, the SELinux label, the /proc/maps
 * dev -- was simply absent for those children: they answered with /data's f2fs
 * values while every stock sibling on the same ROM path answered with the
 * erofs/overlay ones. One stat() on any child of an injected directory, compared
 * against its parent, showed the two on different filesystems.
 *
 * So build the same synthetic inode a rule gets, from the same
 * nomount_create_new_inode(), with the parent's mirror inherited: the child of an
 * injected directory belongs to the same partition as the directory, so the
 * partition-level facts (dev, mapdev, blksize, times, label, the NM_CAP_* answers
 * sampled from a real ancestor dir) are exactly the ones to carry down. Only the
 * ino has to be minted per child -- nm_child_ino() -- and it is minted the same
 * way on the readdir side so d_ino and st_ino agree.
 *
 * NM_FLAG_PUBLIC and NM_FLAG_SHADOWS_STOCK are inherited so a child is hidden
 * from precisely the readers its parent is, and no wider. On the inode side those
 * two bits are read in exactly two places -- nm_hidden_from_caller() and
 * nm_stock_for_caller() -- and a reader that got this far has already been let
 * through both of them on the PARENT directory (a blocked reader cannot traverse
 * a non-PUBLIC, non-shadowing injected dir: nm_inode_permission answers -ENOENT).
 * Without the inheritance a child would answer -ENOENT for a name its own parent
 * had just listed, which is the listed-but-unstattable shape the engine refuses
 * to produce anywhere else. s_path stays empty, so nm_stock_for_caller() still
 * returns NULL here and nothing new is substituted.
 *
 * lookup_one_len_unlocked(), not a hand dispatch: it takes the backing
 * directory's i_rwsem, which ->lookup is entitled to assume and which the raw
 * dispatch never took -- the same unserialised-backing-fs bug the iterate path
 * fixed by going through iterate_dir(). It also stops the raw dispatch's other
 * habit of splicing an inode from the BACKING superblock onto a dentry hanging
 * off the ROM one, which left ovl_dentry_operations (inherited from the ROM sb's
 * s_d_op) pointed at an f2fs inode -- ovl_d_real() would then read OVL_I() out of
 * it. The signature is unchanged from 4.9 (include/linux/namei.h:83) to 6.12
 * (:73). d_name.name is NUL-terminated, which is what it wants.
 *
 * One deliberate semantic change comes with it: lookup_one_len_unlocked() runs
 * inode_permission(base, MAY_EXEC) on the backing directory (v4.9 fs/namei.c:2514,
 * and from 5.10 inside lookup_one_len_common()), which the raw dispatch skipped.
 * That is the same "the caller's own creds are authorised exactly as for a stock
 * path" rule nm_open() already states, and it holds on the deployment shape --
 * ksud creates module dirs 0755 and labels them system_file, which AOSP's
 * domain.te grants every domain r_dir_perms on. A module tree that does not
 * traverse for its readers now fails at lookup instead of at open; that is a
 * packaging bug to relabel, exactly as nm_open() says. */
/* 6.16 split this API in two and re-typed it. Before: lookup_one_len_unlocked()
 * -- which despite the name DOES check MAY_EXEC on the base (v4.9
 * fs/namei.c:2514; 6.12's lookup_one_common() ends in inode_permission(..,
 * MAY_EXEC)). From 6.16 the checking variant is lookup_one_unlocked() taking a
 * struct qstr, and the name lookup_noperm_unlocked() is the one that skips the
 * check. Bind to the CHECKING variant on both sides, or the semantics quietly
 * flip at 6.16 depending on which name looks more familiar. The callee fills in
 * qstr.hash itself (lookup_noperm_common), so QSTR_INIT is complete. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static inline struct dentry *nm_lookup_backing_child(const char *name, struct dentry *base, int len)
{
    struct qstr q = QSTR_INIT(name, len);

    return lookup_one_unlocked(&nop_mnt_idmap, &q, base);
}
#else
static inline struct dentry *nm_lookup_backing_child(const char *name, struct dentry *base, int len)
{
    return lookup_one_len_unlocked(name, base, len);
}
#endif

static struct dentry *nm_dir_child_lookup(struct inode *dir, struct nm_inode_info *info,
                                          struct dentry *dentry)
{
    struct nm_rule_info ri;
    struct dentry *child, *res;
    struct inode *new_inode, *r_child;
    /* Sampled before the backing lookup, for the reason nomount_get_rule_info()
     * spells out: an inode may be stamped with a staler generation than the
     * current one, never a newer one. */
    u32 gen = (u32)atomic_read(&nm_rule_gen);

    child = nm_lookup_backing_child(dentry->d_name.name, info->r_path.dentry,
                                    dentry->d_name.len);
    if (IS_ERR(child))
        return ERR_CAST(child);
    if (d_is_negative(child)) {
        dput(child);
        nm_install_dentry_ops(dentry);
        d_add(dentry, NULL);
        return NULL;
    }

    memset(&ri, 0, sizeof(ri));
    ri.gen = gen;
    /* Same ref discipline as nomount_get_rule_info(): ri owns a path ref of its
     * own, released by nm_put_rule_info() once nomount_create_new_inode() has
     * taken its. The lookup's own ref on @child is dropped separately below. */
    ri.r_path.mnt = info->r_path.mnt;
    ri.r_path.dentry = child;
    path_get(&ri.r_path);

    r_child = d_backing_inode(child);
    ri.flags = info->flags & (NM_FLAG_HAVE_TIMES | NM_FLAG_OVL_INO |
                              NM_FLAG_PUBLIC | NM_FLAG_SHADOWS_STOCK);
    if (r_child && S_ISDIR(r_child->i_mode))
        ri.flags |= NM_FLAG_IS_DIR;

    /* The child's OWN stock file, when the parent rule shadows a real directory.
     *
     * Inheriting NM_FLAG_SHADOWS_STOCK without inheriting an s_path was a hole in
     * per-UID hiding, and both halves of the pair read wrong for a blocked reader:
     * nm_hidden_from_caller() saw the flag and declined to answer -ENOENT, while
     * nm_stock_for_caller() found no s_path and returned NULL -- so open/getattr/
     * xattr/fiemap all served the MODULE's bytes to exactly the reader they are
     * hidden from. The same reader's nm_open() of the PARENT is handed the pinned
     * stock directory, so its readdir listed stock names while lookup resolved
     * module content: two answers about one directory.
     *
     * So resolve the same name under the parent's pinned stock directory and pin
     * THAT as the child's s_path. A hidden reader is then served the stock child,
     * which is what "shadows stock" has meant everywhere else since v18.
     *
     * Three outcomes, deliberately distinct:
     *   found     -> pin it; the flag now has the thing it promises.
     *   negative  -> the module ADDED this name inside a shadowed directory, so
     *                there is nothing underneath: strip the flag and let
     *                nm_hidden_from_caller() answer -ENOENT, exactly as it does
     *                for an added name at the top level.
     *   error     -> we could not ask (the caller cannot search the stock dir).
     *                Leave the flags alone: turning "unmeasured" into "hidden"
     *                would ENOENT a name that may well exist in stock, and the
     *                parent's own readdir would then list a name that cannot be
     *                stat'd -- the shape this engine refuses to produce anywhere.
     *                The "resolved to one of ours" arm below is the same answer
     *                for the same reason: we did not obtain a stock file, so we
     *                have measured nothing about whether one is there.
     *
     * Guarded against pinning one of OUR OWN inodes, the same trap nm_alloc_rule
     * documents: a rule injecting into that stock directory makes this lookup
     * resolve through our hijack, and treating an injection as "stock" would serve
     * it to the reader it is hidden from.
     *
     * Costs nothing on any configuration the Suite builds: it produces no
     * dir-target rule over a live directory at all (mount.rs's
     * inject_would_mask_dir refuses the target, cli::handle_vfs refuses a
     * directory source), so info->s_path.dentry is NULL here and this is one test.
     * Only a hand-issued `nm add <existing-dir> <dir>` reaches the body.
     *
     * Pinned per INODE, not per caller, because the dentry and its inode are
     * shared by every UID -- the same reason nm_alloc_rule resolves s_path once at
     * rule creation rather than deciding at read time.
     *
     * THE CALLER'S CREDS, exactly like the module-side lookup above it. A first
     * cut wrapped this in override_creds(nm_root_cred), reasoning that a reader
     * unable to search the stock directory would otherwise bake "no s_path" into
     * an inode every other UID then shares. That reasoning was fine and the
     * mechanism was not: lookup_one_len_unlocked() ends in inode_permission(),
     * which runs the LSM against current_cred() -- and nm_root_cred comes from
     * prepare_creds() at fs_initcall, so it carries the KERNEL SID, not root's.
     *
     * Measured on an OP15 (CPH2747, 6.12, engine v27), asking the live policy
     * directly through /sys/fs/selinux/access:
     *     kernel_t -> system_file       dir:search  ALLOWED (0x11140053)
     *     kernel_t -> system_data_file  dir:search  ALLOWED
     *     kernel_t -> shell_data_file   dir:search  DENIED  (0x0)
     *     kernel_t -> adb_data_file     dir:search  DENIED  (0x0)
     * so the lookup returned -EACCES on any /data-labelled target, took the
     * error arm below, pinned nothing, and left the v26 behaviour in place --
     * silently, because the denial is dontaudit'd and no AVC is logged. The same
     * rule shape under two labels, blocked reader, root-warmed parent:
     *     shell_data_file       both.txt = MODULE  modonly = MODULE   (inert)
     *     system_data_root_file both.txt = STOCK   modonly = <ENOENT> (works)
     * The other nm_root_cred users in this file never noticed because they only
     * ever scan ROM paths, where kernel_t is allowed.
     *
     * The first-toucher worry it was guarding against is weaker than it looked: a
     * caller that reaches here has already passed nm_inode_permission() on the
     * PARENT, whose mode, owner and context mirror the stock ancestor -- so if it
     * can traverse ours it can search the stock one. Using the caller's creds
     * also removes the LSM dependency entirely rather than trading one label for
     * another. */
    if (unlikely(info->s_path.dentry && (info->flags & NM_FLAG_SHADOWS_STOCK))) {
        struct dentry *schild = nm_lookup_backing_child(dentry->d_name.name,
                                                        info->s_path.dentry,
                                                        dentry->d_name.len);

        if (!IS_ERR(schild)) {
            if (d_is_negative(schild)) {
                ri.flags &= ~NM_FLAG_SHADOWS_STOCK;   /* an ADDED name; hide it */
            } else {
                struct inode *si = d_backing_inode(schild);

                if (si && si->i_op != &nm_file_iops && si->i_op != &nm_dir_iops) {
                    ri.s_path.mnt = info->s_path.mnt;
                    ri.s_path.dentry = schild;
                    path_get(&ri.s_path);   /* ri owns its own ref; see nm_put_rule_info */
                }
            }
            dput(schild);
        }
    }

    ri.v_ino   = nm_child_ino(info->v_ino, dentry->d_name.name, dentry->d_name.len, false);
    ri.v_dino  = (info->flags & NM_FLAG_OVL_INO)
                 ? nm_child_ino(info->v_ino, dentry->d_name.name, dentry->d_name.len, true) : 0;
    ri.v_pdino = info->v_dino ? info->v_dino : info->v_ino;
    ri.v_dev   = info->v_dev;
    ri.v_mapdev = info->v_mapdev;
    ri.v_atime = info->v_atime;
    ri.v_mtime = info->v_mtime;
    ri.v_ctime = info->v_ctime;
    ri.v_attributes = info->v_attributes;
    ri.v_attr_mask  = info->v_attr_mask;
    ri.v_blksize    = info->v_blksize;
    ri.v_result_mask = info->v_result_mask;
    ri.v_cap   = info->v_cap;
    ri.v_uid   = info->v_uid;
    ri.v_gid   = info->v_gid;
    ri.v_mode  = info->v_mode;
    ri.v_ctx_len = info->v_ctx_len;
    if (info->v_ctx_len)
        memcpy(ri.v_ctx, info->v_ctx, info->v_ctx_len + 1);

    new_inode = nomount_create_new_inode(dir->i_sb, &ri);
    nm_put_rule_info(&ri);
    dput(child);
    if (unlikely(!new_inode))
        return ERR_PTR(-ENOMEM);

    nm_install_dentry_ops(dentry);
    res = d_splice_alias(new_inode, dentry);
    if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
    return res;
}

static struct dentry *nm_dir_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct inode *r_dir = nm_get_real_inode(dir);
    struct nm_inode_info *info = dir->i_private;
    const char *name = dentry->d_name.name;
    size_t len = dentry->d_name.len;
    bool hidden_rule = false;

    if (info && info->dir_node) {
        u32 v_hash = full_name_hash(NULL, name, len);
        struct nm_rule_info rule_info;
        /* A blocked reader must get the stock view here too, not just at the top
         * level: skip the injection and fall through to the real dir below (or to
         * a negative for a purely synthesized dir). In practice such a reader
         * cannot resolve the virtual parent in the first place, so this is the
         * belt to that braces -- it keeps the per-UID rule true of this path on
         * its own terms rather than by relying on the parent lookup failing. */
        if (nomount_get_rule_info(info->dir_node, name, len, v_hash, &rule_info, true)) {
            hidden_rule = nm_uid_hidden(rule_info.flags);
            if (!hidden_rule) {
                /* Install our dentry ops on every dentry we manage. Without this the
                 * child inherits sb->s_d_op: harmless on a normal fs (NULL), but on an
                 * overlayfs sb it is ovl_dentry_operations, whose d_revalidate/d_real
                 * run against our synthetic inode (no ovl_entry) and return -ECHILD.
                 * nomount_hijacked_lookup already does this for the first level; the
                 * synthesized deeper subtree (a new dir over overlay) needs it too. */
                if (rule_info.flags & NM_FLAG_WHITEOUT) {
                    nm_install_dentry_ops(dentry); d_add(dentry, NULL);
                    nm_put_rule_info(&rule_info);
                    return NULL;
                }
                if ((rule_info.flags & NM_FLAG_VIRTUAL_DIR) || rule_info.r_path.dentry) {
                    struct inode *new_inode = nomount_create_new_inode(dir->i_sb, &rule_info);
                    if (new_inode) {
                        struct dentry *res;
                        nm_install_dentry_ops(dentry);
                        nm_put_rule_info(&rule_info);
                        /* ops on the spliced-alias result too (same as hijacked_lookup) */
                        res = d_splice_alias(new_inode, dentry);
                        if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
                        return res;
                    }
                }
            }
            nm_put_rule_info(&rule_info);
        }
    }

    /* Blocked reader on a name we DO inject: tag the stock/negative dentry that is
     * about to be cached so it is evicted on last dput and cannot hide the
     * injection from other UIDs (same reasoning as the top-level fallback). Gate on
     * a rule existing, else ordinary files under this dir would be needlessly
     * uncached. */
    if (hidden_rule) {
        nm_install_dentry_ops(dentry);
#ifdef DCACHE_DONTCACHE
        dentry->d_flags |= DCACHE_DONTCACHE;
#endif
    }

    if (r_dir && r_dir->i_op && r_dir->i_op->lookup && info && info->r_path.dentry)
        return nm_dir_child_lookup(dir, info, dentry);

    if (info && (info->flags & NM_FLAG_VIRTUAL_DIR)) {
        nm_install_dentry_ops(dentry);
        d_add(dentry, NULL);
        return NULL;
    }
    return ERR_PTR(-EOPNOTSUPP);
}

struct nm_xattr_proxy {
    struct xattr_handler fake;
    const struct xattr_handler *orig;
};

/* xattr .get/.set receive the name with the handler prefix stripped on most
 * kernels ("selinux"), but vfs_get/setxattr need the FULL name
 * ("security.selinux") — otherwise the backing lookup returns empty and the
 * injected inode is left unlabeled ('?') on erofs. Re-prepend the prefix when
 * missing (robust to versions that pass the full name). *allocp is set to a
 * heap copy the caller must kfree(), or NULL when the original name is reused. */
static const char *nm_full_xattr_name(const struct nm_xattr_proxy *proxy,
                                      const char *name, char **allocp)
{
    const char *pfx = xattr_prefix(proxy->orig);

    *allocp = NULL;
    if (pfx && *pfx && strncmp(name, pfx, strlen(pfx)) != 0) {
        char *full = kasprintf(GFP_KERNEL, "%s%s", pfx, name);

        if (full) { *allocp = full; return full; }
    }
    return name;
}

/* On the LSM asymmetry with nm_listxattr(), which forwards to i_op->listxattr
 * directly while this forwards through vfs_getxattr(): audited, then MEASURED
 * rather than assumed. Across 14 paths on OP15 -- synthesized dirs, injected
 * files, and stock neighbours at three depths -- listxattr and
 * getxattr("security.selinux") agreed on every one, same context, no EACCES.
 * They agree because xattr_permission() short-circuits security.* before any
 * DAC check and SELinux answers the LSM half from the inode's own isec.
 *
 * Deliberately NOT "fixed" to __vfs_getxattr() for symmetry's sake: that skips
 * security_inode_getsecurity(), which is the only thing that reports a context
 * on a partition labelled by genfscon instead of an on-disk xattr -- trading a
 * divergence that does not reproduce for one that would. */
static int nm_xattr_get(const struct xattr_handler *handler, struct dentry *dentry, struct inode *inode, const char *name, void *buffer, size_t size FLAGS_ARG)
{
    struct nm_xattr_proxy *proxy = container_of(handler, struct nm_xattr_proxy, fake);
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        struct nm_inode_info *info = inode->i_private;
        struct path *stock;
        char *alloc;
        const char *full;
        int r;

        if (unlikely(!info)) return -ENODATA;
        /* The other half of the pair nm_listxattr() documents: xattr_permission()
         * short-circuits security.*, so this op answered for a reader that
         * stat() and open() refuse. */
        if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
        stock = nm_stock_for_caller(info);
        if (unlikely(stock)) {
            full = nm_full_xattr_name(proxy, name, &alloc);
            r = vfs_getxattr(IDMAP_PATH(info->s_path) info->s_path.dentry, full, buffer, size);
            kfree(alloc);
            return r;
        }
        full = nm_full_xattr_name(proxy, name, &alloc);
        if (!info->r_path.dentry) {
            r = -ENODATA;
            if (info->v_ctx_len && strcmp(full, "security.selinux") == 0) {
                if (!size)                  r = info->v_ctx_len + 1;
                else if (size < info->v_ctx_len + 1u) r = -ERANGE;
                else { memcpy(buffer, info->v_ctx, info->v_ctx_len + 1); r = info->v_ctx_len + 1; }
            }
            kfree(alloc);
            return r;
        }
        r = vfs_getxattr(IDMAP_PATH(info->r_path) info->r_path.dentry, full, buffer, size);
        kfree(alloc);
        return r;
    }
    return proxy->orig->get(proxy->orig, dentry, inode, name, buffer, size FLAGS_VAL);
}

static int nm_xattr_set(const struct xattr_handler *handler, IDMAP_ARG struct dentry *dentry, struct inode *inode, const char *name, const void *buffer, size_t size, int flags)
{
    struct nm_xattr_proxy *proxy = container_of(handler, struct nm_xattr_proxy, fake);
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        struct nm_inode_info *info = inode->i_private;
        char *alloc;
        const char *full;
        int r;

        if (unlikely(!info || !info->r_path.dentry)) return -ENODATA;
        /* A hidden reader must not be able to WRITE an attribute onto a name it
         * is told does not exist. Harder to reach than the get side (it needs
         * write permission, and the injection targets are read-only ROM paths),
         * but the answer has to be the same one. */
        if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
        full = nm_full_xattr_name(proxy, name, &alloc);
        r = vfs_setxattr(IDMAP_CALL info->r_path.dentry, full, buffer, size, flags);
        kfree(alloc);
        return r;
    }
    return proxy->orig->set(proxy->orig, IDMAP_CALL dentry, inode, name, buffer, size, flags);
}

/* Return 0 from d_revalidate to force a re-resolve. For a BLOCKED reader also
 * unhash a NEGATIVE dentry first: the VFS's d_invalidate() is a no-op on
 * negatives, so a stale negative otherwise stays hashed and the re-lookup just
 * finds it again -- that is what let a blocked reader's fallback-cached negative
 * hide an injected path from unblocked readers too.
 *
 * DO NOT d_drop for a normal (non-blocked) reader. Evicting negatives on revalidate
 * makes an injected directory refuse to cache negative lookups -- abnormal versus a
 * stock dir, and a self-consistency detector (Holmes "Narcissus") flags the
 * asymmetry as "Something Wrong". A normal reader must behave byte-identically to
 * pre-per-UID (plain re-resolve, negative stays cached). The blocked reader's
 * poisoned negative is in any case already evicted at lookup by DCACHE_DONTCACHE on
 * >=5.13; this d_drop is the pre-DONTCACHE fallback and stays gated to that path. */
/* Known cost of the DONTCACHE/d_drop pair: for a BLOCKED reader an injected name
 * is never left in the dcache, while its non-injected siblings are, so repeated
 * lookups of the two differ in cost in a way they do not on a stock device. That
 * is a narrower tell than the poisoned-negative bug it replaces (which was visible
 * to every UID at once), and it only exists for a reader we are already lying to. */
static inline int nm_reval_stale(struct dentry *dentry)
{
    if (nomount_is_uid_blocked(current_uid().val) && d_is_negative(dentry))
        d_drop(dentry);
    return 0;
}

/* The ref-walk confirmed an injected dentry, so re-stamp it with the generation
 * it was validated against and let the RCU fast path answer for it next time.
 * Only ever called where the verdict is already 1, and only for a positive
 * dentry carrying one of our inodes -- so this narrows nothing and can only
 * turn a future -ECHILD into the same 1 the slow path just produced. */
static inline int nm_reval_fresh(struct dentry *dentry, u32 gen)
{
    struct inode *ino = d_inode(dentry);

    /* @gen is sampled at ENTRY to nm_d_revalidate, before the verdict below it
     * reads the rule table -- deliberately NOT re-read here. Re-reading would
     * stamp a generation the verdict was never checked against whenever an
     * add/del lands mid-call, and the RCU fast path would then trust that dentry
     * until the NEXT topology change. An older stamp costs one more ref-walk. */
    if (ino && ino->i_private &&
        (ino->i_op == &nm_file_iops || ino->i_op == &nm_dir_iops))
        WRITE_ONCE(((struct nm_inode_info *)ino->i_private)->gen, gen);
    return 1;
}

/* Is this dentry a PASSTHROUGH child -- an inode we minted in
 * nm_dir_child_lookup() for a name that lives in a DIR-TARGET rule's backing
 * directory and has no rule of its own?
 *
 * It never will have one, and that is the whole point of the question. A
 * dir-target rule (`nm add /product/priv-app/Contacts <moduledir>`) serves every
 * name beneath it by looking the name up in the backing directory and wrapping
 * the result in one of our inodes, with our d_op on the dentry so the per-UID
 * verdict keeps running. But the rule's dir_node only ever holds names that have
 * rules of their OWN -- and a dir-target rule with no sub-rules has no dir_node
 * at all -- so nm_d_revalidate found no rule for such a child and fell through
 * to its two "the rule is gone, re-resolve" arms, verdict 0.
 *
 * The VFS answers a 0 with d_invalidate(), which unhashes the dentry; d_unlinked()
 * is then true forever after, and d_path() appends " (deleted)" to it for every
 * process that already had the file open or mapped. Measured on an OP15 with no
 * cloak patches present, so this is the engine's own doing:
 * "/product/priv-app/Contacts/Contacts.apk (deleted)" in system_server's
 * /proc/PID/maps, with the dev field (00:38) and the inode both correctly
 * mirrored -- the path string was the entire tell. _pathhide cannot answer it,
 * because the observer is system_server, which can never be on a per-app hide
 * list.
 *
 * The right verdict for such a child is "valid". Its parent's own dentry is
 * revalidated on the way down by the same walk, so a rule that goes away takes
 * the whole subtree with it through the parent -- the standard stacking-fs
 * arrangement. What is checked here is only that this really is a passthrough
 * child: our inode's backing dentry is still a live child of the parent's
 * backing directory. A child minted from a RULE points somewhere else entirely
 * (a module file under /data/adb), so a deleted rule still falls through to the
 * re-resolve, which is what it needs. */
static bool nm_is_passthrough_child(struct inode *parent_dir, struct dentry *dentry)
{
    const struct nm_inode_info *pinfo, *cinfo;
    struct inode *cino = d_inode(dentry);

    if (!parent_dir || parent_dir->i_op != &nm_dir_iops)
        return false;
    pinfo = parent_dir->i_private;
    if (!pinfo || !pinfo->r_path.dentry)
        return false;                 /* purely synthesized dir: nothing passes through */
    if (!cino || (cino->i_op != &nm_file_iops && cino->i_op != &nm_dir_iops))
        return false;
    cinfo = cino->i_private;
    return cinfo && cinfo->r_path.dentry &&
           cinfo->r_path.dentry->d_parent == pinfo->r_path.dentry &&
           !d_unhashed(cinfo->r_path.dentry);
}

/* 6.14, not 6.13: v6.13 include/linux/dcache.h still has
 * int (*d_revalidate)(struct dentry *, unsigned int); the parent/name form
 * appears at v6.14. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static int nm_d_revalidate(struct inode *dir, const struct qstr *name, struct dentry *dentry, unsigned int flags)
#else
static int nm_d_revalidate(struct dentry *dentry, unsigned int flags)
#endif
{
    struct inode *parent_dir;
    struct nm_iop *nm_iop;
    struct nomount_dir_node *pdir = NULL;
    struct nm_rule_info rule_info;
    u32 hash, gen;
    bool injected;

    /* RCU-walk fast path.
     *
     * This used to be an unconditional -ECHILD, and that single line was a
     * 100%-precision, UID-independent injection oracle. Every dentry we manage
     * carries DCACHE_OP_REVALIDATE, so refusing the lazy walk forced
     * try_to_unlazy_next() -- which legitimize_links() refuses outright when
     * LOOKUP_CACHED is set -- and path_openat() then answered -EAGAIN. So
     * openat2(RESOLVE_CACHED) separated injected from stock with one syscall, no
     * baseline device and no root: measured on OP15 as unprivileged uid 2000,
     * 260/260 rule paths EAGAIN against 216/216 stock siblings OK in the same
     * eight directories, cold and warm alike, and transitive through synthesized
     * parents so it enumerated directories too.
     *
     * Deliberately narrow. It answers ONLY for a positive dentry whose inode is
     * ours -- exactly that 260-path population. Negatives (whiteouts, the
     * blocked-reader fallback, virtual-dir children) have no inode to read a
     * verdict from and still take the ref-walk, keeping today's behaviour bit for
     * bit. So does anything needing d_drop(), which must not run in a lazy walk.
     *
     * Safety rests on three things, each checked rather than assumed:
     *   - the inode is RCU-freed (erofs and overlayfs both provide ->free_inode),
     *   - i_private is now RCU-freed too (nomount_hijacked_destroy_inode),
     *   - staleness is caught by nm_rule_gen, so no d_name is read here at all --
     *     which is what lets us skip the rename/seqcount argument entirely. Any
     *     add/del/clear bumps the counter and pushes every cached injected dentry
     *     through the ref-walk once, where the full verdict runs and re-stamps.
     * nm_uid_hidden() is re-evaluated per call (static branch + idr_find under
     * rcu_read_lock, no sleeping), so uid block/unblock needs no bump. */
    if (flags & LOOKUP_RCU) {
        struct inode *ino = d_inode_rcu(dentry);
        struct nm_inode_info *rinfo;

        if (!ino || (ino->i_op != &nm_file_iops && ino->i_op != &nm_dir_iops))
            return -ECHILD;
        rinfo = READ_ONCE(ino->i_private);
        if (!rinfo || READ_ONCE(rinfo->gen) != (u32)atomic_read(&nm_rule_gen))
            return -ECHILD;
        /* The one verdict the ref-walk below answers with 0 rather than 1: a
         * blocked reader on a SHADOWING rule with no pinned stock path, where the
         * real filesystem is the only route to the file it is entitled to. */
        if (nm_uid_hidden(rinfo->flags) &&
            (rinfo->flags & NM_FLAG_SHADOWS_STOCK) && !rinfo->s_path.dentry)
            return -ECHILD;
        return 1;
    }

    /* Sampled BEFORE the verdict below reads the rule table; see nm_reval_fresh. */
    gen = (u32)atomic_read(&nm_rule_gen);

    /* Is this a dentry WE instantiated (an injected file/dir inode)? Used below to
     * drop stale ghosts and to keep the per-UID view consistent. */
    injected = dentry->d_inode &&
        (dentry->d_inode->i_op == &nm_file_iops ||
         dentry->d_inode->i_op == &nm_dir_iops);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    parent_dir = dir;
#else
    parent_dir = d_inode(dentry->d_parent);
#endif
    if (!parent_dir) return 1;

    /* Resolve the parent's dir_node. A REAL hijacked dir carries it in a
     * per-inode fake_iop; a SYNTHESIZED virtual dir uses the shared const
     * nm_dir_iops (no fake_iop) and keeps its dir_node in the inode's private
     * info. Missing the virtual-dir case made revalidate return 1 (valid) for a
     * stale NEGATIVE child dentry — created by a transient lookup-before-inject
     * during `nm add` — so that child (e.g. the 2nd+ .so in a new arm64/ dir)
     * stayed ENOENT forever and its readdir path-walk could spin. */
    /* Resolve + pin the parent dir_node under RCU (same discipline as the hijacked
     * handlers): a concurrent del/clear can call_rcu-free nm_iop / the dir_node, and
     * this runs outside any rcu section, so read + inc_not_zero under one and never
     * touch nm_iop after. A node mid-free fails inc_not_zero -> pdir NULL -> the
     * ghost-dentry path below (treated as "parent no longer hijacked"). */
    rcu_read_lock();
    nm_iop = __get_nm(smp_load_acquire(&parent_dir->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    if (nm_iop) {
        pdir = smp_load_acquire(&nm_iop->dir_node);
    } else if (parent_dir->i_op == &nm_dir_iops) {
        struct nm_inode_info *pinfo = parent_dir->i_private;
        if (pinfo) pdir = pinfo->dir_node;
    }
    if (pdir && !atomic_inc_not_zero(&pdir->refcount)) pdir = NULL;
    rcu_read_unlock();
    /* Parent is no longer hijacked (its rule/dir_node was removed by del or clear,
     * and the dir was restored), so any child dentry WE cached is stale. An injected
     * (positive, our-iop) one -> return 0 to invalidate. A stale NEGATIVE we cached
     * (a whiteout that was just removed, or a blocked-uid fallback) must be d_drop'd
     * too: d_invalidate() is a no-op on a negative, so returning 0 alone leaves the
     * file ENOENT until eviction/reboot even though the rule is gone. A positive
     * real-fs dentry we merely tagged still reflects reality -> keep it. */
    if (!pdir) {
        if (injected) {
            /* A dir-target rule that owns no sub-rules has no dir_node, so this
             * arm is also where every one of its passthrough children lands --
             * not because the parent was un-hijacked, but because there was
             * never a node to find. Invalidating them is what stamped
             * "(deleted)" onto the maps of anything holding one open. */
            if (nm_is_passthrough_child(parent_dir, dentry))
                return nm_reval_fresh(dentry, gen);
            return 0;
        }
        if (d_is_negative(dentry)) {
            d_drop(dentry);
            return 0;
        }
        return 1;
    }

    hash = full_name_hash(NULL, dentry->d_name.name, dentry->d_name.len);
    if (nomount_get_rule_info(pdir, dentry->d_name.name, dentry->d_name.len, hash, &rule_info, false)) {
        nm_put_rule_info(&rule_info);
        nm_dir_node_put(pdir);                            /* pin no longer needed past the lookup */
        /* A whiteout hides a stock name -- but NOT from a reader the block list
         * says must see the stock filesystem. Evaluating this before the
         * nm_uid_hidden() test below meant the answer depended on which uid
         * touched the path first: once any ordinary reader resolved the whiteout,
         * d_add(dentry, NULL) left a hashed negative in the SHARED dcache, this
         * branch validated it for everyone, and a blocked reader got -ENOENT for
         * a file it is entitled to see -- without ever reaching ->lookup again.
         * Same first-toucher-wins class the uid-scoped path already guards. */
        if (rule_info.flags & NM_FLAG_WHITEOUT) {
            if (nm_uid_hidden(rule_info.flags))
                return 0;                 /* re-resolve; the blocked reader gets stock */
            return d_is_negative(dentry) ? 1 : 0;
        }

        /* Per-UID consistency: a BLOCKED reader must see the stock fs (non-injected),
         * so an injected dentry is invalid for it; a NORMAL reader must see the
         * injection, so a stock/negative dentry (e.g. one a blocked reader's fallback
         * cached in the shared dcache) is invalid for it. Re-resolving fixes both --
         * and nm_reval_stale() unhashes the negative so the re-resolve actually runs. */
        if (nm_uid_hidden(rule_info.flags)) {
            /* An ADDED name stays hashed and is refused in the ops instead --
             * see nm_hidden_from_caller(). Invalidating here is what marked every
             * other process's existing mapping of this file "(deleted)". */
            /* Both classes are now served from the ops: an ADDED name is refused
             * (-ENOENT), a SHADOWING one hands back the stock file it pinned at
             * rule creation. Neither needs the dentry unhashed, which is what
             * used to mark every other process's mapping "(deleted)". Fall back
             * to invalidation only for a shadowing rule with no pinned stock
             * path -- there the real fs is the only way to reach it. */
            if (injected) {
                struct nm_inode_info *ii = dentry->d_inode->i_private;
                if (!(rule_info.flags & NM_FLAG_SHADOWS_STOCK) ||
                    (ii && ii->s_path.dentry))
                    return nm_reval_fresh(dentry, gen);
                return 0;
            }
            return 1;
        }
        return injected ? nm_reval_fresh(dentry, gen) : nm_reval_stale(dentry);
    }
    nm_dir_node_put(pdir);                                /* pin no longer needed past the lookup */
    /* No rule for this NAME, which for a passthrough child under a dir-target
     * rule is the normal state rather than a removal -- see
     * nm_is_passthrough_child(). The parent has a dir_node here (it owns at
     * least one sub-rule), which is the only difference from the arm above. */
    if (injected && nm_is_passthrough_child(parent_dir, dentry))
        return nm_reval_fresh(dentry, gen);
    return nm_reval_stale(dentry);                        /* rule gone -> re-resolve */
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static const struct file_operations nm_file_fops_mmap_prepare = {
    .owner = THIS_MODULE,
    .llseek = nm_llseek,
    .open = nm_open,
    .release = nm_release,
    .read_iter = nm_read_iter,
    .write_iter = nm_write_iter,
    .mmap_prepare = nm_mmap_prepare,
    .unlocked_ioctl = nm_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_compat_ioctl,
#endif
    .splice_read = nm_splice_read,
    .splice_write = nm_splice_write,
    .fallocate = nm_fallocate,
    .fsync = nm_fsync,
};
#endif

static const struct file_operations nm_file_fops = {
    .owner = THIS_MODULE,
    .llseek = nm_llseek,
    .open = nm_open,
    .release = nm_release,
    .read_iter = nm_read_iter,
    .write_iter = nm_write_iter,
    .mmap = nm_mmap,
    .unlocked_ioctl = nm_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_compat_ioctl,
#endif
    .splice_read = nm_splice_read,
    .splice_write = nm_splice_write,
    .fallocate = nm_fallocate,
    .fsync = nm_fsync,
};

/* access() must agree with stat() and open().
 *
 * Refusing a hidden reader in getattr/open while the dentry stays hashed left
 * inode_permission() answering "yes": measured on OP15, access(F_OK) and
 * access(R_OK) both returned 0 for a file whose stat() and open() returned
 * -ENOENT. No real filesystem does that, and a detector reads it as a permission
 * loophole -- which is precisely the shape one of them (Holmes) reports. So the
 * permission hook has to tell the same story as the rest of the ops. */
static int nm_inode_permission(IDMAP_ARG struct inode *inode, int mask)
{
    if (unlikely(nm_hidden_from_caller(inode->i_private)))
        return -ENOENT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    return generic_permission(idmap, inode, mask);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    return generic_permission(mnt_userns, inode, mask);
#else
    return generic_permission(inode, mask);
#endif
}

static const struct inode_operations nm_file_iops = {
    .permission = nm_inode_permission,
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
    /* Unreachable as written: nm_alloc_rule() resolves r_path with LOOKUP_FOLLOW,
     * so an injected inode mirrors the symlink TARGET and S_ISLNK is never true.
     * Kept for the day that resolution changes; see the symlink note there. */
    .get_link = nm_get_link,
    .readlink = nm_readlink,
    .fiemap = nm_fiemap,
};

static const struct file_operations nm_dir_fops = {
    .owner = THIS_MODULE,
    .open = nm_open,
    .release = nm_release,
    .llseek = nm_llseek,
    .read = generic_read_dir,
    .fsync = nm_dir_fsync,
    .iterate_shared = nm_dir_iterate_dir,
/* 6.5, not 6.6: v6.4 include/linux/fs.h still has int (*iterate)(struct file *,
 * struct dir_context *); v6.5 does not. Naming the member on 6.5.x is a build
 * failure, so the boundary has to be the version it actually went away in. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    .iterate = nm_dir_iterate_dir,
#endif
};

static const struct inode_operations nm_dir_iops = {
    .permission = nm_inode_permission,
    .lookup = nm_dir_lookup,
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
    /* Directories need the readlink answer too, and for the same reason files
     * do. Without it a hidden reader gets -EINVAL here (the VFS answer for "not
     * a symlink") while a genuinely absent path answers -ENOENT -- exactly the
     * existence oracle nm_readlink() closes for nm_file_iops, still open for
     * every rule whose target is a directory and for every synthesized dir,
     * both of which land on THIS vtable. Non-hidden callers see no change:
     * nm_readlink returns the same -EINVAL do_readlinkat would have produced. */
    .readlink = nm_readlink,
};

static const struct dentry_operations nm_dops = {
    .d_revalidate = nm_d_revalidate,
};

/* --- Hijacking Management --- */

/* Runtime umount hook. generic_shutdown_super() evicts all inodes and then calls
 * ->put_super while the sb is still valid, so cure it here: restore s_op/s_xattr,
 * free our per-sb allocations, and mark the entry dead (sb = NULL) so the
 * unload-time nomount_restore_superblocks() never dereferences this soon-to-be-
 * freed sb. Without this, umounting a hijacked partition left nm_sop->sb dangling
 * until module unload (a UAF at unload). Android ~never umounts these, so it is a
 * rarely-hit safety net; the small nm_sop node is reclaimed at unload. */
static void nomount_hijacked_put_super(struct super_block *sb)
{
    struct nm_sop *nm_sop = __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode);
    void (*orig_put)(struct super_block *) = NULL;

    if (nm_sop) {
        int i = 0;
        orig_put = nm_sop->orig_sop ? nm_sop->orig_sop->put_super : NULL;
        smp_store_release(&sb->s_op, nm_sop->orig_sop);
        if (nm_sop->fake_xattr) {
            smp_store_release((const struct xattr_handler ***)&sb->s_xattr, nm_sop->orig_xattr);
            while (nm_sop->orig_xattr[i]) {
                if (nm_sop->fake_xattr[i])
                    kfree(container_of(nm_sop->fake_xattr[i], struct nm_xattr_proxy, fake));
                i++;
            }
            kfree(nm_sop->fake_xattr);
            nm_sop->fake_xattr = NULL;
        }
        /* Dead-mark last: restore_superblocks() skips the sb block once this is
         * NULL, so everything above (which needs a live sb) must run first. */
        WRITE_ONCE(nm_sop->sb, NULL);
    }
    if (orig_put) orig_put(sb);
}

/* Returns 0 when this superblock is ours (already hijacked, or hijacked here),
 * -ENOMEM when it could not be.
 *
 * The result is NOT advisory, and this used to return void. Our ->destroy_inode
 * is the only thing that frees an injected inode's nm_inode_info and the r_path /
 * s_path / dir_node references it owns, and it is installed HERE -- while the
 * directory inode has already been hijacked two lines earlier in the topology
 * walk. Bailing silently therefore left every synthetic inode minted on this
 * superblock afterwards leaking its payload to the backing filesystem's own
 * teardown, for the life of the boot, with nothing said. The two allocations
 * either side of the call in that walk are already hard failures for the same
 * class of reason; this is the third.
 *
 * A missing sb / s_op is not a failure: there is nothing to hijack and nothing to
 * free later either.
 *
 * NB the xattr proxy below is a separate, softer question -- see the note there. */
static inline int nomount_hijack_superblock(struct super_block *sb)
{
    struct nm_sop *nm_sop;
    int i, count = 0;
    if (unlikely(!sb || !sb->s_op)) return 0;
    if (__get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode)) return 0;

    nm_sop = kzalloc(sizeof(*nm_sop), GFP_KERNEL);
    if (unlikely(!nm_sop)) return -ENOMEM;

    nm_sop->fake_sop = *(sb->s_op);
    nm_sop->orig_sop = sb->s_op;
    nm_sop->sb = sb;
    nm_sop->fake_sop.destroy_inode = nomount_hijacked_destroy_inode;
    nm_sop->fake_sop.drop_inode = nomount_hijacked_drop_inode;
    nm_sop->fake_sop.evict_inode = nomount_hijacked_evict_inode;
    nm_sop->fake_sop.put_super = nomount_hijacked_put_super;   /* cure on runtime umount */
    /* Only when the fs actually has one: installing a ->statfs where the
     * original had none would make an unsupported call start answering. */
    if (sb->s_op->statfs)
        nm_sop->fake_sop.statfs = nomount_hijacked_statfs;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    if (!nm_sop->orig_sop->destroy_inode && !nm_sop->orig_sop->free_inode)
        nm_sop->fake_sop.free_inode = free_inode_nonrcu;
#endif

    /* The xattr proxy is a DEGRADATION, not a failure, and stays best-effort on
     * purpose: without it an injected inode answers getxattr through the
     * filesystem's own handler, which reads a zero-initialised on-disk inode and
     * returns -ENODATA. That is a missing label, not a wrong one -- while failing
     * the whole hijack here would leave the caller with no ->destroy_inode at all,
     * which is the leak this function's return value exists to prevent. */
    if (sb->s_xattr && !nm_sop->orig_xattr) {
        const struct xattr_handler **new_array;
        while (sb->s_xattr[count]) count++;
        new_array = kzalloc((count + 1) * sizeof(void *), GFP_KERNEL);
        if (!new_array) {
            nm_warn_once("xattr proxy allocation failed; injected inodes on this mount will report no security label\n");
        } else {
            for (i = 0; i < count; i++) {
                struct nm_xattr_proxy *proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
                if (!proxy) break;
                proxy->orig = sb->s_xattr[i];
                proxy->fake.name = proxy->orig->name;
                proxy->fake.prefix = proxy->orig->prefix;
                proxy->fake.flags = proxy->orig->flags;
                proxy->fake.list = proxy->orig->list;
                if (proxy->orig->get) proxy->fake.get = nm_xattr_get;
                if (proxy->orig->set) proxy->fake.set = nm_xattr_set;
                new_array[i] = &proxy->fake;
            }
            if (i == count) {
                nm_sop->orig_xattr = (const struct xattr_handler **)sb->s_xattr;
                nm_sop->fake_xattr = new_array;
                smp_store_release((const struct xattr_handler ***)&sb->s_xattr, new_array);
                nm_debug("xattr handlers successfully hijacked for dev: 0x%x\n", sb->s_dev);
            } else {
                int j;
                for (j = 0; j < i; j++)
                    kfree(container_of(new_array[j], struct nm_xattr_proxy, fake));
                kfree(new_array);
            }
        }
    }

    list_add_tail_rcu(&nm_sop->list, &nomount_sb_list);
    smp_store_release(&sb->s_op, &nm_sop->fake_sop);
    nm_debug("Superblock successfully hijacked for dev: 0x%x\n", sb->s_dev);
    return 0;
}

static inline void nomount_hijack_virtual_parent(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_fop *nm_fop;

    if (unlikely(!inode->i_fop)) return;
    /* Already ours? RE-ARM -- see the matching note in nomount_hijack_dir_inode. */
    nm_fop = nm_get_fop(smp_load_acquire(&inode->i_fop));
    if (nm_fop) {
        smp_store_release(&nm_fop->dir_node, dir_node);
        return;
    }
    /* A vtable with no readdir op to hook would carry no marker, so nm_get_fop()
     * could never recover it: the inode would be left pointing at a heap
     * file_operations that nothing can ever find, re-arm or neuter. Refuse to
     * hijack what we cannot identify. */
    if (unlikely(!inode->i_fop->iterate_shared
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
                 && !inode->i_fop->iterate
#endif
        )) return;

    nm_fop = kmem_cache_zalloc(nm_fop_cachep, GFP_KERNEL);
    if (likely(nm_fop)) {
        nm_fop->fake_fop = *(inode->i_fop);
        nm_fop->orig_fop = inode->i_fop;
        nm_fop->dir_node = dir_node;

        /* Mirror the ops the filesystem actually implements. Installing
         * ->iterate_shared unconditionally made the pre-6.6 VFS take the SHARED
         * inode lock for a filesystem that only implements ->iterate, i.e. one
         * that declared it needs exclusion -- concurrent readdirs would then race
         * whatever per-directory state it keeps. From 6.6 ->iterate is gone and
         * every directory implements ->iterate_shared, so this is a no-op there.
         * nm_get_fop() probes both, so the hijack is still recognisable. */
        if (nm_fop->orig_fop->iterate_shared)
            nm_fop->fake_fop.iterate_shared = nomount_hijacked_iterate_dir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
        if (nm_fop->orig_fop->iterate)
            nm_fop->fake_fop.iterate = nomount_hijacked_iterate_dir;
#endif

        smp_store_release(&inode->i_fop, &nm_fop->fake_fop);
        nm_debug("i_fop successfully hijacked for virtual parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static inline void nomount_hijack_dir_inode(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_iop *nm_iop;

    if (unlikely(!inode->i_op)) return;
    /* Already ours? RE-ARM it. Teardown neuters (dir_node = NULL) and leaves the
     * vtable installed, so a plain "already hijacked, skip" would hand this
     * directory back with a NULL dir_node -- every handler would fall through to
     * the real fs and the rule would silently never be served. */
    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    if (nm_iop) {
        smp_store_release(&nm_iop->dir_node, dir_node);
        return;
    }
    /* An inode_operations with no ->lookup carries no marker once copied, so
     * __get_nm() could never recover the nm_iop again: the inode would be left
     * pointing at a heap vtable nothing can re-arm, neuter or restore, AND the
     * ->getattr installed below would then find orig_iop == NULL and answer
     * every stat with generic_fillattr instead of the filesystem's own -- for
     * the life of the boot. Reachable, not theoretical: the topology walk hijacks
     * whatever the parent path resolves to, and `nm add /system/etc/hosts/x y`
     * resolves that parent to a REGULAR FILE. Refuse what we cannot identify,
     * exactly as nomount_hijack_virtual_parent() does for a missing readdir op.
     * The rule is simply inert then; its dir_node is reclaimed on delete. */
    if (unlikely(!inode->i_op->lookup)) return;

    nm_iop = kmem_cache_zalloc(nm_iop_cachep, GFP_KERNEL);
    if (likely(nm_iop)) {
        nm_iop->fake_iop = *(inode->i_op);
        nm_iop->orig_iop = inode->i_op;
        nm_iop->dir_node = dir_node;

        if (nm_iop->orig_iop->lookup) nm_iop->fake_iop.lookup = nomount_hijacked_lookup;
        /* THE missing half: without this the stock fs answers getattr directly and
         * every correction below is dead code. */
        nm_iop->fake_iop.getattr = nomount_hijacked_getattr;
        smp_store_release(&inode->i_op, &nm_iop->fake_iop);
        nm_debug("i_op successfully hijacked for parent dir (ino: %lu)\n", inode->i_ino);
    }
}

/* (Hijack vtables are neutered rather than freed -- see struct nm_iop.) */

/* dir_node owns an idr of child nodes, so it can't use the plain struct-only
 * macro. Freed via call_rcu: lockless readers walk children_idr under RCU
 * (nomount_get_rule_info / nomount_actor_proxy / nomount_emit_virtual_children),
 * so the node and its idr internals must outlive any in-flight reader. Both free
 * sites (empty-dir teardown, rule teardown) route here; children removed one at a
 * time elsewhere are kfree_rcu'd + idr_removed first, so the idr is empty (site 1)
 * or holds only this node's own children (site 2) when this runs. */
static void nm_dir_node_rcu_free(struct rcu_head *head)
{
    struct nomount_dir_node *dir_node = container_of(head, struct nomount_dir_node, rcu);
    struct nomount_child_node *child;
    int id;
    idr_for_each_entry(&dir_node->children_idr, child, id)
        kfree(child);
    idr_destroy(&dir_node->children_idr);
    kmem_cache_free(nm_dir_cachep, dir_node);
}

/* Drop a dir_node ref; RCU-free (children first) only when the last ref goes.
 * Deferred to a grace period because lockless readers can still be walking
 * children_idr under rcu_read_lock. */
static void nm_dir_node_put(struct nomount_dir_node *dir_node)
{
    if (dir_node && atomic_dec_and_test(&dir_node->refcount))
        call_rcu(&dir_node->rcu, nm_dir_node_rcu_free);
}

static void nomount_restore_dir_node(struct nomount_dir_node *dir_node)
{
    struct inode *t_inode = dir_node->_tag_ptr & 1UL ? NULL : dir_node->dir_inode;
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;
 
    if (unlikely(!t_inode)) return;

    spin_lock(&t_inode->i_lock);
    nm_iop = __get_nm(smp_load_acquire(&t_inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    /* Neuter, do not restore: the handlers fall through to orig_* on a NULL
     * dir_node, and leaving the vtable installed is what keeps an already-cached
     * file->f_op valid. See struct nm_iop. */
    if (nm_iop && nm_iop->dir_node == dir_node) {
        WRITE_ONCE(nm_iop->dir_node, NULL);
        nm_debug("Successfully cured i_op for dir %lu\n", t_inode->i_ino);
    }

    nm_fop = nm_get_fop(smp_load_acquire(&t_inode->i_fop));
    if (nm_fop && nm_fop->dir_node == dir_node) {
        WRITE_ONCE(nm_fop->dir_node, NULL);
        nm_debug("Successfully cured i_fop for dir %lu\n", t_inode->i_ino);
    }
    spin_unlock(&t_inode->i_lock);
    iput(t_inode);
    dir_node->dir_inode = NULL;
}

static void nomount_restore_superblocks(void)
{
    struct nm_sop *nm_sop, *tmp;

    list_for_each_entry_safe(nm_sop, tmp, &nomount_sb_list, list) {
        int i = 0;
        if (nm_sop->sb) {
            shrink_dcache_sb(nm_sop->sb);
            smp_store_release(&nm_sop->sb->s_op, nm_sop->orig_sop);
            if (nm_sop->fake_xattr) {
                smp_store_release((const struct xattr_handler ***)&nm_sop->sb->s_xattr, nm_sop->orig_xattr);
                while (nm_sop->orig_xattr[i]) {
                    if (nm_sop->fake_xattr[i]) {
                        kfree(container_of(nm_sop->fake_xattr[i], struct nm_xattr_proxy, fake));
                    }
                    i++;
                }
                kfree(nm_sop->fake_xattr);
            }
            nm_debug("Successfully cured superblock for dev: 0x%x\n", nm_sop->sb->s_dev);
        }
        list_del_rcu(&nm_sop->list);
        kfree_rcu(nm_sop, rcu);
    }
}

/*** Module Management ***/

static struct nomount_dir_node *__nomount_alloc_dir_node(struct inode *inode) 
{
    struct nomount_dir_node *dir_node = kmem_cache_alloc(nm_dir_cachep, GFP_KERNEL);
    if (unlikely(!dir_node)) return NULL;
    if (inode) {
        /* A dying inode (I_FREEING/I_WILL_FREE) makes igrab return NULL. Refuse
         * the node then: proceeding would hijack the inode's vtable but leave
         * dir_inode NULL, so the restore path (gated on dir_inode) never cures it
         * -> leaked node + an uncured fake vtable -> UAF after module unload. */
        dir_node->dir_inode = igrab(inode);
        if (unlikely(!dir_node->dir_inode)) {
            kmem_cache_free(nm_dir_cachep, dir_node);
            return NULL;
        }
    } else {
        dir_node->dir_inode = NULL;
    }
    idr_init(&dir_node->children_idr);
    hash_init(dir_node->children_ht);
    dir_node->real_eof = 0;
    dir_node->max_real_pos = 0;
    dir_node->bloom_mask = 0;
    dir_node->has_public = false;         /* kmem_cache_alloc does not zero */
    atomic_set(&dir_node->refcount, 1);   /* structural owner ref */
    return dir_node;
}

/* Re-point the parent's listing entry at the rule's final dirent ino. Called
 * under the write mutex, after the walk has settled v_dino. */
static void nm_restamp_child_ino(struct nomount_dir_node *dir_node, struct nomount_rule *rule)
{
    struct nomount_child_node *child;
    int id = 0;

    if (unlikely(!dir_node)) return;
    while ((child = idr_get_next(&dir_node->children_idr, &id)) != NULL) {
        if (child->rule == rule) {
            WRITE_ONCE(child->fake_ino, rule->v_dino);
            return;
        }
        id++;
    }
}


/* Make a synthesized ancestor of a public rule public too, and keep walking up.
 *
 * A public rule is unreachable if the virtual directories on the way to it stay
 * hidden -- the blocked reader gets ENOENT on the parent and never asks about the
 * child. Fresh ancestors inherit the bit at creation (see the irule below); this
 * covers the other order, where the directory already exists because a NON-public
 * file under it was injected first. Both the rule and the listing entry its parent
 * caches have to be updated, since the by-child walks read the entry's copy.
 *
 * Called under nomount_write_mutex (the only caller is the topology walk), which
 * is what makes the idr walk and the flag stores safe here. Stops at the first
 * ancestor already public (everything above it was promoted with it) and at the
 * first real directory, which needs no permission to be seen. */
static void nm_mark_public_up(struct nomount_rule *rule)
{
    int guard = 64;   /* the topology walk bounds depth; this is the belt to it */

    while (rule && guard-- > 0) {
        struct nomount_child_node *child;
        struct nomount_dir_node *pd;
        int id = 0;

        if (!(rule->flags & NM_FLAG_VIRTUAL_DIR)) break;
        if (rule->flags & NM_FLAG_PUBLIC) break;
        rule->flags |= NM_FLAG_PUBLIC;

        pd = rule->parent_dir;
        if (!pd) break;
        while ((child = idr_get_next(&pd->children_idr, &id)) != NULL) {
            if (child->rule == rule) { child->flags |= NM_FLAG_PUBLIC; break; }
            id++;
        }
        WRITE_ONCE(pd->has_public, true);

        if (!(pd->_tag_ptr & 1UL)) break;   /* a real directory owns this node */
        rule = (struct nomount_rule *)(pd->_tag_ptr & ~1UL);
    }
}

/* Link `rule` into `dir_node` under `name`. Returns 0, or -ENOMEM when the child
 * could not be created.
 *
 * The result is NOT advisory. __nomount_add_rule's shadow path frees the rule it
 * replaces once this has run, on the assumption that the parent's child node was
 * re-pointed at the incoming rule; if that never happened the node still holds
 * the freed pointer and every later lookup or readdir of that directory
 * dereferences it. Failing silently here (the old void return) is what made that
 * reachable, so the allocation failures propagate and the caller aborts the add. */
static int __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule, const char *name, size_t name_len)
{
    struct nomount_child_node *child;
    u32 name_hash;

    if (unlikely(!dir_node)) return -ENOMEM;
    name_hash = full_name_hash(NULL, name, name_len);
    /* rule->parent_dir is published only where the link is actually made -- in
     * the REPLACEMENT branch and after the fresh child is allocated -- not
     * up here. Setting it before the walk left a rule naming a parent that had
     * refused it (the -ENOMEM arms below), and the invariant this back-pointer
     * has to hold is exactly "the parent's child node points AT this rule".
     * nm_detach_rule_locked() and nomount_prune_empty_virtual_dirs() both
     * dereference it, and __nomount_delete_child_locked() can drop the last ref
     * on a real parent and call_rcu-free it, so a rule that is not the parent's
     * child any more must not be able to name it. */
    hash_for_each_possible(dir_node->children_ht, child, hnode, name_hash) {
        if (child->name_hash == name_hash && child->name_len == name_len &&
            memcmp(child->name, name, name_len) == 0) {
            /* REPLACEMENT (the shadow path in __nomount_add_rule, i.e. what a
             * `nomount reload` does on a module update). The incoming rule can
             * differ from the outgoing one in kind (file vs dir), in the dirent
             * ino it publishes, and in how it moves the parent's on-disk size --
             * so refreshing only flags/rule left the child describing the OLD
             * rule on all three counts:
             *   d_type stale  -> nm_dir_nlink_delta() counts the wrong kind, so
             *                    a directory that now contains a subdirectory
             *                    still reported nlink 2. Measured: a file rule
             *                    shadowed by a dir rule left the parent at 2
             *                    where both a fresh dir rule and a real on-disk
             *                    dir report 3 -- a state no filesystem produces,
             *                    i.e. a one-stat tell.
             *   fake_ino stale-> readdir publishes the previous rule's number
             *                    while stat answers the new one. Usually masked
             *                    (the replacement resolves its vpath through the
             *                    still-live injection and inherits v_ino), but
             *                    NOT when the outgoing rule is a whiteout: the
             *                    vpath no longer resolves, so the new rule picks
             *                    a fresh sibling-derived ino and the two diverge.
             * The parent's reported SIZE had the same problem via a cached
             * size_delta counter; that counter is gone -- nm_dir_deltas() now
             * derives the size correction from the live child flags on the same
             * walk as nlink, so it cannot go stale here and cannot ignore the
             * caller's uid either. */
            /* The OUTGOING rule stops being this parent's child right here. It is
             * normally a victim the caller is about to free, but not always: two
             * vpaths that differ only in redundant slashes used to reach this
             * branch with NO victim recorded (the rule-hash dedup keys on exact
             * bytes, this node keys on parent + name), leaving the outgoing rule
             * live in the table with a back-pointer to a node nothing links it to.
             * Deleting the rule that DID keep the child then empties that node,
             * __nomount_delete_child_locked() drops its last ref, call_rcu frees
             * it -- and the orphan's next `nm del` runs atomic_inc_not_zero() and
             * an idr walk over freed memory. nm_norm_vpath() closes that spelling
             * gap; clearing the pointer closes the class. */
            if (child->rule && child->rule != rule)
                child->rule->parent_dir = NULL;
            child->flags = rule->flags;
            child->rule = rule;
            rule->parent_dir = dir_node;
            child->d_type = (rule->flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG;
            WRITE_ONCE(child->fake_ino, rule->v_dino ? rule->v_dino : rule->v_ino);
            if (rule->flags & NM_FLAG_PUBLIC)
                WRITE_ONCE(dir_node->has_public, true);
            return 0;
        }
    }

    child = kmalloc(sizeof(*child) + name_len + 1, GFP_KERNEL);
    if (unlikely(!child)) return -ENOMEM;

    child->fake_ino = rule->v_dino ? rule->v_dino : rule->v_ino;
    child->name_hash = name_hash;
    child->d_type = (rule->flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG;
    child->flags = rule->flags;
    child->name_len = name_len;
    child->rule = rule;
    memcpy(child->name, name, name_len);
    child->name[name_len] = '\0';

    idr_preload(GFP_KERNEL);
    child->id = idr_alloc(&dir_node->children_idr, child, 0, 0, GFP_NOWAIT);
    idr_preload_end();

    if (child->id < 0) {
        kfree(child);
        return -ENOMEM;
    }

    /* Set the bloom bit BEFORE publishing the child via hash_add_rcu: a lockless
     * reader that already sees the child in the table must also see its bloom bit,
     * else the fast-reject would drop a present child. (The reverse window -- bit
     * set, child not yet visible -- is harmless: the reader just falls through to
     * an empty table walk.) */
    WRITE_ONCE(dir_node->bloom_mask, dir_node->bloom_mask | (1ULL << (name_hash & 63)));
    /* Set before publishing the child, same ordering argument as the bloom bit:
     * a reader that can already see the child must also see the gate that lets it
     * look. Never cleared -- see nomount_dir_node.has_public. */
    if (rule->flags & NM_FLAG_PUBLIC)
        WRITE_ONCE(dir_node->has_public, true);
    hash_add_rcu(dir_node->children_ht, &child->hnode, name_hash);
    /* Link made: now the back-pointer is true. */
    rule->parent_dir = dir_node;
    return 0;
}

static void __nomount_delete_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule)
{
    struct nomount_child_node *child;
    int id;

    if (unlikely(!dir_node)) return;
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->rule == rule) {
            hash_del_rcu(&child->hnode);
            idr_remove(&dir_node->children_idr, id);
            kfree_rcu(child, rcu);
            /* Other half of the invariant __nomount_inject_child_locked()
             * establishes: the rule is no longer this parent's child, so it must
             * not keep naming the node -- which the tail of this function can
             * free outright. Every caller that still needs the parent captured
             * it before calling here (nm_detach_rule_locked into a local,
             * nomount_prune_empty_virtual_dirs into `parent`), for exactly the
             * lifetime reason that makes this necessary. */
            rule->parent_dir = NULL;
            break;
        }
    }
    
    if (idr_is_empty(&dir_node->children_idr)) {
        struct inode *dir_inode = dir_node->_tag_ptr & 1UL ? NULL : dir_node->dir_inode;
        if (dir_inode) {
            nomount_restore_dir_node(dir_node);
            nm_dir_node_put(dir_node);
        }
    } else {
        /* Rebuild into a local, publish once: zeroing bloom_mask in place then
         * re-ORing leaves a transient window where a lockless reader sees a
         * subset/zero mask and false-rejects a STILL-PRESENT child. One store means
         * a racing reader sees the old or the new complete mask -- both cover every
         * remaining child. */
        u64 mask = 0;
        idr_for_each_entry(&dir_node->children_idr, child, id)
            mask |= (1ULL << (child->name_hash & 63));
        WRITE_ONCE(dir_node->bloom_mask, mask);
    }
}

/* Where a synthesized inode number has to land.
 *
 * Three sites used to band by masking the low bits off a reference inode and
 * OR-ing or adding a hash: (anc_ino & ~0xFFFF) | hash for a virtual dir, and
 * (sib.ino & ~0xFFFFF) + 0x100000 + spread for a file. Both are correct only
 * while the reference is LARGE. overlayfs gives a merged directory a small
 * sequential ino of its own, so on any overlay-backed ROM path the mask clears
 * the reference entirely and the band collapses to a window fixed at compile
 * time -- one the stock population does not occupy at all.
 *
 * Measured on OP15 against the shipped v13 engine (audit 2026-08-18):
 *   /product/overlay   139 injected files in [1051431..2078996]; stock files
 *                      run 157771..83104768 with ZERO stock entries inside the
 *                      injected window. Bucket by 1M and the 1-2M bucket is
 *                      100% injected.
 *   /product/priv-app  synthesized dirs at 6095/19789/29037; all 67 stock dirs
 *                      sit at 3..71, so `find -maxdepth 1 -type d -inum +1000`
 *                      returns exactly our injections and nothing else.
 * Neither needs a baseline nor a permission: one stat sweep does it. Note the
 * clustering fix that preceded this (hash_64 spread) is orthogonal and still
 * holds -- it scattered values WITHIN the band while the band itself sat off
 * the population, which is why a collision/cluster check could not see this.
 *
 * So measure the population rather than guess a band for it: sample the
 * directory, keep the real st_ino values for the KIND being placed (on overlay,
 * dirs are numbered from a different sequence than files, so a dir must land
 * among dirs), then sit immediately above one of them.
 *
 * Anchoring to an actual neighbour, rather than scattering across [min,max], is
 * what makes this hold on a population that is not uniform. /product/overlay is
 * bimodal -- stock files cluster near 157771 and again near 80M with nothing in
 * between -- so a uniform draw over the range would drop most injections into
 * the empty middle and recreate this same tell in a new shape. Stepping up from
 * a sampled value lands next to a real file whatever the shape is, and the step
 * is capped by the distance to the next sample so it can never collide with one
 * or jump over it.
 */
#define NM_INO_SAMPLES 64      /* neighbour inodes sampled per directory */
#define NM_INO_MINE    256     /* of our own placements we can remember exactly */
#define NM_RANGE_SLOTS 8       /* directories whose sample we keep around */

/* One directory's neighbourhood: the real inodes sampled from it (ascending),
 * plus what we have already handed out there so two injections never land on
 * the same number. */
struct nm_ino_pop {
    u64 v[NM_INO_SAMPLES];
    int n;
    u64 mine[NM_INO_MINE];
    int nmine;
    u64 hw;                    /* highest we placed, for the overflow path */
};

/* Is there already a live rule for this exact path? Callers hold
 * nomount_write_mutex, which is what serializes the table against del/clear. */
static bool nm_path_is_injected(const char *path, size_t len)
{
    struct nomount_rule *r;
    u32 h = full_name_hash(NULL, path, len);

    hash_for_each_possible(nomount_rules_ht, r, vpath_node, h) {
        if (r->v_hash == h && r->v_len == len &&
            memcmp(nm_get_vpath(r), path, len) == 0)
            return true;
    }
    return false;
}

struct nm_ino_scan {
    struct dir_context ctx;
    bool overlay;              /* dirent ino lies here -- must stat each child */
    bool want_dir;
    const char *dirpath;
    int dirlen;
    struct nm_ino_pop *pop;    /* filled directly on the cheap path */
    char (*names)[NAME_MAX + 1];   /* allocated for the overlay path only */
    int n_names;
    char pathbuf[PATH_MAX];    /* reused; the actor must not allocate */
};

static void nm_pop_insert(struct nm_ino_pop *pop, u64 ino)
{
    int j = pop->n;

    if (!ino || pop->n >= NM_INO_SAMPLES)
        return;
    while (j > 0 && pop->v[j - 1] > ino) {
        pop->v[j] = pop->v[j - 1];
        j--;
    }
    pop->v[j] = ino;
    pop->n++;
}

/* Build dirpath/name into the scan's own buffer. No allocation: this runs
 * inside iterate_dir, under the directory's lock. */
static int nm_scan_path(struct nm_ino_scan *s, const char *name, int namelen)
{
    if (s->dirlen + 1 + namelen >= PATH_MAX)
        return -ENAMETOOLONG;
    memcpy(s->pathbuf, s->dirpath, s->dirlen);
    s->pathbuf[s->dirlen] = '/';
    memcpy(s->pathbuf + s->dirlen + 1, name, namelen);
    s->pathbuf[s->dirlen + 1 + namelen] = '\0';
    return s->dirlen + 1 + namelen;
}

static NM_ACTOR_RET nm_ino_actor(struct dir_context *ctx, const char *name,
                                 int namelen, loff_t off, u64 ino, unsigned int dt)
{
    struct nm_ino_scan *s = container_of(ctx, struct nm_ino_scan, ctx);
    int len;

    if (namelen <= 0 || namelen > NAME_MAX || name[0] == '.')
        return NM_ACTOR_CONTINUE;

    len = nm_scan_path(s, name, namelen);
    if (len < 0)
        return NM_ACTOR_CONTINUE;
    if (nm_path_is_injected(s->pathbuf, len))   /* never sample ourselves */
        return NM_ACTOR_CONTINUE;

    if (!s->overlay) {
        /* d_ino IS st_ino off overlayfs, so the dirent stream already carries
         * the number a probe would stat for. Measured on this device: 0 of 15
         * entries differed in /system/app (erofs) while 38 of 38 differed in
         * /product/app (overlay). Taking it here costs nothing, where the
         * kern_path()+stat() per child that this replaces pushed the injection
         * pass from ~30s to ~205s of boot and tripped the 250s OPlus watchdog.
         *
         * DT_UNKNOWN carries no kind, and guessing one would put entries in the
         * wrong population; skip those rather than pollute the sample. */
        if (dt == DT_UNKNOWN)
            return NM_ACTOR_CONTINUE;
        if ((dt == DT_DIR) == s->want_dir)
            nm_pop_insert(s->pop, ino);
        return NM_ACTOR_CONTINUE;
    }

    if (s->names && s->n_names < NM_INO_SAMPLES) {
        memcpy(s->names[s->n_names], name, namelen);
        s->names[s->n_names][namelen] = '\0';
        s->n_names++;
    }
    return NM_ACTOR_CONTINUE;
}


/* Sampled st_ino population of dirpath's entries of one kind.
 *
 * Our OWN injections are skipped. This reads the directory through the hijacked
 * ops, so a cold scan after a reload sees earlier injections as if they were
 * population; feeding those back in would drag the sample toward wherever we
 * last placed things, and in the dense case would ratchet the top up by another
 * offset on every boot until it became the outlier this fix exists to remove. */
static int nm_dir_ino_pop(const char *dirpath, bool want_dir, struct nm_ino_pop *pop)
{
    struct nm_ino_scan *sc;
    struct path dp;
    struct file *dir;
    const struct cred *old;
    int i;

    pop->n = 0;
    pop->nmine = 0;
    pop->hw = 0;
    if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
        return -ENOENT;
    sc = kzalloc(sizeof(*sc), GFP_KERNEL);
    if (!sc) { path_put(&dp); return -ENOMEM; }

    sc->want_dir = want_dir;
    sc->dirpath  = dirpath;
    sc->dirlen   = (int)strlen(dirpath);
    if (sc->dirlen == 1 && dirpath[0] == '/')
        sc->dirlen = 0;                  /* "//x" would not match any rule */
    sc->pop = pop;
#ifdef OVERLAYFS_SUPER_MAGIC
    sc->overlay = dp.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#endif
    /* Only the overlay path needs names kept for a second, stat-ing pass. */
    if (sc->overlay) {
        sc->names = kzalloc(NM_INO_SAMPLES * (NAME_MAX + 1), GFP_KERNEL);
        if (!sc->names) { kfree(sc); path_put(&dp); return -ENOMEM; }
    }

    *((filldir_t *)&sc->ctx.actor) = nm_ino_actor;
    old = override_creds(nm_root_cred);
    dir = dentry_open(&dp, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);
    path_put(&dp);
    if (!IS_ERR(dir)) {
        iterate_dir(dir, &sc->ctx);
        fput(dir);
    }
    revert_creds(old);

    /* Overlay only: resolve what we collected. Classify on the stat result,
     * not the dirent type -- stat() is what a probe reads. */
    for (i = 0; sc->overlay && i < sc->n_names; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->names[i]);
        struct path fp;
        struct kstat fk;

        if (!cp)
            continue;
        if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
            int r = nm_path_stat(&fp, &fk);

            path_put(&fp);
            if (r == 0 && (!!S_ISDIR(fk.mode) == want_dir))
                nm_pop_insert(pop, fk.ino);
        }
        kfree(cp);
    }

    if (sc->names)
        kfree(sc->names);
    kfree(sc);

    return pop->n ? 0 : -ENOENT;
}

/* Small keyed cache. A one-slot version re-scanned every time rule-add
 * alternated between directories, which is most of what a real module set
 * does. Keyed on the path hash rather than the string so the table stays a
 * few KB. Returns the entry ITSELF, never a copy: nm_place_ino records what it
 * handed out in there, and the ~139 APKs going into one directory only stay
 * distinct because each sees the previous one's marks. */
struct nm_range_slot {
    u32 hash;
    u16 len;
    bool want_dir;
    bool valid;
    struct nm_ino_pop pop;
};
static struct nm_range_slot nm_range_cache[NM_RANGE_SLOTS];
static int nm_range_cache_next;

static struct nm_ino_pop *nm_dir_ino_pop_cached(const char *dirpath, bool want_dir)
{
    size_t len = strlen(dirpath);
    u32 h = full_name_hash(NULL, dirpath, len);
    struct nm_range_slot *sl;
    int i;

    for (i = 0; i < NM_RANGE_SLOTS; i++) {
        sl = &nm_range_cache[i];
        if (sl->valid && sl->hash == h && sl->len == (u16)len &&
            sl->want_dir == want_dir)
            return &sl->pop;
    }
    sl = &nm_range_cache[nm_range_cache_next];
    nm_range_cache_next = (nm_range_cache_next + 1) % NM_RANGE_SLOTS;
    sl->valid = false;
    if (nm_dir_ino_pop(dirpath, want_dir, &sl->pop) != 0)
        return NULL;
    sl->hash = h;
    sl->len = (u16)len;
    sl->want_dir = want_dir;
    sl->valid = true;
    return &sl->pop;
}

static bool nm_ino_taken(const struct nm_ino_pop *pop, u64 c)
{
    int i;

    for (i = 0; i < pop->n; i++)
        if (pop->v[i] == c)
            return true;
    for (i = 0; i < pop->nmine; i++)
        if (pop->mine[i] == c)
            return true;
    return false;
}

static unsigned long nm_ino_take(struct nm_ino_pop *pop, u64 c)
{
    if (pop->nmine < NM_INO_MINE)
        pop->mine[pop->nmine++] = c;
    if (c > pop->hw)
        pop->hw = c;
    return (unsigned long)c;
}

/* Sit just above a sampled neighbour: never on top of one, never past the next
 * one, and never on a number we already handed out in this directory.
 *
 * Verified against the real /product/overlay and /product/priv-app populations
 * pulled off the device: at the live load (139 files, 3 dirs) this places every
 * injection within 64 of a real inode, with no collision against stock or
 * against ourselves, no bucket that is all ours, and a longest consecutive run
 * of 4 rather than the 139 the original clustering had. Past NM_INO_MINE
 * injections in ONE directory it degrades to a monotone run above the top --
 * still collision-free, and far beyond anything a real module set produces. */
static unsigned long nm_place_ino(struct nm_ino_pop *pop, u64 spread)
{
    int a, s;

    if (pop->n <= 0)
        return 0;                        /* caller keeps its own fallback */

    if (pop->nmine >= NM_INO_MINE) {      /* exact tracking exhausted */
        u64 c = pop->hw + 1;

        while (nm_ino_taken(pop, c))
            c++;
        return nm_ino_take(pop, c);
    }

    for (a = 0; a < pop->n; a++) {
        int i = (int)((spread + (u64)a) % (u64)pop->n);
        u64 base = pop->v[i];
        u64 room = (i + 1 < pop->n) ? (pop->v[i + 1] - base) : 64;

        if (room > 64)
            room = 64;
        for (s = 1; s < (int)room; s++) {
            u64 cand = base + 1 + ((spread + (u64)s) % (room > 1 ? room - 1 : 1));

            if (!nm_ino_taken(pop, cand))
                return nm_ino_take(pop, cand);
            cand = base + (u64)s;
            if (cand > base && !nm_ino_taken(pop, cand))
                return nm_ino_take(pop, cand);
        }
    }
    {   /* every sampled gap is full -- continue past the top */
        u64 c = pop->v[pop->n - 1] + 1;

        while (nm_ino_taken(pop, c))
            c++;
        return nm_ino_take(pop, c);
    }
}


/* The nearest REAL directory at or above vpath, and its subdir population.
 *
 * nomount_generate_virtual_topology resolves its ancestor two ways: through
 * kern_path (which scans) or by finding an already-existing VIRTUAL rule, which
 * does not. So a virtual dir nested under one already synthesized never got a
 * population, fell back to the masked band, and -- because that band is taken
 * from the ancestor's own v_ino -- inherited whatever the ancestor had.
 *
 * The ascent MUST step over directories a rule already owns, for two reasons.
 * kern_path SUCCEEDS on them (they are live in the VFS, that is the point), so
 * a naive walk stops at the virtual parent and scans a directory holding
 * nothing real. Worse, resolving one INSTANTIATES it, and the ancestor lookup
 * above then reads a synthesized dir's own ino as if it were a stock one --
 * which cascades: measured live, Mms/lib and Mms/lib/arm64 came out at
 * 1102213485 and 1102213508, the raw-hash band of an ancestor, where every real
 * nested dir under /product/priv-app sits at 34..105. Creating the same chain
 * in one pass gave 66/71, which is how the cascade was told apart from a broken
 * placement. */
static struct nm_ino_pop *nm_real_ancestor_pop(const char *vpath)
{
    char *p = kstrdup(vpath, GFP_KERNEL);
    struct nm_ino_pop *pop = NULL;
    struct path dp;
    char *slash;

    if (!p)
        return NULL;
    while ((slash = strrchr(p, '/')) && slash != p) {
        *slash = '\0';
        if (nm_path_is_injected(p, strlen(p)))
            continue;                 /* ours: never resolve it, keep climbing */
        if (kern_path(p, LOOKUP_FOLLOW, &dp) == 0) {
            path_put(&dp);
            pop = nm_dir_ino_pop_cached(p, true);
            break;
        }
    }
    kfree(p);
    return pop;
}

/* Would re-resolving this name build an inode indistinguishable from the one
 * already cached on @dentry, given that @incoming is the rule that now owns it?
 *
 * Every field compared here is one nomount_create_new_inode() copies straight
 * out of the rule, so equality across all of them means the drop below would
 * unhash a dentry only to have the next lookup mint its twin. That is not free:
 * an unhashed dentry is d_unlinked() forever, and d_path() appends " (deleted)"
 * to it in every /proc/PID/maps that already has the file mapped. A `nomount
 * reload` re-adds over every live rule -- 260 of them on the measured device,
 * almost all with an unchanged source -- so the drop fired ~260 times per reload
 * for no benefit at all, and marked whatever system_server had mapped.
 *
 * s_path is deliberately NOT in the comparison, and keeping the cached inode is
 * the better answer there rather than a compromise: a re-add over a live
 * injection resolves its own vpath through that injection, so nm_alloc_rule
 * refuses to pin one of our inodes as "stock" and the incoming rule carries no
 * s_path at all. The inode already holding the real one is the accurate copy;
 * dropping it is what would lose the blocked reader's stock fallback. */
static bool nm_dentry_matches_rule(struct dentry *dentry, const struct nomount_rule *incoming)
{
    const struct nm_inode_info *info;
    struct inode *ino;

    if (!incoming)
        return false;
    ino = d_inode(dentry);
    if (!ino || (ino->i_op != &nm_file_iops && ino->i_op != &nm_dir_iops))
        return false;                 /* stock dentry, or not ours: must be dropped */
    info = ino->i_private;
    return info &&
           info->flags == incoming->flags &&
           info->r_path.dentry == incoming->r_path.dentry &&
           info->r_path.mnt == incoming->r_path.mnt &&
           info->v_ino == incoming->v_ino &&
           info->v_dev == incoming->v_dev &&
           info->v_dino == incoming->v_dino;
}

/* Unhash any dentry cached for `v_path`, so the next lookup resolves through
 * whichever rule owns the name NOW -- unless what is cached is already exactly
 * that, in which case leave it hashed (see nm_dentry_matches_rule). Pass a NULL
 * @incoming to drop unconditionally, which is what the caller wants when the
 * rule that owned the name is about to be freed and nothing replaces it.
 *
 * Replacing a rule re-points the parent's child node (see the REPLACEMENT branch
 * in __nomount_inject_child_locked), but a dentry already cached for that name
 * still points at the OUTGOING rule's inode. When the parent is a real ROM
 * directory the ordinary lookup path revalidates and the stale dentry goes; when
 * the parent is one of our synthesized directories nothing does, and the name
 * keeps resolving to the old inode for the life of the dcache entry.
 *
 * Measured on an OP15, engine v26, two sources with different content:
 *
 *     /system/etc/x.txt      (real ROM dir)   add A, add B -> reads B   correct
 *     /system/etc/nmt/x.txt  (synthesized)    add A, add B -> reads A   stale
 *
 * The rule table takes B in both cases, so the table and the bytes disagree and
 * nothing in userspace can see it: a re-add reports success, `nm list` shows the
 * new source, and reading the path returns the old one. Userspace worked around
 * it by issuing del+add; this makes the plain add correct so it does not have to.
 *
 * Deliberately best-effort. A path that no longer resolves, a parent that is not
 * a directory, or no cached dentry at all all mean there is nothing stale to
 * drop -- none of which is an error worth failing an add over.
 */
static void nm_drop_cached_vpath(const char *v_path, u16 v_len,
                                 const struct nomount_rule *incoming)
{
    struct dentry *dentry;
    struct path p_path;
    struct qstr qname;
    const char *child;
    size_t child_len, parent_len;
    char *parent;
    int i;

    if (unlikely(!v_path || v_len < 2))
        return;

    /* Split on the last '/'. v_path is not guaranteed NUL-terminated at v_len,
     * so scan rather than reaching for strrchr. */
    parent_len = 0;
    for (i = (int)v_len - 1; i > 0; i--) {
        if (v_path[i] == '/') {
            parent_len = (size_t)i;
            break;
        }
    }
    if (!parent_len)                       /* "/name": parent is the root */
        return;

    child = v_path + parent_len + 1;
    child_len = (size_t)v_len - parent_len - 1;
    if (!child_len || child_len > NAME_MAX)
        return;

    parent = kstrndup(v_path, parent_len, GFP_KERNEL);
    if (unlikely(!parent))
        return;

    if (kern_path(parent, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &p_path) == 0) {
        qname.name = child;
        qname.len = child_len;
        qname.hash = full_name_hash(p_path.dentry, child, child_len);
        if (p_path.dentry->d_flags & DCACHE_OP_HASH)
            p_path.dentry->d_op->d_hash(p_path.dentry, &qname);
        dentry = d_lookup(p_path.dentry, &qname);
        if (dentry) {
            if (!nm_dentry_matches_rule(dentry, incoming))
                d_drop(dentry);
            dput(dentry);
        }
        path_put(&p_path);
    }
    kfree(parent);
}

static int nomount_generate_virtual_topology(struct nomount_rule *target_rule)
{
    struct nomount_rule *irule, *ex, *current_rule = target_rule;
    char orig_v_path, *v_path = nm_get_vpath(target_rule);
    int parent_len, p_len = target_rule->v_len;
    const char *child_name, *lookup_path;
    struct nomount_dir_node *dir_node;
    struct hlist_node *tmp;
    struct inode *v_inode;
    struct dentry *dentry;
    struct path p_path;
    struct qstr qname;
    bool found_virtual;
    bool fresh_node = false;   /* this call allocated dir_node -> ours to unwind */
    size_t child_len, irule_size;
    int i, err = 0;
    u32 h_parent;
    HLIST_HEAD(pending_list);
    kuid_t anc_uid = GLOBAL_ROOT_UID;   /* nearest real ancestor owner/mode/times/context, */
    kgid_t anc_gid = GLOBAL_ROOT_GID;   /* to stamp onto the synthesized virtual dirs       */
    umode_t anc_mode = 0755;
    struct timespec64 anc_atime = {0}, anc_mtime = {0}, anc_ctime = {0};
    unsigned long anc_ino = 0;
    u32 anc_blksize = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    u32 anc_result_mask = 0;                 /* statx-era only; unused pre-4.11 */
    u64 anc_attributes = 0, anc_attr_mask = 0;
#endif
    char anc_ctx[NM_CTX_MAX];
    u16 anc_ctx_len = 0;
    bool have_anc = false;
    u8 anc_cap = 0;            /* nearest real ancestor DIR's file-op answers (NM_CAP_*) */
    bool anc_ovl = false;      /* ancestor is on overlayfs => dirent ino != st_ino */
    u64 anc_dino = 0;          /* what the ancestor's own readdir reports for "." */
    struct nm_ino_pop *anc_dpop = NULL;  /* the ancestor's real SUBDIR inodes */

    while (p_len > 1) {
        for (i = p_len - 1; i >= 0; i--) {
            if (v_path[i] == '/') break;
        }
        if (unlikely(i < 0)) break;          /* no separator: nothing to walk up to */

        parent_len = (i == 0) ? 1 : i;
        child_name = v_path + i + 1;
        child_len = p_len - i - 1;
        h_parent = full_name_hash(NULL, v_path, parent_len);
        orig_v_path = v_path[i];
        if (i > 0) v_path[i] = '\0';

        found_virtual = false;
        hash_for_each_possible(nomount_rules_ht, ex, vpath_node, h_parent) {
            if (ex->v_len == parent_len && memcmp(nm_get_vpath(ex), v_path, parent_len) == 0 &&
                (ex->target_uid == 0 || ex->target_uid == target_rule->target_uid)) {
                /* The matched ancestor must be a directory. A file rule adopted
                 * as a parent gains a this_dir nothing can ever list (its inode
                 * carries the file ops), makes nm_dir_deltas on the grandparent
                 * count a phantom child, and wedges its own deletion at -EBUSY
                 * because its idr is now non-empty. Reject the malformed topology
                 * instead of building it. */
                if (!(ex->flags & (NM_FLAG_VIRTUAL_DIR | NM_FLAG_IS_DIR))) {
                    err = -ENOTDIR;
                    break;
                }
                dir_node = ex->this_dir;
                if (!dir_node) {
                    dir_node = __nomount_alloc_dir_node(NULL);
                    if (unlikely(!dir_node)) { err = -ENOMEM; break; }
                    dir_node->owner_rule = ex;
                    dir_node->_tag_ptr = (unsigned long)ex | 1UL;
                    ex->this_dir = dir_node;
                }
                /* The walk ENDS here, so the kern_path() below never runs and
                 * have_anc would stay false -- leaving every irule created in
                 * this call with no ancestor metadata (raw-hash ino, blksize 1,
                 * epoch-0 times, no context). Only the FIRST rule under a new
                 * subtree reaches a real path; every later one stops here, which
                 * is why only the top synthesized level was ever stamped. The
                 * virtual parent already carries the right values -- inherit. */
                if (!have_anc) {
                    anc_uid = ex->v_uid; anc_gid = ex->v_gid;
                    anc_mode = ex->v_mode ? ex->v_mode : 0755;
                    anc_atime = ex->v_atime; anc_mtime = ex->v_mtime; anc_ctime = ex->v_ctime;
                    anc_ino = ex->v_ino; anc_blksize = ex->v_blksize;
                    anc_ovl = !!(ex->flags & NM_FLAG_OVL_INO);
                    anc_dino = ex->v_dino;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                    anc_result_mask = ex->v_result_mask;
                    anc_attributes = ex->v_attributes;
                    anc_attr_mask = ex->v_attr_mask;
#endif
                    anc_ctx_len = ex->v_ctx_len;
                    if (ex->v_ctx_len) memcpy(anc_ctx, ex->v_ctx, ex->v_ctx_len + 1);
                    anc_cap = ex->v_cap;
                    have_anc = true;
                }
                if (target_rule->flags & NM_FLAG_PUBLIC)
                    nm_mark_public_up(ex);
                err = __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
                if (unlikely(err)) break;
                found_virtual = true;
                break;
            }
        }

        if (unlikely(err)) { if (i > 0) v_path[i] = orig_v_path; break; }

        if (found_virtual) {
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        lookup_path = (parent_len == 1) ? "/" : v_path;
        if (kern_path(lookup_path, LOOKUP_FOLLOW, &p_path) == 0) {
            v_inode = d_backing_inode(p_path.dentry);
            if (S_ISDIR(v_inode->i_mode)) {   /* nearest real ancestor -> mirror onto virtual dirs below it */
                struct kstat akst;

                anc_uid = v_inode->i_uid;
                anc_gid = v_inode->i_gid;
                anc_mode = v_inode->i_mode & 0777;
                if (nm_path_stat(&p_path, &akst) == 0) {
                    anc_ino   = (unsigned long)akst.ino;
                    anc_blksize = akst.blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                    anc_result_mask = akst.result_mask;
                    anc_attr_mask   = akst.attributes_mask;
                    /* Mirror the ancestor's attributes, minus the bits that
                     * describe a MOUNT rather than a file: the nearest real
                     * ancestor is often a mount root (/product/priv-app reports
                     * STATX_ATTR_MOUNT_ROOT) and a synthesized child claiming
                     * that would be a tell in its own right. */
                    anc_attributes  = akst.attributes & ~(u64)(
#ifdef STATX_ATTR_MOUNT_ROOT
                                          STATX_ATTR_MOUNT_ROOT |
#endif
                                          STATX_ATTR_AUTOMOUNT);
#endif
                    anc_atime = akst.atime;
                    anc_mtime = akst.mtime;
                    anc_ctime = akst.ctime;
                }
                if (nm_read_secctx(v_inode, anc_ctx, &anc_ctx_len) != 0)
                    anc_ctx_len = 0;
                /* Which file-op answers a real directory HERE gives, for
                 * nm_dir_fsync to replay on the synthesized dirs below. Skipped
                 * when the resolved ancestor is one of our own inodes (a re-add
                 * over a live injection resolves through it): nm_dir_fops now
                 * always has .fsync, so sampling ourselves would bake in
                 * NM_CAP_FSYNC and reopen the very oracle it closes -- the same
                 * trap the shadowing path guards against in nm_alloc_rule. */
                if (v_inode->i_op != &nm_file_iops && v_inode->i_op != &nm_dir_iops)
                    anc_cap = nm_stock_caps(v_inode);
#ifdef OVERLAYFS_SUPER_MAGIC
                anc_ovl = p_path.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#endif
                /* Sample the sibling DIRS while their directory is resolved
                 * here; a virtual dir has to land among them, and on overlay
                 * they are numbered from a different sequence than the files. */
                anc_dpop = nm_dir_ino_pop_cached(lookup_path, true);
                /* What ".." looks like one level down. Copy it from a real
                 * child of this directory: every stock sibling reports the same
                 * lowerdir ino, so anything else is an outlier among them. */
                anc_dino = anc_ino;
                if (anc_ovl) {
                    anc_dino = nm_child_dotdot_of(lookup_path);
                    if (!anc_dino)
                        anc_dino = ((u64)h_parent & 0x03FFFFFFULL) | 0x02000000ULL | 1ULL;
                }
                have_anc = true;
            }
            dir_node = nomount_get_dir_node(v_inode);
            fresh_node = !dir_node;
            if (!dir_node) dir_node = __nomount_alloc_dir_node(v_inode);
            /* No dir_node means the child below can never be linked, and the
             * caller would free the rule this one replaces while the parent still
             * points at it -- so this is a hard failure, not a skip. */
            if (unlikely(!dir_node)) {
                err = -ENOMEM;
            } else {
                nomount_hijack_virtual_parent(dir_node, v_inode);
                nomount_hijack_dir_inode(dir_node, v_inode);
                /* The third hard failure of the three, and the one that used to
                 * be silent: our ->destroy_inode is installed here, and it is
                 * what frees an injected inode's nm_inode_info and the path and
                 * dir_node references it owns. Serving a rule on a superblock we
                 * could not hijack leaks that payload for every inode the rule
                 * ever mints, for the life of the boot. Refuse the add instead --
                 * the unwind below then neuters the node this call armed. */
                err = nomount_hijack_superblock(p_path.dentry->d_sb);
                if (likely(!err)) {

                    qname.name = child_name;
                    qname.len = child_len;
                    qname.hash = full_name_hash(p_path.dentry, child_name, child_len);
                    if (p_path.dentry->d_flags & DCACHE_OP_HASH)
                        p_path.dentry->d_op->d_hash(p_path.dentry, &qname);

                    dentry = d_lookup(p_path.dentry, &qname);
                    if (dentry) {
                        /* Same test, same reason, as the one in
                         * nm_drop_cached_vpath(): a re-add whose cached dentry
                         * already describes the incoming rule has nothing to
                         * invalidate, and unhashing it would only stamp
                         * " (deleted)" onto every mapping of the file. A
                         * synthesized ancestor (current_rule != target_rule) is not
                         * stamped with its final identity yet, so it never matches
                         * and is dropped exactly as before -- which costs nothing,
                         * since d_path() only reads d_unlinked() of the LEAF and a
                         * directory is never the leaf of a mapping. */
                        if (!nm_dentry_matches_rule(dentry, current_rule))
                            d_drop(dentry);
                        dput(dentry);
                    }
                    err = __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
                }
                /* Injection (or the superblock hijack above it) failing AFTER the
                 * inode hijack leaves a node this call created armed on a REAL
                 * inode with no children and a permanent igrab. The caller only
                 * unwinds pending_list, so nothing ever reaches this node again:
                 * the inode stays pinned for the life of the module and the vtable
                 * stays pointing at a dir_node no rule owns. Undo exactly what we
                 * armed -- but only when the node was ours AND is still empty,
                 * since an inherited node holds other rules' children. Same
                 * neuter-in-place the delete path uses. */
                if (unlikely(err) && fresh_node &&
                    idr_is_empty(&dir_node->children_idr)) {
                    nomount_restore_dir_node(dir_node);
                    nm_dir_node_put(dir_node);
                }
            }
            path_put(&p_path);
            
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        irule_size = sizeof(struct nomount_rule) + parent_len + 1 + 2; 
        irule = kzalloc(irule_size, GFP_KERNEL);
        if (!irule) {
            err = -ENOMEM;
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        irule->v_len = parent_len;
        irule->v_hash = h_parent;
        /* A directory synthesized on the way to a public rule is public too, or
         * the rule it leads to cannot be reached -- see nm_mark_public_up(). */
        irule->flags = NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR |
                       (target_rule->flags & NM_FLAG_PUBLIC);
        irule->v_ino = (unsigned long)h_parent;
        irule->target_uid = 0;
        irule->v_uid = GLOBAL_ROOT_UID;   /* defaults; overwritten below if a real ancestor was found */
        irule->v_gid = GLOBAL_ROOT_GID;
        irule->v_mode = 0755;

        memcpy(nm_get_vpath(irule), v_path, parent_len);
        nm_get_vpath(irule)[parent_len] = '\0';
        nm_get_rpath(irule)[0] = '\0';

        dir_node = __nomount_alloc_dir_node(NULL);
        if (unlikely(!dir_node)) { kfree(irule); err = -ENOMEM; if (i > 0) v_path[i] = orig_v_path; break; }
        dir_node->_tag_ptr = (unsigned long)irule | 1UL;
        irule->this_dir = dir_node;
        err = __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
        if (unlikely(err)) {
            /* irule is not on pending_list yet, so nothing else will free it. */
            nm_dir_node_put(dir_node);
            kfree(irule);
            if (i > 0) v_path[i] = orig_v_path;
            break;
        }
        hlist_add_head(&irule->vpath_node, &pending_list);
        current_rule = irule;
        if (i > 0) v_path[i] = orig_v_path;
        p_len = i; 
    }

    if (likely(err == 0)) {
        u64 prev_dino = anc_dino;

        hlist_for_each_entry_safe(irule, tmp, &pending_list, vpath_node) {
            hlist_del_init(&irule->vpath_node);
            if (have_anc) {   /* stamp the nearest real ancestor's owner/mode/times/context */
                irule->v_uid = anc_uid;
                irule->v_gid = anc_gid;
                irule->v_mode = anc_mode;
                irule->flags |= NM_FLAG_HAVE_TIMES;
                irule->v_atime = anc_atime;
                irule->v_mtime = anc_mtime;
                irule->v_ctime = anc_ctime;
                irule->v_ctx_len = anc_ctx_len;
                if (anc_ctx_len) memcpy(irule->v_ctx, anc_ctx, anc_ctx_len + 1);
                irule->v_cap = anc_cap;
                /* A raw name hash puts a synthesized dir billions away from its
                 * stock siblings (erofs dir inos are small); derive one in the
                 * nearest real ancestor's magnitude band instead. */
                if (!anc_dpop)      /* ancestor was an existing virtual rule */
                    anc_dpop = nm_real_ancestor_pop(nm_get_vpath(irule));
                if (anc_dpop && anc_dpop->n)
                    irule->v_ino = nm_place_ino(anc_dpop, (u64)irule->v_hash);
                else if (anc_ino)
                    irule->v_ino = (anc_ino & ~0xFFFFUL) | (irule->v_hash & 0xFFFF) | 1UL;
                /* Split stat's ino from readdir's when the tree is overlay-backed,
                 * and keep them equal when it is not. The list runs top-down, so
                 * prev_dino is this dir's parent. The parent's listing entry was
                 * created earlier in the walk, before v_ino was narrowed above --
                 * restamp it, or the entry and stat disagree on every synthesized
                 * dir (which is what shipped, and is itself a probe). */
                if (anc_ovl) {
                    irule->flags |= NM_FLAG_OVL_INO;
                    /* Band it like a lowerdir image ino (tens of millions on the
                     * OP15 erofs partitions) rather than handing out the raw
                     * 32-bit hash, which lands billions away from every real
                     * dirent -- the same magnitude argument as v_ino above. */
                    irule->v_dino = ((u64)irule->v_hash & 0x03FFFFFFULL) | 0x02000000ULL | 1ULL;
                } else {
                    irule->v_dino = (u64)irule->v_ino;
                }
                irule->v_pdino = prev_dino;
                prev_dino = irule->v_dino;
                if (irule->parent_dir)
                    nm_restamp_child_ino(irule->parent_dir, irule);
                /* Without this a synthesized dir reports st_blksize=1 (the
                 * generic_fillattr fallback) where every real dir reports the
                 * fs block size -- a one-stat divergence. */
                irule->v_blksize = anc_blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                /* Without these a synthesized dir answers statx with a mask and
                 * attribute set no stock dir on the partition produces (atime
                 * reported as valid, IMMUTABLE absent). */
                irule->v_result_mask = anc_result_mask;
                irule->v_attributes  = anc_attributes;
                irule->v_attr_mask   = anc_attr_mask;
#endif
            }
            hash_add_rcu(nomount_rules_ht, &irule->vpath_node, irule->v_hash);
        }
    } else {
        hlist_for_each_entry_safe(irule, tmp, &pending_list, vpath_node) {
            hlist_del_init(&irule->vpath_node);
            nm_free_rule(irule);
        }
    }

    return err;
}

static void nomount_prune_empty_virtual_dirs(struct nomount_dir_node *dir_node, struct hlist_head *victims)
{
    struct nomount_rule *owner;

    while (dir_node && idr_is_empty(&dir_node->children_idr)) {
        struct nomount_dir_node *parent;
        bool parent_virtual;

        owner = dir_node->_tag_ptr & 1UL ? (struct nomount_rule *)(dir_node->_tag_ptr & ~1UL) : NULL;
        /* Only prune a SYNTHESIZED ancestor (NM_FLAG_VIRTUAL_DIR), same test
         * nm_mark_public_up uses to decide "this dir exists only to hold
         * children". A user-added directory rule (backing path, IS_DIR but not
         * VIRTUAL_DIR) can also acquire a this_dir when a later rule turns out to
         * be its child; pruning on empty would silently delete that user rule and
         * keep climbing, and the netlink del returns 0 so userspace never learns
         * its rule is gone. Stop at the first non-synthesized owner. */
        if (!owner || !(owner->flags & NM_FLAG_VIRTUAL_DIR)) break;

        /* Capture the parent's kind BEFORE the delete: __nomount_delete_child_locked
         * can empty and free a REAL (tag 0) parent via call_rcu, so re-reading it
         * after would be a UAF. A VIRTUAL (tag 1) parent is freed only via its
         * owner's nm_free_rule, so it survives and is the only one safe to walk to. */
        parent = owner->parent_dir;
        parent_virtual = parent && (parent->_tag_ptr & 1UL);

        hash_del_rcu(&owner->vpath_node);
        if (parent) __nomount_delete_child_locked(parent, owner);
        nm_debug("Pruned empty virtual directory: %s\n", nm_get_vpath(owner));
        dir_node = parent_virtual ? parent : NULL;
        hlist_add_head(&owner->victim_node, victims);
    }
}

/*** Rule Operations ***/

/* ---- Pure-injection dev/ino/time mirroring --------------------------------
 * A pure injection (no stock file at its vpath) has nothing to mirror at its
 * own path, and every parent directory reports the overlay-TOP dev (OnePlus
 * /product = 0x1b/0x38) with a synthetic ino — an outlier vs stock *files*,
 * which carry a lowerdir dev + small ino + the ROM-build times. So we locate a
 * real sibling FILE (walk up to the nearest real ancestor, scan it, descend one
 * level when a level holds only dirs) and mirror its dev + times, deriving an
 * in-range ino. Read-only, privileged (nm_root_cred), bounded depth/fanout. */
/* The dev a STOCK file at this path reports in /proc/<pid>/maps.
 *
 * show_map_vma() prints <accessor>(vma->vm_file)'s i_sb->s_dev, and WHICH
 * accessor it uses changed upstream at 6.8:
 *
 *   < 6.8   file_inode(vma->vm_file)
 *           ovl_mmap() installs the REAL (lower) file on the vma and does not put
 *           it back, so a stock file on an overlay maps with the LOWER fs dev.
 *   >= 6.8  file_user_inode(vma->vm_file)
 *           which resolves a backing file back to the USER-visible inode, so a
 *           stock file maps with the OVERLAY dev instead.
 *
 * Both halves are measured, on two devices whose results looked contradictory
 * until the accessor explained them:
 *
 *   OP11 / 5.15 / /product/priv-app (overlay, 6-deep lowerdir)
 *       stock fe:22 and fe:28 -- the erofs dev of whichever layer holds each
 *       file, so not even one value for the directory -- while injected showed
 *       00:22, the anonymous overlay sb our synthetic inode lives on. 10 of ~4848
 *       /product mappings were 00:22 and every one was ours.
 *   OP15 / 6.12 / /product/overlay (overlay, 8-deep lowerdir)
 *       all 7748 mappings 00:1b, stock and injected alike. Nothing to fix, and
 *       taking the lower here would have CREATED the split it removes on 5.15.
 *
 * So there is no single right answer, and picking either one unconditionally is
 * wrong on half the fleet. Follow the accessor.
 */
static dev_t nm_stock_map_dev(struct dentry *dentry)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    return d_backing_inode(dentry)->i_sb->s_dev;
#else
    struct inode *real = d_real_inode(dentry);

    if (real)
        return real->i_sb->s_dev;
    return d_backing_inode(dentry)->i_sb->s_dev;
#endif
}

struct nm_sib_scan {
    struct dir_context ctx;
    dev_t dir_dev;                       /* this dir's overlay-top dev, to skip */
    char files[6][NAME_MAX + 1];
    char subdirs[4][NAME_MAX + 1];
    int n_files, n_subdirs;
};

static NM_ACTOR_RET nm_sib_actor(struct dir_context *ctx, const char *name,
                                 int namelen, loff_t off, u64 ino, unsigned int dt)
{
    struct nm_sib_scan *s = container_of(ctx, struct nm_sib_scan, ctx);

    if (namelen <= 0 || namelen > NAME_MAX || name[0] == '.')
        return NM_ACTOR_CONTINUE;
    if (dt == DT_REG && s->n_files < 6) {
        memcpy(s->files[s->n_files], name, namelen);
        s->files[s->n_files][namelen] = '\0';
        s->n_files++;
    } else if (dt == DT_DIR && s->n_subdirs < 4) {
        memcpy(s->subdirs[s->n_subdirs], name, namelen);
        s->subdirs[s->n_subdirs][namelen] = '\0';
        s->n_subdirs++;
    }
    return NM_ACTOR_CONTINUE;
}

/* Read what a REAL sibling directory reports for "..", so a synthesized dir one
 * level down can report the same thing. Its own ".." refers to the real parent,
 * and on overlayfs that dirent carries a lowerdir ino every stock sibling
 * shares: 67 of 68 dirs under /product/priv-app answered 179 or 455 while a
 * synthesized one answered a raw path hash, 3.2e9 -- an outlier a probe spots by
 * comparing siblings, no baseline needed. */
struct nm_dotdot_scan {
    struct dir_context ctx;
    u64 ino;
    char subdir[NAME_MAX + 1];
    int sublen;
};

static NM_ACTOR_RET nm_dotdot_actor(struct dir_context *ctx, const char *name, int namelen,
                                    loff_t off, u64 ino, unsigned int dt)
{
    struct nm_dotdot_scan *d = container_of(ctx, struct nm_dotdot_scan, ctx);

    if (namelen == 2 && name[0] == '.' && name[1] == '.') {
        d->ino = ino;
    } else if (!d->sublen && dt == DT_DIR && namelen > 0 && namelen <= NAME_MAX &&
               name[0] != '.') {
        memcpy(d->subdir, name, namelen);
        d->subdir[namelen] = '\0';
        d->sublen = namelen;
    }
    return NM_ACTOR_CONTINUE;
}

static int nm_iter_dotdot(const char *dirpath, struct nm_dotdot_scan *sc)
{
    struct path dp;
    struct file *dir;
    const struct cred *old;

    if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
        return -ENOENT;
    *((filldir_t *)&sc->ctx.actor) = nm_dotdot_actor;
    old = override_creds(nm_root_cred);
    dir = dentry_open(&dp, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);
    path_put(&dp);
    if (IS_ERR(dir)) { revert_creds(old); return -EACCES; }
    iterate_dir(dir, &sc->ctx);
    fput(dir);
    revert_creds(old);
    return 0;
}

/* The ".." a child of dirpath would report: scan dirpath for a real subdir,
 * then read that subdir's own "..". */
static u64 nm_child_dotdot_of(const char *dirpath)
{
    struct nm_dotdot_scan *a, *b;
    char *cp;
    u64 out = 0;

    a = kzalloc(sizeof(*a), GFP_KERNEL);
    if (!a) return 0;
    if (nm_iter_dotdot(dirpath, a) != 0 || !a->sublen) { kfree(a); return 0; }
    cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, a->subdir);
    kfree(a);
    if (!cp) return 0;
    b = kzalloc(sizeof(*b), GFP_KERNEL);
    if (b) {
        if (nm_iter_dotdot(cp, b) == 0) out = b->ino;
        kfree(b);
    }
    kfree(cp);
    return out;
}

static int nm_scan_dir_for_file(const char *dirpath, struct kstat *out,
                                char *octx, u16 *octxlen, dev_t *omapdev, u8 *ocap, int depth)
{
    struct nm_sib_scan *sc;
    struct path dp;
    struct kstat dkst;
    struct file *dir;
    const struct cred *old;
    bool dir_is_overlay = false;
    int i, pass, ret = -ENOENT;

    if (depth > 2)
        return -ENOENT;
    if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
        return -ENOENT;

    sc = kzalloc(sizeof(*sc), GFP_KERNEL);
    if (!sc) { path_put(&dp); return -ENOMEM; }
    /* "dev differs from the directory" identifies the LOWER-LAYER file on an
     * overlay mount -- but a BIND MOUNT looks identical, and mirroring one
     * imports its foreign dev/mtime. Seen live: a bound LSPosed dex2oat in
     * /apex/com.android.art/bin was picked as the sibling for a new injection,
     * giving it /data's dev and the module file's mtime. So only prefer a
     * differing dev where the directory really is overlayfs. */
#ifdef OVERLAYFS_SUPER_MAGIC
    dir_is_overlay = dp.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#endif
    /* dir_context.actor is const; heap alloc can't use a designated initializer,
     * so assign through a cast (matches how the VFS treats it internally). */
    *((filldir_t *)&sc->ctx.actor) = nm_sib_actor;
    if (nm_path_stat(&dp, &dkst) == 0)
        sc->dir_dev = dkst.dev;

    old = override_creds(nm_root_cred);
    dir = dentry_open(&dp, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);
    path_put(&dp);
    if (!IS_ERR(dir)) {
        iterate_dir(dir, &sc->ctx);
        fput(dir);
    }
    revert_creds(old);

    /* Two passes. Pass 0 prefers a file whose dev differs from the directory's:
     * on an overlay-backed partition that is the lower-layer file, and using it
     * avoids mirroring the overlay-TOP dev. Pass 1 accepts ANY real file.
     *
     * Pass 1 is what makes this work off overlay. On a plain erofs/ext4 mount a
     * file and its parent share a dev, so the dev != test rejected every
     * candidate, the scan walked to / and failed, and the caller fell back to a
     * RAW NAME HASH for the inode -- an injected file on /vendor reported ino
     * 2.7e9 next to stock siblings at 1.1e6. */
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < sc->n_files; i++) {
            char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->files[i]);
            struct path fp;
            struct kstat fk;

            if (!cp) continue;
            if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
                int r = nm_path_stat(&fp, &fk);
                char fctx[NM_CTX_MAX];
                u16 fctxlen = 0;
                dev_t fmapdev = 0;
                u8 fcap = 0;

                /* Read the label and the lower dev BEFORE dropping the
                 * reference; a pure injection has no stock file of its own to
                 * copy either from. */
                if (r == 0) {
                    if (nm_read_secctx(d_backing_inode(fp.dentry), fctx, &fctxlen) != 0)
                        fctxlen = 0;
                    /* Through the mount, not past it -- same reasoning as the
                     * shadowing path below: a stock file on an overlay-backed
                     * dir MAPS with the overlay's own dev (00:1b measured on
                     * /product/overlay), while d_real_inode() answers with the
                     * erofs lower (fe:19). Fixing only the other assignment left
                     * every PURE injection -- which is what reaches this sibling
                     * scan -- still announcing the lower dev in /proc/<pid>/maps. */
                    fmapdev = nm_stock_map_dev(fp.dentry);
                    fcap = nm_stock_caps(d_backing_inode(fp.dentry));
                }
                path_put(&fp);
                if (r == 0 && (pass == 1 ||
                               (dir_is_overlay ? fk.dev != sc->dir_dev
                                               : fk.dev == sc->dir_dev))) {
                    *out = fk;
                    if (octx && octxlen) {
                        *octxlen = fctxlen;
                        if (fctxlen) memcpy(octx, fctx, fctxlen + 1);
                    }
                    if (omapdev) *omapdev = fmapdev;
                    if (ocap) *ocap = fcap;
                    kfree(cp); ret = 0; goto done;
                }
            }
            kfree(cp);
        }
    }
    /* else descend into a real subdir (bounded) */
    for (i = 0; i < sc->n_subdirs; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->subdirs[i]);

        if (!cp) continue;
        if (nm_scan_dir_for_file(cp, out, octx, octxlen, omapdev, ocap, depth + 1) == 0) { kfree(cp); ret = 0; goto done; }
        kfree(cp);
    }
done:
    kfree(sc);
    return ret;
}

/* One-entry cache: pure injections in the same directory (e.g. the ~139
 * /product/overlay APKs, or the 25 Mms libs) share a sibling, so we avoid
 * re-scanning. Rule-add is serialized under nomount_write_mutex, so the static
 * state needs no extra locking; a stale hit at worst yields another valid file
 * dev on the same partition. */
static char nm_sib_cache_dir[PATH_MAX];
static struct kstat nm_sib_cache_kst;
static char nm_sib_cache_ctx[NM_CTX_MAX];
static u16 nm_sib_cache_ctxlen;
static dev_t nm_sib_cache_mapdev;
static u8 nm_sib_cache_cap;
static bool nm_sib_cache_valid;

static int nm_find_sibling_meta(const char *vpath, struct kstat *out,
                                char *octx, u16 *octxlen, dev_t *omapdev, u8 *ocap)
{
    char *path = kstrdup(vpath, GFP_KERNEL);
    char *slash;
    int ret = -ENOENT;

    if (!path)
        return -ENOENT;
    slash = strrchr(path, '/');
    if (slash && slash != path)
        *slash = '\0';                   /* path = immediate parent dir */

    if (nm_sib_cache_valid && strcmp(nm_sib_cache_dir, path) == 0) {
        *out = nm_sib_cache_kst;
        if (octx && octxlen) {
            *octxlen = nm_sib_cache_ctxlen;
            if (nm_sib_cache_ctxlen) memcpy(octx, nm_sib_cache_ctx, nm_sib_cache_ctxlen + 1);
        }
        if (omapdev) *omapdev = nm_sib_cache_mapdev;
        if (ocap) *ocap = nm_sib_cache_cap;
        kfree(path);
        return 0;
    }

    for (;;) {
        if (nm_scan_dir_for_file(path, out, octx, octxlen, omapdev, ocap, 0) == 0) { ret = 0; break; }
        slash = strrchr(path, '/');
        if (!slash || slash == path)
            break;
        *slash = '\0';                   /* ascend */
    }
    if (ret == 0) {                      /* cache keyed on vpath's immediate parent */
        const char *vslash = strrchr(vpath, '/');

        /* Derive the key BEFORE touching the cache. The old order wrote the full
         * vpath into nm_sib_cache_dir first and only then checked whether it
         * could be truncated to a parent -- so for a vpath one level below root
         * ("/foo") there was nothing to truncate, the key was left as the whole
         * path, and nm_sib_cache_valid still described the PREVIOUS directory's
         * payload. Any later lookup whose parent happened to spell that same
         * string then got another directory's ino/dev/ctx/cap: mirrored metadata
         * from the wrong partition, which is worse than no mirroring at all. */
        if (vslash && vslash != vpath && (size_t)(vslash - vpath) < PATH_MAX) {
            size_t plen = vslash - vpath;

            memcpy(nm_sib_cache_dir, vpath, plen);
            nm_sib_cache_dir[plen] = '\0';
            nm_sib_cache_kst = *out;
            nm_sib_cache_ctxlen = (octx && octxlen) ? *octxlen : 0;
            if (nm_sib_cache_ctxlen) memcpy(nm_sib_cache_ctx, octx, nm_sib_cache_ctxlen + 1);
            nm_sib_cache_mapdev = omapdev ? *omapdev : 0;
            nm_sib_cache_cap = ocap ? *ocap : 0;
            nm_sib_cache_valid = true;
        }
    }
    kfree(path);
    return ret;
}

/* Does this path contain a run of two or more '/'? */
static bool nm_vpath_has_slash_run(const char *p, size_t len)
{
    size_t i;

    for (i = 1; i < len; i++)
        if (p[i] == '/' && p[i - 1] == '/')
            return true;
    return false;
}

/* Collapse runs of '/' out of a client-supplied virtual path while copying it.
 *
 * A rule is KEYED on the vpath bytes -- hash, length and memcmp -- but every
 * consumer of the same string splits it on '/' and skips the empty components a
 * doubled slash produces. So "/system/etc//zz" and "/system/etc/zz" are two
 * different keys naming one file, and the pair walks straight past both dedup
 * loops in __nomount_add_rule(): the second add reaches the REPLACEMENT branch
 * of __nomount_inject_child_locked() instead, which keys on parent + name, and
 * re-points that child at the incoming rule with no victim recorded. The
 * outgoing rule stays in the table, reachable by `nm del`, still naming a
 * dir_node that no longer links to it -- and deleting the rule that DID keep the
 * child can empty and call_rcu-free that node underneath it.
 *
 * Normalising at rule creation makes the two spellings one key, so the dedup
 * fires and a replacement becomes a proper victim again. (The dangling
 * back-pointer is fixed on its own terms in __nomount_inject_child_locked();
 * this closes the only way found to reach it.)
 *
 * Writes at most @len bytes plus a NUL to @dst and returns the collapsed length,
 * which is never longer than @len. A trailing '/' is trimmed by the caller
 * before this runs. '.' and '..' components are deliberately NOT resolved:
 * doing that lexically is wrong wherever a symlink is involved, and no caller
 * produces them -- both the bundled client and the Suite send resolved paths. */
static size_t nm_norm_vpath(char *dst, const char *src, size_t len)
{
    size_t i, o = 0;

    for (i = 0; i < len; i++) {
        if (src[i] == '/' && o > 0 && dst[o - 1] == '/')
            continue;
        dst[o++] = src[i];
    }
    dst[o] = '\0';
    return o;
}

static struct nomount_rule *nm_alloc_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid)
{
    struct nomount_rule *rule;
    bool is_whiteout = (flags & NM_FLAG_WHITEOUT);
    struct path v_path_struct;

    /* Must be absolute. A vpath with no '/' makes the parent scan in
     * nomount_generate_virtual_topology() run off the front of the buffer:
     * i ends at -1, parent_len becomes -1, and full_name_hash() is handed it as
     * a size_t -- a ~4GB read. The bundled client always sends absolute paths,
     * so nothing validated it. */
    if (!v_path || v_len == 0 || v_path[0] != '/') return ERR_PTR(-EINVAL);
    if (!r_path && !is_whiteout) return ERR_PTR(-EINVAL);
    while (v_len > 1 && v_path[v_len - 1] == '/') { v_len--; }
    if (!is_whiteout) { while (r_len > 1 && r_path[r_len - 1] == '/') { r_len--; } }

    if (is_whiteout) r_len = 0;
    /* Sized on the CALLER's v_len: nm_norm_vpath() can only shrink the vpath, so
     * the rpath still fits at the (lower) offset the collapsed length puts it at
     * -- at worst a couple of bytes go unused. */
    rule = kzalloc((sizeof(struct nomount_rule) + v_len + 1 + r_len + 1), GFP_KERNEL);
    if (!rule) return ERR_PTR(-ENOMEM);

    INIT_HLIST_NODE(&rule->vpath_node);
    rule->flags = flags & NM_FLAGS_USER_MASK;
    rule->target_uid = target_uid;
    /* v_len is set from the NORMALISED copy and before anything reaches for the
     * rpath, which nm_get_rpath() offsets by it. Hash the stored bytes too, or
     * the two spellings would still be two keys. */
    rule->v_len = (u16)nm_norm_vpath(nm_get_vpath(rule), v_path, v_len);
    rule->v_hash = full_name_hash(NULL, nm_get_vpath(rule), rule->v_len);

    if (is_whiteout) {
        nm_get_rpath(rule)[0] = '\0';
    } else {
        memcpy(nm_get_rpath(rule), r_path, r_len);
        nm_get_rpath(rule)[r_len] = '\0';
    }

    /* LOOKUP_FOLLOW: a module symlink is injected as a copy of its target, not as
     * a symlink -- readlink() fails and a dangling link instantiates nothing.
     * Deliberate: switching to no-follow also changes how symlink-to-directory is
     * classified (NM_FLAG_IS_DIR below), which is load-bearing for RRO overlay
     * dirs. No installed module currently ships a content symlink. */
    if (!is_whiteout) {
        /* An unresolvable backing path used to leave r_path NULL and the rule
         * live: readdir emitted the child, lookup could not build an inode, so
         * the entry listed but ENOENTed on stat. No real read-only fs produces
         * a dirent that cannot be stat'd, which makes it a one-syscall-pair
         * probe -- and a module shipping a broken symlink (LOOKUP_FOLLOW is
         * what makes a dangling one unresolvable) was enough to create it.
         * Reject at add time instead. */
        if (kern_path(nm_get_rpath(rule), LOOKUP_FOLLOW, &rule->r_path) != 0) {
            kfree(rule);
            return ERR_PTR(-ENOENT);
        }
        if (S_ISDIR(d_backing_inode(rule->r_path.dentry)->i_mode))
            rule->flags |= NM_FLAG_IS_DIR;
    }

    if (kern_path(nm_get_vpath(rule), LOOKUP_FOLLOW, &v_path_struct) == 0) {
        struct kstat kst;
        /* The name is already there, so serving it does not change the parent's
         * entry count -- see NM_FLAG_SHADOWS_STOCK. */
        rule->flags |= NM_FLAG_SHADOWS_STOCK;
        /* Classify a WHITEOUT from the path it hides. IS_DIR is normally taken
         * from the backing path above, but a whiteout has none -- so a hidden
         * directory was typed DT_REG and nm_dir_deltas skipped it: the
         * parent's size shrank correctly while its link count kept counting the
         * subdirectory. Measured 9 links against 2+8 subdirs. The vpath is
         * already resolved here, so this costs nothing. */
        if ((rule->flags & NM_FLAG_WHITEOUT) &&
            S_ISDIR(d_backing_inode(v_path_struct.dentry)->i_mode))
            rule->flags |= NM_FLAG_IS_DIR;
        /* Mirror both the dev AND ino a *stock* file at this path reports (what
         * a detector's stat()/maps sees) rather than the raw backing values.
         * On overlay-mounted partitions the raw i_sb->s_dev is the overlay-top
         * dev and the raw i_ino skips overlay xino remapping, so injected
         * inodes become dev/ino outliers vs their stock siblings. */
        /* Capture the context of the file being SHADOWED. Everything else here
         * mirrors the stock file; the context did not, and was taken from the
         * backing file instead -- which ksud labels system_file. That matches
         * stock on /system and /product by luck and is wrong everywhere else:
         * a config injected into /vendor reported system_file among
         * vendor_configs_file siblings (one getxattr to spot), and with
         * S_PRIVATE gone SELinux now enforces that label, so a vendor domain
         * allowed the stock file can be denied the injected one. */
        if (nm_read_secctx(d_backing_inode(v_path_struct.dentry),
                           rule->v_ctx, &rule->v_ctx_len) != 0)
            rule->v_ctx_len = 0;
        /* On overlayfs a mapping is of the LOWER file, so show_map_vma prints
         * the lower sb's dev while stat reports the overlay's. Spoofing maps to
         * the stat dev made the two agree -- which no stock file on an overlay
         * mount does: 139/139 injected agreed where 15/15 stock differed, an
         * mmap+statx pair apart. d_real_inode() resolves to the lower inode on
         * overlayfs and to the inode itself everywhere else. */
        /* The dev a stock file at this path reports IN MAPS -- taken through the
         * mount, not resolved past it. d_real_inode() steps through overlayfs to
         * the lower layer, which is right for the dev/ino a stock file *stats*
         * as, but wrong for the mapping: measured on /product/overlay, every
         * stock file maps with 00:1b (the overlay mount's own dev, 0:27) while
         * every injected one mapped with fe:19 (the erofs lower). One grep of
         * /proc/self/maps separated the two populations completely. On a plain
         * erofs path the two calls agree, which is why /system, /my_product,
         * /my_stock and /product/etc already matched. */
        rule->v_mapdev = nm_stock_map_dev(v_path_struct.dentry);
        if (nm_path_stat(&v_path_struct, &kst) == 0) {
            rule->v_ino = kst.ino;
            rule->v_dev = kst.dev;
            rule->flags |= NM_FLAG_HAVE_TIMES;
            rule->v_atime = kst.atime;   /* mirror the stock file's times too */
            rule->v_mtime = kst.mtime;
            rule->v_ctime = kst.ctime;
            rule->v_blksize = kst.blksize;
            rule->v_cratio = nm_size_ratio(kst.size, kst.blocks);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_result_mask = kst.result_mask;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_attributes = kst.attributes;   /* STATX_ATTR_* only exist >= 4.11 */
            rule->v_attr_mask = kst.attributes_mask;
#endif
            /* ONLY when this dentry is really the stock file. On a REPLACEMENT
             * (the reload delta re-adds a live vpath without a clear) the
             * kern_path above resolves THROUGH our own injection, so the inode
             * here is ours -- and nm_file_fops always has .fsync, so v_cap would
             * come back with NM_CAP_FSYNC set and nm_fsync would go back to
             * forwarding to the f2fs backing file: 0 where all 24 erofs siblings
             * answer -EINVAL. The oracle would reopen on the second reload and
             * stay open until reboot. Same trap s_path guards against three
             * blocks below, and the same reason __nomount_add_rule inherits
             * SHADOWS_STOCK from the victim rather than re-deriving it. */
            {
                struct inode *ci = d_backing_inode(v_path_struct.dentry);

                if (ci && ci->i_op != &nm_file_iops && ci->i_op != &nm_dir_iops) {
                    rule->v_cap = nm_stock_caps(ci);
                    if (nm_stock_takes_odirect(&v_path_struct))
                        rule->v_cap |= NM_CAP_ODIRECT;
                }
            }
        } else {
            rule->v_ino = d_backing_inode(v_path_struct.dentry)->i_ino;
            rule->v_dev = d_backing_inode(v_path_struct.dentry)->i_sb->s_dev;
        }
        /* Keep it. A hidden reader is entitled to the file this rule shadows, and
         * pinning it here is what lets nm_open()/getattr serve that reader from
         * the ops instead of invalidating the shared dentry -- which is what used
         * to mark every other process's mapping of this path "(deleted)".
         * Guarded against pinning one of OUR OWN inodes: re-adding a rule over a
         * live injection resolves the vpath to the virtual inode, and treating
         * that as "stock" would serve the injection to the very reader it must be
         * hidden from. */
        {
            struct inode *si = d_backing_inode(v_path_struct.dentry);
            if (si && si->i_op != &nm_file_iops && si->i_op != &nm_dir_iops)
                rule->s_path = v_path_struct;          /* takes the ref */
            else
                path_put(&v_path_struct);
        }
    } else {
        /* Pure injection (no stock file): mirror a real sibling FILE's dev +
         * times, and derive an ino in the sibling's magnitude band. Mirroring
         * the parent *directory* would leak the overlay-top dev, so we hunt for
         * a real file instead (see nm_find_sibling_meta). */
        struct kstat sib;

        if (nm_find_sibling_meta(nm_get_vpath(rule), &sib,
                                 rule->v_ctx, &rule->v_ctx_len, &rule->v_mapdev,
                                 &rule->v_cap) == 0) {
            rule->v_dev   = sib.dev;
            rule->flags |= NM_FLAG_HAVE_TIMES;
            rule->v_atime = sib.atime;
            rule->v_mtime = sib.mtime;
            rule->v_ctime = sib.ctime;
            rule->v_blksize    = sib.blksize;
            rule->v_cratio     = nm_size_ratio(sib.size, sib.blocks);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_result_mask = sib.result_mask;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_attributes = sib.attributes;
            rule->v_attr_mask  = sib.attributes_mask;
#endif
            /* Derive from the BACKING file's inode: unique per file and, unlike
             * a global counter, STABLE across boots. A counter depends on module
             * scan order, so every injected file's ino would shift on reboot
             * while stock inodes never move -- a divergence in its own right and
             * breaks anything keying a cache on (dev,ino). A path hash alone is
             * stable but collides. Magnitude is not the tell it looks like: a
             * clean /system on this device spans ino 334..24.5M, so the band here
             * sits well inside what real filesystems produce.
             *
             * ...but magnitude was never the whole tell. Adding the backing ino
             * LINEARLY also inherited its ORDER: a module's files are written to
             * /data together, so their inodes are consecutive, and the derived
             * ones came out consecutive too. Measured on /product/overlay: 139
             * injected files occupied 139 consecutive values (span 138 -- every
             * integer used), while the 78 stock entries in the same directory
             * formed 25 ragged clusters spread over 3..83M, because an overlay
             * dir merges several erofs layers. One readdir plus one stat finds a
             * perfectly dense run whose length is exactly the module's file
             * count, and it needs no baseline at all.
             *
             * So mix instead of add. hash_64 destroys the input's ordering while
             * staying a pure function of it, which keeps every property the
             * paragraph above depends on: same file -> same ino across boots, no
             * dependence on scan order. The vpath hash is folded in so two module
             * files that happen to share a backing inode (a hardlinked payload)
             * still separate.
             *
             * Collisions: 20 bits = ~1M slots per band, and a band is per stock
             * sibling, so the population that can collide is one directory's
             * injections. At 139 files that is ~1% for a single pair -- against a
             * clustering tell that was 100% reliable. */
            /* r_path is unset for a whiteout, and for a backing path that did not
             * resolve (e.g. a dangling module symlink) -- both reach here when the
             * vpath does not exist either, so this MUST NOT deref it blindly. */
            {
                u64 uniq = rule->r_path.dentry
                         ? (u64)d_backing_inode(rule->r_path.dentry)->i_ino
                         : (u64)rule->v_hash;
                u64 spread = hash_64(uniq ^ ((u64)rule->v_hash << 32), 32);
                char *vp = nm_get_vpath(rule);
                char *slash = strrchr(vp, '/');
                struct nm_ino_pop *pop;

                rule->v_ino = (unsigned long)((sib.ino & ~0xFFFFFULL) + 0x100000ULL +
                                              (spread & 0xFFFFFULL));
                if (slash && slash != vp) {
                    char *parent = kstrndup(vp, slash - vp, GFP_KERNEL);

                    if (parent) {
                        pop = nm_dir_ino_pop_cached(parent,
                                                    !!(rule->flags & NM_FLAG_IS_DIR));
                        if (pop)
                            rule->v_ino = nm_place_ino(pop, spread);
                        kfree(parent);
                    }
                }
            }
        } else {
            /* last resort: previous parent-dir dev fallback */
            char *vp = nm_get_vpath(rule);
            char *slash = strrchr(vp, '/');

            /* Masked, never the raw hash. full_name_hash() is a full-width u32,
             * so an unmasked value lands in the billions while the inodes around
             * it are 2-8 digits: an adreno driver injected into a synthesized
             * /vendor/gpu/kbc reported ino 1.4e9-3.2e9 where nothing under
             * /vendor exceeds 1.4e7 (3308 files sampled). One stat, no baseline.
             * Refined below into the parent's band once its ino is known. */
            rule->v_ino = (unsigned long)((u64)rule->v_hash & 0xFFFFFULL) | 1UL;
            rule->v_dev = 0;
            if (slash && slash != vp) {
                char *parent = kstrndup(vp, slash - vp, GFP_KERNEL);

                if (parent) {
                    if (kern_path(parent, LOOKUP_FOLLOW, &v_path_struct) == 0) {
                        struct kstat kst;

                        if (nm_path_stat(&v_path_struct, &kst) == 0) {
                            struct nm_ino_pop *pop;

                            rule->v_dev = kst.dev;
                            /* Land among the parent's real entries. Falls back
                             * to the old magnitude band when the parent has
                             * nothing of our kind to measure -- a synthesized
                             * parent is itself anchored to a real ancestor, so
                             * that stays inside the partition's inode range even
                             * when every directory above us is virtual. */
                            pop = nm_dir_ino_pop_cached(parent,
                                                        !!(rule->flags & NM_FLAG_IS_DIR));
                            if (pop)
                                rule->v_ino = nm_place_ino(pop, (u64)rule->v_hash);
                            else
                                rule->v_ino = (unsigned long)((kst.ino & ~0xFFFFFULL) + 0x100000ULL +
                                                              ((u64)rule->v_hash & 0xFFFFFULL));
                            /* Mirror the parent dir's times too: leaving these 0
                             * makes getattr fall through to the backing file's
                             * (module-install) mtime -- a fresh-timestamp tell. */
                            rule->flags |= NM_FLAG_HAVE_TIMES;
                            rule->v_atime = kst.atime;
                            rule->v_mtime = kst.mtime;
                            rule->v_ctime = kst.ctime;
                        }
                        path_put(&v_path_struct);
                    }
                    kfree(parent);
                }
            }
        }
    }

    return rule;
}
static void nm_free_rule(struct nomount_rule *rule)
{
    if (unlikely(!rule)) return;
    if (rule->r_path.dentry) path_put(&rule->r_path);
    if (rule->s_path.dentry) path_put(&rule->s_path);
    /* Defer the dir_node (and its remaining children) to an RCU grace period:
     * lockless readers can still be walking children_idr. The plain kfree of the
     * children here previously raced kfree_rcu'd siblings; the callback frees them
     * post-grace instead. */
    nm_dir_node_put(rule->this_dir);
    kfree(rule);
}

static void nm_detach_rule_locked(struct nomount_rule *rule, struct hlist_head *victims, bool prune)
{
    hash_del_rcu(&rule->vpath_node);
    if (rule->parent_dir) {
        struct nomount_dir_node *p_dir = rule->parent_dir;
        /* __nomount_delete_child_locked can drop the last ref on a REAL parent
         * (call_rcu free), so pin p_dir across it before prune walks it. */
        bool pinned = atomic_inc_not_zero(&p_dir->refcount);

        __nomount_delete_child_locked(p_dir, rule);
        if (prune && pinned) nomount_prune_empty_virtual_dirs(p_dir, victims);
        if (pinned) nm_dir_node_put(p_dir);
    }
    hlist_add_head(&rule->victim_node, victims);
}

/*
 * A target with fewer than two path components is a partition root (/system,
 * /vendor, /product) or the filesystem root itself. Serving one redirects an
 * ENTIRE partition at a single backing file: every exec under it then fails
 * ENOTDIR. That is not a boot-time hazard, it is immediate -- and it takes adb
 * with it, because adbd spawns /system/bin/sh, so the only recovery is a
 * physical reboot.
 *
 * mount.rs::is_partition_root() already refuses these when the Suite builds a
 * plan, but `nm` ships inside the module and speaks to this interface directly:
 * a module script, a WebUI action or a root shell reaches the engine without
 * passing through that check. The guard has to live on this side too.
 *
 * Measured 2026-08-22 on an OP11 (5.15): `nm add /system <file>` made the
 * running system unusable in one command, and `adb reboot` could not recover it
 * because that also needs a shell. The same class bootlooped an OP15 earlier
 * through `nm add /product`, which masked the stock overlays and took zygote
 * down at forkSystemServer.
 *
 * Counts components rather than slashes so "//system", "/system/" and
 * "/system//" all answer the same.
 */
static bool nm_target_too_shallow(const char *p, u16 len)
{
    int comps = 0;
    u16 i = 0;

    while (i < len) {
        while (i < len && p[i] == '/')
            i++;
        if (i >= len)
            break;
        if (++comps >= 2)
            return false;
        while (i < len && p[i] != '/')
            i++;
    }
    return true;
}

/* Is this rule's target inside a directory the PackageManager scans -- a path
 * PM parses and advertises to every app (see NM_FLAG_PUBLIC)?
 *
 * The layout is <partition>/<scan-dir>/..., so the scan dir is the SECOND path
 * component. Mirrors pmcache::PM_SCAN_DIRS in userspace, which is the source of
 * truth for which rules get --public; the kernel keeps the same test only to
 * decide whether a SHADOWS_STOCK rule may KEEP the bit at the strip below, so a
 * mislabelling client cannot leak a replaced file PM never advertised. This
 * covers a package's whole codePath -- Contacts.apk AND the shared libraries in
 * its lib/<abi> dir -- not just the .apk, because PM publishes nativeLibraryDir;
 * a blocked reader that got ENOENT on a lib PM said exists is the same tell a
 * blocked reader of the stock .apk bytes is. Case-sensitive, like PM's scan. */
static bool nm_vpath_in_pm_scandir(const struct nomount_rule *rule)
{
    /* Both lists mirror pmcache.rs (ROM_ROOTS / PM_SCAN_DIRS). Userspace is the
     * source of truth for which rules get --public; the kernel repeats the test
     * only so a mislabelling client cannot keep the bit on a shadowing rule PM
     * never advertised, so it must be at least as strict as userspace. */
    static const char *const roots[] = {
        "system", "system_ext", "product", "vendor", "odm", "my_product",
        "my_region", "my_stock", "my_company", "my_carrier", "my_engineering",
        "my_heytap", "my_preload",
    };
    static const char *const dirs[] = {
        "app", "priv-app", "overlay", "app-ext", "priv-app-ext",
    };
    const char *v = nm_get_vpath(rule);
    u16 len = rule->v_len, i, start = 0, seg = 0;
    unsigned int d;

    for (i = 0; i <= len; i++) {
        if (i != len && v[i] != '/')
            continue;
        if (i > start) {                    /* a non-empty path segment ended */
            u16 seglen = i - start;
            const char *const *tab;
            unsigned int n;

            seg++;
            if (seg == 1) {                 /* <partition> */
                tab = roots; n = ARRAY_SIZE(roots);
            } else if (seg == 2) {          /* <scan-dir> */
                tab = dirs;  n = ARRAY_SIZE(dirs);
            } else {
                return false;               /* unreachable; both slots matched */
            }
            for (d = 0; d < n; d++)
                if (strlen(tab[d]) == seglen &&
                    memcmp(v + start, tab[d], seglen) == 0)
                    break;
            if (d == n)
                return false;               /* this slot did not match */
            if (seg == 2)
                return true;                /* partition AND scan dir matched */
        }
        start = i + 1;
    }
    return false;
}

/* `victims`, when non-NULL, collects rules this add REPLACED instead of freeing
 * them inline. A replacement must outlive one RCU grace period before it can be
 * freed, and paying that per rule cost the batch form N grace periods: a reload
 * re-adds over every live rule (260 on the measured device), inside the boot
 * injection pass whose watchdog budget is already tight. The DEL batch has always
 * collected and paid once; this lets ADD do the same. A NULL list keeps the old
 * inline behaviour for the single-rule callers. */
static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid,
                              struct hlist_head *victims)
{
    struct nomount_rule *rule, *existing, *victim = NULL;
    int err = 0;

    if (unlikely(nm_target_too_shallow(v_path, v_len))) {
        nm_warn("refusing rule on '%.*s': fewer than two path components would mask a whole partition\n",
                (int)v_len, v_path);
        return -EINVAL;
    }

    mutex_lock(&nomount_write_mutex);

    /* nm_alloc_rule() reads/writes the static sibling-metadata cache, which is
     * only safe under nomount_write_mutex; allocate inside the lock. */
    rule = nm_alloc_rule(v_path, r_path, v_len, r_len, flags, target_uid);
    if (IS_ERR(rule)) {
        mutex_unlock(&nomount_write_mutex);
        return PTR_ERR(rule);
    }

    /* Rules are keyed on (vpath, target_uid), but a parent's child nodes are keyed
     * on NAME ALONE -- one node per name, whose ->rule the inject path overwrites.
     * So a second rule on the same vpath with a DIFFERENT target_uid does not dedup
     * here, then silently steals the child node from the first: the earlier rule
     * stays in the table and is still listed, but nothing can ever reach it, and
     * deleting it finds no child to remove and reports success. Refuse the
     * collision rather than build a topology that cannot represent it. */
    /* rule->v_len, not the caller's: nm_alloc_rule() trims a trailing '/' and
     * collapses '/' runs, so comparing on the raw length would let two spellings
     * of one path past the dedup. See nm_norm_vpath(). */
    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == rule->v_len &&
            existing->target_uid != target_uid &&
            memcmp(nm_get_vpath(existing), nm_get_vpath(rule), rule->v_len) == 0) {
            nm_warn("refusing rule on '%.*s' for uid %u: uid %u already owns this path\n",
                    (int)rule->v_len, nm_get_vpath(rule), target_uid, existing->target_uid);
            mutex_unlock(&nomount_write_mutex);
            nm_free_rule(rule);
            return -EEXIST;
        }
    }

    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == rule->v_len &&
             existing->target_uid == target_uid &&
             memcmp(nm_get_vpath(existing), nm_get_vpath(rule), rule->v_len) == 0) {
            /* Refuse to shadow a rule that still owns a populated virtual
             * subtree: freeing its dir_node (nm_free_rule -> call_rcu) would
             * leave descendant rules' parent_dir dangling and UAF on a later
             * del. The caller must remove the children first. Leaf/file rules
             * (this_dir NULL or empty) are safe to shadow. */
            if (existing->this_dir &&
                !idr_is_empty(&existing->this_dir->children_idr)) {
                mutex_unlock(&nomount_write_mutex);
                nm_free_rule(rule);
                return -EBUSY;
            }
            /* Inherit "a STOCK entry underlies this name" from the rule being
             * replaced; do NOT keep what nm_alloc_rule just measured.
             *
             * NM_FLAG_SHADOWS_STOCK is set there from kern_path(vpath), and by
             * the time a REPLACEMENT is added that path already resolves --
             * through the outgoing rule's own injection. So every replacement
             * concluded it was shadowing stock, and nm_dir_deltas() then declined
             * to count it: measured on OP15, adding a dir rule took the parent
             * from nlink 2 to 3, and re-adding the same vpath dropped it back to
             * 2 while the entry was still a descendable directory. Since d_type
             * is identical across a dir->dir replacement, that is provably this
             * flag and not the child-node refresh below it.
             *
             * The outgoing rule resolved the vpath BEFORE any of ours served it,
             * so its answer is the one about the real filesystem. Carry it over:
             * replacing a pure injection stays an addition (+1 link, +dirent
             * bytes), and replacing a rule that really did shadow a stock file
             * stays neutral -- which is what stops the count double-moving. */
            rule->flags = (rule->flags & ~NM_FLAG_SHADOWS_STOCK) |
                          (existing->flags & NM_FLAG_SHADOWS_STOCK);
            /* Same reason, same source: the outgoing rule sampled v_cap when the
             * vpath still resolved to the REAL stock file. A replacement cannot
             * re-derive it (kern_path now lands on our own inode), so nm_alloc_rule
             * deliberately leaves it 0 in that case -- carry the measured one over
             * rather than losing the fsync/O_DIRECT mirror on every reload. */
            if (!rule->v_cap)
                rule->v_cap = existing->v_cap;
            hash_del_rcu(&existing->vpath_node);
            victim = existing;
            nm_debug("Shadowing existing rule for: %s\n", nm_get_vpath(rule));
            break;
        }
    }

    /* PUBLIC excuses a name from hiding. On a rule that shadows a stock file the
     * blocked reader is served the stock bytes from the ops (nm_stock_for_caller),
     * and for an ordinary file that is consistent on its own; honouring the bit
     * there would hand it the module's copy instead -- a real leak, and one a
     * client could ask for by mislabelling. Decide it HERE rather than in
     * nm_alloc_rule: a replacement re-derives SHADOWS_STOCK from the rule it
     * replaces just above, and measuring it earlier would strip the bit off every
     * re-added rule (a reload resolves the vpath through the live injection, so
     * nm_alloc_rule always concludes "shadowing").
     *
     * A PM-scanned codePath is the exception, because "served the stock bytes" is
     * NOT consistent there. The PackageManager runs as system_server, which is
     * never blocked, so it parses the MODULE's copy and publishes THAT identity --
     * version, signature, codePath, nativeLibraryDir -- to every app that asks. A
     * blocked reader handed the stock bytes (or ENOENT) for the same path computes
     * something different from what PM just advertised, the exact disagreement
     * PUBLIC exists to remove; hiding the module's copy buys nothing once PM has
     * described it. Measured on OP15: PM reported com.android.contacts 16.80.0
     * parsed from a 74641847-byte /product/priv-app/Contacts/Contacts.apk while a
     * blocked uid read the 64249089-byte stock one -- and the shared libraries
     * under /product/priv-app/Mms/lib/arm64 were hidden while PM published that
     * lib dir, so the exemption is the whole codePath, not just the .apk.
     *
     * Restricted to PM scan dirs so the anti-mislabelling guard still covers every
     * other shadowing rule -- a client cannot leak an arbitrary replaced file by
     * asking. Userspace only sets the bit for a file under a PM codePath
     * (pmcache::is_pm_published), so this widens nothing it does not request. */
    if ((rule->flags & NM_FLAG_SHADOWS_STOCK) && !nm_vpath_in_pm_scandir(rule))
        rule->flags &= ~NM_FLAG_PUBLIC;

    err = nomount_generate_virtual_topology(rule);
    if (err != 0) {
        /* The victim is already out of the rule hash, but its PARENT may still
         * hold a child node pointing at it: the re-injection that would have
         * re-pointed that node at `rule` is exactly what just failed. Freeing it
         * now would leave that node dereferencing freed memory on every later
         * lookup or readdir of the directory. Detach explicitly instead of
         * relying on the overwrite. (No-op when the re-point did happen.) */
        if (victim)
            __nomount_delete_child_locked(victim->parent_dir, victim);
        if (victim && victims)
            hlist_add_head(&victim->victim_node, victims);
        /* The victim is out of the hash and about to be freed, but a dentry
         * cached for this name may still point at its inode -- and after this
         * return nothing in the table can ever reconcile it. Drop it here,
         * while `rule` still holds the normalized vpath to name it by.
         * Unconditional (NULL, not `rule`): the add FAILED, so nothing is left
         * to serve this name and there is no incoming rule for a cached dentry
         * to still be describing. */
        nm_drop_cached_vpath(nm_get_vpath(rule), rule->v_len, NULL);
        mutex_unlock(&nomount_write_mutex);
        nm_free_rule(rule);
        if (victim && !victims) {
            synchronize_rcu();
            nm_free_rule(victim);
        }
        return err;
    }

    hash_add_rcu(nomount_rules_ht, &rule->vpath_node, rule->v_hash);
    atomic_inc(&nm_rule_gen);

    /* A dentry cached for this name may still point at the inode of whatever
     * this add replaced; without dropping it the path keeps serving the old
     * source while the table names the new one. See nm_drop_cached_vpath.
     *
     * NOT gated on `victim`: that only tracks rule-hash dedup, and the topology
     * walk can re-point a child node without one being recorded.
     *
     * It IS gated on the cached dentry actually differing from `rule`, which is
     * a change from "always drop": unhashing costs far more than a re-lookup.
     * d_unlinked() is permanent for whoever already holds the dentry, and
     * d_path() then reports the file " (deleted)" in their /proc/PID/maps for as
     * long as the mapping lives. A reload re-adds over every live rule with an
     * unchanged source, so the always-drop form marked the module's whole
     * footprint at once -- measured on OP15 as Contacts.apk reading "(deleted)"
     * in system_server's maps with a perfectly mirrored dev and inode. See
     * nm_dentry_matches_rule() for what "differing" is tested on; anything that
     * is not byte-for-byte the same rule is still dropped.
     *
     * Inside the lock, like the identical sequence in
     * nomount_generate_virtual_topology: kern_path under nomount_write_mutex is
     * the established pattern here (nm_alloc_rule does it twice per add), and
     * dropping after the unlock spans synchronize_rcu -- a window in which a
     * concurrent lookup installs a fresh dentry that we would then unhash for
     * nothing.
     *
     * nm_get_vpath(rule)/rule->v_len, not the caller's: nm_alloc_rule trims a
     * trailing '/', and the untrimmed form makes the split produce an empty
     * child name and drop nothing at all. */
    nm_drop_cached_vpath(nm_get_vpath(rule), rule->v_len, rule);
    /* Same argument on the success path: the topology walk normally re-points the
     * parent's child node at `rule`, but it can return 0 having taken a branch
     * that did not (a replacement whose name resolves through a different
     * ancestor). Detaching here is a no-op when it did, and removes a stale
     * pointer to the about-to-be-freed victim when it did not. */
    if (unlikely(victim))
        __nomount_delete_child_locked(victim->parent_dir, victim);
    if (unlikely(victim) && victims)
        hlist_add_head(&victim->victim_node, victims);
    mutex_unlock(&nomount_write_mutex);

    if (unlikely(victim) && !victims) {
        synchronize_rcu();
        nm_free_rule(victim);
    }

    if (flags & NM_FLAG_WHITEOUT)
        nm_debug("Successfully added whiteout rule: %s\n", nm_get_vpath(rule));
    else
        nm_debug("Successfully added injection rule: %s -> %s\n", nm_get_vpath(rule), nm_get_rpath(rule));
        
    return 0;
}

static int __nomount_del_rule(const char *v_path, size_t v_len, unsigned int target_uid, struct hlist_head *r_victims)
{
    struct nomount_rule *rule;
    char *norm = NULL;
    int ret = -ENOENT;
    u32 hash;

    /* Rules are filed under the NORMALISED vpath (nm_norm_vpath), so a del that
     * spells the same path with a trailing or doubled '/' has to be brought to
     * the same spelling or it reports -ENOENT for a rule that is plainly there --
     * and the client, having been told the rule is gone, stops trying. Trim
     * in place; only pay for a copy when there is a '/' run to collapse. */
    while (v_len > 1 && v_path[v_len - 1] == '/') v_len--;
    if (unlikely(nm_vpath_has_slash_run(v_path, v_len))) {
        norm = kmalloc(v_len + 1, GFP_KERNEL);
        if (!norm) return -ENOMEM;
        v_len = nm_norm_vpath(norm, v_path, v_len);
        v_path = norm;
    }
    hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == v_len && rule->target_uid == target_uid &&
                memcmp(nm_get_vpath(rule), v_path, v_len) == 0) {
            /* Refuse to delete a rule that still owns a populated virtual subtree:
             * nm_free_rule() would free its dir_node while descendant rules keep a
             * parent_dir pointer into it, dangling -> UAF on a later del/clear. The
             * caller must remove the children first. Mirrors the shadow-path guard
             * in __nomount_add_rule(). (nm clear is unaffected: it detaches every
             * rule before any dir_node is freed.) */
            if (rule->this_dir && !idr_is_empty(&rule->this_dir->children_idr)) {
                ret = -EBUSY;
                break;
            }
            nm_detach_rule_locked(rule, r_victims, true);
            ret = 0;
            break;
        }
    }
    kfree(norm);
    return ret;
}

/* NB: this drops the blocked-UID set as well as the rules -- per-UID hiding is
 * runtime-only state and CLEAR_ALL is its reset. Any caller that clears in order to
 * rebuild (the Suite's mount pass does exactly that) must re-apply its persistent
 * block list afterwards, or every hidden app is silently unhidden. */
static void __nomount_clear_all(bool is_exit)
{
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    int bkt, i;
    HLIST_HEAD(r_victims);

    /* Drop the per-directory inode samples with the rules they were taken for.
     *
     * nm_ino_pop carries `mine` (up to NM_INO_MINE exact placements) and `hw`,
     * and nm_place_ino() steps around both so two injections in one directory
     * never collide. Those marks describe rules that no longer exist after this
     * function returns, and the Suite clears before every re-injection pass --
     * so without this the marks ACCUMULATE across passes: the 139 rules in
     * /product/overlay leave 139 marks, the next pass adds 139 more, and the
     * third crosses NM_INO_MINE and falls into nm_place_ino's exhausted branch,
     * which walks up from `hw` and hands out a DENSE CONSECUTIVE RUN -- the
     * clustering tell the sampled-placement design exists to remove, measured as
     * 139 consecutive inodes against 25 ragged stock clusters. Resetting also
     * restores the "same file, same ino" property across a reload, since the
     * placement is a pure function of (stock population, spread) once `mine` is
     * empty. Within ONE pass nothing changes: the cache is only invalidated
     * here, so consecutive adds in the same directory still see each other. */
    nm_sib_cache_valid = false;
    for (i = 0; i < NM_RANGE_SLOTS; i++)
        nm_range_cache[i].valid = false;

    static_branch_disable(&nomount_active_uids);
    hash_for_each_safe(nomount_rules_ht, bkt, tmp, rule, vpath_node) {
        nm_detach_rule_locked(rule, &r_victims, false);
    }
    atomic_inc(&nm_rule_gen);
    synchronize_rcu();
    /* Destroy the uid idr only after the grace period: nomount_is_uid_blocked()
     * does a lockless idr_find() under rcu_read_lock(), and a reader that already
     * passed the static-branch check may still be walking the radix nodes. */
    idr_destroy(&nomount_uid_idr);
    hlist_for_each_entry_safe(rule, tmp, &r_victims, victim_node) {
        nm_free_rule(rule);
    }

    if (is_exit) nomount_restore_superblocks();
}

/*** Netlink control API (private raw netlink) ***/

static struct sock *nm_nl_sk;
static int nomount_nl_set_knob(struct nlattr **attrs);

static int nomount_nl_add_rule(struct nlattr **attrs)
{
    if (attrs[NOMOUNT_ATTR_PAYLOAD]) {
        struct nlattr *attr = attrs[NOMOUNT_ATTR_PAYLOAD];
        const char *data = nla_data(attr), *v_ptr, *r_ptr;
        int len = nla_len(attr);
        int pos = 0, err = 0, first_err = 0, nfail = 0;
        struct nomount_rule *v_rule;
        struct hlist_node *v_tmp;
        HLIST_HEAD(a_victims);

        while (pos + 12 <= len) {
            u32 flags      = get_unaligned((const u32 *)(data + pos));
            u32 target_uid = get_unaligned((const u32 *)(data + pos + 4));
            u16 vp_len     = get_unaligned((const u16 *)(data + pos + 8));
            u16 rp_len     = get_unaligned((const u16 *)(data + pos + 10));
            pos += 12;

            if (pos + vp_len + rp_len > len) { if (!first_err) first_err = -EINVAL; break; }
            if (unlikely(vp_len >= PATH_MAX || rp_len >= PATH_MAX)) { if (!first_err) first_err = -ENAMETOOLONG; break; }

            v_ptr = data + pos; pos += vp_len;
            r_ptr = data + pos;  pos += rp_len;
            err = __nomount_add_rule(v_ptr, r_ptr, vp_len, rp_len, flags, target_uid, &a_victims);
            if (err) {
                nm_err("Failed to inject rule batch entry (err: %d)\n", err);
                nfail++;
                if (!first_err) first_err = err;
            }
        }
        /* One grace period for the whole batch, not one per replaced rule. */
        if (!hlist_empty(&a_victims)) {
            synchronize_rcu();
            hlist_for_each_entry_safe(v_rule, v_tmp, &a_victims, victim_node)
                nm_free_rule(v_rule);
        }
        /* Report the first rejection instead of an unconditional 0.
         *
         * Returning success for a batch in which nothing applied made a module
         * whose files were REFUSED (an unresolvable backing path, -ENOENT from
         * nm_alloc_rule) indistinguishable from one that injected cleanly: the
         * `nm` client exits 0, the Suite counts the rule as applied, and the
         * reload delta then believes it is already live. The per-entry Err arm
         * in mount.rs (st.failed) exists for exactly this and could never fire.
         *
         * Every entry is still ATTEMPTED -- the loop does not stop at the first
         * failure -- so this reports a partial batch rather than aborting one. */
        if (first_err)
            nm_warn("rule batch: %d entr%s rejected (first err %d)\n",
                    nfail, nfail == 1 ? "y" : "ies", first_err);
        return first_err;

    } else if (attrs[NOMOUNT_ATTR_VIRTUAL_PATH] && attrs[NOMOUNT_ATTR_REAL_PATH]) {
        char *v_str = nla_data(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        char *r_str = nla_data(attrs[NOMOUNT_ATTR_REAL_PATH]);
        /* strnlen, not nla_len()-1: NLA_NUL_STRING only guarantees a NUL exists
         * within the attribute, not that it is the LAST byte. A trailing-junk
         * string would key the rule on "/a/b\0junk" (hash and child name) while
         * kern_path resolves only "/a/b", so SHADOWS_STOCK, s_path, v_ino and the
         * context all describe a different path than the rule is filed under --
         * an inert rule that still reports applied. */
        int v_len = strnlen(v_str, nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]));
        int r_len = strnlen(r_str, nla_len(attrs[NOMOUNT_ATTR_REAL_PATH]));
        u32 flags = attrs[NOMOUNT_ATTR_FLAGS] ? nla_get_u32(attrs[NOMOUNT_ATTR_FLAGS]) : 0;
        u32 target_uid = attrs[NOMOUNT_ATTR_UID] ? nla_get_u32(attrs[NOMOUNT_ATTR_UID]) : 0;

        if (v_len == 0) return -EINVAL;
        /* Single rule: no batch to amortise over, so free the victim inline. */
        return __nomount_add_rule(v_str, r_str, v_len, r_len, flags, target_uid, NULL);
    }
    return -EINVAL;
}

static int nomount_nl_del_rule(struct nlattr **attrs)
{
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    bool busy = false;
    HLIST_HEAD(r_victims);

    if (attrs[NOMOUNT_ATTR_PAYLOAD]) {
        struct nlattr *attr = attrs[NOMOUNT_ATTR_PAYLOAD];
        const char *data = nla_data(attr);
        int len = nla_len(attr);
        int pos = 0;

        mutex_lock(&nomount_write_mutex);
        while (pos + 6 <= len) {
            u32 target_uid = get_unaligned((const u32 *)(data + pos));
            u16 vp_len     = get_unaligned((const u16 *)(data + pos + 4));
            pos += 6; if (pos + vp_len > len) break;
            if (__nomount_del_rule(data + pos, vp_len, target_uid, &r_victims) == -EBUSY)
                busy = true;
            pos += vp_len;
        }
        atomic_inc(&nm_rule_gen);
        mutex_unlock(&nomount_write_mutex);
    } else if (attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) {
        char *v_path = nla_data(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        /* strnlen for the same reason as the add path above. */
        int v_len = strnlen(v_path, nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]));
        u32 target_uid = attrs[NOMOUNT_ATTR_UID] ? nla_get_u32(attrs[NOMOUNT_ATTR_UID]) : 0;

        mutex_lock(&nomount_write_mutex);
        if (__nomount_del_rule(v_path, v_len, target_uid, &r_victims) == -EBUSY)
            busy = true;
        atomic_inc(&nm_rule_gen);
        mutex_unlock(&nomount_write_mutex);
    } else {
        return -EINVAL;
    }

    /* -EBUSY is not -ENOENT: the rule exists but still owns a populated virtual
     * subtree, so the caller must remove the children first. */
    if (hlist_empty(&r_victims)) return busy ? -EBUSY : -ENOENT;
    synchronize_rcu();

    hlist_for_each_entry_safe(rule, tmp, &r_victims, victim_node) {
        nm_debug("Deleted rule for: %s\n", nm_get_vpath(rule));
        nm_free_rule(rule);
    }

    return 0;
}

static int nomount_nl_clear_rules(void)
{
    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all(false);
    mutex_unlock(&nomount_write_mutex);
    nm_info("Cleared all active rules and UIDs\n");
    return 0;
}

static int nomount_nl_dump_rules(struct sk_buff *skb, struct netlink_callback *cb)
{
    struct nomount_rule *rule;
    int current_bkt = cb->args[0];
    int skip_nodes  = cb->args[1];
    int bkt, node_idx = 0, emitted = 0;
    long gen = (long)atomic_read(&nm_rule_gen) + 1;
    void *hdr;

    /* Resume is by (bucket, ordinal), which a concurrent add/del would shift
     * under us -- skipping or duplicating rules in a multi-part dump. Abort
     * instead: a short list silently feeding a reload delta is worse. */
    if (!cb->args[2]) cb->args[2] = gen;
    else if (cb->args[2] != gen) return -EAGAIN;

    rcu_read_lock();
    for (bkt = current_bkt; bkt < (1 << NOMOUNT_HASH_BITS); bkt++) {
        node_idx = 0;
        hlist_for_each_entry_rcu(rule, &nomount_rules_ht[bkt], vpath_node) {
            if (node_idx < skip_nodes) { node_idx++; continue; }
            hdr = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
                            NM_CMD_TO_TYPE(NM_CMD_GET_LIST), 0, NLM_F_MULTI);
            if (!hdr) goto out;

            if (nla_put_string(skb, NOMOUNT_ATTR_VIRTUAL_PATH, nm_get_vpath(rule)) ||
                nla_put_string(skb, NOMOUNT_ATTR_REAL_PATH, nm_get_rpath(rule)) ||
                nla_put_u32(skb, NOMOUNT_ATTR_FLAGS, rule->flags) ||
                nla_put_u32(skb, NOMOUNT_ATTR_UID, rule->target_uid)) {
                nlmsg_cancel(skb, hdr);
                goto out;
            }
            nlmsg_end(skb, hdr);
            node_idx++;
            emitted++;
        }
        skip_nodes = 0;
    }

out:
    rcu_read_unlock();
    cb->args[0] = bkt;
    cb->args[1] = node_idx;
    /* A rule too big for an empty skb can never be emitted: the put fails, we
     * cancel, and returning 0 here reads to netlink_dump() as end-of-dump --
     * NLMSG_DONE, no error, and the caller silently gets a SHORT LIST. Resume is
     * by (bucket, ordinal) and args[1] is not advanced past it, so a retry hits
     * the same rule and truncates identically. This is the same class the
     * generation guard above exists to prevent, reached by a different door, so
     * fail loudly instead. NLMSG_GOODSIZE (~3968B on 4K pages) against a policy
     * that permits PATH_MAX on both strings is what makes it reachable; the
     * dump control now also asks for a bigger buffer up front. */
    if (!emitted && bkt < (1 << NOMOUNT_HASH_BITS))
        return -EMSGSIZE;
    return skb->len;
}

static int nomount_nl_add_uid(struct nlattr **attrs)
{
    unsigned int uid;
    int ret;

    if (!attrs[NOMOUNT_ATTR_UID])
        return -EINVAL;

    uid = nla_get_u32(attrs[NOMOUNT_ATTR_UID]) % NM_PER_USER_RANGE; /* store/match appid */

    mutex_lock(&nomount_write_mutex);
    /* Ask the TABLE whether this appid is already listed, not
     * nomount_is_uid_blocked(). That helper answers a different question --
     * "is a caller running as this uid hidden from" -- and returns true for the
     * whole app-zygote (90000..98999) and platform-isolated (99000..99999)
     * pools whether or not anything was ever added for them. So `nm block 99000`
     * reported -EEXIST against an empty table and the appid never got listed:
     * the pools are covered by the range test at READ time, but the entry the
     * operator asked for was silently absent, so `nm l u` did not show it and
     * removing it later answered -ENOENT.
     *
     * It also short-circuits on the static branch, so before the FIRST uid is
     * added it returned false unconditionally -- the duplicate check it was
     * doing could not fire on an empty table at all.
     *
     * idr_find() under the write mutex is the direct question and has neither
     * quirk. Moved inside the lock while we are here: the old test raced a
     * concurrent add, which idr_alloc then rejected as -ENOSPC and this
     * function reported as -ENOMEM. */
    idr_preload(GFP_KERNEL);
    if (idr_find(&nomount_uid_idr, uid)) {
        idr_preload_end();
        mutex_unlock(&nomount_write_mutex);
        return -EEXIST;
    }
    ret = idr_alloc(&nomount_uid_idr, (void *)8, uid, uid + 1, GFP_NOWAIT);
    idr_preload_end();

    if (ret >= 0) {
        static_branch_enable(&nomount_active_uids);
        nm_info("Successfully added blocked UID: %u\n", uid);
        ret = 0;
    } else {
        /* -ENOSPC means the slot filled between the check and the alloc; report
         * it as the duplicate it is, not as an allocation failure. */
        ret = (ret == -ENOSPC) ? -EEXIST : -ENOMEM;
    }
    mutex_unlock(&nomount_write_mutex);

    return ret;
}

static int nomount_nl_del_uid(struct nlattr **attrs)
{
    unsigned int uid;
    int ret = -ENOENT;

    if (!attrs[NOMOUNT_ATTR_UID])
        return -EINVAL;

    uid = nla_get_u32(attrs[NOMOUNT_ATTR_UID]) % NM_PER_USER_RANGE; /* store/match appid */

    mutex_lock(&nomount_write_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    if (idr_remove(&nomount_uid_idr, uid)) {
#else
    /* pre-4.11 idr_remove() returns void; probe presence first */
    if (idr_find(&nomount_uid_idr, uid)) {
        idr_remove(&nomount_uid_idr, uid);
#endif
        if (idr_is_empty(&nomount_uid_idr))
            static_branch_disable(&nomount_active_uids);

        nm_info("Successfully removed blocked UID: %u\n", uid);
        ret = 0;
    }
    mutex_unlock(&nomount_write_mutex);

    return ret;
}

static int nomount_nl_dump_uids(struct sk_buff *skb, struct netlink_callback *cb)
{
    int id = cb->args[0];

    if (!static_branch_unlikely(&nomount_active_uids)) return 0;
    rcu_read_lock();
    while (idr_get_next(&nomount_uid_idr, &id) != NULL) {
        void *hdr;
        hdr = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
                        NM_CMD_TO_TYPE(NM_CMD_GET_UIDS), 0, NLM_F_MULTI);
        if (!hdr) break;
        if (nla_put_u32(skb, NOMOUNT_ATTR_UID, id)) {
            nlmsg_cancel(skb, hdr);
            break;
        }
        nlmsg_end(skb, hdr);
        id++;
    }
    rcu_read_unlock();
    cb->args[0] = id;
    return skb->len;
}

/* Stream the _ghost rule tables.
 *
 * Reuses NOMOUNT_ATTR_VIRTUAL_PATH for the rule text rather than adding an
 * attribute: it is already an NLA_NUL_STRING in the policy and already parsed
 * by the client, and a rule here occupies the same slot in the message that a
 * rule's target does in NM_CMD_GET_LIST.
 *
 * ghost_get_rule() takes its own lock per call, so nothing is held across
 * nlmsg_put() -- which is the whole reason it hands back one rule at a time.
 * A kernel without the _ghost patch set has the weak symbol NULL and returns
 * an empty dump, so `nm l g` prints nothing instead of an error the caller
 * would have to tell apart from "no rules configured". */
static int nomount_nl_dump_ghost(struct sk_buff *skb, struct netlink_callback *cb)
{
    char rule[NM_GHOST_RULE_MAX];
    int idx = cb->args[0];
    void *hdr;

    if (!ghost_get_rule)
        return 0;

    while (ghost_get_rule(idx, rule, sizeof(rule)) > 0) {
        /* TERMINATE IT OURSELVES. `rule` is uninitialised stack and ghost.c lives
         * in a SEPARATE repository (the _ghost patch set), so its NUL is a
         * cross-repo contract, not something this file can see -- and the comment
         * on NM_GHOST_RULE_MAX above already says the two sides can drift.
         * nla_put_string() calls strlen(), so a fill that reached the end of the
         * buffer, or any future ghost_get_rule() that returns a length without
         * terminating, walks off this array and copies whatever follows it on the
         * stack into a netlink message. One store makes the loop depend on nothing
         * but its own buffer; a correct _ghost never notices. */
        rule[sizeof(rule) - 1] = '\0';
        hdr = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
                        NM_CMD_TO_TYPE(NM_CMD_GET_GHOST), 0, NLM_F_MULTI);
        if (!hdr) break;
        if (nla_put_string(skb, NOMOUNT_ATTR_VIRTUAL_PATH, rule)) {
            nlmsg_cancel(skb, hdr);
            break;
        }
        nlmsg_end(skb, hdr);
        idx++;
    }
    cb->args[0] = idx;
    return skb->len;
}

static int nomount_nl_get_version(struct sk_buff *req, struct nlmsghdr *req_nlh)
{
    u32 portid = NETLINK_CB(req).portid;
    struct sk_buff *msg;
    void *hdr;

    msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg) return -ENOMEM;

    hdr = nlmsg_put(msg, portid, req_nlh->nlmsg_seq,
                    NM_CMD_TO_TYPE(NM_CMD_GET_VERSION), 0, 0);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    if (nla_put_u32(msg, NOMOUNT_ATTR_VERSION, NOMOUNT_VERSION)) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    nlmsg_end(msg, hdr);
    return nlmsg_unicast(nm_nl_sk, msg, portid);
}

static const struct nla_policy nomount_genl_policy[__NOMOUNT_ATTR_MAX] = {
    [NOMOUNT_ATTR_VIRTUAL_PATH] = { .type = NLA_NUL_STRING, .len = PATH_MAX },
    [NOMOUNT_ATTR_REAL_PATH]    = { .type = NLA_NUL_STRING, .len = PATH_MAX },
    [NOMOUNT_ATTR_FLAGS]        = { .type = NLA_U32 },
    [NOMOUNT_ATTR_UID]          = { .type = NLA_U32 },
    [NOMOUNT_ATTR_VERSION]      = { .type = NLA_U32 },
    [NOMOUNT_ATTR_PAYLOAD]      = { .type = NLA_BINARY },
};

/*
 * Dispatch one control request. The command is carried in nlmsg_type; the two
 * GET_* commands are streamed via the standard dump machinery.
 *
 * CAP_SYS_ADMIN on every command, dumps included.
 *
 * It was CAP_NET_ADMIN, which is the faithful translation of the GENL_ADMIN_PERM
 * flag the generic-netlink family carried before the move to a private protocol
 * -- and a bad fit for what this interface actually grants. One ADD_RULE
 * redirects any path on any ROM partition at any file, which is root-equivalent:
 * it can serve a chosen binary at /system/bin/<anything> that every domain on the
 * device already executes. CAP_NET_ADMIN is not a root-equivalent capability on
 * Android and is held by domains that are not (netd, system_server), so the gate
 * was strictly weaker than the privilege behind it.
 *
 * Nothing legitimate loses access: every caller in the tree is uid 0 with a full
 * capability set -- the module's five boot entry points under ksud, customize.sh
 * during install, the WebUI through ksu.exec, and the Suite binary shelling out
 * to `nm`. None of the privilege-dropping probes in `nomount check` touch the
 * socket; they fork, drop, and then only stat/open.
 *
 * netlink_capable() still measures against init_user_ns, so a user namespace
 * cannot manufacture either capability.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
static int nm_nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
                         struct netlink_ext_ack *extack)
#else
static int nm_nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
#endif
{
    struct nlattr *attrs[__NOMOUNT_ATTR_MAX];
    int cmd = NM_TYPE_TO_CMD(nlh->nlmsg_type);
    int ret;

    if (!netlink_capable(skb, CAP_SYS_ADMIN))
        return -EPERM;

    if (cmd == NM_CMD_GET_LIST || cmd == NM_CMD_GET_UIDS || cmd == NM_CMD_GET_GHOST) {
        struct netlink_dump_control c = {
            .dump = cmd == NM_CMD_GET_LIST ? nomount_nl_dump_rules
                  : cmd == NM_CMD_GET_UIDS ? nomount_nl_dump_uids
                                           : nomount_nl_dump_ghost,
            /* Without this netlink allocates NLMSG_GOODSIZE (~3968B on 4K
             * pages), which cannot hold one rule whose two PATH_MAX strings the
             * attribute policy allows -- and an un-emittable first rule ends the
             * dump early with no error. Ask for a buffer that always fits one. */
            .min_dump_alloc = 2 * PATH_MAX + 512,
        };
        return netlink_dump_start(nm_nl_sk, skb, nlh, &c);
    }

    ret = NM_NLMSG_PARSE(nlh, attrs);
    if (ret < 0)
        return ret;

    switch (cmd) {
    case NM_CMD_ADD_RULE:    return nomount_nl_add_rule(attrs);
    case NM_CMD_DEL_RULE:    return nomount_nl_del_rule(attrs);
    case NM_CMD_CLEAR_ALL:   return nomount_nl_clear_rules();
    case NM_CMD_ADD_UID:     return nomount_nl_add_uid(attrs);
    case NM_CMD_DEL_UID:     return nomount_nl_del_uid(attrs);
    case NM_CMD_GET_VERSION: return nomount_nl_get_version(skb, nlh);
    case NM_CMD_SET_KNOB:    return nomount_nl_set_knob(attrs);
    default:                 return -EINVAL;
    }
}

static void nm_nl_rcv(struct sk_buff *skb)
{
    netlink_rcv_skb(skb, &nm_nl_rcv_msg);
}

/* Netlink knob setter. Payload: [u32 knob][value bytes]; empty value clears. */
static int nomount_nl_set_knob(struct nlattr **attrs)
{
    const char *data, *val;
    u32 knob;
    int len, vlen;

    if (!attrs[NOMOUNT_ATTR_PAYLOAD]) return -EINVAL;
    data = nla_data(attrs[NOMOUNT_ATTR_PAYLOAD]);
    len  = nla_len(attrs[NOMOUNT_ATTR_PAYLOAD]);
    if (len < 4) return -EINVAL;
    knob = get_unaligned((const u32 *)data);
    val  = data + 4;
    vlen = len - 4;

    switch (knob) {
    case NM_KNOB_VDIR_EROFS_SIZE:
        WRITE_ONCE(nm_vdir_erofs_size, vlen > 0 && val[0] == '1');
        return 0;
    case NM_KNOB_HIDE_ISOLATED: {
        unsigned int pools;

        /* Single decimal digit 0..3; empty value restores the default. */
        if (vlen <= 0) {
            WRITE_ONCE(nm_hide_isolated, NM_HIDE_APPZYGOTE | NM_HIDE_ISOLATED);
            return 0;
        }
        if (val[0] < '0' || val[0] > '3') return -EINVAL;
        pools = val[0] - '0';
        WRITE_ONCE(nm_hide_isolated, pools);
        nm_info("Isolated-pool hiding set to %u\n", pools);
        return 0;
    }
    case NM_KNOB_GHOST:
        if (!ghost_ctl)
            return -EINVAL;
        if (vlen == 0)          /* presence probe; see NM_KNOB_GHOST */
            return 0;
        /* Verbatim, same reasoning as pathhide: _ghost owns its parser. */
        return ghost_ctl(val, vlen);
    default:
        return -EINVAL;
    }
}

static int __init nomount_init(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) { return -ENOMEM; }
    cred->uid = cred->euid = cred->suid = cred->fsuid = GLOBAL_ROOT_UID;
    cred->gid = cred->egid = cred->sgid = cred->fsgid = GLOBAL_ROOT_GID;
    cap_raise(cred->cap_effective, CAP_DAC_OVERRIDE);
    cap_raise(cred->cap_effective, CAP_DAC_READ_SEARCH);
    nm_root_cred = cred;

    hash_init(nomount_rules_ht);
    nm_dir_cachep = kmem_cache_create("vfs_dnode", sizeof(struct nomount_dir_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_inode_cachep = kmem_cache_create("vfs_ninfo", sizeof(struct nm_inode_info), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_iop_cachep = kmem_cache_create("vfs_iops", sizeof(struct nm_iop), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_fop_cachep = kmem_cache_create("vfs_fops", sizeof(struct nm_fop), 0, SLAB_HWCACHE_ALIGN, NULL);

    if (!nm_dir_cachep || !nm_inode_cachep || !nm_iop_cachep || !nm_fop_cachep) {
        nm_err("Failed to allocate memory slab caches\n");
        if (nm_dir_cachep) kmem_cache_destroy(nm_dir_cachep);
        if (nm_inode_cachep) kmem_cache_destroy(nm_inode_cachep);
        if (nm_iop_cachep) kmem_cache_destroy(nm_iop_cachep);
        if (nm_fop_cachep) kmem_cache_destroy(nm_fop_cachep);
        put_cred(nm_root_cred);
        return -ENOMEM;
    }

    /* Registering the protocol makes socket(AF_NETLINK, SOCK_RAW, NOMOUNT_NL_PROTO)
     * succeed here where a stock kernel answers EPROTONOSUPPORT -- an existence tell
     * for anything that can create the socket at all. Every command behind it is
     * netlink_capable(CAP_SYS_ADMIN)-gated, and for app domains SELinux denies
     * netlink_socket:create first (EACCES on stock and here alike), so the tell is
     * not reachable from an app; a domain that does hold netlink_socket would see it. */
    {
        struct netlink_kernel_cfg cfg = { .input = nm_nl_rcv, };
        nm_nl_sk = netlink_kernel_create(&init_net, NOMOUNT_NL_PROTO, &cfg);
    }
    if (!nm_nl_sk) {
        nm_err("Failed to create netlink socket (proto %d)\n", NOMOUNT_NL_PROTO);
        kmem_cache_destroy(nm_dir_cachep);
        kmem_cache_destroy(nm_inode_cachep);
        kmem_cache_destroy(nm_iop_cachep);
        kmem_cache_destroy(nm_fop_cachep);
        put_cred(nm_root_cred);
        return -ENOMEM;
    }

    nm_info("Loaded successfully\n");
    return 0;
}

/* Rewrite the (dev, ino) pair /proc/<pid>/maps reports for a mapped injected
 * file. show_map_vma() reads inode->i_sb->s_dev/i_ino RAW — it never calls
 * ->getattr — so without this an injected mapping shows the overlay-top dev
 * (major 0), an outlier vs stock file-backed mappings. Only our own created
 * inodes (nm_file_iops/nm_dir_iops + nm_inode_info in i_private) are touched;
 * hijacked real inodes and everything else are left alone. */
void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
                                 unsigned long *ino)
{
    const struct nm_inode_info *info;

    if (unlikely(!inode || !dev || !ino))
        return;
    if (inode->i_op != &nm_file_iops && inode->i_op != &nm_dir_iops)
        return;
    info = inode->i_private;
    if (unlikely(!info))
        return;
    if (info->v_mapdev)
        *dev = info->v_mapdev;
    else if (info->v_dev)
        *dev = info->v_dev;
    *ino = info->v_ino;
}

static void __exit nomount_exit(void)
{

    netlink_kernel_release(nm_nl_sk);

    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all(true);
    mutex_unlock(&nomount_write_mutex);

    /* Drain pending call_rcu frees (dir_node) before destroying their slab caches,
     * else kmem_cache_destroy races the deferred kmem_cache_free. */
    rcu_barrier();

    /* NB: hijack vtables are deliberately NOT freed here, and the caches below are
     * destroyed with those objects still live. That is only reachable in a
     * modular build, which no target uses (obj-y everywhere), and it is the safe
     * direction: an inode still points at fake_iop/fake_fop, and a struct file
     * may still cache f_op, so freeing them at unload would be the UAF this
     * design exists to avoid. See the note on struct nm_iop. */
    kmem_cache_destroy(nm_dir_cachep);
    kmem_cache_destroy(nm_inode_cachep);
    kmem_cache_destroy(nm_iop_cachep);
    kmem_cache_destroy(nm_fop_cachep);
    put_cred(nm_root_cred);

    nm_info("Unloaded successfully\n");
}

/* --- Known residual identity surface (measured 2026-08-21, OP15/6.12) --------
 *
 * The tells this driver DOES close: no /sys/kernel/<name> kobject (the knobs
 * ride netlink), no Generic Netlink family name to resolve, no MODULE_VERSION so
 * no /sys/module/<name>/version (verified absent on-device), disguised slab
 * cache names, and no debug strings in a production build.
 *
 * What remains, deliberately:
 *
 * 1. /proc/kallsyms. All 67 function symbols in this object are named
 *    nomount_* and nm_*, and kallsyms lists local text symbols too. kptr_restrict
 *    zeroes the addresses but not the names. The file is mode 0444 with SELinux
 *    type proc_kallsyms, so on a stock Android policy app domains cannot read it
 *    and `shell` can; that gate was NOT verified from an untrusted_app context
 *    here, so treat app reachability as unmeasured rather than as safe.
 *
 *    Closing it means renaming every identifier, or a build-time mangling layer.
 *    Both cost real debuggability (a stack trace or KASAN report from a stealth
 *    build no longer names anything), both have to be kept in step as functions
 *    are added, and neither actually makes the object anonymous -- 67 symbols
 *    sharing one invented prefix is still a distinctive cluster, just one that
 *    does not name the project. That trade is a deployment decision, not one to
 *    bake in here. It is recorded so it is an accepted risk, not an oversight.
 *
 * 2. /proc/slabinfo lists vfs_dnode / vfs_ninfo / vfs_iops / vfs_fops. The names
 *    are deliberately generic and the file is 0440 root:log.
 *
 * 3. A hijacked superblock is never un-hijacked at runtime -- see
 *    nomount_restore_superblocks(), which only the (dead, __exit) unload path
 *    calls. This is CORRECT, not a leak: `nm clear` frees the rules and cures the
 *    hijacked directory inodes, but synthetic inodes can still be pinned by an
 *    open fd, and those need our ->destroy_inode to free their nm_inode_info and
 *    our ->evict_inode to leave i_data alone. Restoring s_op while any such inode
 *    lives would hand it to the backing fs's teardown, which knows nothing about
 *    i_private -- a leak at best. The fall-through cost when no rules exist is a
 *    predictable-branch call per inode teardown on that sb.
 */

/* MODULE_VERSION() on BUILT-IN code emits a __modver entry, and kernel/params.c
 * turns that into /sys/module/<KBUILD_MODNAME>/version -- mode 0444, verified
 * readable by an ordinary app uid, printing the project name and version. That
 * is the same class of tell as the /sys/kernel dir this driver already dropped,
 * and strictly worse (that one was 0600). AUTHOR/DESCRIPTION only add
 * identifying strings to .modinfo. CONFIG_NOMOUNT is bool, so none of this
 * metadata is ever consumed: the driver cannot be built as a module. */
MODULE_LICENSE("GPL");

fs_initcall(nomount_init);
module_exit(nomount_exit);
