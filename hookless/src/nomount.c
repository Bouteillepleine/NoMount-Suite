#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/huge_mm.h>
#include <linux/hash.h>
#include <linux/sort.h>
#include <linux/sched.h>
#include "nomount.h"

#if IS_ENABLED(CONFIG_OVERLAY_FS) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && \
    defined(__has_include)
#if __has_include("overlayfs/ovl_entry.h")
#include "overlayfs/ovl_entry.h"
#include <linux/uaccess.h>
#define NM_OVL_LAST_INO 1
#else
/* Out of tree the header comes from NM_OVL_SRC (lkm/Makefile; CI points it at the DDK
 * image's own source). Without it nm_ovl_reserve_dir_ino() compiles to `return 0` and a
 * synthesized overlay directory lands above every inode on the device, where the 00_ zip
 * puts it next to its stock siblings. nm_place_dir_ino()'s `inoplace:` line carries
 * ovl=%d at runtime, so a dmesg capture says which build it came from. */
#warning "overlayfs/ovl_entry.h not found: no overlay dir-inode reservation (expected out of tree; see lkm/Makefile)"
#endif
#endif

#define NM_PER_USER_RANGE   100000
#define NM_APPZYGOTE_START  90000
#define NM_APPZYGOTE_END    98999
#define NM_ISOLATED_START   99000
#define NM_ISOLATED_END     99999

#define NM_SDKSANDBOX_START 20000
#define NM_SDKSANDBOX_END   29999
#define NM_SDKSANDBOX_OFF   10000

#define NM_GHOST_RULE_MAX 200
/* The cloaks are optional companions, so the engine must link without them.
 * These are weak DEFINITIONS that a tree carrying _ghost/_pathhide overrides
 * with its own. They used to be weak undefined references tested as pointers,
 * and on arm64 the address of a symbol that may be absent is loaded through
 * the GOT: a kernel without the companion patches then failed its vmlinux link
 * on "Unexpected GOT/PLT entries detected!". -ENOSYS is the absent marker; the
 * real functions answer a NULL buffer with -EINVAL and never return it.
 */
#ifndef NM_OOT_COMPANION_STUBS
int ghost_ctl(const char *buf, size_t count);
int ghost_get_rule(int idx, char *out, size_t outsz);
int __weak ghost_ctl(const char *buf, size_t count) { return -ENOSYS; }
int __weak ghost_get_rule(int idx, char *out, size_t outsz) { return -ENOSYS; }
#endif
#define nm_have_ghost() (ghost_get_rule(0, NULL, 0) != -ENOSYS)

#define NM_PATHHIDE_RULE_MAX 128
#ifndef NM_OOT_COMPANION_STUBS
int pathhide_ctl(const char *buf, size_t count);
int pathhide_get_rule(int idx, char *out, size_t outsz);
int __weak pathhide_ctl(const char *buf, size_t count) { return -ENOSYS; }
int __weak pathhide_get_rule(int idx, char *out, size_t outsz) { return -ENOSYS; }
#endif
#define nm_have_pathhide() (pathhide_get_rule(0, NULL, 0) != -ENOSYS)

static atomic_t nm_rule_gen = ATOMIC_INIT(0);
static struct kmem_cache *nm_dir_cachep __read_mostly, *nm_inode_cachep __read_mostly;
static struct kmem_cache *nm_iop_cachep __read_mostly, *nm_fop_cachep __read_mostly;
static const struct cred *nm_root_cred;

static void nm_dir_node_put(struct nomount_dir_node *dir_node);
static void nomount_restore_dir_node(struct nomount_dir_node *dir_node);
static void __nomount_delete_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule);
static void nm_detach_rule_locked(struct nomount_rule *rule, struct hlist_head *victims, bool prune);
static void nm_free_rule(struct nomount_rule *rule);
static void nm_forget_dev_caches(dev_t dev);
static void nm_fa_sample_path(const struct path *p, struct nm_fa_sample *s);
static int nm_hijacked_erofs_listing(struct file *file, struct dir_context *ctx,
                                     struct nomount_dir_node *pdir,
                                     const struct file_operations *orig_fop);
static bool nm_hijacked_erofs_size(struct nomount_dir_node *d, unsigned int bs, loff_t *out);
static void nm_rlist_free(struct nm_rlist *rl);
static DEFINE_STATIC_KEY_FALSE(nomount_active_uids);

static int nm_read_secctx(struct inode *in, char *dst, u16 *dlen)
{
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

#define NM_HIDE_APPZYGOTE   0x1
#define NM_HIDE_ISOLATED    0x2
static unsigned int nm_hide_isolated __read_mostly = NM_HIDE_APPZYGOTE | NM_HIDE_ISOLATED;

static __always_inline unsigned int nm_appid_of(uid_t uid)
{
    unsigned int appid = uid % NM_PER_USER_RANGE;

    if (appid >= NM_SDKSANDBOX_START && appid <= NM_SDKSANDBOX_END)
        appid -= NM_SDKSANDBOX_OFF;
    return appid;
}

static __always_inline bool nomount_is_uid_blocked(uid_t uid)
{
    unsigned int appid, pools;
    bool is_blocked;
    if (!static_branch_unlikely(&nomount_active_uids)) return false;
    appid = uid % NM_PER_USER_RANGE;
    pools = READ_ONCE(nm_hide_isolated);
    if ((pools & NM_HIDE_APPZYGOTE) &&
        appid >= NM_APPZYGOTE_START && appid <= NM_APPZYGOTE_END)
        return true;
    if ((pools & NM_HIDE_ISOLATED) &&
        appid >= NM_ISOLATED_START && appid <= NM_ISOLATED_END)
        return true;
    appid = nm_appid_of(uid);
    rcu_read_lock();
    is_blocked = (idr_find(&nomount_uid_idr, appid) != NULL);
    rcu_read_unlock();
    return is_blocked;
}

bool nm_uid_blocked(uid_t uid);
bool nm_uid_blocked(uid_t uid)
{
    return nomount_is_uid_blocked(uid);
}

/* Whether a scope admits the calling uid. Shared by the rule (at lookup) and the copy an
 * inode carries (at every later op), so the two can never disagree. */
static __always_inline bool nm_scope_admits(unsigned int target_uid, unsigned int uid_end,
                                            u8 deny_n, const unsigned int *deny)
{
    unsigned int uid = current_uid().val;

    if (uid_end) {
        /* Range mode: RAW uids, and deliberately not per-user. "every uid except
         * system_server" works because system_server is 1000 on every user; a
         * range like 10200-10200 matches user 0 only, which is the point.
         */
        if (uid < target_uid || uid > uid_end)
            return false;
    } else if (target_uid) {
        /* Legacy mode, unchanged: target_uid is an appid, matched across users. */
        if ((target_uid % NM_PER_USER_RANGE) != (uid % NM_PER_USER_RANGE))
            return false;
    }

    /* Exclusion is by APPID, so one entry covers that app under every user -- a
     * work profile included. It applies to both modes: the scope above selects
     * raw uids, this subtracts apps from whatever it selected.
     */
    if (deny_n) {
        /* nm_appid_of, as the hide list does: an excluded app's SDK-sandbox uid is the app. */
        unsigned int appid = nm_appid_of(uid);
        u8 i;

        for (i = 0; i < deny_n && i < NM_DENY_MAX; i++)
            if (deny[i] == appid)
                return false;
    }

    return true;
}

static __always_inline bool nm_rule_live(const struct nomount_rule *rule)
{
    /* A minted intermediate is reachable from its parent's children_idr before
     * the fill pass stamps ino/times/secctx/blksize. Serving it there handed an
     * unprivileged reader v_ino = the raw name hash and v_blksize = 0 (measured
     * on an OP15: st_ino 1779265970 beside stock 10..37, st_blksize 1, repaired
     * ~116us later). Absent until stamped; the acquire orders the metadata. */
    return rule && !smp_load_acquire(&rule->pending);
}

/* Read end, start, deny in that order, against nm_widen_scope_up() writing deny, start,
 * end: any mix a reader can see is then the old scope or wider, never narrower. */
static __always_inline void nm_scope_snapshot(const struct nomount_rule *rule,
                                              unsigned int *start, unsigned int *end, u8 *dn)
{
    *end = READ_ONCE(rule->uid_end);
    smp_rmb();
    *start = READ_ONCE(rule->target_uid);
    smp_rmb();
    *dn = READ_ONCE(rule->deny_n);
}

static __always_inline bool nm_rule_visible(const struct nomount_rule *rule)
{
    unsigned int start, end;
    u8 dn;

    if (!nm_rule_live(rule)) return false;
    nm_scope_snapshot(rule, &start, &end, &dn);
    return nm_scope_admits(start, end, dn, rule->deny_appid);
}

static __always_inline bool nm_scope_copy_admits(const struct nm_scope_copy *s)
{
    return nm_scope_admits(s->uid, s->uid_end, s->deny_n, s->deny);
}

/* Two rules on one vpath are the SAME rule only if they are served to the same
 * set of uids. Scope is therefore part of both the add-clash key and the delete
 * key -- delete has always matched target_uid exactly rather than as a wildcard,
 * and widening that now would let a narrow delete remove a broad rule.
 */
static __always_inline bool nm_scope_eq(const struct nomount_rule *rule,
                                        const struct nm_uid_scope *scope)
{
    u8 i;

    if (rule->target_uid != scope->uid ||
        rule->uid_end    != scope->uid_end ||
        rule->deny_n     != scope->deny_n)
        return false;
    for (i = 0; i < rule->deny_n; i++)
        if (rule->deny_appid[i] != scope->deny[i])
            return false;
    return true;
}

/* Reject a scope that cannot mean what the caller wrote, rather than silently
 * serving a different set of uids than they asked for.
 */
static __always_inline bool nm_scope_invalid(const struct nm_uid_scope *scope)
{
    unsigned int i;

    if (scope->uid_end && scope->uid_end < scope->uid)
        return true;
    if (scope->deny_n > NM_DENY_MAX)
        return true;
    /* Sorted and strictly increasing, so the delete key is canonical: two rules
     * hiding from the same apps must compare equal whatever order the caller
     * listed them in, and a duplicate would make deny_n overstate the count.
     */
    for (i = 0; i < scope->deny_n; i++) {
        if (scope->deny[i] >= NM_PER_USER_RANGE)
            return true;
        if (i && scope->deny[i] <= scope->deny[i - 1])
            return true;
    }
    return false;
}

/* Read the scope off a parsed message. DENY_APPIDS is one packed array rather
 * than a repeated attribute because nlmsg_parse() keeps only the last instance
 * of a repeated attr, which would silently drop every appid but one.
 */
static int nm_scope_from_attrs(struct nm_uid_scope *scope, struct nlattr **attrs)
{
    const struct nlattr *a = attrs[NOMOUNT_ATTR_DENY_APPIDS];

    memset(scope, 0, sizeof(*scope));
    scope->uid     = attrs[NOMOUNT_ATTR_UID]     ? nla_get_u32(attrs[NOMOUNT_ATTR_UID])     : 0;
    scope->uid_end = attrs[NOMOUNT_ATTR_UID_END] ? nla_get_u32(attrs[NOMOUNT_ATTR_UID_END]) : 0;
    if (a) {
        int blen = nla_len(a);

        if (blen <= 0 || blen % (int)sizeof(scope->deny[0]) ||
            blen > (int)sizeof(scope->deny))
            return -EINVAL;
        memcpy(scope->deny, nla_data(a), blen);
        scope->deny_n = blen / (int)sizeof(scope->deny[0]);
    }
    return 0;
}

static __always_inline bool nm_uid_hidden(u32 flags)
{
    return !(flags & NM_FLAG_PUBLIC) &&
           nomount_is_uid_blocked(current_uid().val);
}

/* Whether this caller is served the rule behind an inode: in its scope and not hidden from
 * by the hide list. Everyone else gets the stock file, or ENOENT where there is none. */
static __always_inline bool nm_info_served(const struct nm_inode_info *info)
{
    return nm_scope_copy_admits(&info->v_scope) && !nm_uid_hidden(info->flags);
}

static __always_inline bool nm_rinfo_served(const struct nm_rule_info *ri)
{
    return nm_scope_copy_admits(&ri->v_scope) && !nm_uid_hidden(ri->flags);
}

static __always_inline bool nm_child_visible(const struct nomount_child_node *child)
{
    return child && nm_rule_visible(READ_ONCE(child->rule)) && !nm_uid_hidden(child->flags);
}

#define __get_nm(ptr, type, member, field, hook_func) ({ \
    typeof(ptr) __p = (ptr); \
    (likely(__p) && __p->field == (hook_func)) ? container_of(__p, type, member) : NULL; \
})

static struct dentry *nomount_hijacked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags);
static int nomount_hijacked_iterate_dir(struct file *file, struct dir_context *ctx);
static bool nm_vdir_erofs_size __read_mostly;
#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xE0F5E1E2
#endif
static loff_t nm_vdir_size(struct nomount_dir_node *d, unsigned int blocksize);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static int nomount_hijacked_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat);
#else
static int nomount_hijacked_getattr(IDMAP_ARG const struct path *path, struct kstat *stat,
                                    u32 request_mask, unsigned int query_flags);
#endif
static u64 nm_child_dotdot_of(const char *dirpath);
static void nm_dsnap_drop(struct nm_inode_info *info);
static loff_t nm_dsnap_dir_size(struct inode *v_inode, struct nm_inode_info *info);

static __always_inline struct nomount_dir_node *nomount_get_dir_node(struct inode *inode)
{
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;

    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
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

/* Whether a rule covers this name at all, visible to the caller or not. */
static __always_inline bool nm_name_has_rule(struct nomount_dir_node *dir_node,
                                             const char *name, size_t len, u32 hash)
{
    struct nomount_child_node *child;
    bool found = false;

    if (unlikely(!dir_node)) return false;
    if (!(READ_ONCE(dir_node->bloom_mask) & (1ULL << (hash & 63)))) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            found = READ_ONCE(child->rule) != NULL;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

/* any_scope: match the rule whoever is asking, and let the caller decide per uid from the
 * scope copied into rule_info. One rule per vpath (a second scope is refused at add). */
static __always_inline bool nomount_get_rule_info(struct nomount_dir_node *dir_node, const char *name, size_t len, u32 hash, struct nm_rule_info *rule_info, bool get_path, bool any_scope)
{
    struct nomount_child_node *child;
    bool found = false;

    rule_info->gen = (u32)atomic_read(&nm_rule_gen);
    rule_info->this_dir = NULL;
    rule_info->r_path.dentry = NULL;
    rule_info->r_path.mnt = NULL;
    rule_info->s_path.dentry = NULL;
    rule_info->s_path.mnt = NULL;
    memset(&rule_info->v_scope, 0, sizeof(rule_info->v_scope));
    if (unlikely(!dir_node)) return false;
    if (!(READ_ONCE(dir_node->bloom_mask) & (1ULL << (hash & 63)))) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            struct nomount_rule *rule = smp_load_acquire(&child->rule);
            if (any_scope ? nm_rule_live(rule) : nm_rule_visible(rule)) {
                rule_info->flags = rule->flags;
                nm_scope_snapshot(rule, &rule_info->v_scope.uid, &rule_info->v_scope.uid_end,
                                  &rule_info->v_scope.deny_n);
                memcpy(rule_info->v_scope.deny, rule->deny_appid, sizeof(rule_info->v_scope.deny));
                if (rule_info->v_scope.uid || rule_info->v_scope.uid_end || rule_info->v_scope.deny_n)
                    rule_info->flags |= NM_FLAG_UID_SCOPED;
                rule_info->v_ino = rule->v_ino;
                rule_info->v_dino = rule->v_dino;
                rule_info->v_pdino = rule->v_pdino;
                rule_info->v_dev = rule->v_dev;
                rule_info->v_mapdev = rule->v_mapdev;
                rule_info->v_atime = rule->v_atime;
                rule_info->v_mtime = rule->v_mtime;
                rule_info->v_ctime = rule->v_ctime;
                NM_BTIME_COPY(rule_info->v_btime, rule->v_btime);
                rule_info->v_attributes = rule->v_attributes;
                rule_info->v_attr_mask = rule->v_attr_mask;
                rule_info->v_blksize = rule->v_blksize;
                rule_info->v_cratio = rule->v_cratio;
                rule_info->v_result_mask = rule->v_result_mask;
                rule_info->v_dio_mem = rule->v_dio_mem;
                rule_info->v_dio_off = rule->v_dio_off;
                rule_info->v_cap = rule->v_cap;
                rule_info->v_fa = rule->v_fa;
                rule_info->v_cfile = rule->v_cfile;
                rule_info->v_uid = rule->v_uid;
                rule_info->v_gid = rule->v_gid;
                rule_info->v_mode = rule->v_mode;
                rule_info->v_ctx_len = rule->v_ctx_len;
                if (rule->v_ctx_len) memcpy(rule_info->v_ctx, rule->v_ctx, rule->v_ctx_len + 1);
                rule_info->this_dir = smp_load_acquire(&rule->this_dir);
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
    const struct nm_inode_info *dir_info;
    int emitted;
    bool refused;
    bool stock_space;   /* listing the stock dir for a caller served s_path */
};

static inline void nm_proxy_note(struct nomount_proxy_ctx *p, loff_t off)
{
    if (p->stock_space)
        nm_note_stock_pos(p->dir_node, off);
    else
        nm_note_real_pos(p->dir_node, off);
}

static inline unsigned long nm_child_ino(unsigned long base, const char *name, int len, bool dirent)
{
    u64 h = (u64)full_name_hash(NULL, name, len) | (dirent ? (1ULL << 32) : 0);
    unsigned int bits, w;

    if ((u64)base >= 0x100000ULL)
        return (unsigned long)(((u64)base & ~0xFFFFFULL) + 0x100000ULL +
                               hash_64(h ^ ((u64)base << 32), 20));

    bits = fls64((u64)base | 0xFFFULL);
    w = bits - 2;
    return (unsigned long)((1ULL << (bits + 1)) +
                           hash_64(h ^ ((u64)base << 32), w));
}

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

    rcu_read_lock();
    hash_for_each_possible_rcu(proxy->dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == namelen && memcmp(child->name, name, namelen) == 0) {
            if (nm_child_visible(child)) {
                if ((child->flags & NM_FLAG_SHADOWS_STOCK) &&
                    !(child->flags & NM_FLAG_WHITEOUT)) {
                    u64 fino = child->fake_ino;
                    unsigned char dt = child->d_type;

                    rcu_read_unlock();
                    nm_proxy_note(proxy, offset);
                    proxy->orig_ctx->pos = proxy->ctx.pos;
                    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen,
                                                 offset, fino, dt);
                    proxy->ctx.pos = proxy->orig_ctx->pos;
                    if (ret == NM_ACTOR_CONTINUE) proxy->emitted++;
                    else proxy->refused = true;
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
    if (proxy->dir_info)
        ino = nm_dirent_ino(proxy->dir_info, name, namelen);
    nm_proxy_note(proxy, offset);
    proxy->orig_ctx->pos = proxy->ctx.pos;
    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino, d_type);
    proxy->ctx.pos = proxy->orig_ctx->pos;
    if (ret == NM_ACTOR_CONTINUE) proxy->emitted++;
    else proxy->refused = true;

    return ret;
}

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

/* The injected tail of a listing, after the real entries, at base + gap + k where k counts
 * only the children THIS caller may see. Child ids are shared by every caller, so packing
 * by id left a gap wherever a sibling hidden from the reader sat (eo-7 c). gap comes from
 * nm_tail_gap(): 0 where the real pass handed out dense indices, 1 elsewhere.
 *
 * True when it found a child to offer, emitted or not. A pass that found none leaves the
 * caller's position where the real filesystem left it: every stock fs keeps f_pos unchanged
 * on a getdents that returns nothing. */
static bool nm_emit_tail(struct dir_context *ctx, struct nomount_dir_node *dir_node,
                         loff_t base, bool real_pass_done, loff_t gap)
{
    struct nomount_child_node *child;
    loff_t skip = 0, k = 0;
    bool any = false;
    int id = 0;

    if (!dir_node || !base) return false;
    if (ctx->pos >= base + gap && ctx->pos <= base + NM_POS_HEADROOM)
        skip = ctx->pos - base - gap;

    if (!atomic_inc_not_zero(&dir_node->refcount)) return false;

    for (;;) {
        char name[NAME_MAX + 1];
        int found = -1, nlen = 0;
        u64 fino = 0;
        unsigned char dt = 0;

        rcu_read_lock();
        while ((child = idr_get_next(&dir_node->children_idr, &id)) != NULL) {
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
        id = found + 1;
        if (k < skip) {
            k++;
            continue;
        }
        any = true;
        ctx->pos = base + gap + k;
        if (!dir_emit(ctx, name, nlen, fino, dt))
            break;
        k++;
        ctx->pos = base + gap + k;
    }

    nm_dir_node_put(dir_node);
    return any;
}

static inline bool nomount_emit_virtual_children(struct dir_context *ctx, struct nomount_dir_node *dir_node,
                                                 bool real_pass_done, loff_t gap)
{
    return dir_node && nm_emit_tail(ctx, dir_node, READ_ONCE(dir_node->real_eof), real_pass_done, gap);
}

static void nm_mirror_blocks(const struct nm_inode_info *info, struct inode *v_inode,
                             const struct path *backing, struct kstat *stat);

static inline bool nm_victim_is_overlay(const struct super_block *sb)
{
#ifdef OVERLAYFS_SUPER_MAGIC
    return sb && sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#else
    return false;
#endif
}

/* A merged overlay directory hands out dense indices, 0..N-1 ending at N, so stock's
 * terminal d_off is the entry count and the tail has to start AT N: one position of gap
 * there made the terminal entries + 1 (engine-oracles-5). Sparse spaces -- erofs byte
 * offsets, ext4/f2fs hash cookies, an overlay directory passed through to one layer --
 * keep the gap that separates the tail from the fs's own positions. */
static inline loff_t nm_tail_gap(const struct super_block *sb, loff_t base, loff_t max_pos)
{
    return (nm_victim_is_overlay(sb) && base > 0 && max_pos + 1 == base) ? 0 : 1;
}

/* Whether a caller the rule does not serve may share the injected inode, with its ops
 * handing it the stock file: a regular file standing in for a stock regular file, off
 * overlayfs. A directory builds its children per caller, a type change answers with the
 * wrong ops, and an overlay victim maps through the overlay's own mapping -- those keep a
 * per-caller dentry, as before. */
static __always_inline bool nm_shareable_stock(umode_t vmode, const struct path *s_path,
                                               const struct super_block *vsb, u32 flags)
{
    struct inode *si;

    if (!(flags & NM_FLAG_SHADOWS_STOCK) ||
        (flags & (NM_FLAG_WHITEOUT | NM_FLAG_VIRTUAL_DIR | NM_FLAG_STOCK_ONLY)) ||
        !s_path->dentry || nm_victim_is_overlay(vsb))
        return false;
    si = d_backing_inode(s_path->dentry);
    return si && S_ISREG(si->i_mode) && S_ISREG(vmode);
}

/* What an absent name answers: a create-type lookup on a read-only victim says EROFS, as
 * it does for a name that is not there at all. */
static __always_inline int nm_absent_errno(const struct inode *ino, unsigned int flags)
{
    return ((flags & LOOKUP_CREATE) && ino && IS_RDONLY(ino)) ? -EROFS : -ENOENT;
}

static struct inode *nomount_create_new_inode(struct super_block *virtual_sb, struct nm_rule_info *rule_info)
{
    struct inode *inode;
    struct nm_inode_info *info;

    inode = new_inode(virtual_sb);
    if (unlikely(!inode)) return NULL;

    info = kmem_cache_alloc(nm_inode_cachep, GFP_KERNEL | __GFP_ZERO);
    if (unlikely(!info)) {
        iput(inode);
        return NULL;
    }

    info->flags = rule_info->flags;
    info->gen = rule_info->gen;
    info->v_ctx_len = rule_info->v_ctx_len;
    if (rule_info->v_ctx_len) memcpy(info->v_ctx, rule_info->v_ctx, rule_info->v_ctx_len + 1);
    info->dir_node = rule_info->this_dir;
    if (info->dir_node) atomic_inc(&info->dir_node->refcount);
    info->dsnap = NULL;
    spin_lock_init(&info->dsnap_lock);
    if (rule_info->flags & NM_FLAG_VIRTUAL_DIR) {
        info->r_path.dentry = NULL;
        info->r_path.mnt = NULL;
    } else {
        info->r_path = rule_info->r_path;
        path_get(&info->r_path);
    }
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
    NM_BTIME_COPY(info->v_btime, rule_info->v_btime);
    info->v_attributes = rule_info->v_attributes;
    info->v_attr_mask = rule_info->v_attr_mask;
    info->v_blksize = rule_info->v_blksize;
    info->v_cratio = rule_info->v_cratio;
    info->v_result_mask = rule_info->v_result_mask;
    info->v_dio_mem = rule_info->v_dio_mem;
    info->v_dio_off = rule_info->v_dio_off;
    info->v_cap = rule_info->v_cap;
    info->v_fa = rule_info->v_fa;
    info->v_cfile = rule_info->v_cfile;
    info->v_scope = rule_info->v_scope;
    if ((rule_info->flags & NM_FLAG_HAVE_VOWN) && !(rule_info->flags & NM_FLAG_VIRTUAL_DIR)) {
        info->v_mode = rule_info->v_mode;
        info->v_uid = rule_info->v_uid;
        info->v_gid = rule_info->v_gid;
    }

    inode->i_private = info;
    inode->i_ino = rule_info->v_ino;
    if (rule_info->flags & NM_FLAG_VIRTUAL_DIR) {
        inode->i_mode = S_IFDIR | (rule_info->v_mode ? rule_info->v_mode : 0755);
        inode->i_size = 4096;
        /* What FIOQSIZE reads. overlayfs never sets i_blocks, so stock answers 0 there. */
        inode->i_blocks = nm_victim_is_overlay(virtual_sb) ? 0 : 8;
        inode->i_uid = rule_info->v_uid;
        inode->i_gid = rule_info->v_gid;
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
        if (rule_info->v_ctx_len)
            security_inode_notifysecctx(inode, rule_info->v_ctx, rule_info->v_ctx_len);
        inode->i_op = &nm_dir_iops;
        inode->i_fop = &nm_dir_fops;
    } else {
        struct inode *real_inode = d_backing_inode(rule_info->r_path.dentry);
        inode->i_mode = real_inode->i_mode;
        /* Always the module's size. FIONREAD reads it straight off this inode, so a caller
         * served the stock file through it sees the module's (eo-6), but kernel_read_file()
         * sizes .ko and firmware loads from it too, and those readers ARE served the module:
         * one inode holds one size. eo-6 needs the ioctl itself to ask the served file. */
        inode->i_size = i_size_read(real_inode);
        inode->i_blocks = real_inode->i_blocks;
        /* FIOQSIZE reads i_blocks, so it has to agree with what getattr reports. */
        if (nm_victim_is_overlay(virtual_sb)) {
            inode->i_blocks = 0;
        } else {
            struct kstat kst = { .mode = real_inode->i_mode, .size = inode->i_size,
                                 .blocks = real_inode->i_blocks };

            nm_mirror_blocks(info, inode, &rule_info->r_path, &kst);
            inode->i_blocks = kst.blocks;
        }
        inode->i_uid = real_inode->i_uid;
        inode->i_gid = real_inode->i_gid;
        if (rule_info->flags & NM_FLAG_HAVE_VOWN) {
            inode->i_mode = (real_inode->i_mode & S_IFMT) | (rule_info->v_mode & 07777);
            inode->i_uid = rule_info->v_uid;
            inode->i_gid = rule_info->v_gid;
        }
        nm_sync_inode_times(inode, real_inode);
       if (S_ISDIR(real_inode->i_mode)) {
            set_nlink(inode, real_inode->i_nlink);
            inode->i_op = &nm_dir_iops;
            inode->i_fop = &nm_dir_fops;
        } else {
            bool thp = (rule_info->v_cap & NM_CAP_KNOWN) &&
                       (rule_info->v_cap & NM_CAP_THPMAP);

            inode->i_op = &nm_file_iops;
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
            if (!S_ISLNK(real_inode->i_mode) && real_inode->i_fop && real_inode->i_fop->mmap_prepare)
                inode->i_fop = thp ? &nm_file_fops_mmap_prepare_thp : &nm_file_fops_mmap_prepare;
            else
        #endif
                inode->i_fop = thp ? &nm_file_fops_thp : &nm_file_fops;
        }
        inode->i_mapping = real_inode->i_mapping;
        {
            char ctx[NM_CTX_MAX];
            u16 ctxlen = 0;

            if (rule_info->v_ctx_len) {
                security_inode_notifysecctx(inode, rule_info->v_ctx, rule_info->v_ctx_len);
            } else if (nm_read_secctx(real_inode, ctx, &ctxlen) == 0) {
                security_inode_notifysecctx(inode, ctx, ctxlen);
                memcpy(info->v_ctx, ctx, ctxlen + 1);
                info->v_ctx_len = ctxlen;
            }
        }
    }

    inode->i_flags |= S_NOATIME | S_NOCMTIME | S_NOSEC;
    inode->i_opflags |= IOP_XATTR;
    if (!S_ISLNK(inode->i_mode)) inode->i_opflags |= IOP_NOFOLLOW;

    return inode;
}

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

    rcu_read_lock();
    nm_iop = __get_nm(smp_load_acquire(&dir->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    orig_iop = nm_iop ? nm_iop->orig_iop : NULL;
    pdir = nm_iop ? smp_load_acquire(&nm_iop->dir_node) : NULL;
    if (pdir && !atomic_inc_not_zero(&pdir->refcount)) pdir = NULL;
    rcu_read_unlock();

    if (unlikely(!pdir))
        goto fallback;

    v_hash = full_name_hash(NULL, name, len);
    if (nomount_get_rule_info(pdir, name, len, v_hash, &rule_info, true, true)) {
        /* A caller the rule does not serve still gets the SHARED injected dentry when a
         * regular file replaces a stock regular file (nm_shareable_stock): the inode's ops
         * hand it the stock one. A real dentry of its own would be invalidated by the next
         * caller the rule does serve, and every mapping of it would read "(deleted)". */
        if (!nm_rinfo_served(&rule_info) &&
            !(rule_info.r_path.dentry && d_backing_inode(rule_info.r_path.dentry) &&
              nm_shareable_stock(d_backing_inode(rule_info.r_path.dentry)->i_mode,
                                 &rule_info.s_path, dir->i_sb, rule_info.flags))) {
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
                res = d_splice_alias(new_inode, dentry);
                if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
                ret = res;
                goto out;
            }
        }
        nm_put_rule_info(&rule_info);
    }

fallback:
    {
        /* Any name a rule covers, whoever is asking: a caller the rule leaves on
         * the real file (scoped out, deny-listed, hidden from) or one whose
         * materialization failed. The real dentry it gets must carry
         * nm_d_revalidate, or the next caller -- one the rule does apply to --
         * is handed it straight from the dcache. As upstream's nm_hijacked_lookup.
         */
        bool tagged = pdir && nm_name_has_rule(pdir, name, len,
                                               full_name_hash(NULL, name, len));

        if (tagged)
            nm_tag_passthrough_dentry(dentry);

        if (orig_iop && orig_iop->lookup)
            ret = orig_iop->lookup(dir, dentry, flags);

        /* After the filesystem's lookup, which may set d_op itself (fscrypt and
         * casefold before 6.9) or splice in an alias, on whatever the caller is
         * handed.
         */
        if (tagged && !IS_ERR(ret))
            nm_retag_passthrough_dentry(ret ? ret : dentry);
    }

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
        .refused = false,
    };
    loff_t start;
    int res = 0;

    rcu_read_lock();
    nm_fop = nm_get_fop(smp_load_acquire(&file->f_op));
    orig_fop = nm_fop ? nm_fop->orig_fop : NULL;
    pdir = nm_fop ? smp_load_acquire(&nm_fop->dir_node) : NULL;
    if (pdir && !atomic_inc_not_zero(&pdir->refcount)) pdir = NULL;
    rcu_read_unlock();

    if (unlikely(!orig_fop || !pdir ||
                 (nomount_is_uid_blocked(current_uid().val) &&
                  !READ_ONCE(pdir->has_public))))
        goto do_real_iterate;

    /* erofs: one byte-sorted, erofs-packed listing of the real and the injected entries,
     * whose terminal is the size getattr reports. Appending the injected names after the
     * stock tail broke erofs's order, its d_off stride and its terminal (eo-7 a). */
    if (file_inode(file)->i_sb->s_magic == EROFS_SUPER_MAGIC_V1) {
        int r = nm_hijacked_erofs_listing(file, ctx, pdir, orig_fop);

        if (r <= 0) {
            res = r;
            goto out;
        }
    }

    if (unlikely(nm_is_virtual_pos(pdir, ctx->pos))) {
        nomount_emit_virtual_children(ctx, pdir, true,
                                      nm_tail_gap(file_inode(file)->i_sb, READ_ONCE(pdir->real_eof),
                                                  READ_ONCE(pdir->max_real_pos)));
        goto out;
    }

    start = ctx->pos;
    proxy_ctx.ctx.pos = ctx->pos;
    proxy_ctx.orig_ctx = ctx;
    proxy_ctx.dir_node = pdir;
    proxy_ctx.emitted = 0;

    res = nm_call_iterate(file, &proxy_ctx.ctx, orig_fop);
    ctx->pos = proxy_ctx.ctx.pos;
    /* A pass that listed entries and ran to the end records where the fs ended. One that
     * listed nothing proves nothing: an lseek past the end lands there too. */
    if (res >= 0 && !proxy_ctx.refused && proxy_ctx.emitted > 0)
        WRITE_ONCE(pdir->real_end, ctx->pos);
    if (res < 0 || proxy_ctx.emitted > 0 || proxy_ctx.refused) goto out;

    {
        loff_t base = READ_ONCE(pdir->real_eof);

        /* A pass that began past the published end -- an lseek beyond it -- gets what stock
         * gives there, nothing, and must not move the base every other reader decodes
         * against (em-3). Resuming at the fs's own recorded end is not that. */
        if (base && start > base && start != READ_ONCE(pdir->real_end))
            goto out;
        nm_publish_real_eof(pdir, ctx->pos);
        nomount_emit_virtual_children(ctx, pdir, true,
                                      nm_tail_gap(file_inode(file)->i_sb, READ_ONCE(pdir->real_eof),
                                                  READ_ONCE(pdir->max_real_pos)));
    }
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

static void nomount_hijacked_destroy_inode(struct inode *inode);
/* Defined below, beside the long explanation of why the pin can never be dropped.
 * Declared here because the three hijack paths now take it before publishing. */
static void nm_pin_module(void);

/* The original super_operations behind a hijacked superblock, or NULL.
 *
 * nomount_restore_superblocks() frees the nm_sop with kfree_rcu(), which only waits for
 * readers that are INSIDE an RCU read-side critical section. These callbacks had none:
 * a reader preempted between loading s_op and dereferencing the nm_sop it points at can
 * resume after a full grace period has elapsed and then call through freed memory. The
 * window is teardown-only (restore_superblocks runs from the module exit path), but the
 * call it makes is an indirect one, so landing in freed memory is arbitrary execution.
 *
 * Only the nm_sop read is inside the section, and the pointer is copied out. orig_sop
 * points at the filesystem's own const super_operations, which outlives us, so the call
 * itself MUST stay outside: evict_inode and statfs both sleep, and sleeping under
 * rcu_read_lock is a bug in its own right.
 */
static const struct super_operations *nm_orig_sop(struct super_block *sb)
{
    const struct super_operations *orig = NULL;
    struct nm_sop *nm_sop;

    if (unlikely(!sb))
        return NULL;
    rcu_read_lock();
    nm_sop = __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop,
                      destroy_inode, nomount_hijacked_destroy_inode);
    if (nm_sop)
        orig = nm_sop->orig_sop;
    rcu_read_unlock();
    return orig;
}

static void nm_iop_rcu_free(struct rcu_head *head)
{
    kmem_cache_free(nm_iop_cachep, container_of(head, struct nm_iop, rcu));
}

static void nm_fop_rcu_free(struct rcu_head *head)
{
    kmem_cache_free(nm_fop_cachep, container_of(head, struct nm_fop, rcu));
}

static void nomount_hijacked_destroy_inode(struct inode *inode)
{
    const struct super_operations *orig;
    struct nm_iop *dead_iop = NULL;
    struct nm_fop *dead_fop = NULL;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        if (inode->i_private) {
            struct nm_inode_info *info = inode->i_private;

            WRITE_ONCE(inode->i_private, NULL);
            if (info->r_path.dentry) path_put(&info->r_path);
            if (info->s_path.dentry) path_put(&info->s_path);
            if (info->dir_node) nm_dir_node_put(info->dir_node);
            nm_dsnap_drop(info);
            info->r_path.dentry = NULL;
            info->s_path.dentry = NULL;
            info->dir_node = NULL;
            call_rcu(&info->rcu, nm_inode_info_rcu_free);
        }
    } else {
        /* A hijacked STOCK inode on its way out: this is the one moment that knows the
         * per-inode vtable copies can never be reached again, so it is the only place
         * they can be freed. Read BEFORE orig->destroy_inode() -- that is the
         * filesystem's destructor and it frees the inode, so touching inode->i_op
         * afterwards would itself be a use-after-free.
         *
         * lookup then getattr: nomount_hijack_dir_inode() only installs our lookup when
         * the original had one, and getattr unconditionally, so matching on one field
         * alone would miss half the cases. __get_nm() only matches a table whose field
         * already points at OUR function, so neither probe can claim a foreign vtable.
         *
         * dir_node must already be NULL here: a live rule holds an igrab on this inode,
         * so it cannot be dying. If it is not, something detached without restoring and
         * freeing would orphan a live dir_node -- say so and leak instead. */
        dead_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop,
                            lookup, nomount_hijacked_lookup);
        if (!dead_iop)
            dead_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop,
                                getattr, nomount_hijacked_getattr);
        dead_fop = nm_get_fop(inode->i_fop);
        if (dead_iop && READ_ONCE(dead_iop->dir_node)) {
            WARN_ONCE(1, "nomount: inode dying with a live dir_node on its i_op\n");
            dead_iop = NULL;
        }
        if (dead_fop && READ_ONCE(dead_fop->dir_node)) {
            WARN_ONCE(1, "nomount: inode dying with a live dir_node on its i_fop\n");
            dead_fop = NULL;
        }
    }
    orig = nm_orig_sop(inode->i_sb);
    if (orig && orig->destroy_inode) {
        orig->destroy_inode(inode);
    }
    /* After the destructor: `inode` is gone, these two are not reachable through it any
     * more, and call_rcu() still covers an RCU walker mid-flight through the copy. */
    if (dead_iop)
        call_rcu(&dead_iop->rcu, nm_iop_rcu_free);
    if (dead_fop)
        call_rcu(&dead_fop->rcu, nm_fop_rcu_free);
}

static int nomount_hijacked_drop_inode(struct inode *inode)
{
    const struct super_operations *orig;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        return !inode->i_nlink || inode_unhashed(inode);
    }

    orig = nm_orig_sop(inode->i_sb);
    if (orig && orig->drop_inode) {
        return orig->drop_inode(inode);
    }

    return !inode->i_nlink || inode_unhashed(inode);
}

static void nomount_hijacked_evict_inode(struct inode *inode)
{
    const struct super_operations *orig;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        truncate_inode_pages_final(&inode->i_data);
        clear_inode(inode);
        return;
    }
    orig = nm_orig_sop(inode->i_sb);
    if (orig && orig->evict_inode) {
        orig->evict_inode(inode);
    } else {
        truncate_inode_pages_final(&inode->i_data);
        clear_inode(inode);
    }
}

static __always_inline bool nm_hidden_from_caller(const struct nm_inode_info *info)
{
    return info && !(info->flags & NM_FLAG_SHADOWS_STOCK) && !nm_info_served(info);
}

static __always_inline struct path *nm_stock_for_caller(struct nm_inode_info *info)
{
    if (!info || !info->s_path.dentry) return NULL;
    if (!(info->flags & NM_FLAG_SHADOWS_STOCK)) return NULL;
    return nm_info_served(info) ? NULL : &info->s_path;
}

#ifdef FMODE_NOWAIT
#define NM_FMODE_NOWAIT_ FMODE_NOWAIT
#else
#define NM_FMODE_NOWAIT_ 0
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define NM_FMODE_FROM_REAL (NM_FMODE_NOWAIT_ | FMODE_CAN_ODIRECT)
#else
#define NM_FMODE_FROM_REAL NM_FMODE_NOWAIT_
#endif

static int nm_open(struct inode *inode, struct file *file)
{
    struct nm_inode_info *info = inode->i_private;
    struct file *real_file;

    if (unlikely(!info)) return -ENODEV;
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    {
        struct path *stock = nm_stock_for_caller(info);
        if (unlikely(stock)) {
            real_file = dentry_open(stock, file->f_flags, current_cred());
            if (IS_ERR(real_file)) return PTR_ERR(real_file);
            file->private_data = real_file;
            file->f_mapping = real_file->f_mapping;
            /* This caller reads the stock file: it gets that file's NOWAIT and O_DIRECT
             * answers, not the engine table's (engine-oracles-3). */
            file->f_mode |= real_file->f_mode & NM_FMODE_FROM_REAL;
            return 0;
        }
    }
    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
        file->private_data = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
        if (info->v_cap & NM_CAP_ODIRECT)
            file->f_mode |= FMODE_CAN_ODIRECT;
#endif
        return 0;
    }
    if (unlikely(!info->r_path.dentry)) return -ENODEV;

    /* An f2fs directory refuses O_DIRECT; whether this one takes it is the victim's answer. */
    real_file = dentry_open(&info->r_path,
                            S_ISDIR(inode->i_mode) ? file->f_flags & ~O_DIRECT : file->f_flags,
                            current_cred());
    if (IS_ERR(real_file)) {
        nm_debug("open of backing file denied (relabel the module tree)\n");
        return PTR_ERR(real_file);
    }

    file->private_data = real_file;
#ifdef FMODE_NOWAIT
    /* RWF_NOWAIT is refused on the outer file's f_mode before it reaches nm_read_iter. */
    if (S_ISREG(inode->i_mode) && (info->v_cap & NM_CAP_NOWAIT))
        file->f_mode |= real_file->f_mode & FMODE_NOWAIT;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    if (unlikely(info->v_cap & NM_CAP_ODIRECT))
        file->f_mode |= FMODE_CAN_ODIRECT;
#else
    if (unlikely((file->f_flags & O_DIRECT) && (info->v_cap & NM_CAP_KNOWN) &&
                 !(info->v_cap & NM_CAP_ODIRECT))) {
        fput(real_file);
        file->private_data = NULL;
        return -EINVAL;
    }
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
        switch (whence) {
        case SEEK_END: {
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
        case SEEK_DATA:
        case SEEK_HOLE: {
            struct nm_inode_info *vi = file_inode(file)->i_private;
            struct super_block *sb = file_inode(file)->i_sb;
            loff_t sz = i_size_read(file_inode(file));

            if (vi && vi->dir_node &&
                (sb->s_magic == EROFS_SUPER_MAGIC_V1 || nm_vdir_erofs_size))
                sz = nm_vdir_size(vi->dir_node, sb->s_blocksize);
            if ((unsigned long long)offset >= (unsigned long long)sz)
                return -ENXIO;
            if (whence == SEEK_HOLE)
                offset = sz;
            file->f_pos = offset;
            return offset;
        }
        default:       return -EINVAL;
        }
        return vfs_setpos(file, offset, file_inode(file)->i_sb->s_maxbytes);
    }

    if ((whence == SEEK_END || whence == SEEK_DATA || whence == SEEK_HOLE) &&
        S_ISDIR(file_inode(file)->i_mode)) {
        struct nm_inode_info *di = file_inode(file)->i_private;

        if (di && di->r_path.dentry &&
            real_file->f_path.dentry == di->r_path.dentry) {
            loff_t sz = nm_dsnap_dir_size(file_inode(file), di);

            if (sz > 0) {
                if (whence != SEEK_END) {
                    if ((unsigned long long)offset >= (unsigned long long)sz) return -ENXIO;
                    if (whence == SEEK_HOLE) offset = sz;
                    file->f_pos = offset;
                    return offset;
                }
                offset += sz;
                if (offset < 0) return -EINVAL;
                file->f_pos = offset;
                return offset;
            }
        }
    }

    if (whence == SEEK_DATA || whence == SEEK_HOLE) {
        real_file->f_pos = file->f_pos;
        res = vfs_llseek(real_file, offset, whence);
        file->f_pos = real_file->f_pos;
        return res;
    }

    res = generic_file_llseek_size(file, offset, whence,
                                   file_inode(file)->i_sb->s_maxbytes,
                                   i_size_read(file_inode(real_file)));
    if (res >= 0) real_file->f_pos = res;

    return res;
}

static ssize_t nm_forward_iter(struct kiocb *iocb, struct iov_iter *iter,
                               struct file *real_file, bool is_write)
{
    struct kiocb kio = *iocb;
    ssize_t ret;

    kio.ki_filp = real_file;
    kio.ki_complete = NULL;
    kio.private = NULL;

    ret = is_write ? real_file->f_op->write_iter(&kio, iter)
                   : real_file->f_op->read_iter(&kio, iter);
    iocb->ki_pos = kio.ki_pos;

    return ret;
}

#ifdef FOP_DONTCACHE
static bool nm_takes_dontcache(struct file *file, struct file *real_file)
{
    struct nm_inode_info *info = file_inode(file)->i_private;

    return (real_file->f_op->fop_flags & FOP_DONTCACHE) && info &&
           (info->v_cap & (NM_CAP_KNOWN | NM_CAP_DONTCACHE)) == (NM_CAP_KNOWN | NM_CAP_DONTCACHE);
}
#endif

static ssize_t nm_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct file *real_file = iocb->ki_filp->private_data;

    if (!real_file || !real_file->f_op->read_iter) return -EINVAL;
#ifdef FOP_DONTCACHE
    /* The tables take RWF_DONTCACHE so f2fs victims answer like stock; others refuse here. */
    if (unlikely(iocb->ki_flags & IOCB_DONTCACHE) && !nm_takes_dontcache(iocb->ki_filp, real_file))
        return -EOPNOTSUPP;
#endif
    if (unlikely(iocb->ki_flags & IOCB_DIRECT)) {
        struct inode *vi = file_inode(iocb->ki_filp);

        if (vi->i_sb != file_inode(real_file)->i_sb) {
            struct nm_inode_info *info = vi->i_private;
            unsigned int bs = (info && info->v_dio_off) ? info->v_dio_off :
                              (vi->i_sb->s_blocksize ? vi->i_sb->s_blocksize : 4096);
            unsigned int mask = bs - 1;

            if (!iov_iter_count(to))
                return 0;
            if ((iocb->ki_pos | iov_iter_count(to) | iov_iter_alignment(to)) & mask)
                return -EINVAL;
        }
    }
    return nm_forward_iter(iocb, to, real_file, false);
}

static ssize_t nm_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *real_file = iocb->ki_filp->private_data;

    if (!real_file || !real_file->f_op->write_iter) return -EINVAL;
#ifdef FOP_DONTCACHE
    if (unlikely(iocb->ki_flags & IOCB_DONTCACHE) && !nm_takes_dontcache(iocb->ki_filp, real_file))
        return -EOPNOTSUPP;
#endif
    return nm_forward_iter(iocb, from, real_file, true);
}

static int nm_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct file *real_file = file->private_data;

    if (!real_file) return -ENODEV;
    return generic_file_readonly_mmap(file, vma);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
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

/* The cmds every filesystem with an ioctl answers alike; anything else is the backing fs's own.
 * Overlay's ioctl (before 5.13) knows the flags but not FS_IOC_GETVERSION. */
static bool nm_ioctl_generic(unsigned int cmd, const struct super_block *vsb)
{
    switch (cmd) {
    case FS_IOC_GETVERSION:
#if defined(FS_IOC32_GETVERSION) && BITS_PER_LONG == 64
    case FS_IOC32_GETVERSION:
#endif
#ifdef OVERLAYFS_SUPER_MAGIC
        if (vsb->s_magic == OVERLAYFS_SUPER_MAGIC)
            return false;
#endif
        return true;
    case FS_IOC_GETFLAGS:
#ifdef FS_IOC_FSGETXATTR
    case FS_IOC_FSGETXATTR:
#endif
#if defined(FS_IOC32_GETFLAGS) && BITS_PER_LONG == 64
    case FS_IOC32_GETFLAGS:
#endif
        return true;
    }
    return false;
}

/* erofs, or an overlay over it: an unsampled path there gets erofs's answer. */
static bool nm_victim_ro_image(const struct super_block *sb)
{
#ifdef OVERLAYFS_SUPER_MAGIC
    if (sb->s_magic == OVERLAYFS_SUPER_MAGIC)
        return true;
#endif
    return sb->s_magic == EROFS_SUPER_MAGIC_V1;
}

static long nm_ioctl_as_stock(struct file *file, unsigned int cmd, unsigned long arg, bool compat)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    const struct path *src;
    struct file *sf;
    long ret;

    if (unlikely(!info))
        return -ENOTTY;

    /* Answer as the stock file where there is one; otherwise from the file we serve, but
     * only as far as the VICTIM answers ioctls at all. The backing file is f2fs: asking it
     * blindly made FS_IOC_GETVERSION succeed on injected /product files whose erofs and
     * overlay siblings all answer -ENOTTY. */
    src = info->s_path.dentry ? &info->s_path
        : info->r_path.dentry ? &info->r_path
        : NULL;
    if (!src)
        return -ENOTTY;

    if (!info->s_path.dentry) {
        struct super_block *vsb = file_inode(file)->i_sb;

        if ((info->v_cap & NM_CAP_KNOWN) ? !(info->v_cap & NM_CAP_IOCTL) : nm_victim_ro_image(vsb))
            return -ENOTTY;
        if (src->dentry->d_sb->s_magic != vsb->s_magic && !nm_ioctl_generic(cmd, vsb))
            return -ENOTTY;
    }

    {
        struct inode *si = d_backing_inode(src->dentry);

        if (si && si->i_fop && !si->i_fop->unlocked_ioctl
#ifdef CONFIG_COMPAT
            && !si->i_fop->compat_ioctl
#endif
           )
            return -ENOTTY;
    }

    sf = dentry_open(src, O_RDONLY | O_LARGEFILE, current_cred());
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

static long nm_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->fallocate) return -EOPNOTSUPP;
    return real_file->f_op->fallocate(real_file, mode, offset, len);
}

static u16 nm_size_ratio(loff_t size, blkcnt_t blocks)
{
    u64 alloc = (u64)blocks << 9;
    u64 r;

    if (size < 8192 || alloc == 0)
        return 0;
    r = div64_u64(alloc << 10, (u64)size);
    /* At or above 1:1 the sample was stored uncompressed; 0 says so. */
    if (r >= 1024)
        return 0;
    if (r < 128) r = 128;
    if (r > 896) r = 896;
    return (u16)r;
}

/* st_blocks in the victim's units. The backing file is f2fs, which counts an inline file
 * in 512-byte sectors; an erofs or overlay file is always whole blocks, and exactly
 * round_up(size) unless it is compressed. A same-type backing fs keeps its own count. */
static void nm_mirror_blocks(const struct nm_inode_info *info, struct inode *v_inode,
                             const struct path *backing, struct kstat *stat)
{
    u64 bs = info->v_blksize ? info->v_blksize : v_inode->i_sb->s_blocksize;
    u64 want, rup, cap;
    bool compressed = info->v_cratio != 0;

    if (backing->dentry && backing->dentry->d_sb->s_magic == v_inode->i_sb->s_magic)
        return;
    /* ext4 fast symlinks count 0 blocks; erofs and overlay ones are whole blocks too. */
    if (!S_ISREG(stat->mode) && !(S_ISLNK(stat->mode) && nm_victim_ro_image(v_inode->i_sb)))
        return;
    if (!bs || (bs & (bs - 1)))
        bs = 4096;
#ifdef STATX_ATTR_COMPRESSED
    if (info->v_attr_mask & STATX_ATTR_COMPRESSED)
        compressed = compressed && (info->v_attributes & STATX_ATTR_COMPRESSED);
#endif
    rup = ((u64)stat->size + bs - 1) & ~(bs - 1);
    if (!compressed || (u64)stat->size <= bs) {
        stat->blocks = (blkcnt_t)(rup >> 9);
        return;
    }
    want = div64_u64((u64)stat->size * info->v_cratio, 1024);
    want = (want + bs - 1) & ~(bs - 1);
    cap = rup - bs;
    if (want > cap)
        want = cap;
    stat->blocks = (blkcnt_t)((want ? want : rup) >> 9);
}

static int nomount_hijacked_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct inode *inode = d_backing_inode(dentry);
    const struct super_operations *orig;

    if (inode && (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) &&
        unlikely(nm_hidden_from_caller(inode->i_private)))
        return -ENOENT;

    orig = nm_orig_sop(dentry->d_sb);
    if (orig && orig->statfs)
        return orig->statfs(dentry, buf);
    return -ENOSYS;
}

static u8 nm_stock_caps(struct inode *ino)
{
    u8 cap = NM_CAP_KNOWN;

    if (!ino) return 0;
    if (ino->i_fop && ino->i_fop->fsync) cap |= NM_CAP_FSYNC;
    if (ino->i_fop && ino->i_fop->get_unmapped_area) cap |= NM_CAP_THPMAP;
    if (ino->i_fop && (ino->i_fop->unlocked_ioctl
#ifdef CONFIG_COMPAT
                       || ino->i_fop->compat_ioctl
#endif
                      ))
        cap |= NM_CAP_IOCTL;
#ifdef FOP_DONTCACHE
    if (ino->i_fop && (ino->i_fop->fop_flags & FOP_DONTCACHE)) cap |= NM_CAP_DONTCACHE;
#endif
    return cap;
}

/* What the stock file's own ->open grants: O_DIRECT, and FMODE_NOWAIT (f2fs, ext4). */
static u8 nm_stock_open_caps(struct path *p)
{
    struct file *f;
    u8 cap = 0;

    if (!p || !p->dentry) return 0;
    f = dentry_open(p, O_RDONLY | O_DIRECT | O_LARGEFILE, current_cred());
    if (!IS_ERR(f))
        cap |= NM_CAP_ODIRECT;
    else if (d_is_reg(p->dentry))
        f = dentry_open(p, O_RDONLY | O_LARGEFILE, current_cred());
    if (IS_ERR(f)) return cap;
#ifdef FMODE_NOWAIT
    if (f->f_mode & FMODE_NOWAIT) cap |= NM_CAP_NOWAIT;
#endif
    fput(f);
    return cap;
}

static int nm_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct file *real_file = file->private_data;
    struct nm_inode_info *info = file_inode(file)->i_private;

    if (info && (info->v_cap & NM_CAP_KNOWN) && !(info->v_cap & NM_CAP_FSYNC))
        return -EINVAL;
    if (info && !(info->v_cap & NM_CAP_KNOWN) &&
        file_inode(file)->i_sb->s_magic == EROFS_SUPER_MAGIC_V1)
        return -EINVAL;
    if (!real_file || !real_file->f_op->fsync) return -EINVAL;
    return real_file->f_op->fsync(real_file, start, end, datasync);
}

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
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    stock = nm_stock_for_caller(info);
    if (unlikely(stock)) {
        struct inode *si = d_backing_inode(stock->dentry);

        if (!si || !si->i_op || !si->i_op->listxattr) return -EOPNOTSUPP;
        return si->i_op->listxattr(stock->dentry, buffer, size);
    }
    if (info->flags & NM_FLAG_VIRTUAL_DIR) {
        if (!info->v_ctx_len) return 0;
        if (!size) return sizeof(nm_selinux_name);
        if (size < sizeof(nm_selinux_name)) return -ERANGE;
        memcpy(buffer, nm_selinux_name, sizeof(nm_selinux_name));
        return sizeof(nm_selinux_name);
    }
    if (unlikely(!d_backing_inode(info->r_path.dentry)->i_op->listxattr))
        return -EOPNOTSUPP;

    return d_backing_inode(info->r_path.dentry)->i_op->listxattr(info->r_path.dentry, buffer, size);
}

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

#define NM_EROFS_DIRENT_SZ 12

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
# define NM_PARENT_INO(dentry) d_parent_ino(dentry)
#else
# define NM_PARENT_INO(dentry) parent_ino(dentry)
#endif

struct nm_epack {
    unsigned int blocksize;
    loff_t full;
    unsigned int used;
    unsigned int slot;
};

static loff_t nm_epack_step(struct nm_epack *p, unsigned int namelen)
{
    unsigned int need = NM_EROFS_DIRENT_SZ + namelen;
    loff_t off;

    if (p->blocksize && p->used + need > p->blocksize) {
        p->full += p->blocksize;
        p->used = 0;
        p->slot = 0;
    }
    off = p->full + (loff_t)NM_EROFS_DIRENT_SZ * p->slot;
    p->used += need;
    p->slot++;
    return off;
}

static inline loff_t nm_epack_end(const struct nm_epack *p)
{
    return p->full + p->used;
}

/* ---- erofs-shaped listings ----------------------------------------------------------
 *
 * Every valid erofs directory is strictly byte-sorted (lookup binary-searches it), its
 * d_off steps by the 12-byte dirent within a block, and its terminal is i_size. A listing
 * the engine serves on an erofs victim is built to the same shape: one sorted stream,
 * offsets from nm_epack, terminal == the size getattr reports, and nothing past it. */
struct nm_lent {
    const char *name;
    u16 len;
    u8  dt;
    u64 ino;
};

static int nm_lent_cmp(const void *a, const void *b)
{
    const struct nm_lent *x = a, *y = b;
    int r = memcmp(x->name, y->name, min(x->len, y->len));

    if (r) return r;
    return (int)x->len - (int)y->len;
}

/* The injected entries a caller may see in a listing, byte-sorted. skip_shadow leaves out
 * children served in place of a stock entry of the same name. */
struct nm_ltail {
    struct nm_lent *e;
    char *names;
    unsigned int n;
};

static void nm_ltail_free(struct nm_ltail *t)
{
    kvfree(t->e);
    kvfree(t->names);
    t->e = NULL;
    t->names = NULL;
    t->n = 0;
}

static int nm_ltail_collect(struct nomount_dir_node *d, bool skip_shadow, unsigned int extra,
                            struct nm_ltail *t)
{
    struct nomount_child_node *ch;
    unsigned int cap = extra, bytes = 0, n = 0, off = 0;
    int id;

    memset(t, 0, sizeof(*t));
    if (d) {
        rcu_read_lock();
        idr_for_each_entry(&d->children_idr, ch, id) {
            cap++;
            bytes += min_t(unsigned int, ch->name_len, NAME_MAX);
        }
        rcu_read_unlock();
    }
    /* Room for adds racing the count; a listing never truncates silently below. */
    cap += 16;
    bytes += 16 * NAME_MAX;
    t->e = kvmalloc_array(cap, sizeof(*t->e), GFP_KERNEL | __GFP_NOWARN);
    t->names = kvmalloc(bytes, GFP_KERNEL | __GFP_NOWARN);
    if (!t->e || !t->names) {
        nm_ltail_free(t);
        return -ENOMEM;
    }
    if (d) {
        rcu_read_lock();
        idr_for_each_entry(&d->children_idr, ch, id) {
            unsigned int l = min_t(unsigned int, ch->name_len, NAME_MAX);

            if (!nm_child_visible(ch) || (ch->flags & NM_FLAG_WHITEOUT))
                continue;
            if (skip_shadow && (ch->flags & NM_FLAG_SHADOWS_STOCK))
                continue;
            if (n + extra >= cap || off + l > bytes) {
                rcu_read_unlock();
                nm_ltail_free(t);
                return -EAGAIN;
            }
            memcpy(t->names + off, ch->name, l);
            t->e[n].name = t->names + off;
            t->e[n].len = (u16)l;
            t->e[n].dt = ch->d_type;
            t->e[n].ino = ch->fake_ino;
            off += l;
            n++;
        }
        rcu_read_unlock();
    }
    t->n = n;
    return 0;
}

/* Emit a sorted array erofs-shaped. At or past the end, f_pos stays where it was. */
static void nm_emit_lents(struct dir_context *ctx, const struct nm_lent *e, unsigned int n,
                          unsigned int blocksize)
{
    struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
    loff_t start = ctx->pos < 0 ? 0 : ctx->pos;
    bool emitting = false, full = false;
    unsigned int i;

    for (i = 0; i < n; i++) {
        loff_t off = nm_epack_step(&pk, e[i].len);

        if (!emitting) {
            if (off < start) continue;
            emitting = true;
        }
        ctx->pos = off;
        if (!dir_emit(ctx, e[i].name, e[i].len, e[i].ino, e[i].dt)) {
            full = true;
            break;
        }
    }
    if (!full && start < nm_epack_end(&pk))
        ctx->pos = nm_epack_end(&pk);
}

static loff_t nm_lents_size(const struct nm_lent *e, unsigned int n, unsigned int blocksize)
{
    struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
    unsigned int i;

    for (i = 0; i < n; i++)
        nm_epack_step(&pk, e[i].len);
    return nm_epack_end(&pk);
}

/* A synthesized directory: "." and ".." and the visible children, sorted together as
 * mkfs.erofs sorts them. Slots 0 and 1 of the tail are reserved for the dots. */
static int nm_vdir_lents(struct nomount_dir_node *d, u64 dot_ino, u64 dotdot_ino,
                         struct nm_ltail *t)
{
    unsigned int i;
    int err = nm_ltail_collect(d, false, 2, t);

    if (err)
        return err;
    for (i = t->n; i > 0; i--)
        t->e[i + 1] = t->e[i - 1];
    t->e[0] = (struct nm_lent){ .name = ".", .len = 1, .dt = DT_DIR, .ino = dot_ino };
    t->e[1] = (struct nm_lent){ .name = "..", .len = 2, .dt = DT_DIR, .ino = dotdot_ino };
    t->n += 2;
    sort(t->e, t->n, sizeof(*t->e), nm_lent_cmp, NULL);
    return 0;
}

static loff_t nm_vdir_size(struct nomount_dir_node *d, unsigned int blocksize)
{
    struct nm_ltail t;
    loff_t sz;

    if (nm_vdir_lents(d, 0, 0, &t)) {
        /* Out of memory: the same names packed unsorted, which can only differ at a
         * block boundary -- better than a size that ignores the children. */
        struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
        struct nomount_child_node *ch;
        int id;

        nm_epack_step(&pk, 1);
        nm_epack_step(&pk, 2);
        if (d) {
            rcu_read_lock();
            idr_for_each_entry(&d->children_idr, ch, id)
                if (nm_child_visible(ch) && !(ch->flags & NM_FLAG_WHITEOUT))
                    nm_epack_step(&pk, min_t(unsigned int, ch->name_len, NAME_MAX));
            rcu_read_unlock();
        }
        return nm_epack_end(&pk);
    }
    sz = nm_lents_size(t.e, t.n, blocksize);
    nm_ltail_free(&t);
    return sz;
}

static int nm_vdir_iterate_erofs(struct file *file, struct dir_context *ctx,
                                 struct nm_inode_info *info,
                                 struct nomount_dir_node *d,
                                 unsigned int blocksize)
{
    struct inode *v_inode = file_inode(file);
    u64 dot = (info->flags & NM_FLAG_OVL_INO)
            ? (info->v_dino ? info->v_dino : info->v_ino) : v_inode->i_ino;
    u64 dotdot = (info->flags & NM_FLAG_OVL_INO)
               ? (info->v_pdino ? info->v_pdino : info->v_ino)
               : NM_PARENT_INO(file->f_path.dentry);
    struct nm_ltail t;

    if (d && !atomic_inc_not_zero(&d->refcount)) d = NULL;
    if (nm_vdir_lents(d, dot, dotdot, &t)) {
        if (d) nm_dir_node_put(d);
        return -ENOMEM;
    }
    nm_emit_lents(ctx, t.e, t.n, blocksize);
    nm_ltail_free(&t);
    if (d) nm_dir_node_put(d);
    return 0;
}

/* A hijacked erofs directory's own entries, "." and ".." included, in on-disk order --
 * which is byte order. Read once: the image does not change under us. */
struct nm_rent {
    u32 noff;
    u16 len;
    u8  dt;
    u64 ino;
    loff_t roff;        /* the offset erofs itself gave this entry */
};

struct nm_rlist {
    bool ok;            /* false: too large to serve this way, use the append path */
    unsigned int n;
    struct nm_rent *ent;
    char *names;
};

#define NM_RLIST_MAX_ENTS  4096
#define NM_RLIST_MAX_BYTES (128 * 1024)

/* Sized by a counting pass first, so a five-entry directory holds five entries rather
 * than the worst case: there is one of these per hijacked erofs directory. */
struct nm_rlist_walk {
    struct dir_context ctx;
    struct nm_rlist *rl;    /* NULL: count only */
    unsigned int n;
    unsigned int nbytes;
    unsigned int cap_n, cap_bytes;
    bool overflow;
};

static NM_ACTOR_RET nm_rlist_actor(struct dir_context *ctx, const char *name, int namelen,
                                   loff_t off, u64 ino, unsigned int dt)
{
    struct nm_rlist_walk *w = container_of(ctx, struct nm_rlist_walk, ctx);
    struct nm_rlist *rl = w->rl;

    if (namelen <= 0 || namelen > NAME_MAX || w->n >= w->cap_n ||
        w->nbytes + (unsigned int)namelen > w->cap_bytes) {
        w->overflow = true;
        return !NM_ACTOR_CONTINUE;
    }
    if (!rl) {
        w->n++;
        w->nbytes += (unsigned int)namelen;
        return NM_ACTOR_CONTINUE;
    }
    rl->ent[rl->n].noff = w->nbytes;
    rl->ent[rl->n].len = (u16)namelen;
    rl->ent[rl->n].dt = (u8)dt;
    rl->ent[rl->n].ino = ino;
    rl->ent[rl->n].roff = off;
    memcpy(rl->names + w->nbytes, name, namelen);
    w->nbytes += (unsigned int)namelen;
    w->n++;
    rl->n++;
    return NM_ACTOR_CONTINUE;
}

/* kvfree, from an RCU callback too: vfree defers itself in interrupt context. */
static void nm_rlist_free(struct nm_rlist *rl)
{
    if (!rl) return;
    kvfree(rl->ent);
    kvfree(rl->names);
    kfree(rl);
}

/* With the directory's lock held shared, through the filesystem's own iterate: our fop
 * is on the file, and going through it would come straight back here. NULL is transient
 * (out of memory); a list with !ok is the verdict "too large", kept so it is not retried. */
static struct nm_rlist *nm_rlist_build(struct file *file, const struct file_operations *orig_fop)
{
    struct nm_rlist_walk c = { .ctx.actor = nm_rlist_actor, .cap_n = NM_RLIST_MAX_ENTS,
                               .cap_bytes = NM_RLIST_MAX_BYTES };
    struct nm_rlist_walk w = { .ctx.actor = nm_rlist_actor };
    struct nm_rlist *rl = kzalloc(sizeof(*rl), GFP_KERNEL | __GFP_NOWARN);

    if (!rl) return NULL;
    c.ctx.pos = 0;
    if (nm_call_iterate(file, &c.ctx, orig_fop) < 0) {
        nm_rlist_free(rl);
        return NULL;
    }
    if (c.overflow || c.n < 2)
        return rl;                  /* ok == false: served by the append path */
    rl->ent = kvmalloc_array(c.n, sizeof(*rl->ent), GFP_KERNEL | __GFP_NOWARN);
    rl->names = kvmalloc(c.nbytes ? c.nbytes : 1, GFP_KERNEL | __GFP_NOWARN);
    if (!rl->ent || !rl->names) {
        nm_rlist_free(rl);
        return NULL;
    }
    w.rl = rl;
    w.cap_n = c.n;
    w.cap_bytes = c.nbytes;
    w.ctx.pos = 0;
    if (nm_call_iterate(file, &w.ctx, orig_fop) < 0) {
        nm_rlist_free(rl);
        return NULL;
    }
    rl->ok = !w.overflow && rl->n == c.n;
    /* Only where nm_epack reproduces this image exactly -- every real offset and the
     * terminal -- so a caller shown no injected entry still gets a byte-identical listing
     * from the merged path. Otherwise the append path serves it, as before. */
    if (rl->ok) {
        struct nm_epack pk = { .blocksize = file_inode(file)->i_sb->s_blocksize,
                               .full = 0, .used = 0, .slot = 0 };
        unsigned int i;

        for (i = 0; i < rl->n && rl->ok; i++)
            if (nm_epack_step(&pk, rl->ent[i].len) != rl->ent[i].roff)
                rl->ok = false;
        if (rl->ok && nm_epack_end(&pk) != i_size_read(file_inode(file)))
            rl->ok = false;
        for (i = 1; i < rl->n && rl->ok; i++) {
            const struct nm_rent *x = &rl->ent[i - 1], *y = &rl->ent[i];
            struct nm_lent a = { .name = rl->names + x->noff, .len = x->len };
            struct nm_lent b = { .name = rl->names + y->noff, .len = y->len };

            if (nm_lent_cmp(&a, &b) >= 0)
                rl->ok = false;
        }
        if (!rl->ok)
            nm_debug("erofs listing of ino %lu does not match the packing model; appending\n",
                     file_inode(file)->i_ino);
    }
    if (!rl->ok) {
        kvfree(rl->ent);
        kvfree(rl->names);
        rl->ent = NULL;
        rl->names = NULL;
        rl->n = 0;
    }
    return rl;
}

static struct nm_rlist *nm_rlist_get(struct nomount_dir_node *d, struct file *file,
                                     const struct file_operations *orig_fop)
{
    struct nm_rlist *rl = smp_load_acquire(&d->rlist);

    if (!rl && file && orig_fop) {
        struct nm_rlist *nrl = nm_rlist_build(file, orig_fop);

        if (!nrl)
            return NULL;
        if (cmpxchg(&d->rlist, NULL, nrl) != NULL)
            nm_rlist_free(nrl);
        rl = smp_load_acquire(&d->rlist);
    }
    return (rl && rl->ok) ? rl : NULL;
}

/* Built when a directory is hijacked, so getattr never has to read it. */
static void nm_rlist_prime(struct nomount_dir_node *d, const struct path *p, struct inode *dir)
{
    const struct file_operations *orig_fop = NULL;
    const struct cred *old;
    struct nm_fop *nf;
    struct file *f;

    if (!d || smp_load_acquire(&d->rlist) || dir->i_sb->s_magic != EROFS_SUPER_MAGIC_V1)
        return;
    rcu_read_lock();
    nf = nm_get_fop(smp_load_acquire(&dir->i_fop));
    orig_fop = nf ? nf->orig_fop : NULL;
    rcu_read_unlock();
    if (!orig_fop)
        return;
    old = override_creds(nm_root_cred);
    f = dentry_open(p, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);
    if (!IS_ERR(f)) {
        inode_lock_shared(dir);
        nm_rlist_get(d, f, orig_fop);
        inode_unlock_shared(dir);
        fput(f);
    }
    revert_creds(old);
}

/* What this caller gets in place of a stock entry: itself, a shadowing child's identity,
 * or nothing (a whiteout or a hidden-for-it name). The proxy actor's rule, in one place. */
static bool nm_real_entry_for_caller(struct nomount_dir_node *d, struct nm_lent *e)
{
    struct nomount_child_node *child;
    u32 hash = full_name_hash(NULL, e->name, e->len);
    bool keep = true;

    if (!(READ_ONCE(d->bloom_mask) & (1ULL << (hash & 63))))
        return true;
    rcu_read_lock();
    hash_for_each_possible_rcu(d->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == e->len &&
            memcmp(child->name, e->name, e->len) == 0) {
            if (nm_child_visible(child)) {
                if ((child->flags & NM_FLAG_SHADOWS_STOCK) &&
                    !(child->flags & NM_FLAG_WHITEOUT)) {
                    e->ino = child->fake_ino;
                    e->dt = child->d_type;
                } else {
                    keep = false;
                }
            }
            break;
        }
    }
    rcu_read_unlock();
    return keep;
}

/* The real list (already in byte order) and this caller's sorted tail, merged. */
struct nm_mwalk {
    const struct nm_rlist *rl;
    const struct nm_ltail *t;
    struct nomount_dir_node *d;
    unsigned int i, j;
};

static bool nm_mwalk_next(struct nm_mwalk *w, struct nm_lent *out)
{
    struct nm_lent r;
    bool have_r = false;

    while (w->i < w->rl->n) {
        const struct nm_rent *re = &w->rl->ent[w->i];

        r.name = w->rl->names + re->noff;
        r.len = re->len;
        r.dt = re->dt;
        r.ino = re->ino;
        if (nm_real_entry_for_caller(w->d, &r)) {
            have_r = true;
            break;
        }
        w->i++;
    }
    if (w->j < w->t->n && (!have_r || nm_lent_cmp(&w->t->e[w->j], &r) < 0)) {
        *out = w->t->e[w->j++];
        return true;
    }
    if (have_r) {
        *out = r;
        w->i++;
        return true;
    }
    return false;
}

static int nm_hijacked_erofs_listing(struct file *file, struct dir_context *ctx,
                                     struct nomount_dir_node *pdir,
                                     const struct file_operations *orig_fop)
{
    unsigned int bs = file_inode(file)->i_sb->s_blocksize;
    struct nm_epack pk = { .blocksize = bs, .full = 0, .used = 0, .slot = 0 };
    /* Built lazily only at the start of a listing, so one listing never changes path
     * halfway through: the two paths number positions differently. */
    struct nm_rlist *rl = nm_rlist_get(pdir, ctx->pos == 0 ? file : NULL, orig_fop);
    loff_t start = ctx->pos < 0 ? 0 : ctx->pos;
    bool emitting = false, full = false;
    struct nm_mwalk w;
    struct nm_ltail t;
    struct nm_lent e;

    if (!rl)
        return 1;
    if (nm_ltail_collect(pdir, true, 0, &t))
        return -ENOMEM;
    sort(t.e, t.n, sizeof(*t.e), nm_lent_cmp, NULL);
    w = (struct nm_mwalk){ .rl = rl, .t = &t, .d = pdir, .i = 0, .j = 0 };
    while (nm_mwalk_next(&w, &e)) {
        loff_t off = nm_epack_step(&pk, e.len);

        if (!emitting) {
            if (off < start) continue;
            emitting = true;
        }
        ctx->pos = off;
        if (!dir_emit(ctx, e.name, e.len, e.ino, e.dt)) {
            full = true;
            break;
        }
    }
    if (!full && start < nm_epack_end(&pk))
        ctx->pos = nm_epack_end(&pk);
    nm_ltail_free(&t);
    return 0;
}

static bool nm_hijacked_erofs_size(struct nomount_dir_node *d, unsigned int bs, loff_t *out)
{
    struct nm_epack pk = { .blocksize = bs, .full = 0, .used = 0, .slot = 0 };
    struct nm_rlist *rl = nm_rlist_get(d, NULL, NULL);
    struct nm_mwalk w;
    struct nm_ltail t;
    struct nm_lent e;

    if (!rl || nm_ltail_collect(d, true, 0, &t))
        return false;
    sort(t.e, t.n, sizeof(*t.e), nm_lent_cmp, NULL);
    w = (struct nm_mwalk){ .rl = rl, .t = &t, .d = d, .i = 0, .j = 0 };
    while (nm_mwalk_next(&w, &e))
        nm_epack_step(&pk, e.len);
    *out = nm_epack_end(&pk);
    nm_ltail_free(&t);
    return true;
}

#define NM_DSNAP_MAX_ENTS  1024
#define NM_DSNAP_MAX_BYTES (32 * 1024)

struct nm_dsnap_ent {
    u32 noff;
    u16 len;
    u8  d_type;
};

struct nm_dsnap {
    atomic_t refcount;
    bool ok;
    loff_t stamp_size;
    s64 stamp_sec;
    long stamp_nsec;
    loff_t size;
    unsigned int n;
    unsigned int nbytes;
    struct nm_dsnap_ent *ent;
    char *names;
};

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

    if (namelen == 1 && name[0] == '.') return NM_ACTOR_CONTINUE;
    if (namelen == 2 && name[0] == '.' && name[1] == '.') return NM_ACTOR_CONTINUE;
    if (namelen <= 0 || namelen > NAME_MAX ||
        b->n >= NM_DSNAP_MAX_ENTS ||
        b->nbytes + (unsigned int)namelen > NM_DSNAP_MAX_BYTES) {
        b->overflow = true;
        return !NM_ACTOR_CONTINUE;
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

static struct nm_dsnap *nm_dsnap_make(struct nm_inode_info *info, struct inode *bi,
                                      unsigned int blocksize, bool *transient)
{
    struct nm_dsnap_walk b = { .ctx.actor = nm_dsnap_actor };
    struct nm_epack pk = { .blocksize = blocksize, .full = 0, .used = 0, .slot = 0 };
    const struct cred *old;
    struct file *dir;
    struct nm_dsnap *s;
    struct timespec64 mt;
    unsigned int i, off = 0;
    bool cannot_build = false;

    s = kzalloc(sizeof(*s), GFP_NOFS | __GFP_NOWARN);
    if (!s) { *transient = true; return NULL; }
    atomic_set(&s->refcount, 1);
    mt = nm_inode_mtime(bi);
    s->stamp_size = i_size_read(bi);
    s->stamp_sec = mt.tv_sec;
    s->stamp_nsec = mt.tv_nsec;

    b.ent = kmalloc_array(NM_DSNAP_MAX_ENTS, sizeof(*b.ent), GFP_NOFS | __GFP_NOWARN);
    b.names = kmalloc(NM_DSNAP_MAX_BYTES, GFP_NOFS | __GFP_NOWARN);
    if (!b.ent || !b.names) { cannot_build = true; *transient = true; goto out; }

    old = override_creds(nm_root_cred);
    dir = dentry_open(&info->r_path, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);
    if (!IS_ERR(dir)) {
        if (iterate_dir(dir, &b.ctx) < 0) {
            cannot_build = true;
            *transient = true;
        }
        fput(dir);
    } else {
        nm_debug("cannot open a dir-target's backing directory (relabel the module tree); serving it unmodified\n");
        cannot_build = true;
    }
    revert_creds(old);
    if (cannot_build) goto out;
    if (b.overflow) goto out;

    sort(b.ent, b.n, sizeof(*b.ent), nm_dsnap_cmp, NULL);

    s->ent = kmalloc_array(b.n + 1, sizeof(*s->ent), GFP_NOFS | __GFP_NOWARN);
    s->names = kmalloc(b.nbytes + 1, GFP_NOFS | __GFP_NOWARN);
    if (!s->ent || !s->names) { cannot_build = true; *transient = true; goto out; }

    nm_epack_step(&pk, 1);
    nm_epack_step(&pk, 2);
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
    if (cannot_build) {
        nm_dsnap_free(s);
        return NULL;
    }
    return s;
}

static struct nm_dsnap *nm_dsnap_get_ex(struct nm_inode_info *info, unsigned int blocksize,
                                        bool *transient)
{
    struct nm_dsnap *s, *stale;
    struct inode *bi;

    *transient = false;
    if (!info || !info->r_path.dentry) return NULL;
    if (info->flags & NM_FLAG_VIRTUAL_DIR) return NULL;
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

    s = nm_dsnap_make(info, bi, blocksize, transient);
    if (!s) return NULL;

    spin_lock(&info->dsnap_lock);
    stale = info->dsnap;
    info->dsnap = s;
    atomic_inc(&s->refcount);
    spin_unlock(&info->dsnap_lock);
    nm_dsnap_put(stale);

    if (!s->ok) { nm_dsnap_put(s); return NULL; }
    return s;
}

static struct nm_dsnap *nm_dsnap_get(struct nm_inode_info *info, unsigned int blocksize)
{
    bool transient;

    return nm_dsnap_get_ex(info, blocksize, &transient);
}

static void nm_dsnap_drop(struct nm_inode_info *info)
{
    struct nm_dsnap *s;

    spin_lock(&info->dsnap_lock);
    s = info->dsnap;
    info->dsnap = NULL;
    spin_unlock(&info->dsnap_lock);
    nm_dsnap_put(s);
}

static loff_t nm_dsnap_dir_size(struct inode *v_inode, struct nm_inode_info *info)
{
    struct super_block *sb = v_inode->i_sb;
    unsigned int bs = sb->s_blocksize ? sb->s_blocksize : 4096;
    struct nm_dsnap *s;
    loff_t sz;

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
    /* At or past the end erofs leaves f_pos where it was. */
    if (!full && start < nm_epack_end(&pk))
        ctx->pos = nm_epack_end(&pk);
    return 0;
}

#if defined(STATX_DIOALIGN) && defined(STATX_BTIME)
#define NM_STATX_WANT (STATX_BASIC_STATS | STATX_DIOALIGN | STATX_BTIME)
#elif defined(STATX_DIOALIGN)
#define NM_STATX_WANT (STATX_BASIC_STATS | STATX_DIOALIGN)
#elif defined(STATX_BTIME)
#define NM_STATX_WANT (STATX_BASIC_STATS | STATX_BTIME)
#else
#define NM_STATX_WANT (STATX_BASIC_STATS)
#endif

static int nm_path_stat(const struct path *p, struct kstat *st)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    return vfs_getattr_nosec((struct path *)p, st);
#else
    return vfs_getattr_nosec(p, st, NM_STATX_WANT, AT_STATX_SYNC_AS_STAT);
#endif
}

static s32 nm_child_size_contrib(const struct nomount_child_node *child)
{
    s32 bytes = (s32)(NM_EROFS_DIRENT_SZ + child->name_len);

    if (child->flags & NM_FLAG_WHITEOUT) {
        if (!(child->flags & NM_FLAG_SHADOWS_STOCK))
            return 0;
        return -bytes;
    }
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

static void nm_dir_nlink_fix(struct kstat *stat, int nld)
{
    s64 nl;

    if (!nld)
        return;
    nl = (s64)stat->nlink + (s64)nld;
    if (nl < 2) nl = 2;
    if (nl > (s64)UINT_MAX) nl = (s64)UINT_MAX;
    stat->nlink = (unsigned int)nl;
}

static void nm_dir_stat_fix(struct nm_inode_info *info, struct inode *v_inode,
                            struct kstat *stat)
{
    int nld;
    s32 delta;
    loff_t fixed;

    if (!info->dir_node || !info->r_path.dentry)
        return;

    nm_dir_deltas(info->dir_node, &nld, &delta);
    /* ABOVE the gate. The link count has nothing to do with erofs: a directory that
     * gained injected children has a higher nlink whatever filesystem it sits on, and
     * leaving it unfixed on an ext4 or f2fs ROM is a one-stat disagreement with the
     * children the engine does fix. It matched the victim side at nm_dir_nlink_fix's
     * other caller and not here.
     *
     * No `nlink != 1` test, unlike the victim side: that guard is there because erofs
     * does not maintain directory link counts and reports 1, so adding to it would
     * leave one directory at 3 among a partition of 1s. Here stat->nlink comes from
     * vfs_getattr_nosec() on info->r_path -- the module copy, on ext4, which does
     * maintain it -- and nm_mirror_stat() does not overwrite nlink, so the value is
     * never the erofs 1 the guard exists for. */
    nm_dir_nlink_fix(stat, nld);

    /* The knob gates here too. The injected side accepts it as an alternative to the
     * erofs magic and this did not, so with it set on a non-erofs /system an injected
     * directory got the synthesized size and the stock directory holding it did not --
     * one getdents64 and one stat on each is enough to see them disagree.
     *
     * And the magic read has to be the ROM's. This tested
     * d_backing_inode(info->r_path.dentry)->i_sb->s_magic -- r_path is the MODULE
     * directory under /data/adb, so on an ext4 /data the answer was about the wrong
     * filesystem entirely: the decision is whether the directory the caller is
     * STAT'ING reports erofs-shaped sizes, and that is v_inode. Same mistake as the one
     * the paragraph above records, one layer over. */
    if (v_inode && v_inode->i_sb->s_magic != EROFS_SUPER_MAGIC_V1 &&
        !READ_ONCE(nm_vdir_erofs_size))
        return;

    if (!delta)
        return;
    if (stat->size <= 0 || stat->size >= 4096)
        return;
    fixed = stat->size + delta;
    if (fixed <= 0 || fixed >= 4096)
        return;
    stat->size = fixed;
}

#define NM_HSIZE_EROFS 1
#define NM_HSIZE_DELTA 2
/* The size a served caller of a hijacked directory is told. getattr and llseek both answer
 * from here: SEEK_END read the victim's own i_size while stat reported the merged one, 531
 * against 601 on /product/etc/sysconfig (engine-oracles-1). 0 when nothing changes. */
static int nm_hijacked_dir_size(struct inode *inode, struct nomount_dir_node *d, loff_t real,
                                s32 delta, loff_t *out)
{
    /* erofs: the size of the listing this caller gets, packed the same way, so its
     * terminal d_off and st_size agree. */
    if (inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1) {
        unsigned int bs = inode->i_sb->s_blocksize ? inode->i_sb->s_blocksize : 4096;

        if (nm_hijacked_erofs_size(d, bs, out))
            return NM_HSIZE_EROFS;
    }
    /* Same gate as nm_dir_stat_fix: a victim left unfixed among fixed children is the tell. */
    if (delta && (inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1 ||
                  READ_ONCE(nm_vdir_erofs_size)) &&
        real > 0 && real < 4096) {
        loff_t fixed = real + delta;

        if (fixed > 0 && fixed < 4096) {
            *out = fixed;
            return NM_HSIZE_DELTA;
        }
    }
    return 0;
}

static loff_t nomount_hijacked_llseek(struct file *file, loff_t offset, int whence)
{
    struct inode *inode = file_inode(file);
    const struct file_operations *orig_fop;
    struct nomount_dir_node *d;
    struct nm_fop *nm_fop;
    loff_t res = 0, sz;
    bool sized = false;
    int nld;
    s32 delta;

    rcu_read_lock();
    nm_fop = nm_get_fop(smp_load_acquire(&file->f_op));
    orig_fop = nm_fop ? nm_fop->orig_fop : NULL;
    d = nm_fop ? smp_load_acquire(&nm_fop->dir_node) : NULL;
    if (d && !atomic_inc_not_zero(&d->refcount)) d = NULL;
    rcu_read_unlock();

    if (d && (whence == SEEK_END || whence == SEEK_DATA || whence == SEEK_HOLE) &&
        !(nomount_is_uid_blocked(current_uid().val) && !READ_ONCE(d->has_public))) {
        nm_dir_deltas(d, &nld, &delta);
        sized = nm_hijacked_dir_size(inode, d, i_size_read(inode), delta, &sz) != 0;
        if (sized)
            res = generic_file_llseek_size(file, offset, whence, inode->i_sb->s_maxbytes, sz);
    }
    if (d) nm_dir_node_put(d);
    if (sized)
        return res;
    if (orig_fop && orig_fop->llseek)
        return orig_fop->llseek(file, offset, whence);
    return generic_file_llseek(file, offset, whence);
}

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    if (orig_iop && orig_iop->getattr)
        res = orig_iop->getattr(mnt, dentry, stat);
    else { generic_fillattr(inode, stat); res = 0; }
#else
    if (orig_iop && orig_iop->getattr)
        res = orig_iop->getattr(IDMAP_CALL path, stat, request_mask, query_flags);
    else {
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        generic_fillattr(IDMAP_CALL request_mask, inode, stat);
# else
        generic_fillattr(IDMAP_CALL inode, stat);
# endif
        res = 0;
    }
#endif
    if (res || !d)
        goto out;
    if (nomount_is_uid_blocked(current_uid().val) && !READ_ONCE(d->has_public))
        goto out;

    nm_dir_deltas(d, &nld, &delta);
    if (stat->nlink != 1)
        nm_dir_nlink_fix(stat, nld);

    {
        loff_t sz;
        int how = nm_hijacked_dir_size(inode, d, stat->size, delta, &sz);

        if (how && sz != stat->size) {
            stat->size = sz;
            if (how == NM_HSIZE_EROFS) {
                unsigned int bs = inode->i_sb->s_blocksize ? inode->i_sb->s_blocksize : 4096;

                stat->blocks = (blkcnt_t)(round_up(sz, (loff_t)bs) >> 9);
            }
        }
    }
out:
    if (d) nm_dir_node_put(d);
    return res;
}

static void nm_mirror_stat(const struct nm_inode_info *info, struct inode *v_inode,
                           struct kstat *stat)
{
    stat->ino = info->v_ino;
    stat->dev = info->v_dev ? info->v_dev : v_inode->i_sb->s_dev;
    if (info->flags & NM_FLAG_HAVE_VOWN) {
        stat->mode = (stat->mode & S_IFMT) | (info->v_mode & 07777);
        stat->uid = info->v_uid;
        stat->gid = info->v_gid;
    }
    if (info->flags & NM_FLAG_HAVE_TIMES) {
        stat->atime = info->v_atime;
        stat->mtime = info->v_mtime;
        stat->ctime = info->v_ctime;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    if (info->v_attr_mask) {
        stat->attributes = info->v_attributes;
        stat->attributes_mask = info->v_attr_mask;
    }
#endif
    if (info->v_blksize) stat->blksize = info->v_blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    if (info->v_result_mask) stat->result_mask &= info->v_result_mask;
#ifdef STATX_BTIME
    if (stat->result_mask & STATX_BTIME) {
        stat->btime = info->v_btime;
    } else {
        stat->btime.tv_sec = 0;
        stat->btime.tv_nsec = 0;
    }
#endif
#ifdef STATX_DIOALIGN
    if (stat->result_mask & STATX_DIOALIGN) {
        stat->dio_mem_align = info->v_dio_mem;
        stat->dio_offset_align = info->v_dio_off;
    } else {
        stat->dio_mem_align = 0;
        stat->dio_offset_align = 0;
    }
#endif
#endif
}

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
    {
        struct path *stock = nm_stock_for_caller(info);
        if (unlikely(stock)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            return vfs_getattr_nosec(stock, stat, request_mask, query_flags);
#else
            return vfs_getattr_nosec(stock, stat);
#endif
        }
    }

    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        generic_fillattr(IDMAP_CALL request_mask, v_inode, stat);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        generic_fillattr(IDMAP_CALL v_inode, stat);
#else
        generic_fillattr(v_inode, stat);
#endif
#if defined(STATX_BTIME) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        /* generic_fillattr() does not know about btime -- it is per-filesystem -- so it
         * leaves STATX_BTIME out of result_mask, and nm_mirror_stat() only ever masks
         * result_mask DOWN (`&= info->v_result_mask`). Between the two, a synthesized
         * directory could never report a creation time while EVERY real directory on a
         * btime-capable ROM reports one: a single statx(STATX_BTIME) separated the two
         * classes, with no rule or timing involved.
         *
         * Asserted here rather than in nm_mirror_stat() because only this arm has the
         * problem -- an injected file mirrors a real inode whose own getattr filled the
         * bit in. The OR goes BEFORE the mirror on purpose: the `&=` there then keeps
         * the bit only if the sampled ancestor actually had one, so a ROM without btime
         * still reports none, and nm_mirror_stat()'s own `else` arm zeroes the value.
         * v_result_mask and v_btime both reach a synthesized rule from the ancestor
         * sample (anc_result_mask / anc_btime). */
        stat->result_mask |= info->v_result_mask & STATX_BTIME;
#endif
        nm_mirror_stat(info, v_inode, stat);
        /* i_blocks is 0 on an overlay victim (FIOQSIZE), but a stock overlay directory
         * stats the real directory's blocks. */
        if (!stat->blocks && nm_victim_is_overlay(v_inode->i_sb))
            stat->blocks = 8;
        stat->nlink = nm_vdir_nlink(info->dir_node);
        if (v_inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1 || READ_ONCE(nm_vdir_erofs_size)) {
            unsigned long vbs = v_inode->i_sb->s_blocksize;

            stat->size = nm_vdir_size(info->dir_node, vbs);
            if (vbs)
                stat->blocks = (blkcnt_t)((((u64)stat->size + vbs - 1) & ~((u64)vbs - 1)) >> 9);
        }
        /* A SEEK_END lock reads i_size raw, and the LKM has no fs/locks.c hook: keep this
         * engine-owned inode's i_size at the size stat just gave. */
        if (unlikely(i_size_read(v_inode) != stat->size)) {
            spin_lock(&v_inode->i_lock);
            i_size_write(v_inode, stat->size);
            spin_unlock(&v_inode->i_lock);
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
            if (!nm_dsnap_size_fix(info, v_inode, stat))
                nm_dir_stat_fix(info, v_inode, stat);
        } else {
            nm_mirror_blocks(info, v_inode, &info->r_path, stat);
        }
    }
    return res;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
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
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    if (info->flags & NM_FLAG_VIRTUAL_DIR) return 0;

    {
        struct iattr battr = *attr;

        battr.ia_valid &= ~ATTR_FILE;
        battr.ia_file = NULL;

        /* The write lands on the BACKING mount, and that is not the mount the
         * VFS counted before calling here -- it counted the virtual path's.
         * Unreachable while every rule shadows a read-only stock mount, because
         * the syscall is refused with -EROFS long before this; a rule over a
         * writable mount would otherwise write through a frozen or
         * read-only-remounted filesystem. Taken outside inode_lock, which is
         * the order every in-tree caller of notify_change() uses.
         */
        err = mnt_want_write(info->r_path.mnt);
        if (unlikely(err))
            return err;
        inode_lock(d_backing_inode(info->r_path.dentry));
        err = notify_change(IDMAP_CALL info->r_path.dentry, &battr, NULL);
        inode_unlock(d_backing_inode(info->r_path.dentry));
        mnt_drop_write(info->r_path.mnt);
    }

    if (likely(!err)) {
        struct inode *bi = d_backing_inode(info->r_path.dentry);

        if (attr->ia_valid & ATTR_MODE) {
            v_inode->i_mode = bi->i_mode;
            if (info->flags & NM_FLAG_HAVE_VOWN)
                info->v_mode = bi->i_mode & 07777;
        }
        if (attr->ia_valid & ATTR_UID) {
            v_inode->i_uid = bi->i_uid;
            if (info->flags & NM_FLAG_HAVE_VOWN)
                info->v_uid = bi->i_uid;
        }
        if (attr->ia_valid & ATTR_GID) {
            v_inode->i_gid = bi->i_gid;
            if (info->flags & NM_FLAG_HAVE_VOWN)
                info->v_gid = bi->i_gid;
        }
        nm_sync_inode_times(v_inode, bi);
    }
    return err;
}

static const char *nm_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *done)
{
    struct nm_inode_info *info = inode->i_private;
    struct inode *real_inode;
    struct dentry *target_dentry;
    struct path *stock;

    /* RCU-walk: nothing pins this inode, and destroy NULLs the paths read below between
     * the two loads. -ECHILD makes the VFS retry in ref-walk, holding the dentry. */
    if (!dentry)
        return ERR_PTR(-ECHILD);
    if (unlikely(!info || !info->r_path.dentry))
        return ERR_PTR(-EIO);

    if (unlikely(nm_hidden_from_caller(info)))
        return ERR_PTR(-ENOENT);
    stock = nm_stock_for_caller(info);
    if (unlikely(stock)) {
        struct inode *si = d_backing_inode(stock->dentry);

        if (si && si->i_op && si->i_op->get_link)
            return si->i_op->get_link(dentry ? stock->dentry : NULL, si, done);
        return ERR_PTR(-EINVAL);
    }

    real_inode = d_backing_inode(info->r_path.dentry);
    target_dentry = dentry ? info->r_path.dentry : NULL;
    if (real_inode && real_inode->i_op && real_inode->i_op->get_link) {
        return real_inode->i_op->get_link(target_dentry, real_inode, done);
    }

    return ERR_PTR(-EINVAL);
}

static int nm_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
                     u64 start, u64 len)
{
    struct nm_inode_info *info = inode->i_private;
    struct inode *real_inode;

    if (unlikely(!info)) return -EOPNOTSUPP;
    if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
    if (unlikely((info->flags & NM_FLAG_VIRTUAL_DIR) || !info->r_path.dentry))
        return -EOPNOTSUPP;
    {
        struct path *stock = nm_stock_for_caller(info);

        real_inode = d_backing_inode(stock ? stock->dentry : info->r_path.dentry);
    }
    if (!real_inode || !real_inode->i_op || !real_inode->i_op->fiemap)
        return -EOPNOTSUPP;
    return real_inode->i_op->fiemap(real_inode, fieinfo, start, len);
}

/* The position space the tail continues: the file this listing proxies (the stock directory
 * for a uid-blocked caller), or, for a virtual directory with nothing behind it, its own
 * dots at 0 and 1 on the victim's superblock. */
static loff_t nm_dir_tail_gap(struct file *file, struct file *real_file,
                              const struct nomount_dir_node *d, bool stock_space)
{
    if (!real_file)
        return nm_victim_is_overlay(file_inode(file)->i_sb) ? 0 : 1;
    if (stock_space)
        return nm_tail_gap(file_inode(real_file)->i_sb, READ_ONCE(d->stock_eof),
                           READ_ONCE(d->max_stock_pos));
    return nm_tail_gap(file_inode(real_file)->i_sb, READ_ONCE(d->real_eof),
                       READ_ONCE(d->max_real_pos));
}

static int nm_dir_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    struct nomount_dir_node *dir_node = info ? info->dir_node : NULL;
    struct file *real_file = file->private_data;
    /* A uid-blocked caller is served info->s_path, a position space of its own. */
    bool stock_space = real_file && info && info->r_path.dentry &&
                       real_file->f_path.dentry != info->r_path.dentry;
    loff_t start = ctx->pos;
    loff_t eof = 0;
    int res = 0;

    if (likely(info)) {
        struct super_block *sb = file_inode(file)->i_sb;

        if (sb->s_magic == EROFS_SUPER_MAGIC_V1 || READ_ONCE(nm_vdir_erofs_size)) {
            if (!real_file && (info->flags & NM_FLAG_VIRTUAL_DIR))
                return nm_vdir_iterate_erofs(file, ctx, info, dir_node,
                                             sb->s_blocksize);
            if (real_file && !(info->flags & NM_FLAG_VIRTUAL_DIR) &&
                info->r_path.dentry &&
                real_file->f_path.dentry == info->r_path.dentry) {
                bool transient;
                struct nm_dsnap *snap = nm_dsnap_get_ex(info, sb->s_blocksize, &transient);

                if (snap) {
                    res = nm_dsnap_iterate(file, ctx, info, snap, sb->s_blocksize);
                    nm_dsnap_put(snap);
                    return res;
                }
                if (ctx->pos && transient) {
                    nm_warn_once("a directory listing was cut short: the dirent snapshot could not be rebuilt mid-read (low memory). Re-run the listing.\n");
                    return 0;
                }
            }
        }
    }

    if (stock_space) {
        if (unlikely(nm_is_stock_virtual_pos(dir_node, ctx->pos))) {
            nm_emit_tail(ctx, dir_node, READ_ONCE(dir_node->stock_eof), true,
                         nm_dir_tail_gap(file, real_file, dir_node, true));
            return 0;
        }
    } else if (unlikely(nm_is_virtual_pos(dir_node, ctx->pos))) {
        nomount_emit_virtual_children(ctx, dir_node,
                                      !(info && (info->flags & NM_FLAG_VIRTUAL_DIR)),
                                      nm_dir_tail_gap(file, real_file, dir_node, false));
        return 0;
    }

    if (real_file) {
        struct nomount_proxy_ctx proxy_ctx = {
            .ctx.actor = nomount_actor_proxy, .ctx.pos = ctx->pos,
            .orig_ctx = ctx, .dir_node = dir_node,
            .dir_info = (info && real_file->f_path.dentry == info->r_path.dentry)
                        ? info : NULL,
            .emitted = 0,
            .refused = false,
            .stock_space = stock_space,
        };
        res = iterate_dir(real_file, &proxy_ctx.ctx);
        ctx->pos = proxy_ctx.ctx.pos;
        if (dir_node && res >= 0 && !proxy_ctx.refused && proxy_ctx.emitted > 0)
            WRITE_ONCE(*(stock_space ? &dir_node->stock_end : &dir_node->real_end), ctx->pos);
        if (res < 0 || proxy_ctx.emitted > 0 || proxy_ctx.refused) return res;
        if (!dir_node) return res;
        /* A uid-blocked caller lists info->s_path, in that directory's own position space:
         * it must not publish into r_path's, which every other reader decodes against. It
         * still gets the PUBLIC children lookup serves it, or stat would find a name
         * getdents omits (regressions-13). */
        if (stock_space) {
            loff_t sbase = READ_ONCE(dir_node->stock_eof);

            if (sbase && start > sbase && start != READ_ONCE(dir_node->stock_end))
                return res;
            nm_publish_stock_eof(dir_node, ctx->pos);
            nm_emit_tail(ctx, dir_node, READ_ONCE(dir_node->stock_eof), true,
                         nm_dir_tail_gap(file, real_file, dir_node, true));
            return res;
        }
        eof = READ_ONCE(dir_node->real_eof);
        if (eof && start > eof && start != READ_ONCE(dir_node->real_end))
            return res;
        nm_publish_real_eof(dir_node, ctx->pos);
    } else if (info && (info->flags & NM_FLAG_VIRTUAL_DIR)) {
        if (ctx->pos < 2 && !nm_emit_dots(file, ctx, info)) return 0;
        if (!dir_node) return 0;
        nm_publish_real_eof(dir_node, 2);
    } else {
        return -ENOTDIR;
    }

    nomount_emit_virtual_children(ctx, dir_node,
                                  !(info && (info->flags & NM_FLAG_VIRTUAL_DIR)),
                                  nm_dir_tail_gap(file, real_file, dir_node, false));
    return res;
}

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
    u32 gen = (u32)atomic_read(&nm_rule_gen);
    bool own_stock = false;
    umode_t s_mode = 0;
    kuid_t s_uid = GLOBAL_ROOT_UID;
    kgid_t s_gid = GLOBAL_ROOT_GID;

    {
        struct path *stock = nm_stock_for_caller(info);

        if (unlikely(stock && stock->dentry)) {
            child = nm_lookup_backing_child(dentry->d_name.name, stock->dentry,
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
            ri.r_path.mnt = stock->mnt;
            ri.r_path.dentry = child;
            path_get(&ri.r_path);
            r_child = d_backing_inode(child);
            if (r_child) {
                ri.v_ino = r_child->i_ino;
                ri.v_dev = r_child->i_sb->s_dev;
            }
            ri.flags = (info->flags & (NM_FLAG_OVL_INO | NM_FLAG_PUBLIC)) |
                       NM_FLAG_SHADOWS_STOCK | NM_FLAG_STOCK_ONLY;
            ri.v_scope = info->v_scope;
            ri.s_path.mnt = stock->mnt;
            ri.s_path.dentry = child;
            path_get(&ri.s_path);
            if (r_child && S_ISDIR(r_child->i_mode))
                ri.flags |= NM_FLAG_IS_DIR;
            new_inode = nomount_create_new_inode(dir->i_sb, &ri);
            nm_put_rule_info(&ri);
            dput(child);
            if (!new_inode)
                return ERR_PTR(-ENOMEM);
            nm_install_dentry_ops(dentry);
            res = d_splice_alias(new_inode, dentry);
            if (!IS_ERR(res) && res)
                nm_install_dentry_ops(res);
            return res;
        }
    }

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
    ri.r_path.mnt = info->r_path.mnt;
    ri.r_path.dentry = child;
    path_get(&ri.r_path);

    r_child = d_backing_inode(child);
    ri.flags = info->flags & (NM_FLAG_HAVE_TIMES | NM_FLAG_OVL_INO |
                              NM_FLAG_PUBLIC | NM_FLAG_SHADOWS_STOCK);
    if (r_child && S_ISDIR(r_child->i_mode))
        ri.flags |= NM_FLAG_IS_DIR;

    if (unlikely(info->s_path.dentry && (info->flags & NM_FLAG_SHADOWS_STOCK))) {
        struct dentry *schild = nm_lookup_backing_child(dentry->d_name.name,
                                                        info->s_path.dentry,
                                                        dentry->d_name.len);

        if (!IS_ERR(schild)) {
            if (d_is_negative(schild)) {
                ri.flags &= ~NM_FLAG_SHADOWS_STOCK;
            } else {
                struct inode *si = d_backing_inode(schild);

                if (si && si->i_op != &nm_file_iops && si->i_op != &nm_dir_iops) {
                    ri.s_path.mnt = info->s_path.mnt;
                    ri.s_path.dentry = schild;
                    path_get(&ri.s_path);
                    if (!S_ISDIR(si->i_mode) && r_child && !S_ISDIR(r_child->i_mode)) {
                        own_stock = true;
                        s_mode = si->i_mode & 07777;
                        s_uid = si->i_uid;
                        s_gid = si->i_gid;
                    }
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
    NM_BTIME_COPY(ri.v_btime, info->v_btime);
    ri.v_attributes = info->v_attributes;
    ri.v_attr_mask  = info->v_attr_mask;
    ri.v_blksize    = info->v_blksize;
    ri.v_result_mask = info->v_result_mask;
    ri.v_dio_mem = info->v_dio_mem;
    ri.v_dio_off = info->v_dio_off;
    ri.v_cap   = info->v_cap;
    ri.v_fa    = info->v_fa;
    ri.v_cfile = info->v_cfile;
    ri.v_scope = info->v_scope;
    /* A file child mirrors a stock FILE, not this directory: erofs reports DIOALIGN and
     * maps THP-aligned only for regular files. Times and label stay the directory's. */
    if (!(ri.flags & NM_FLAG_IS_DIR) && info->v_cfile.known) {
        ri.v_attributes  = info->v_cfile.attributes;
        ri.v_attr_mask   = info->v_cfile.attr_mask;
        ri.v_result_mask = info->v_cfile.result_mask;
        ri.v_dio_mem = info->v_cfile.dio_mem;
        ri.v_dio_off = info->v_cfile.dio_off;
        ri.v_cap     = info->v_cfile.cap;
        ri.v_fa      = info->v_cfile.fa;
    }
    ri.v_uid   = info->v_uid;
    ri.v_gid   = info->v_gid;
    ri.v_mode  = info->v_mode;
    if (own_stock) {
        ri.v_mode = s_mode;
        ri.v_uid = s_uid;
        ri.v_gid = s_gid;
        ri.flags |= NM_FLAG_HAVE_VOWN;
    }
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
        if (nomount_get_rule_info(info->dir_node, name, len, v_hash, &rule_info, true, true)) {
            /* As nomount_hijacked_lookup: an unserved caller shares the injected dentry
             * when it stands in for a stock file, and is handed the stock one by the ops. */
            hidden_rule = !nm_rinfo_served(&rule_info) &&
                          !(rule_info.r_path.dentry && d_backing_inode(rule_info.r_path.dentry) &&
                            nm_shareable_stock(d_backing_inode(rule_info.r_path.dentry)->i_mode,
                                               &rule_info.s_path, dir->i_sb, rule_info.flags));
            if (!hidden_rule) {
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
                        res = d_splice_alias(new_inode, dentry);
                        if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
                        return res;
                    }
                }
            }
            nm_put_rule_info(&rule_info);
        }
    }

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

static const char *nm_full_xattr_name(const struct nm_xattr_proxy *proxy,
                                      const char *name, char **allocp)
{
    const char *pfx = xattr_prefix(proxy->orig);

    *allocp = NULL;
    if (pfx && *pfx && strncmp(name, pfx, strlen(pfx)) != 0) {
        char *full = kasprintf(GFP_KERNEL, "%s%s", pfx, name);

        if (!full) return NULL;
        *allocp = full;
        return full;
    }
    return name;
}

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
        if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
        stock = nm_stock_for_caller(info);
        if (unlikely(stock)) {
            full = nm_full_xattr_name(proxy, name, &alloc);
            if (unlikely(!full)) return -ENOMEM;
            r = vfs_getxattr(IDMAP_PATH(info->s_path) info->s_path.dentry, full, buffer, size);
            kfree(alloc);
            return r;
        }
        full = nm_full_xattr_name(proxy, name, &alloc);
        if (unlikely(!full)) return -ENOMEM;
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

        if (unlikely(!info)) return -ENODATA;
        if (unlikely(nm_hidden_from_caller(info))) return -ENOENT;
        {
            struct path *stock = nm_stock_for_caller(info);

            if (unlikely(stock)) {
                full = nm_full_xattr_name(proxy, name, &alloc);
                if (unlikely(!full)) return -ENOMEM;
                /* Same reason as the r_path arm below, which already does this. */
                r = mnt_want_write(info->s_path.mnt);
                if (!r) {
                    r = vfs_setxattr(IDMAP_PATH(info->s_path) stock->dentry, full, buffer,
                                     size, flags);
                    mnt_drop_write(info->s_path.mnt);
                }
                kfree(alloc);
                return r;
            }
        }
        if (unlikely(!info->r_path.dentry)) return -ENODATA;
        full = nm_full_xattr_name(proxy, name, &alloc);
        if (unlikely(!full)) return -ENOMEM;
        r = mnt_want_write(info->r_path.mnt);
        if (!r) {
            r = vfs_setxattr(IDMAP_CALL info->r_path.dentry, full, buffer, size, flags);
            mnt_drop_write(info->r_path.mnt);
        }
        kfree(alloc);
        return r;
    }
    return proxy->orig->set(proxy->orig, IDMAP_CALL dentry, inode, name, buffer, size, flags);
}

static inline int nm_reval_stale(struct dentry *dentry)
{
    if (nomount_is_uid_blocked(current_uid().val) && d_is_negative(dentry))
        d_drop(dentry);
    return 0;
}

static inline int nm_reval_fresh(struct dentry *dentry, u32 gen)
{
    struct inode *ino = d_inode(dentry);

    if (ino && ino->i_private &&
        (ino->i_op == &nm_file_iops || ino->i_op == &nm_dir_iops))
        WRITE_ONCE(((struct nm_inode_info *)ino->i_private)->gen, gen);
    return 1;
}

static bool nm_stock_only_mismatch(struct dentry *dentry)
{
    struct inode *ino = dentry->d_inode;
    struct nm_inode_info *ii = ino ? ino->i_private : NULL;

    /* A stock-only child was made for a caller its directory's rule does not serve. */
    return ii && (ii->flags & NM_FLAG_STOCK_ONLY) && nm_info_served(ii);
}

static bool nm_is_passthrough_child(struct inode *parent_dir, struct dentry *dentry)
{
    const struct nm_inode_info *pinfo, *cinfo;
    struct inode *cino = d_inode(dentry);

    if (!parent_dir || parent_dir->i_op != &nm_dir_iops)
        return false;
    pinfo = parent_dir->i_private;
    if (!pinfo || !pinfo->r_path.dentry)
        return false;
    if (!cino || (cino->i_op != &nm_file_iops && cino->i_op != &nm_dir_iops))
        return false;
    cinfo = cino->i_private;
    return cinfo && cinfo->r_path.dentry &&
           cinfo->r_path.dentry->d_parent == pinfo->r_path.dentry &&
           !d_unhashed(cinfo->r_path.dentry);
}

/* Does this dentry's cached snapshot still describe the rule that is live now?
 *
 * nm_reval_fresh() only stamps the generation and returns 1, so an injected dentry was
 * blessed without ever being rechecked against its rule: after a hot-swap, or a rule
 * replaced in place with different identity, the caller kept serving the previous one for
 * as long as the dentry lived.
 *
 * Four fields, not nm_dentry_matches_rule()'s six. The other two are r_path.dentry/mnt,
 * which are only populated when the rule info is fetched with get_path=true -- a path
 * reference taken and dropped on every revalidate of every injected name, in the lookup
 * hot path. These four are the identity an app can observe through stat(), and they are
 * already in the rule_info the caller fetched, so the check costs four comparisons.
 *
 * Comparing flags is sound even though rule_info synthesizes NM_FLAG_UID_SCOPED on top of
 * the rule's own: nm_inode_info.flags is assigned FROM rule_info.flags, so both sides come
 * through the same synthesis.
 */
static bool nm_scope_copy_eq(const struct nm_scope_copy *a, const struct nm_scope_copy *b)
{
    u8 i;

    if (a->uid != b->uid || a->uid_end != b->uid_end || a->deny_n != b->deny_n)
        return false;
    for (i = 0; i < a->deny_n && i < NM_DENY_MAX; i++)
        if (a->deny[i] != b->deny[i])
            return false;
    return true;
}

static bool nm_reval_info_agrees(struct dentry *dentry, const struct nm_rule_info *ri)
{
    const struct nm_inode_info *info;
    struct inode *ino = d_inode(dentry);

    if (!ino || (ino->i_op != &nm_file_iops && ino->i_op != &nm_dir_iops))
        return false;
    info = ino->i_private;
    return info &&
           info->flags == ri->flags &&
           info->v_ino == ri->v_ino &&
           info->v_dev == ri->v_dev &&
           info->v_dino == ri->v_dino &&
           info->v_pdino == ri->v_pdino &&
           nm_scope_copy_eq(&info->v_scope, &ri->v_scope);
}

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

    if (flags & LOOKUP_RCU) {
        struct inode *ino = d_inode_rcu(dentry);
        struct nm_inode_info *rinfo;

        if (!ino || (ino->i_op != &nm_file_iops && ino->i_op != &nm_dir_iops))
            return -ECHILD;
        rinfo = READ_ONCE(ino->i_private);
        if (!rinfo || READ_ONCE(rinfo->gen) != (u32)atomic_read(&nm_rule_gen))
            return -ECHILD;
        if ((rinfo->flags & NM_FLAG_STOCK_ONLY) && nm_info_served(rinfo))
            return -ECHILD;
        /* Decided per caller from the scope the inode carries, never by invalidating
         * the dentry: that would unhash it for every process, and every mapping of it
         * would then read "(deleted)". An added name is absent for an unserved caller,
         * and a negative return other than 0 fails its lookup without touching the
         * dentry. A replaced one is served stock by the inode's ops. */
        if (!(rinfo->flags & NM_FLAG_STOCK_ONLY) && !nm_info_served(rinfo)) {
            if (!(rinfo->flags & NM_FLAG_SHADOWS_STOCK))
                return nm_absent_errno(ino, flags);
            /* Not shareable: as before this change, a hide-list caller keeps it where there
             * is a stock file to serve, and anyone else re-walks. */
            if (!nm_shareable_stock(ino->i_mode, &rinfo->s_path, ino->i_sb, rinfo->flags) &&
                !(nm_uid_hidden(rinfo->flags) && rinfo->s_path.dentry))
                return -ECHILD;
        }
        return 1;
    }

    gen = (u32)atomic_read(&nm_rule_gen);

    injected = dentry->d_inode &&
        (dentry->d_inode->i_op == &nm_file_iops ||
         dentry->d_inode->i_op == &nm_dir_iops);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    parent_dir = dir;
#else
    parent_dir = d_inode(dentry->d_parent);
#endif
    if (!parent_dir) return 1;

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
    if (!pdir) {
        if (injected) {
            struct nm_inode_info *ii = dentry->d_inode->i_private;

            if (nm_stock_only_mismatch(dentry))
                return 0;
            if (ii && !nm_info_served(ii) &&
                (ii->flags & NM_FLAG_SHADOWS_STOCK) && !ii->s_path.dentry)
                return 0;
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
    /* Matched whoever is asking; who is served is decided below from the scope. */
    if (nomount_get_rule_info(pdir, dentry->d_name.name, dentry->d_name.len, hash, &rule_info,
                              false, true)) {
        bool served = nm_rinfo_served(&rule_info);

        nm_put_rule_info(&rule_info);
        nm_dir_node_put(pdir);
        if (rule_info.flags & NM_FLAG_WHITEOUT) {
            /* Stock for a caller the whiteout does not serve, absence for one it does --
             * and for that one a real stock dentry fails the lookup rather than being
             * unhashed under whoever has it mapped. */
            if (!served)
                return d_is_negative(dentry) ? 0 : 1;
            return d_is_negative(dentry) ? 1 : nm_absent_errno(dentry->d_inode, flags);
        }
        if (injected) {
            struct nm_inode_info *ii = dentry->d_inode->i_private;

            if (nm_stock_only_mismatch(dentry))
                return 0;
            if (!nm_reval_info_agrees(dentry, &rule_info))
                return 0;               /* the rule changed under this dentry */
            if (served)
                return nm_reval_fresh(dentry, gen);
            /* Unserved: never invalidate the shared dentry (every mapping of it would read
             * "(deleted)"). An added name fails this caller's lookup only; a replaced one
             * is handed the stock file by the inode's ops. */
            if (!(rule_info.flags & NM_FLAG_SHADOWS_STOCK)) {
                nm_reval_fresh(dentry, gen);    /* keep the RCU arm deciding it */
                return nm_absent_errno(dentry->d_inode, flags);
            }
            if (ii && nm_shareable_stock(dentry->d_inode->i_mode, &ii->s_path,
                                         dentry->d_sb, ii->flags))
                return nm_reval_fresh(dentry, gen);
            /* Not shareable: as before this change. */
            return (nm_uid_hidden(rule_info.flags) && ii && ii->s_path.dentry)
                       ? nm_reval_fresh(dentry, gen) : 0;
        }
        /* A real dentry under a name with a rule: right for a caller the rule does not
         * serve; a caller it does serve drops it to reach the injected one. */
        if (!served)
            return 1;
        return nm_reval_stale(dentry);
    }
    nm_dir_node_put(pdir);
    if (injected && nm_stock_only_mismatch(dentry))
        return 0;
    if (injected && nm_is_passthrough_child(parent_dir, dentry)) {
        struct nm_inode_info *ii = dentry->d_inode->i_private;

        /* A module-only child, for a caller its directory's rule does not serve: absent,
         * as the RCU arm answers it, without unhashing it. */
        if (ii && !nm_info_served(ii) &&
            !(ii->flags & (NM_FLAG_SHADOWS_STOCK | NM_FLAG_STOCK_ONLY))) {
            nm_reval_fresh(dentry, gen);
            return nm_absent_errno(dentry->d_inode, flags);
        }
        return nm_reval_fresh(dentry, gen);
    }
    return nm_reval_stale(dentry);
}

#ifdef FOP_DONTCACHE
#define NM_FOP_FLAGS .fop_flags = FOP_DONTCACHE,
#else
#define NM_FOP_FLAGS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static const struct file_operations nm_file_fops_mmap_prepare = {
    .owner = THIS_MODULE,
    NM_FOP_FLAGS
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

static const struct file_operations nm_file_fops_mmap_prepare_thp = {
    .owner = THIS_MODULE,
    NM_FOP_FLAGS
    .llseek = nm_llseek,
    .open = nm_open,
    .release = nm_release,
    .read_iter = nm_read_iter,
    .write_iter = nm_write_iter,
    .mmap_prepare = nm_mmap_prepare,
    .get_unmapped_area = thp_get_unmapped_area,
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

static const struct file_operations nm_file_fops_thp = {
    .owner = THIS_MODULE,
    NM_FOP_FLAGS
    .llseek = nm_llseek,
    .open = nm_open,
    .release = nm_release,
    .read_iter = nm_read_iter,
    .write_iter = nm_write_iter,
    .mmap = nm_mmap,
    .get_unmapped_area = thp_get_unmapped_area,
    .unlocked_ioctl = nm_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_compat_ioctl,
#endif
    .splice_read = nm_splice_read,
    .splice_write = nm_splice_write,
    .fallocate = nm_fallocate,
    .fsync = nm_fsync,
};

static const struct file_operations nm_file_fops = {
    .owner = THIS_MODULE,
    NM_FOP_FLAGS
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

#ifdef NM_HAVE_FILEATTR
/* FS_IOC_GETFLAGS / FS_IOC_FSGETXATTR reach fileattr_get, never ->unlocked_ioctl (5.13+),
 * so without this an engine inode answered ENOTTY where an ext4/f2fs sibling answers flags
 * and an overlay one EACCES. A shadowing rule asks its stock file; a pure injection
 * replays what its stock sibling answered when the rule was made. -ENOIOCTLCMD continues
 * to ->unlocked_ioctl, which is what a stock inode without fileattr_get gives too. */
static int nm_fileattr_get(struct dentry *dentry, nm_fattr_t *fa)
{
    struct inode *inode = d_inode(dentry);
    struct nm_inode_info *info = inode ? inode->i_private : NULL;
    const struct path *src = NULL;
    struct inode *si;
    int k;

    if (unlikely(!info))
        return -ENOIOCTLCMD;
    if (unlikely(nm_hidden_from_caller(info)))
        return -ENOENT;
    if (info->s_path.dentry) {
        src = &info->s_path;
    } else if (S_ISLNK(inode->i_mode)) {
        return -ENOIOCTLCMD;        /* no symlink iops has fileattr_get */
    } else if (info->v_fa.known) {
        k = fa->fsx_valid ? 1 : 0;
        if (info->v_fa.err[k])
            return info->v_fa.err[k];
        *fa = info->v_fa.fa[k];
        return 0;
    } else if ((info->flags & NM_FLAG_VIRTUAL_DIR) || nm_victim_ro_image(inode->i_sb)) {
        return -ENOIOCTLCMD;
    } else {
        src = &info->r_path;
    }
    si = src->dentry ? d_backing_inode(src->dentry) : NULL;
    if (!si || !si->i_op || !si->i_op->fileattr_get)
        return -ENOIOCTLCMD;
    return si->i_op->fileattr_get(src->dentry, fa);
}
#endif

static const struct inode_operations nm_file_iops = {
    .permission = nm_inode_permission,
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
    .get_link = nm_get_link,
    .fiemap = nm_fiemap,
#ifdef NM_HAVE_FILEATTR
    .fileattr_get = nm_fileattr_get,
#endif
};

/* The ioctl pair is here for the same reason it is on all four nm_file_fops tables, and
 * its absence here was an omission rather than a decision: a directory served by this
 * table refused FS_IOC_GETFLAGS, FS_IOC_FSGETXATTR and FS_IOC_GETVERSION outright, so one
 * ioctl() separated every engine directory from every real one on a filesystem that
 * answers them.
 *
 * nm_ioctl_as_stock() is self-limiting, which is why wiring it in needs no knowledge of
 * the victim filesystem: it forwards to s_path, else r_path, and first checks whether
 * that stock inode's own i_fop has an ioctl at all -- returning -ENOTTY when it does not.
 * So an ext4 or f2fs directory answers exactly what it would have answered, and an erofs
 * one (erofs_dir_fops has no unlocked_ioctl) still refuses, which is also stock.
 *
 * RESIDUAL, narrower and conditional: a SYNTHESIZED directory has neither s_path nor
 * r_path -- its vpath never existed -- so nm_ioctl_as_stock() finds no source and returns
 * -ENOTTY. That matches stock on an erofs victim partition and does NOT on an ext4/f2fs
 * one, where its real siblings would answer. Closing it means answering from sampled
 * metadata rather than forwarding, and what to sample depends on what the ancestor's
 * filesystem actually returns for a DIRECTORY -- unmeasured, so not guessed at here.
 */
static const struct file_operations nm_dir_fops = {
    .owner = THIS_MODULE,
    .open = nm_open,
    .release = nm_release,
    .llseek = nm_llseek,
    .read = generic_read_dir,
    .fsync = nm_dir_fsync,
    .unlocked_ioctl = nm_unlocked_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nm_compat_ioctl,
#endif
    .iterate_shared = nm_dir_iterate_dir,
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
#ifdef NM_HAVE_FILEATTR
    .fileattr_get = nm_fileattr_get,
#endif
};

static const struct dentry_operations nm_dops = {
    .d_revalidate = nm_d_revalidate,
};

/* A passthrough dentry is the real one a lookup hands a caller that a scoped
 * rule leaves on the stock file (system_server under --uid-excluded 1000), or
 * that a hidden rule is hidden from. The next caller of the name may be one the
 * rule redirects, and only nm_d_revalidate tells them apart. Without it that
 * caller reuses the stock dentry from the dcache and never reaches the hijacked
 * lookup -- nor does anyone after it, while any process keeps the file open.
 *
 * nm_dops can only go on a dentry that has no d_op. Where the superblock hands
 * one out at d_alloc (f2fs and ext4 with casefold or fscrypt since 6.6: every
 * dentry on Android's /data), the tag used to stop at DCACHE_DONTCACHE. Here
 * such a dentry gets a copy of its own d_op with d_revalidate chained: ours
 * first, then the filesystem's, so casefold hashing and fscrypt's no-key-name
 * checks are kept.
 *
 * Copies are made once per original d_op and kept for good: dentries point at
 * them past every rule, as they do at nm_dops, and the originals are the
 * filesystems' static tables. One slot per distinct table, not per dentry:
 * Android uses one to three (casefold, fscrypt, both). The table is static, so
 * nothing is allocated in lookup; should it ever fill, the dentry is unhashed
 * after the lookup instead (nm_retag_passthrough_dentry).
 */
#define NM_DOPS_CHAIN_MAX 16

struct nm_dops_chain {
    struct dentry_operations ops;
    const struct dentry_operations *orig;
};

static struct nm_dops_chain nm_dops_chains[NM_DOPS_CHAIN_MAX];
static int nm_dops_chain_n;
static DEFINE_SPINLOCK(nm_dops_chain_lock);

static bool nm_is_dops_chain(const struct dentry_operations *ops)
{
    const void *p = ops;

    return p >= (const void *)nm_dops_chains &&
           p < (const void *)(nm_dops_chains + NM_DOPS_CHAIN_MAX);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static int nm_d_revalidate_chain(struct inode *dir, const struct qstr *name,
                                 struct dentry *dentry, unsigned int flags)
{
    const struct nm_dops_chain *c =
        container_of(READ_ONCE(dentry->d_op), const struct nm_dops_chain, ops);
    int r = nm_d_revalidate(dir, name, dentry, flags);

    if (r <= 0 || !c->orig->d_revalidate) return r;
    return c->orig->d_revalidate(dir, name, dentry, flags);
}
#else
static int nm_d_revalidate_chain(struct dentry *dentry, unsigned int flags)
{
    const struct nm_dops_chain *c =
        container_of(READ_ONCE(dentry->d_op), const struct nm_dops_chain, ops);
    int r = nm_d_revalidate(dentry, flags);

    if (r <= 0 || !c->orig->d_revalidate) return r;
    return c->orig->d_revalidate(dentry, flags);
}
#endif

static const struct dentry_operations *nm_get_dops_chain(const struct dentry_operations *orig)
{
    const struct dentry_operations *ret = NULL;
    static bool warned;
    int i;

    spin_lock(&nm_dops_chain_lock);
    for (i = 0; i < nm_dops_chain_n; i++) {
        if (nm_dops_chains[i].orig == orig) {
            ret = &nm_dops_chains[i].ops;
            goto out;
        }
    }
    if (nm_dops_chain_n < NM_DOPS_CHAIN_MAX) {
        struct nm_dops_chain *c = &nm_dops_chains[nm_dops_chain_n];

        c->ops = *orig;
        c->ops.d_revalidate = nm_d_revalidate_chain;
        c->orig = orig;
        /* Readers find the entry through a dentry's d_op, never through the
         * count, so publishing the count needs no ordering of its own. The table
         * itself does: the caller's later d_op store must not be seen before it.
         */
        smp_wmb();
        nm_dops_chain_n++;
        ret = &c->ops;
    } else if (!warned) {
        warned = true;
        nm_warn("out of chained dentry ops; unhashing rule dentries on this filesystem instead\n");
    }
out:
    spin_unlock(&nm_dops_chain_lock);
    return ret;
}

/* Whether the filesystem's own lookup will d_set_d_op() this dentry: before
 * 6.9, ext4 and f2fs do so for every dentry on a casefold-capable superblock
 * (generic_set_encrypted_ci_d_ops). Setting ours first would only be replaced,
 * with a WARN from d_set_d_op on the way.
 *
 * Read off the parent rather than sb->s_encoding, which only exists under
 * CONFIG_UNICODE: the lookup that made the parent gave it the same ops, so it
 * carries DCACHE_OP_HASH/COMPARE -- and keeps them through a chain copy, which
 * only replaces d_revalidate. From 6.9 the dentry already has its d_op from
 * d_alloc, and this is never asked.
 */
static bool nm_fs_sets_d_op_in_lookup(const struct dentry *dentry)
{
    return !dentry->d_op &&
           (READ_ONCE(dentry->d_parent->d_flags) & (DCACHE_OP_HASH | DCACHE_OP_COMPARE));
}

/* Before the filesystem's lookup. The dentry is still in lookup, hashed nowhere
 * a path walk looks, so its d_op and flags can be set outright -- the safe time
 * to do it. Done here wherever the filesystem will leave it alone.
 */
static void nm_tag_passthrough_dentry(struct dentry *dentry)
{
    const struct dentry_operations *orig = dentry->d_op, *chain;

#ifdef DCACHE_DONTCACHE
    dentry->d_flags |= DCACHE_DONTCACHE;
#endif
    if (orig == &nm_dops || nm_is_dops_chain(orig) || nm_fs_sets_d_op_in_lookup(dentry))
        return;
    if (!orig) {
        nm_install_dentry_ops(dentry);
        return;
    }
    chain = nm_get_dops_chain(orig);
    if (!chain)
        return;
    dentry->d_op = chain;
    dentry->d_flags |= DCACHE_OP_REVALIDATE;
}

/* After the filesystem's lookup, on the dentry the caller gets: whatever the
 * filesystem set inside its lookup (casefold before 6.9), or an alias it
 * spliced in. It is hashed by now and a path walk may be reading it under RCU.
 *
 * With DCACHE_OP_REVALIDATE already set, swapping the d_op pointer is enough:
 * a walker sees the old table or the new one, and both have a d_revalidate.
 * Without it the flag has to be raised too, and that is upstream's way
 * (nm_hijack_dentry_ops): d_op first, then the flags with release semantics,
 * so a walker that sees the flag finds a d_op that answers it. The walker's
 * side has no matching barrier, which is the narrow window upstream accepts.
 */
static void nm_retag_passthrough_dentry(struct dentry *dentry)
{
    const struct dentry_operations *orig, *chain;
    bool drop = false;

    spin_lock(&dentry->d_lock);
#ifdef DCACHE_DONTCACHE
    dentry->d_flags |= DCACHE_DONTCACHE;
#endif
    orig = dentry->d_op;
    if (orig == &nm_dops || nm_is_dops_chain(orig)) {
        spin_unlock(&dentry->d_lock);
        return;
    }
    spin_unlock(&dentry->d_lock);

    chain = orig ? nm_get_dops_chain(orig) : &nm_dops;
    if (!chain) {
        /* No slot left for this d_op. Unhash the dentry rather than leave a
         * real one without nm_d_revalidate in the dcache: this caller still
         * opens the file it was handed, and every later lookup of the name
         * misses and comes back through the hijacked lookup. While it stays
         * open, /proc shows it as "(deleted)".
         */
        d_drop(dentry);
        return;
    }

    spin_lock(&dentry->d_lock);
    if (dentry->d_op == orig) {
        if (dentry->d_flags & DCACHE_OP_REVALIDATE) {
            /* Both tables answer d_revalidate, so swapping the pointer is the
             * whole job: a walker reads one or the other and either way has a
             * call it can make.
             */
            WRITE_ONCE(dentry->d_op, chain);
        } else {
            /* No flag means the table being replaced has no d_revalidate, and
             * raising it on a hashed dentry is not safe at any kernel version:
             * fs/namei.c does
             *     if (dentry->d_flags & DCACHE_OP_REVALIDATE)
             *             return dentry->d_op->d_revalidate(...);
             * unconditionally, and an RCU walker on another CPU reads those two
             * with nothing ordering them on its side, so it can pair the new
             * flag with the stale d_op and call through a NULL pointer. A
             * release store here cannot close that: the missing barrier is the
             * reader's. Unhash instead -- the next lookup comes back through
             * nomount_hijacked_lookup and is tagged while still unhashed, which
             * is safe everywhere.
             */
            drop = true;
        }
    }
    spin_unlock(&dentry->d_lock);

    if (drop)
        d_drop(dentry);
}

/* The real dir_node a possibly-virtual one hangs beneath.
 *
 * A virtual node carries its owner rule in _tag_ptr instead of a dir_inode, and that owner
 * is itself parented somewhere -- ultimately under a real, hijacked directory. Walking that
 * chain is what lets a caller ask "which filesystem does this rule really live on?" for a
 * rule nested under synthesized intermediates.
 */
static struct nomount_dir_node *nm_real_dir_node_of(struct nomount_dir_node *d)
{
    int guard = 64;

    while (d && (d->_tag_ptr & 1UL) && guard-- > 0) {
        struct nomount_rule *owner = (struct nomount_rule *)(d->_tag_ptr & ~1UL);

        d = owner ? owner->parent_dir : NULL;
    }
    return (d && (d->_tag_ptr & 1UL)) ? NULL : d;
}

static void nomount_hijacked_put_super(struct super_block *sb)
{
    struct nm_sop *nm_sop = __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode);
    void (*orig_put)(struct super_block *) = NULL;
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    HLIST_HEAD(victims);

    /* Remove the rule outright, not just its child entry.
     *
     * This used to call __nomount_delete_child_locked(), which unhooks the rule from its
     * parent directory and nulls ->parent_dir but leaves the rule itself in
     * nomount_rules_ht. It therefore kept being printed by NM_CMD_GET_LIST and kept
     * matching __nomount_del_rule, while injecting nothing -- userspace's picture of the
     * rule set silently diverging from the kernel's for every rule on the filesystem
     * going away. nm_detach_rule_locked() does both halves, and the victims/
     * synchronize_rcu/free protocol is the one __nomount_clear_all uses.
     */
    /* Resolve through virtual parents, do not skip them.
     *
     * This used to test `rule->parent_dir` directly and require a real node, so a rule
     * nested under a synthesized intermediate -- whose parent_dir IS a virtual node --
     * failed the test and stayed in the table, while the intermediate itself (parented
     * under a real node on this sb) matched and was freed. nm_free_rule() then dropped the
     * last reference to the virtual dir_node, and the surviving child was left pointing at
     * freed slab: the next del or clear did atomic_inc_not_zero() and an idr walk on it.
     *
     * Resolve every rule BEFORE detaching any. Detaching nulls parent_dir, so in a single
     * pass an intermediate visited first cut its descendants off from the walk and they
     * stayed in the table, listed and matched by del but serving nothing. victim_node is
     * unused while a rule is live, so it carries the collected set between the passes.
     */
    {
        HLIST_HEAD(dying);
        bool any = false;

        mutex_lock(&nomount_write_mutex);
        hash_for_each(nomount_rules_ht, bkt, rule, vpath_node) {
            struct nomount_dir_node *d = nm_real_dir_node_of(rule->parent_dir);

            if (d && d->dir_inode && d->dir_inode->i_sb == sb)
                hlist_add_head(&rule->victim_node, &dying);
        }
        hlist_for_each_entry_safe(rule, tmp, &dying, victim_node) {
            hlist_del(&rule->victim_node);
            nm_detach_rule_locked(rule, &victims, false);
            any = true;
        }
        if (any)
            atomic_inc(&nm_rule_gen);
        /* A recycled anon dev number must not inherit this filesystem's placement state. */
        nm_forget_dev_caches(sb->s_dev);
        mutex_unlock(&nomount_write_mutex);
    }
    if (!hlist_empty(&victims)) {
        synchronize_rcu();
        hlist_for_each_entry_safe(rule, tmp, &victims, victim_node)
            nm_free_rule(rule);
    }

    if (nm_sop) {
        int i = 0;
        orig_put = nm_sop->orig_sop ? nm_sop->orig_sop->put_super : NULL;
        if (nm_sop->orig_export)
            smp_store_release(&sb->s_export_op, nm_sop->orig_export);
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
        WRITE_ONCE(nm_sop->sb, NULL);
        /* Drop it from the list and free it, rather than leaving a dead entry behind.
         *
         * This path only nulled ->sb, so every unmount of a hijacked filesystem leaked
         * one nm_sop and left nomount_sb_list a little longer -- unbounded across
         * mount/unmount cycles, with nomount_restore_superblocks() walking the corpses
         * each time it runs.
         *
         * Freeing is safe exactly here: s_op was restored with a store-release above, so
         * no NEW reader can reach this object through it, and every existing reader is
         * inside an RCU read-side section (nm_orig_sop), which is what kfree_rcu waits
         * for. The list itself is serialised by nomount_write_mutex, which guards the
         * list_add_tail_rcu in nomount_hijack_superblock and the walk in
         * nomount_restore_superblocks -- and this runs outside the mutex taken above, so
         * it has to be retaken. put_super may sleep, so that is allowed.
         */
        mutex_lock(&nomount_write_mutex);
        list_del_rcu(&nm_sop->list);
        mutex_unlock(&nomount_write_mutex);
        kfree_rcu(nm_sop, rcu);
    }
    if (orig_put) orig_put(sb);
}

static inline bool nm_is_own_inode(const struct inode *inode);

static const struct export_operations *nm_orig_export(struct super_block *sb)
{
    const struct export_operations *orig = NULL;
    struct nm_sop *nm_sop;

    rcu_read_lock();
    nm_sop = __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop,
                      destroy_inode, nomount_hijacked_destroy_inode);
    if (nm_sop)
        orig = nm_sop->orig_export;
    rcu_read_unlock();
    return orig;
}

/* The stock inode a shadowing engine inode stands in for, on the same sb, referenced:
 * s_path may be its only holder, and a delete on a writable victim drops the inode. */
static struct inode *nm_shadowed_inode(struct inode *inode)
{
    struct nm_inode_info *info;
    struct dentry *d;
    struct inode *s = NULL;

    if (!nm_is_own_inode(inode))
        return NULL;
    info = READ_ONCE(inode->i_private);
    d = info ? info->s_path.dentry : NULL;
    if (!d)
        return NULL;
    spin_lock(&d->d_lock);
    if (d->d_inode && d->d_inode->i_sb == inode->i_sb && !nm_is_own_inode(d->d_inode))
        s = igrab(d->d_inode);
    spin_unlock(&d->d_lock);
    return s;
}

#define NM_FILEID_INO64_GEN         0x81
#define NM_FILEID_INO64_GEN_PARENT  0x82

/* An engine inode comes from the victim's own alloc_inode() with the fs-private part left
 * zero. Two encoders read that part: overlayfs dereferences the NULL lower inode (an oops
 * from any app's inotify fdinfo) and erofs prints nid 0 beside the in-band ino. On those two
 * an engine inode gets the handle stock would give it; every other encoder only reads
 * generic inode fields and is called as before.
 */
static int nm_encode_fh(struct inode *inode, u32 *fh, int *max_len, struct inode *parent)
{
    struct super_block *sb = inode->i_sb;
    const struct export_operations *orig = nm_orig_export(sb);
    struct inode *si, *sp;
    int len, ret;

    if (!orig || !orig->encode_fh)
        return FILEID_INVALID;
    if (sb->s_magic != EROFS_SUPER_MAGIC_V1
#ifdef OVERLAYFS_SUPER_MAGIC
        && sb->s_magic != OVERLAYFS_SUPER_MAGIC
#endif
       )
        return orig->encode_fh(inode, fh, max_len, parent);

    si = nm_shadowed_inode(inode);
    sp = parent ? nm_shadowed_inode(parent) : NULL;
    if (si)
        inode = si;
    if (sp)
        parent = sp;
    if (!nm_is_own_inode(inode) && !(parent && nm_is_own_inode(parent))) {
        ret = orig->encode_fh(inode, fh, max_len, parent);
        goto out;
    }
    /* ovl_encode_fh answers this for a connectable request and for any encode error. */
    ret = FILEID_INVALID;
    if (sb->s_magic != EROFS_SUPER_MAGIC_V1)
        goto out;
    /* erofs_encode_fh's layout; a stock erofs inode's i_ino is its nid on 64-bit. */
    len = parent ? 6 : 3;
    if (*max_len < len) {
        *max_len = len;
        goto out;
    }
    fh[0] = (u32)((u64)inode->i_ino >> 32);
    fh[1] = (u32)inode->i_ino;
    fh[2] = inode->i_generation;
    if (parent) {
        fh[3] = (u32)((u64)parent->i_ino >> 32);
        fh[4] = (u32)parent->i_ino;
        fh[5] = parent->i_generation;
    }
    *max_len = len;
    ret = parent ? NM_FILEID_INO64_GEN_PARENT : NM_FILEID_INO64_GEN;
out:
    if (sp)
        iput(sp);
    if (si)
        iput(si);
    return ret;
}

/* Only the filesystems the engine is built for. kernfs (sysfs, cgroup) identifies its
 * superblocks by s_op pointer and BUG()s on a foreign one. Checked before ANY hijack of an
 * inode on the superblock, not only its s_op: a refused one would otherwise keep our
 * per-inode op copies, and code comparing f_op against its own table would miss. */
static bool nm_sb_supported(const struct super_block *sb)
{
    switch (sb->s_magic) {
    case EROFS_SUPER_MAGIC_V1:
    case EXT4_SUPER_MAGIC:
    case F2FS_SUPER_MAGIC:
    case SQUASHFS_MAGIC:
    case TMPFS_MAGIC:
    case RAMFS_MAGIC:
#ifdef OVERLAYFS_SUPER_MAGIC
    case OVERLAYFS_SUPER_MAGIC:
#endif
        return true;
    default:
        return false;
    }
}

static inline int nomount_hijack_superblock(struct super_block *sb)
{
    struct nm_sop *nm_sop;
    int i, count = 0;
    if (unlikely(!sb || !sb->s_op)) return 0;
    if (__get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode)) return 0;
    if (!nm_sb_supported(sb)) {
        nm_debug("not hijacking a superblock of magic 0x%lx\n", sb->s_magic);
        return -EOPNOTSUPP;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
    if (!sb->s_op->destroy_inode) {
        nm_warn("not hijacking a superblock whose fs has no destroy_inode (pre-5.2): our hook would suppress the VFS's own free path\n");
        return -EOPNOTSUPP;
    }
#endif

    nm_sop = kzalloc(sizeof(*nm_sop), GFP_KERNEL);
    if (unlikely(!nm_sop)) return -ENOMEM;

    nm_sop->fake_sop = *(sb->s_op);
    nm_sop->orig_sop = sb->s_op;
    nm_sop->sb = sb;
    nm_sop->fake_sop.destroy_inode = nomount_hijacked_destroy_inode;
    nm_sop->fake_sop.drop_inode = nomount_hijacked_drop_inode;
    nm_sop->fake_sop.evict_inode = nomount_hijacked_evict_inode;
    nm_sop->fake_sop.put_super = nomount_hijacked_put_super;
    if (sb->s_op->statfs)
        nm_sop->fake_sop.statfs = nomount_hijacked_statfs;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    if (!nm_sop->orig_sop->destroy_inode && !nm_sop->orig_sop->free_inode)
        nm_sop->fake_sop.free_inode = free_inode_nonrcu;
#endif

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
    /* Before the publish, not after a rule succeeds: once s_op names our table an
     * unload frees the text it points at. See nm_pin_module(). */
    nm_pin_module();
    smp_store_release(&sb->s_op, &nm_sop->fake_sop);
    /* After s_op: nm_encode_fh finds the original table through it. */
    if (sb->s_export_op && sb->s_export_op->encode_fh) {
        nm_sop->orig_export = sb->s_export_op;
        nm_sop->fake_export = *sb->s_export_op;
        nm_sop->fake_export.encode_fh = nm_encode_fh;
        smp_store_release(&sb->s_export_op,
                          (const struct export_operations *)&nm_sop->fake_export);
    }
    nm_debug("Superblock successfully hijacked for dev: 0x%x\n", sb->s_dev);
    return 0;
}

static inline bool nm_is_own_inode(const struct inode *inode)
{
    const struct inode_operations *iop = smp_load_acquire(&inode->i_op);

    return iop == &nm_dir_iops || iop == &nm_file_iops;
}

static inline int nomount_hijack_virtual_parent(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_fop *nm_fop;

    if (unlikely(nm_is_own_inode(inode))) return -EBUSY;
    if (unlikely(!inode->i_fop)) return 0;
    nm_fop = nm_get_fop(smp_load_acquire(&inode->i_fop));
    if (nm_fop) {
        smp_store_release(&nm_fop->dir_node, dir_node);
        return 0;
    }
    if (unlikely(!inode->i_fop->iterate_shared
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
                 && !inode->i_fop->iterate
#endif
        )) return 0;

    nm_fop = kmem_cache_zalloc(nm_fop_cachep, GFP_KERNEL);
    if (unlikely(!nm_fop))
        return -ENOMEM;

    nm_fop->fake_fop = *(inode->i_fop);
    nm_fop->orig_fop = inode->i_fop;
    nm_fop->dir_node = dir_node;

    if (nm_fop->orig_fop->iterate_shared)
        nm_fop->fake_fop.iterate_shared = nomount_hijacked_iterate_dir;
    if (nm_fop->orig_fop->llseek)
        nm_fop->fake_fop.llseek = nomount_hijacked_llseek;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    if (nm_fop->orig_fop->iterate)
        nm_fop->fake_fop.iterate = nomount_hijacked_iterate_dir;
#endif

    /* Before the publish: i_fop can never be put back, so from here on an unload
     * would leave iterate_shared pointing into freed text. See nm_pin_module(). */
    nm_pin_module();
    smp_store_release(&inode->i_fop, &nm_fop->fake_fop);
    nm_debug("i_fop successfully hijacked for virtual parent dir (ino: %lu)\n", inode->i_ino);
    return 0;
}

static inline int nomount_hijack_dir_inode(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_iop *nm_iop;

    if (unlikely(!inode->i_op)) return 0;
    if (unlikely(nm_is_own_inode(inode))) return -EBUSY;
    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup);
    if (nm_iop) {
        smp_store_release(&nm_iop->dir_node, dir_node);
        return 0;
    }
    if (unlikely(!inode->i_op->lookup)) return 0;

    nm_iop = kmem_cache_zalloc(nm_iop_cachep, GFP_KERNEL);
    if (unlikely(!nm_iop))
        return -ENOMEM;

    nm_iop->fake_iop = *(inode->i_op);
    nm_iop->orig_iop = inode->i_op;
    nm_iop->dir_node = dir_node;

    if (nm_iop->orig_iop->lookup) nm_iop->fake_iop.lookup = nomount_hijacked_lookup;
    nm_iop->fake_iop.getattr = nomount_hijacked_getattr;
    /* Before the publish, same reason as i_fop above. See nm_pin_module(). */
    nm_pin_module();
    smp_store_release(&inode->i_op, &nm_iop->fake_iop);
    nm_debug("i_op successfully hijacked for parent dir (ino: %lu)\n", inode->i_ino);
    return 0;
}

static void nm_dir_node_rcu_free(struct rcu_head *head)
{
    struct nomount_dir_node *dir_node = container_of(head, struct nomount_dir_node, rcu);
    struct nomount_child_node *child;
    int id;
    idr_for_each_entry(&dir_node->children_idr, child, id)
        kfree(child);
    idr_destroy(&dir_node->children_idr);
    nm_rlist_free(dir_node->rlist);
    kmem_cache_free(nm_dir_cachep, dir_node);
}

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

/* Once a rule exists, this module can never be unloaded again.
 *
 * A victim directory is hijacked by pointing inode->i_op at a per-inode copy of its
 * own vtable whose lookup/getattr are ours, and the engine's own inodes point i_op
 * straight at nm_dir_iops/nm_file_iops. nomount_restore_dir_node() does not put
 * either pointer back -- it NEUTERS the hijack by clearing nm_iop->dir_node so the
 * handlers fall through, and that is deliberate: the VFS treats i_op as immutable
 * for an inode's lifetime and dereferences it as a plain stable pointer, so there is
 * no sequence -- synchronize_rcu() included -- that proves no CPU is mid-flight
 * through the copy at the moment it would be restored. Installing a superset once is
 * safe; uninstalling it is not.
 *
 * So those pointers outlive every rule, and shrink_dcache_sb() only reclaims UNUSED
 * dentries: a directory that is some process's cwd or has an open fd keeps its
 * inode, and its i_op keeps pointing into this module's text. Unloading then leaves
 * the next lookup on it jumping into freed text, and kmem_cache_destroy() on the
 * vfs_iops cache runs with objects still installed.
 *
 * Refusing the unload is the honest answer: rmmod returns -EBUSY instead. The pin is
 * never dropped, including across `nomount clear`, because clearing rules does not
 * take the pointers back.
 *
 * Taken when a fake vtable is PUBLISHED, not when a rule succeeds. It used to be
 * called once, from __nomount_add_rule()'s success path, while the three publishes
 * happen earlier -- so anything failing in between (an order-0 kmalloc in
 * __nomount_inject_child_locked, or nomount_hijack_superblock() returning
 * -EOPNOTSUPP on a pre-5.2 fs with no ->destroy_inode) left i_op and i_fop pointing
 * into module text with nothing pinned. On a hide=0 build rmmod then returned 0, the
 * text was freed, and the next lookup on that directory was an indirect call into
 * reclaimed memory. The sentence that used to end this comment -- that nomount_exit()
 * can only run on a module that never held a rule, so the caches it destroys are
 * empty -- was true of rules and false of hijacks, which is what hid it.
 *
 * __module_get, not try_module_get: we are inside a netlink command, so this
 * module's refcount is already non-zero and the get cannot fail. Both are no-ops
 * when THIS_MODULE is NULL, which is what a CONFIG_NOMOUNT=y build has.
 */
static void nm_pin_module(void)
{
    static bool pinned;

    if (!pinned) {
        pinned = true;
        __module_get(THIS_MODULE);
    }
}

static void nomount_restore_superblocks(void)
{
    struct nm_sop *nm_sop, *tmp;

    list_for_each_entry_safe(nm_sop, tmp, &nomount_sb_list, list) {
        int i = 0;
        if (nm_sop->sb) {
            shrink_dcache_sb(nm_sop->sb);
            if (nm_sop->orig_export)
                smp_store_release(&nm_sop->sb->s_export_op, nm_sop->orig_export);
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

static struct nomount_dir_node *__nomount_alloc_dir_node(struct inode *inode) 
{
    struct nomount_dir_node *dir_node = kmem_cache_alloc(nm_dir_cachep, GFP_KERNEL);
    if (unlikely(!dir_node)) return NULL;
    if (inode) {
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
    dir_node->stock_eof = 0;
    dir_node->max_stock_pos = 0;
    dir_node->real_end = 0;
    dir_node->stock_end = 0;
    dir_node->rlist = NULL;
    dir_node->bloom_mask = 0;
    dir_node->has_public = false;
    atomic_set(&dir_node->refcount, 1);
    return dir_node;
}

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

/* Widen a minted directory to unscoped, and every scoped minted directory above it: a
 * wider directory under a narrower parent is still unreachable for the readers it gained.
 * The store order only ever widens (deny, then the start, then the end), so a lockless
 * reader never sees a narrower scope in between. */
static bool nm_widen_scope_up(struct nomount_rule *rule)
{
    int guard = 64;
    bool any = false;

    while (rule && guard-- > 0 && (rule->flags & NM_FLAG_VIRTUAL_DIR)) {
        struct nomount_dir_node *pd;

        if (rule->target_uid || rule->uid_end || rule->deny_n) {
            WRITE_ONCE(rule->deny_n, 0);
            smp_wmb();
            WRITE_ONCE(rule->target_uid, 0);
            smp_wmb();
            WRITE_ONCE(rule->uid_end, 0);
            any = true;
        }
        pd = rule->parent_dir;
        if (!pd || !(pd->_tag_ptr & 1UL)) break;
        rule = (struct nomount_rule *)(pd->_tag_ptr & ~1UL);
    }
    return any;
}

static void nm_mark_public_up(struct nomount_rule *rule)
{
    int guard = 64;

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

        if (!(pd->_tag_ptr & 1UL)) break;
        rule = (struct nomount_rule *)(pd->_tag_ptr & ~1UL);
    }
}

/* Does any surviving child still carry NM_FLAG_PUBLIC? Callers hold
 * nomount_write_mutex. Only reached when a child stopped being public, so the walk is
 * off the common path. */
static bool nm_dir_has_public(struct nomount_dir_node *dir_node)
{
    struct nomount_child_node *c;
    int id = 0;

    idr_for_each_entry(&dir_node->children_idr, c, id)
        if (c->flags & NM_FLAG_PUBLIC)
            return true;
    return false;
}

static int __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule, const char *name, size_t name_len)
{
    struct nomount_child_node *child;
    u32 name_hash;

    if (unlikely(!dir_node)) return -ENOMEM;
    name_hash = full_name_hash(NULL, name, name_len);
    hash_for_each_possible(dir_node->children_ht, child, hnode, name_hash) {
        if (child->name_hash == name_hash && child->name_len == name_len &&
            memcmp(child->name, name, name_len) == 0) {
            bool was_pub = child->flags & NM_FLAG_PUBLIC;

            if (child->rule && child->rule != rule)
                child->rule->parent_dir = NULL;
            WRITE_ONCE(child->flags, rule->flags);
            WRITE_ONCE(child->d_type, (rule->flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG);
            WRITE_ONCE(child->fake_ino, rule->v_dino ? rule->v_dino : rule->v_ino);
            smp_store_release(&child->rule, rule);
            rule->parent_dir = dir_node;
            if (rule->flags & NM_FLAG_PUBLIC)
                WRITE_ONCE(dir_node->has_public, true);
            else if (was_pub)
                /* The same latch as the delete path, in its other form: this branch
                 * REPLACES a child in place, so replacing the node's last PUBLIC child
                 * with a rule that is not public clears the bit on the child and used to
                 * leave it set on the node -- keeping blocked uids on the hijacked lookup
                 * path for children that are no longer public. Only walked when a public
                 * child actually stopped being one, so the common replace is untouched. */
                WRITE_ONCE(dir_node->has_public, nm_dir_has_public(dir_node));
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

    WRITE_ONCE(dir_node->bloom_mask, dir_node->bloom_mask | (1ULL << (name_hash & 63)));
    if (rule->flags & NM_FLAG_PUBLIC)
        WRITE_ONCE(dir_node->has_public, true);
    hash_add_rcu(dir_node->children_ht, &child->hnode, name_hash);
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
        u64 mask = 0;
        /* has_public was write-only in the whole engine: set true at three sites, given
         * false once at allocation, and never recomputed. So removing the last PUBLIC
         * child left the node latched public for its lifetime, and a blocked uid stayed
         * on the hijacked lookup path for children that are no longer public at all --
         * `nomount clear` included, since it frees nodes rather than rebuilding them.
         * Rebuilt from the survivors here, in the same walk that rebuilds bloom_mask;
         * the child carries the bit too (nm_mark_public_up sets both). */
        bool pub = false;
        idr_for_each_entry(&dir_node->children_idr, child, id) {
            mask |= (1ULL << (child->name_hash & 63));
            if (child->flags & NM_FLAG_PUBLIC)
                pub = true;
        }
        WRITE_ONCE(dir_node->bloom_mask, mask);
        WRITE_ONCE(dir_node->has_public, pub);
    }
}

#define NM_INO_SAMPLES 256
#define NM_INO_POP_SAMPLES 256
#define NM_INO_MINE    256
#define NM_INO_SUB     256
#define NM_INO_SUBDIRS 64
#define NM_INO_SUBNAMES 64
#define NM_RANGE_SLOTS 8

struct nm_ino_pop {
    u64 v[NM_INO_POP_SAMPLES];
    int n;
    u64 mine[NM_INO_MINE];
    int nmine;
    u64 sub[NM_INO_SUB];
    int nsub;
    u64 hw;
    dev_t dev;
};

#define NM_DEV_INO_SLOTS 16

#define NM_USED_ORDER 20

struct nm_dev_ino {
    dev_t dev;
    u64 hw;
    u64 dmin;
    u64 dmax;
    u64 amax;
    unsigned long *used;
    char *seed;
    int dmax_err;
    bool dmax_valid;
    bool e2big_retried;
    bool valid;
};

static struct nm_dev_ino nm_dev_ino_tab[NM_DEV_INO_SLOTS];
static int nm_dev_ino_next;
static int nm_subtree_dir_ino_max(const char *root, dev_t dev, u64 *out_min,
                                  u64 *out_max, u64 *out_any, unsigned long *used);

/* Which placement path this build actually compiled, so a dmesg capture identifies the
 * zip it came from rather than leaving the 00_/01_ difference invisible. */
#ifdef NM_OVL_LAST_INO
#define NM_OVL_COMPILED 1
#else
#define NM_OVL_COMPILED 0
#endif

/* Bloom over every inode number the subtree scan saw: a clear bit is never a used number. */
static void nm_used_add(unsigned long *used, u64 ino)
{
    if (!used)
        return;
    __set_bit(hash_64(ino, NM_USED_ORDER), used);
    __set_bit(hash_64(ror64(ino, 32) + 1, NM_USED_ORDER), used);
}

/* NULL-safe, like nm_used_add() above. It was not, and nm_place_dir_ino() reaches it
 * twice without a guard: a failed kvzalloc of the 128 KB bitmap left used == NULL while
 * dmax_valid went true (see nm_dev_ino_seed), and test_bit(nr, NULL) is a NULL deref on
 * the rule-add path. nm_ino_unavailable() guards with `di->used &&`, which is why only
 * two of the three call sites could crash. A missing bitmap now also fails the seed, so
 * this should be unreachable -- that is exactly why it must not depend on one assignment
 * staying right. No bitmap means nothing is known to be used, so: false. */
static bool nm_used_test(const unsigned long *used, u64 ino)
{
    if (!used)
        return false;
    return test_bit(hash_64(ino, NM_USED_ORDER), used) &&
           test_bit(hash_64(ror64(ino, 32) + 1, NM_USED_ORDER), used);
}

static int nm_dev_ino_seed(struct nm_dev_ino *s, const char *seed)
{
    size_t sz = BITS_TO_LONGS(1UL << NM_USED_ORDER) * sizeof(long);
    u64 lo = 0, m = 0, a = 0;
    int err;

    if (s->used)
        memset(s->used, 0, sz);
    else
        s->used = kvzalloc(sz, GFP_KERNEL | __GFP_NOWARN);
    kfree(s->seed);
    s->seed = kstrdup(seed, GFP_KERNEL);
    err = nm_subtree_dir_ino_max(seed, s->dev, &lo, &m, &a, s->used);
    /* A failed kvzalloc is a failed seed. The scan takes `used` and nm_used_add() is a
     * no-op on NULL, so without this the walk returns 0, dmax_err stays 0 -- which is
     * what nm_dev_ino_get() retries on -- and dmax_valid goes true with no bitmap at
     * all. Placement then ran with an EMPTY exclusion set, permanently and with no
     * retry, which is the collision this bitmap exists to prevent; and two of the three
     * nm_used_test() call sites had no NULL guard, so it was a kernel NULL deref on the
     * rule-add path rather than only a degradation. -ENOMEM here routes it into the
     * existing one-shot retry. */
    if (!err && !s->used)
        err = -ENOMEM;
    s->dmax_err = err;
    if (err == 0 && s->used) {
        struct nomount_rule *r;
        int bkt;

        /* The scan skips injected paths; the numbers already handed out stay taken.
         *
         * v_dino as well as v_ino. An overlay-flagged virtual ancestor carries a second,
         * independently assigned number -- (v_hash & 0x03FFFFFF) | 0x02000000 | 1, set
         * directly rather than through the placer -- and it entered no exclusion set
         * anywhere. It is app-visible: it is what the parent's dirent reports for that
         * child and what "." reports inside it, so it shows up in `ls -i`. Two ancestors
         * whose hashes collide, or an overlay-counter placement landing in that band,
         * would hand the same number to two entries. */
        hash_for_each(nomount_rules_ht, bkt, r, vpath_node) {
            nm_used_add(s->used, r->v_ino);
            if (r->v_dino && r->v_dino != r->v_ino)
                nm_used_add(s->used, r->v_dino);
        }
    }
    if (err == 0) {
        s->dmin = lo;
        s->dmax = m;
        s->amax = a;
        s->dmax_valid = true;
    } else {
        kvfree(s->used);
        s->used = NULL;
    }
    return err;
}

static struct nm_dev_ino *nm_dev_ino_get(dev_t dev, const char *seed)
{
    struct nm_dev_ino *s = NULL;
    int i, err;

    if (!dev)
        return NULL;
    for (i = 0; i < NM_DEV_INO_SLOTS; i++) {
        if (nm_dev_ino_tab[i].valid && nm_dev_ino_tab[i].dev == dev) {
            s = &nm_dev_ino_tab[i];
            /* Every transient failure, not just -ENOMEM. -E2BIG is more than
             * NM_DMAX_DIRS directories on the partition OR a single DT_UNKNOWN dirent
             * anywhere in the walk, and -ENOENT is an ascended scan root with no
             * same-dev subdirectory -- both can differ on the next attempt, and a slot
             * that failed once used to stay in the degraded path for the rest of the
             * boot. Still one-shot per call, so the expensive walk is not repeated per
             * rule; a slot that keeps failing simply keeps answering !dmax_valid. */
            /* -E2BIG is deterministic for a given partition and is the expensive walk:
             * retried once per slot, not on every range-cache miss. */
            if (!s->dmax_valid && seed &&
                (s->dmax_err == -ENOMEM || s->dmax_err == -ENOENT ||
                 (s->dmax_err == -E2BIG && !s->e2big_retried))) {
                if (s->dmax_err == -E2BIG)
                    s->e2big_retried = true;
                err = nm_dev_ino_seed(s, seed);
                nm_debug("inoseed: retry dev=%u:%u seed='%s' err=%d dmax=%llu amax=%llu\n",
                         MAJOR(dev), MINOR(dev), seed, err,
                         (unsigned long long)s->dmax, (unsigned long long)s->amax);
            }
            return s;
        }
    }
    if (!seed)
        return NULL;
    for (i = 0; i < NM_DEV_INO_SLOTS; i++) {
        if (!nm_dev_ino_tab[i].valid) {
            s = &nm_dev_ino_tab[i];
            break;
        }
    }
    if (!s) {
        s = &nm_dev_ino_tab[nm_dev_ino_next];
        nm_dev_ino_next = (nm_dev_ino_next + 1) % NM_DEV_INO_SLOTS;
    }
    s->dev = dev;
    s->hw = 0;
    s->dmin = 0;
    s->dmax = 0;
    s->amax = 0;
    s->dmax_valid = false;
    s->e2big_retried = false;
    err = nm_dev_ino_seed(s, seed);
    s->valid = true;
    /* The seed path is what the dmax/amax scan walked, and this table is 16 slots with
     * round-robin eviction -- a device with more partitions than that can have an entry
     * re-seeded from a DIFFERENT path later. Both facts decide the number a synthesized
     * directory ends up with, and neither was visible from outside. */
    nm_debug("inoseed: dev=%u:%u seed='%s' err=%d dmax=%llu amax=%llu slot=%d\n",
             MAJOR(dev), MINOR(dev), seed, err,
             (unsigned long long)s->dmax, (unsigned long long)s->amax,
             (int)(s - nm_dev_ino_tab));
    return s;
}

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
    bool overlay;
    bool want_dir;
    const char *dirpath;
    int dirlen;
    struct nm_ino_pop *pop;
    char (*names)[NAME_MAX + 1];
    int n_names;
    char (*dirs)[NAME_MAX + 1];
    int n_dirs;
    char pathbuf[PATH_MAX];
};

static struct file *nm_open_dir(struct path *p, const struct cred *caller)
{
    struct file *f = dentry_open(p, O_RDONLY | O_DIRECTORY | O_NOATIME, nm_root_cred);

    if (IS_ERR(f) && caller && caller != nm_root_cred)
        f = dentry_open(p, O_RDONLY | O_DIRECTORY | O_NOATIME, caller);
    return f;
}

static void nm_sub_insert(struct nm_ino_pop *pop, u64 ino)
{
    int i;

    if (!ino || pop->nsub >= NM_INO_SUB)
        return;
    for (i = 0; i < pop->nsub; i++)
        if (pop->sub[i] == ino)
            return;
    pop->sub[pop->nsub++] = ino;
}

static void nm_pop_insert(struct nm_ino_pop *pop, u64 ino)
{
    int j = pop->n;

    if (!ino || pop->n >= NM_INO_POP_SAMPLES)
        return;
    while (j > 0 && pop->v[j - 1] > ino) {
        pop->v[j] = pop->v[j - 1];
        j--;
    }
    pop->v[j] = ino;
    pop->n++;
}

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

    if (namelen <= 0 || namelen > NAME_MAX ||
        (namelen == 1 && name[0] == '.') ||
        (namelen == 2 && name[0] == '.' && name[1] == '.'))
        return NM_ACTOR_CONTINUE;

    len = nm_scan_path(s, name, namelen);
    if (len < 0)
        return NM_ACTOR_CONTINUE;
    if (nm_path_is_injected(s->pathbuf, len))
        return NM_ACTOR_CONTINUE;

    if (!s->overlay) {
        if (dt == DT_UNKNOWN)
            return NM_ACTOR_CONTINUE;
        if ((dt == DT_DIR) == s->want_dir) {
            nm_pop_insert(s->pop, ino);
        } else if (dt == DT_DIR && s->dirs && s->n_dirs < NM_INO_SUBDIRS) {
            memcpy(s->dirs[s->n_dirs], name, namelen);
            s->dirs[s->n_dirs][namelen] = '\0';
            s->n_dirs++;
        }
        return NM_ACTOR_CONTINUE;
    }

    if (s->names && s->n_names < NM_INO_SAMPLES) {
        memcpy(s->names[s->n_names], name, namelen);
        s->names[s->n_names][namelen] = '\0';
        s->n_names++;
    }
    return NM_ACTOR_CONTINUE;
}

struct nm_sub_scan {
    struct dir_context ctx;
    char (*names)[NAME_MAX + 1];
    int n_names;
};

static NM_ACTOR_RET nm_sub_actor(struct dir_context *ctx, const char *name,
                                 int namelen, loff_t off, u64 ino, unsigned int dt)
{
    struct nm_sub_scan *s = container_of(ctx, struct nm_sub_scan, ctx);

    if (namelen <= 0 || namelen > NAME_MAX || name[0] == '.')
        return NM_ACTOR_CONTINUE;
    if (s->n_names >= NM_INO_SUBNAMES)
        return NM_ACTOR_CONTINUE;
    memcpy(s->names[s->n_names], name, namelen);
    s->names[s->n_names][namelen] = '\0';
    s->n_names++;
    return NM_ACTOR_CONTINUE;
}

static void nm_sub_collect(const char *dirpath, struct nm_ino_pop *pop,
                           char (*names)[NAME_MAX + 1])
{
    struct nm_sub_scan sc;
    struct path dp;
    struct file *dir;
    int i;

    if (!names || pop->nsub >= NM_INO_SUB)
        return;
    if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
        return;
    memset(&sc, 0, sizeof(sc));
    sc.names = names;
    *((filldir_t *)&sc.ctx.actor) = nm_sub_actor;
    dir = nm_open_dir(&dp, NULL);
    path_put(&dp);
    if (!IS_ERR(dir)) {
        iterate_dir(dir, &sc.ctx);
        fput(dir);
    }
    for (i = 0; i < sc.n_names && pop->nsub < NM_INO_SUB; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, names[i]);
        struct path fp;
        struct kstat fk;

        if (!cp)
            continue;
        if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
            int r = nm_path_stat(&fp, &fk);

            path_put(&fp);
            if (r == 0 && !S_ISDIR(fk.mode))
                nm_sub_insert(pop, fk.ino);
        }
        kfree(cp);
    }
}

static void nm_mark_injected_taken(const char *dirpath, struct nm_ino_pop *pop)
{
    struct nomount_rule *r;
    size_t dlen = strlen(dirpath);
    int bkt;

    hash_for_each(nomount_rules_ht, bkt, r, vpath_node) {
        const char *vp = nm_get_vpath(r);
        const char *slash = strrchr(vp, '/');
        size_t plen;

        if (!slash)
            continue;
        plen = (slash == vp) ? 1 : (size_t)(slash - vp);
        if (plen != dlen)
            continue;
        if (plen == 1 ? (dirpath[0] != '/') : (memcmp(vp, dirpath, plen) != 0))
            continue;
        nm_sub_insert(pop, r->v_ino);
    }
}

static int nm_dir_ino_pop(const char *dirpath, bool want_dir, struct nm_ino_pop *pop)
{
    struct nm_ino_scan *sc;
    struct path dp;
    struct file *dir;
    const struct cred *old;
    char (*subnames)[NAME_MAX + 1] = NULL;
    dev_t dir_dev = 0;
    dev_t report_dev = 0;
    int i;

    pop->n = 0;
    pop->nmine = 0;
    pop->nsub = 0;
    pop->hw = 0;
    pop->dev = 0;
    if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
        return -ENOENT;
    {
        struct kstat dk;

        if (nm_path_stat(&dp, &dk) == 0) {
            dir_dev = dk.dev;
            pop->dev = dk.dev;
        }
    }
    nm_mark_injected_taken(dirpath, pop);
    sc = kzalloc(sizeof(*sc), GFP_KERNEL | __GFP_NOWARN);
    if (!sc) { path_put(&dp); return -ENOMEM; }

    sc->want_dir = want_dir;
    sc->dirpath  = dirpath;
    sc->dirlen   = (int)strlen(dirpath);
    if (sc->dirlen == 1 && dirpath[0] == '/')
        sc->dirlen = 0;
    sc->pop = pop;
#ifdef OVERLAYFS_SUPER_MAGIC
    sc->overlay = dp.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#endif
    if (sc->overlay) {
        sc->names = vzalloc(NM_INO_SAMPLES * (NAME_MAX + 1));
        if (!sc->names) { kfree(sc); path_put(&dp); return -ENOMEM; }
    } else if (!want_dir) {
        sc->dirs = vzalloc(NM_INO_SUBDIRS * (NAME_MAX + 1));
    }
    if (!want_dir)
        subnames = vzalloc(NM_INO_SUBNAMES * (NAME_MAX + 1));

    *((filldir_t *)&sc->ctx.actor) = nm_ino_actor;
    old = override_creds(nm_root_cred);
    dir = nm_open_dir(&dp, old);
    path_put(&dp);
    if (!IS_ERR(dir)) {
        iterate_dir(dir, &sc->ctx);
        fput(dir);
    }
    revert_creds(old);

    for (i = 0; sc->overlay && i < sc->n_names; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->names[i]);
        struct path fp;
        struct kstat fk;

        if (!cp)
            continue;
        if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
            int r = nm_path_stat(&fp, &fk);

            path_put(&fp);
            if (r == 0 && (!!S_ISDIR(fk.mode) == want_dir)) {
                if (!want_dir) {
                    if (fk.dev != dir_dev && !report_dev) {
                        report_dev = fk.dev;
                        pop->dev = fk.dev;
                        pop->n = 0;
                    }
                    if (report_dev ? fk.dev != report_dev : fk.dev != dir_dev) {
                        kfree(cp);
                        continue;
                    }
                }
                nm_pop_insert(pop, fk.ino);
            } else if (r == 0 && !want_dir && S_ISDIR(fk.mode))
                nm_sub_collect(cp, pop, subnames);
        }
        kfree(cp);
    }

    for (i = 0; sc->dirs && i < sc->n_dirs && pop->nsub < NM_INO_SUB; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->dirs[i]);

        if (!cp)
            continue;
        nm_sub_collect(cp, pop, subnames);
        kfree(cp);
    }

    if (subnames)
        vfree(subnames);
    if (sc->names)
        vfree(sc->names);
    if (sc->dirs)
        vfree(sc->dirs);
    kfree(sc);

    return 0;
}

struct nm_range_slot {
    u32 hash;
    u16 len;
    bool want_dir;
    bool valid;
    /* The path itself, because (hash, len, want_dir) is not a key. full_name_hash is
     * 32-bit, so two different parents of the same length that collide used to be served
     * each other's inode population -- and that population is what the placer samples,
     * so the result is a directory placed from the wrong parent's numbers: precisely the
     * mis-placement the rest of this machinery exists to avoid. The slot already owns a
     * ~2 KB nm_ino_pop, so one small string is not a cost. */
    char *path;
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
            sl->want_dir == want_dir &&
            sl->path && !memcmp(sl->path, dirpath, len))
            return &sl->pop;
    }
    sl = &nm_range_cache[nm_range_cache_next];
    nm_range_cache_next = (nm_range_cache_next + 1) % NM_RANGE_SLOTS;
    sl->valid = false;
    kfree(sl->path);
    sl->path = NULL;
    if (nm_dir_ino_pop(dirpath, want_dir, &sl->pop) != 0)
        return NULL;
    nm_dev_ino_get(sl->pop.dev, dirpath);

    sl->hash = h;
    sl->len = (u16)len;
    sl->want_dir = want_dir;
    sl->path = kstrndup(dirpath, len, GFP_KERNEL);
    /* Only cached once it can be identified again. On an allocation failure this answer
     * is still correct for THIS caller, so hand it back -- but leave the slot invalid so
     * the next lookup re-scans instead of trusting a slot nothing can key. */
    sl->valid = sl->path != NULL;
    return &sl->pop;
}

/* Invalid implies no path. The two rule-removal callers only cleared `valid`, which left
 * a string attached to a slot nothing would look at until its turn came round again --
 * bounded by NM_RANGE_SLOTS and freed on recycle, so not a leak today, but it stops
 * being bounded the moment someone adds a teardown path. */
static void nm_range_cache_flush(void)
{
    int i;

    for (i = 0; i < NM_RANGE_SLOTS; i++) {
        nm_range_cache[i].valid = false;
        kfree(nm_range_cache[i].path);
        nm_range_cache[i].path = NULL;
    }
}

#define NM_DMAX_NAMES 128
#define NM_DMAX_DIRS  8192
#define NM_DMAX_DIRS_MIN 2048

struct nm_dmax_scan {
    struct dir_context ctx;
    char (*names)[NAME_MAX + 1];
    int n_names;
    int seen;
    int skip;
    u64 amax;
    unsigned long *used;
    bool more;
    bool unknown_dt;
};

static NM_ACTOR_RET nm_dmax_actor(struct dir_context *ctx, const char *name,
                                  int namelen, loff_t off, u64 ino, unsigned int dt)
{
    struct nm_dmax_scan *s = container_of(ctx, struct nm_dmax_scan, ctx);
    int idx;

    if (namelen <= 0 || namelen > NAME_MAX ||
        (namelen == 1 && name[0] == '.') ||
        (namelen == 2 && name[0] == '.' && name[1] == '.'))
        return NM_ACTOR_CONTINUE;

    if (ino > s->amax)
        s->amax = ino;
    nm_used_add(s->used, ino);

    if (dt == DT_UNKNOWN) {
        s->unknown_dt = true;
        return NM_ACTOR_CONTINUE;
    }
    if (dt != DT_DIR)
        return NM_ACTOR_CONTINUE;

    idx = s->seen++;
    if (idx < s->skip)
        return NM_ACTOR_CONTINUE;
    if (s->n_names >= NM_DMAX_NAMES) {
        s->more = true;
        return NM_ACTOR_CONTINUE;
    }
    memcpy(s->names[s->n_names], name, namelen);
    s->names[s->n_names][namelen] = '\0';
    s->n_names++;
    return NM_ACTOR_CONTINUE;
}

static int nm_subtree_dir_ino_max(const char *root, dev_t dev, u64 *out_min,
                                  u64 *out_max, u64 *out_any, unsigned long *used)
{
    char **queue;
    struct nm_dmax_scan *sc;
    u64 min = 0, max = 0, any = 0;
    int qhead = 0, qtail = 0, visited = 0, ret = 0, i, skip;
    int cap = NM_DMAX_DIRS;

    queue = kvcalloc(cap, sizeof(*queue), GFP_KERNEL | __GFP_NOWARN);
    if (!queue) {
        cap = NM_DMAX_DIRS_MIN;
        queue = kvcalloc(cap, sizeof(*queue), GFP_KERNEL | __GFP_NOWARN);
    }
    if (!queue)
        return -ENOMEM;
    sc = kzalloc(sizeof(*sc), GFP_KERNEL | __GFP_NOWARN);
    if (!sc) {
        kvfree(queue);
        return -ENOMEM;
    }
    sc->names = kvzalloc(NM_DMAX_NAMES * (NAME_MAX + 1), GFP_KERNEL | __GFP_NOWARN);
    if (!sc->names) {
        kfree(sc);
        kvfree(queue);
        return -ENOMEM;
    }
    queue[qtail] = kstrdup(root, GFP_KERNEL);
    if (!queue[qtail]) {
        ret = -ENOMEM;
        goto out;
    }
    for (;;) {
        char *up = kstrdup(queue[qtail], GFP_KERNEL);
        char *slash;
        struct path pp;
        struct kstat pk;

        if (!up)
            break;
        slash = strrchr(up, '/');
        if (!slash || slash == up) {
            kfree(up);
            break;
        }
        *slash = '\0';
        if (kern_path(up, LOOKUP_FOLLOW, &pp) != 0) {
            kfree(up);
            break;
        }
        if (nm_path_stat(&pp, &pk) != 0 || pk.dev != dev) {
            path_put(&pp);
            kfree(up);
            break;
        }
        path_put(&pp);
        kfree(queue[qtail]);
        queue[qtail] = up;
    }
    {
        struct path rp;
        struct kstat rk;

        if (kern_path(queue[qtail], LOOKUP_FOLLOW, &rp) == 0) {
            if (nm_path_stat(&rp, &rk) == 0 && rk.dev == dev)
                nm_used_add(used, rk.ino);
            path_put(&rp);
        }
    }
    sc->used = used;
    qtail++;

    while (qhead < qtail && ret == 0) {
        char *dirpath = queue[qhead++];
        const struct cred *old;
        struct path dp;
        struct file *dir;

        /* Up to NM_DMAX_DIRS directories, each a kern_path() and a getattr, all
         * under nomount_write_mutex on the rule-add path. The inner re-read loop
         * already yields; this is the loop that does the walking. */
        cond_resched();

        if (++visited > cap) {
            ret = -E2BIG;
            break;
        }
        if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
            continue;

        *((filldir_t *)&sc->ctx.actor) = nm_dmax_actor;
        old = override_creds(nm_root_cred);
        dir = nm_open_dir(&dp, old);
        path_put(&dp);
        if (IS_ERR(dir)) {
            revert_creds(old);
            continue;
        }

        skip = 0;
        for (;;) {
            sc->n_names = 0;
            sc->seen = 0;
            sc->skip = skip;
            sc->more = false;
            sc->unknown_dt = false;
            vfs_llseek(dir, 0, SEEK_SET);
            sc->ctx.pos = 0;
            iterate_dir(dir, &sc->ctx);
            if (sc->unknown_dt) {
                ret = -E2BIG;
                break;
            }

            for (i = 0; i < sc->n_names; i++) {
                char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->names[i]);
                struct path fp;
                struct kstat fk;

                if (!cp) {
                    ret = -ENOMEM;
                    break;
                }
                if (nm_path_is_injected(cp, strlen(cp))) {
                    kfree(cp);
                    continue;
                }
                if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
                    int r = nm_path_stat(&fp, &fk);

                    path_put(&fp);
                    if (r == 0 && S_ISDIR(fk.mode) && fk.dev == dev) {
                        nm_used_add(used, fk.ino);
                        if (!min || fk.ino < min)
                            min = fk.ino;
                        if (fk.ino > max)
                            max = fk.ino;
                        if (qtail < cap) {
                            queue[qtail] = cp;
                            qtail++;
                            continue;
                        }
                        ret = -E2BIG;
                    }
                }
                kfree(cp);
                if (ret)
                    break;
            }
            if (ret || !sc->more || !sc->n_names)
                break;
            skip += sc->n_names;
            cond_resched();
        }
        fput(dir);
        revert_creds(old);
    }

out:
    any = sc->amax;
    for (i = 0; i < qtail; i++)
        kfree(queue[i]);
    kvfree(queue);
    kvfree(sc->names);
    kfree(sc);
    if (ret == 0 && !max)
        ret = -ENOENT;
    if (ret == 0) {
        *out_min = min;
        *out_max = max;
        *out_any = any > max ? any : max;
    }
    return ret;
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
    for (i = 0; i < pop->nsub; i++)
        if (pop->sub[i] == c)
            return true;
    return false;
}

/* Taken by this directory's own sample, or by anything on the partition: di->used holds
 * every inode the subtree scan saw plus every number nm_place_dir_ino() has handed out.
 *
 * nm_ino_take() feeds that set too, so the file placer and the directory placer now
 * exclude each other in BOTH directions. They shared nothing before: a number given to an
 * injected file was recorded only in that file's parent sample, which the directory placer
 * never consults, so a directory synthesized later on the same dev could be handed a
 * number an injected file already held -- and two names sharing (st_dev, st_ino) on one
 * filesystem is the oracle, not merely untidy.
 *
 * The set is a bloom, so it over-reports: a rejected candidate may have been free. That
 * only costs us the next number along, which is what nm_place_dir_ino() already accepts.
 */
static bool nm_ino_unavailable(struct nm_ino_pop *pop, struct nm_dev_ino *di, u64 c)
{
    if (nm_ino_taken(pop, c))
        return true;
    return di && di->used && nm_used_test(di->used, c);
}

static unsigned long nm_ino_take(struct nm_ino_pop *pop, u64 c)
{
    struct nm_dev_ino *di;

    if (pop->nmine < NM_INO_MINE)
        pop->mine[pop->nmine++] = c;
    if (c > pop->hw)
        pop->hw = c;
    di = nm_dev_ino_get(pop->dev, NULL);
    if (di) {
        if (c > di->hw)
            di->hw = c;
        nm_used_add(di->used, c);
    }
    return (unsigned long)c;
}

static unsigned long nm_place_ino(struct nm_ino_pop *pop, u64 spread)
{
    struct nm_dev_ino *di = nm_dev_ino_get(pop->dev, NULL);
    u64 dhw = di ? di->hw : 0;
    int a, s;

    if (pop->n <= 0)
        return 0;

    if (pop->nmine >= NM_INO_MINE) {
        u64 c = pop->hw + 1;
        int guard = 4096;

        if (c <= dhw)
            c = dhw + 1;
        while (nm_ino_unavailable(pop, di, c) && guard--)
            c++;
        return nm_ino_take(pop, c);
    }

    for (a = 0; a < pop->n; a++) {
        int i = (int)((spread + (u64)a) % (u64)pop->n);
        u64 base = pop->v[i];
        u64 room = (i + 1 < pop->n) ? (pop->v[i + 1] - base) : 64;

        if (room > 64)
            room = 64;
        if (i + 1 >= pop->n && base < dhw)
            room = 1;
        for (s = 1; s < (int)room; s++) {
            u64 cand = base + 1 + ((spread + (u64)s) % (room > 1 ? room - 1 : 1));

            if (!nm_ino_unavailable(pop, di, cand))
                return nm_ino_take(pop, cand);
            cand = base + (u64)s;
            if (cand > base && !nm_ino_unavailable(pop, di, cand))
                return nm_ino_take(pop, cand);
        }
    }
    {
        u64 c = pop->v[pop->n - 1] + 1;
        int guard = 4096;

        if (c <= dhw)
            c = dhw + 1;
        while (nm_ino_unavailable(pop, di, c) && guard--)
            c++;
        return nm_ino_take(pop, c);
    }
}

/* On a non-samefs overlay without xino, directory numbers come from ofs->last_ino, which
 * only grows. Taking the next one is what overlayfs does for its own directories, and it
 * never hands that number to anything else. dmax above the counter means the numbers on
 * this mount are not counter-issued. */
/* `local_max` is the highest inode among the siblings of the directory being placed, not
 * the partition-wide dmax.
 *
 * The question this guard asks is "are the numbers on THIS mount counter-issued", and dmax
 * cannot answer it: dmax is measured over the partition SEED subtree, which spans other
 * filesystems and other overlay mounts, so on a mount whose own directories are perfectly
 * counter-issued it is routinely far above this sb's counter -- and the reservation was
 * refused exactly where it was correct. Measured on a CPH2747: /product/priv-app is its own
 * overlay mount whose dirs run 2..74, the partition dmax was ~384, so this returned 0 and
 * placement fell through to the partition band and produced 201 and 202.
 */
#ifdef NM_OVL_LAST_INO
/* struct ovl_fs is private to overlayfs and not KMI-stable, and the LKM is built against a
 * DDK tree and loaded onto other point releases, so the build-time offset of last_ino is a
 * guess until the live superblock confirms the layout. 9e1a53b incremented it unchecked
 * and was reverted. Every read is fault-safe; only a layout that passes every invariant
 * overlayfs keeps (super.c: layers[i].idx = i, fsid < numfs, xino_mode -1..32, last_ino
 * counting up from 1) gets the increment. */
static bool nm_ovl_layout_ok(struct ovl_fs *ofs, u64 local_max)
{
    unsigned int numlayer, numfs, i;
    struct ovl_layer *layers;
    int xino, idx, fsid;
    long last;

    if (copy_from_kernel_nofault(&numlayer, &ofs->numlayer, sizeof(numlayer)) ||
        copy_from_kernel_nofault(&numfs, &ofs->numfs, sizeof(numfs)) ||
        copy_from_kernel_nofault(&layers, &ofs->layers, sizeof(layers)) ||
        copy_from_kernel_nofault(&xino, &ofs->xino_mode, sizeof(xino)) ||
        copy_from_kernel_nofault(&last, &ofs->last_ino.counter, sizeof(last)))
        return false;
    if (numlayer < 1 || numlayer > 500 || numfs < 1 || numfs > numlayer || !layers)
        return false;
    if (xino < -1 || xino > 32)
        return false;
    if (last < 1 || (u64)last < local_max || (u64)last > local_max + (1UL << 20))
        return false;
    for (i = 0; i < numlayer; i++) {
        if (copy_from_kernel_nofault(&idx, &layers[i].idx, sizeof(idx)) ||
            copy_from_kernel_nofault(&fsid, &layers[i].fsid, sizeof(fsid)))
            return false;
        if (idx != (int)i || fsid < 0 || (unsigned int)fsid >= numfs)
            return false;
    }
    return true;
}
#endif

static u64 nm_ovl_reserve_dir_ino(struct nm_dev_ino *di, u64 local_max)
{
    u64 c = 0;
#ifdef NM_OVL_LAST_INO
    struct super_block *sb;
    struct path p;

    if (!di->seed || kern_path(di->seed, LOOKUP_FOLLOW, &p) != 0)
        return 0;
    sb = p.dentry->d_sb;
    if (sb->s_magic == OVERLAYFS_SUPER_MAGIC && sb->s_dev == di->dev) {
        struct ovl_fs *ofs = sb->s_fs_info;

        if (local_max && nm_ovl_layout_ok(ofs, local_max))
            c = (u64)atomic_long_inc_return(&ofs->last_ino);
        else if (local_max)
            nm_debug("inoplace: dev=%u:%u overlay layout not confirmed, counter untouched\n",
                     MAJOR(di->dev), MINOR(di->dev));
    }
    path_put(&p);
#endif
    return c;
}

/* A synthesized DIRECTORY takes a free number from inside the range its stock siblings
 * occupy: the gap among its own siblings first (when di->used can prove it unused
 * partition-wide), then the overlay's own counter for a contiguous overlay parent, then the
 * directory band the seed scan measured. Only with none of those does it go above every
 * number in play, which is what all of them did before v1.3.215: on an OP15 two dirs
 * injected into /product came out at 89,750,657 and ...658 against a partition ceiling of
 * 4,770,560, and `find -type d -inum +N` returned exactly the invented ones.
 *
 * The `inoplace:` line names the branch that won and `inoseed:` the path that was scanned;
 * one boot with NOMOUNT_DEBUG shows both.
 */
static unsigned long nm_place_dir_ino(struct nm_ino_pop *pop, u64 spread)
{
    struct nm_dev_ino *di = nm_dev_ino_get(pop->dev, NULL);
    const char *won = "dmax";
    u64 c, start;

    if (!di || !di->dmax_valid) {
        /* NOT nm_place_ino(): that is the gap fit the comment four lines below forbids
         * by name, and for want_dir=true the population carries no subtree knowledge at
         * all -- nm_dir_ino_pop allocates neither dirs nor subnames -- so it would fit a
         * directory into a gap between sampled FILE inodes. That is the 109/110-beside-oat
         * state, measured and reverted once already.
         *
         * Stay above everything we do know about, which is what the valid path does on
         * purpose. c3f7733 widened the door here: a failed 128 KB kvzalloc used to leave
         * dmax_valid true with a NULL bitmap (a NULL deref in nm_used_test), and making it
         * -ENOMEM routed those adds down this path instead. Trading a crash for a tell was
         * right; leaving the tell was not.
         *
         * With nothing known at all, 0 hands it back to the caller's hash-derived
         * sibling+1MiB form rather than inventing a number from a same-type sample. */
        u64 above = 0;

        /* Above the sampled stock maximum too, and past anything already taken: hw is
         * only the high-water of numbers the ENGINE placed, so hw + 1 could be a stock
         * sibling's inode. */
        if (di && di->hw)
            above = di->hw + 1;
        if (pop->hw && pop->hw + 1 > above)
            above = pop->hw + 1;
        if (pop->n && pop->v[pop->n - 1] + 1 > above)
            above = pop->v[pop->n - 1] + 1;
        while (above && nm_ino_taken(pop, above))
            above++;
        nm_debug("inoplace: dev=%u:%u no dmax (di=%d err=%d ovl=%d) -> above=%llu (no gap-fit)\n",
                 MAJOR(pop->dev), MINOR(pop->dev), !!di, di ? di->dmax_err : 0,
                 NM_OVL_COMPILED, (unsigned long long)above);
        if (!above)
            return 0;
        return nm_ino_take(pop, above);
    }

    /* Placed ABOVE every inode the scan saw, band tell and all. Do not "fix" this by
     * gap-fitting through nm_place_ino() -- that was tried, shipped, and measured.
     *
     * The tell is real: amax comes from nm_dmax_actor(), which records the largest inode
     * of ANY kind, so a synthesized directory lands above the biggest FILE on the device.
     * On a CPH2747 that put /product/priv-app/Mms at 89,750,659 beside stock siblings at
     * 4..34, and `find /product/priv-app -maxdepth 1 -type d -inum +1000` returned the
     * injected directories and nothing else.
     *
     * But gap-fitting through nm_place_ino() replaced it with a WORSE one. That tests
     * candidates with nm_ino_taken(pop, ...), and pop holds a sample of the parent's
     * DIRECT entries only, so ino 109 and 110 were free there and taken one level down:
     * Mms collided with /product/priv-app/GlobalDrag/oat and NumberRecognition with
     * GlobalSearch/oat. Two names on one filesystem cannot share (st_dev, st_ino) unless
     * they are the same file, so one pass over the partition grouped by that pair names
     * every entry the engine invented -- the same single scan the band cost -- and
     * anything using the pair as file identity now conflates the two.
     *
     * Inode numbers are unique per filesystem regardless of type, so without the
     * partition's used-inode set the only number that cannot collide is one above every
     * inode. That set is di->used; this path is what remains when it is missing or full.
     */
    /* The LOCAL sibling range first, when di->used is there to make it safe.
     *
     * In band partition-wide is not in band locally. dmin..dmax below is measured over the
     * partition seed subtree, so a number inside it can still sit far above the siblings an
     * app actually sees: on a CPH2747 /product/priv-app ran 3..74 while the two injected
     * directories got 201 and 202, and `find -maxdepth 1 -type d -inum +100` returned
     * exactly those two. The band closed the 89.7M tell and left a smaller one.
     *
     * This is NOT the 2026-11-08 gap-fit that was reverted. That tested candidates against
     * `pop` alone -- a sample of this directory's DIRECT entries -- so a number free here
     * was taken one level down and two names ended up sharing (st_dev, st_ino). The
     * difference is di->used: every inode the partition scan saw plus every number already
     * handed out. A candidate clearing both is in band locally AND unused partition-wide,
     * which the earlier attempt had no way to establish.
     */
    if (di->used && pop->n > 1) {
        u64 lo = pop->v[0], hi = pop->v[pop->n - 1];

        if (hi > lo + 1) {
            u64 span = hi - lo - 1;
            u64 lim = span < 4096 ? span : 4096;
            u64 i;

            for (i = 0; i < lim; i++) {
                c = lo + 1 + (spread + i) % span;
                if (nm_used_test(di->used, c) || nm_ino_taken(pop, c))
                    continue;
                nm_used_add(di->used, c);
                nm_debug("inoplace: dev=%u:%u local %llu..%llu -> ino=%llu (try %llu)\n",
                         MAJOR(pop->dev), MINOR(pop->dev),
                         (unsigned long long)lo, (unsigned long long)hi,
                         (unsigned long long)c, (unsigned long long)i);
                return nm_ino_take(pop, c);
            }
        }
    }

    /* A contiguous local population has no gap to fit into -- at boot the counter has
     * barely moved, so this is the common case, not the exception. The next number the
     * mount's own counter would issue is then the best answer available: it is what
     * overlayfs hands its own new directories, so "the only entry above the stock max" is
     * equally true of any directory created after ours, and it cannot collide.
     */
    c = nm_ovl_reserve_dir_ino(di, pop->n ? pop->v[pop->n - 1] : 0);
    if (c) {
        nm_used_add(di->used, c);
        nm_debug("inoplace: dev=%u:%u overlay counter -> ino=%llu\n",
                 MAJOR(pop->dev), MINOR(pop->dev), (unsigned long long)c);
        return nm_ino_take(pop, c);
    }
    if (di->used && di->dmax > di->dmin + 1) {
        u64 span = di->dmax - di->dmin - 1;
        u64 lim = span < 65536 ? span : 65536;
        u64 i;

        /* Strictly inside the directory band the scan measured. On overlayfs these are
         * handed out by a per-sb counter that only grows, so a number below dmax that is
         * free now is never issued later; dmax + 1 would be. */
        for (i = 0; i < lim; i++) {
            c = di->dmin + 1 + (spread + i) % span;
            if (nm_used_test(di->used, c) || nm_ino_taken(pop, c))
                continue;
            nm_used_add(di->used, c);
            nm_debug("inoplace: dev=%u:%u dir band %llu..%llu -> ino=%llu (in-band, try %llu)\n",
                     MAJOR(pop->dev), MINOR(pop->dev),
                     (unsigned long long)di->dmin, (unsigned long long)di->dmax,
                     (unsigned long long)c, (unsigned long long)i);
            return nm_ino_take(pop, c);
        }
    }
    c = di->dmax;
    if (di->amax > c) { c = di->amax;  won = "di->amax"; }
    if (pop->hw > c)  { c = pop->hw;   won = "pop->hw"; }
    if (di->hw > c)   { c = di->hw;    won = "di->hw"; }
    c++;
    start = c;
    while (nm_ino_taken(pop, c))
        c++;
    nm_debug("inoplace: dev=%u:%u dmax=%llu amax=%llu di_hw=%llu pop_hw=%llu pop_n=%d "
             "pop_lo=%llu pop_hi=%llu -> ino=%llu (winner=%s, +%llu for collisions)\n",
             MAJOR(pop->dev), MINOR(pop->dev),
             (unsigned long long)di->dmax, (unsigned long long)di->amax,
             (unsigned long long)di->hw, (unsigned long long)pop->hw, pop->n,
             (unsigned long long)(pop->n ? pop->v[0] : 0),
             (unsigned long long)(pop->n ? pop->v[pop->n - 1] : 0),
             (unsigned long long)c, won, (unsigned long long)(c - start));
    return nm_ino_take(pop, c);
}

static unsigned long nm_place_any_ino(dev_t dev, u64 spread)
{
    struct nm_dev_ino *di = nm_dev_ino_get(dev, NULL);
    u64 c;

    if (!di || !di->dmax_valid || !di->amax)
        return 0;
    c = di->amax;
    if (di->hw > c)
        c = di->hw;
    c += 1 + (spread & 3);
    di->hw = c;
    return (unsigned long)c;
}

static unsigned long nm_place_entry_ino(struct nm_ino_pop *pop, const char *parent,
                                        bool is_dir, u64 spread)
{
    struct nm_ino_pop *alt;
    dev_t dev = pop ? pop->dev : 0;
    unsigned long ino;

    if (is_dir)
        return pop ? nm_place_dir_ino(pop, spread) : 0;
    if (pop && pop->n)
        return nm_place_ino(pop, spread);

    alt = nm_dir_ino_pop_cached(parent, true);
    if (alt && alt->dev)
        dev = alt->dev;
    ino = nm_place_any_ino(dev, spread);
    if (ino)
        return ino;
    if (alt && alt->n)
        return nm_place_ino(alt, spread);
    return 0;
}

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
            continue;
        if (kern_path(p, LOOKUP_FOLLOW, &dp) == 0) {
            path_put(&dp);
            pop = nm_dir_ino_pop_cached(p, true);
            break;
        }
    }
    kfree(p);
    return pop;
}

static bool nm_dentry_matches_rule(struct dentry *dentry, const struct nomount_rule *incoming)
{
    const struct nm_inode_info *info;
    struct inode *ino;

    if (!incoming)
        return false;
    ino = d_inode(dentry);
    if (!ino || (ino->i_op != &nm_file_iops && ino->i_op != &nm_dir_iops))
        return false;
    info = ino->i_private;
    return info &&
           info->flags == incoming->flags &&
           info->r_path.dentry == incoming->r_path.dentry &&
           info->r_path.mnt == incoming->r_path.mnt &&
           info->v_ino == incoming->v_ino &&
           info->v_dev == incoming->v_dev &&
           info->v_dino == incoming->v_dino;
}

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

    parent_len = 0;
    for (i = (int)v_len - 1; i > 0; i--) {
        if (v_path[i] == '/') {
            parent_len = (size_t)i;
            break;
        }
    }
    if (!parent_len)
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
    struct nomount_rule *irule, *ex, *uid_clash, *current_rule = target_rule;
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
    bool fresh_node = false;
    size_t child_len, irule_size;
    int i, err = 0;
    u32 h_parent;
    HLIST_HEAD(pending_list);
    kuid_t anc_uid = GLOBAL_ROOT_UID;
    kgid_t anc_gid = GLOBAL_ROOT_GID;
    umode_t anc_mode = 0755;
    struct timespec64 anc_atime = {0}, anc_mtime = {0}, anc_ctime = {0};
    NM_BTIME_DECL(anc_btime);
    unsigned long anc_ino = 0;
    u32 anc_blksize = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    u32 anc_result_mask = 0;
    u32 anc_dio_mem = 0, anc_dio_off = 0;
    u64 anc_attributes = 0, anc_attr_mask = 0;
#endif
    char anc_ctx[NM_CTX_MAX];
    u16 anc_ctx_len = 0;
    bool have_anc = false;
    u8 anc_cap = 0;
    struct nm_fa_sample anc_fa = { 0 };
    bool anc_ovl = false;
    u64 anc_dino = 0;
    struct nm_ino_pop *anc_dpop = NULL;

    while (p_len > 1) {
        for (i = p_len - 1; i >= 0; i--) {
            if (v_path[i] == '/') break;
        }
        if (unlikely(i < 0)) break;

        parent_len = (i == 0) ? 1 : i;
        child_name = v_path + i + 1;
        child_len = p_len - i - 1;
        h_parent = full_name_hash(NULL, v_path, parent_len);
        orig_v_path = v_path[i];
        if (i > 0) v_path[i] = '\0';

        found_virtual = false;
        uid_clash = NULL;
        hash_for_each_possible(nomount_rules_ht, ex, vpath_node, h_parent) {
            if (ex->v_len == parent_len && memcmp(nm_get_vpath(ex), v_path, parent_len) == 0) {
                /* Keep walking past a parent scoped to some other uid: a compatible rule
                 * may be further down the bucket, and which one came first was previously
                 * decided by hash order. */
                if (!(ex->flags & NM_FLAG_VIRTUAL_DIR) &&
                    ex->target_uid != 0 && ex->target_uid != target_rule->target_uid) {
                    uid_clash = ex;
                    continue;
                }
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
                    /* ex is already in the hash: publish the node only once it is initialised. */
                    smp_store_release(&ex->this_dir, dir_node);
                }
                if (!have_anc) {
                    anc_uid = ex->v_uid; anc_gid = ex->v_gid;
                    anc_mode = ex->v_mode ? ex->v_mode : 0755;
                    anc_atime = ex->v_atime; anc_mtime = ex->v_mtime; anc_ctime = ex->v_ctime;
                    NM_BTIME_COPY(anc_btime, ex->v_btime);
                    anc_ino = ex->v_ino; anc_blksize = ex->v_blksize;
                    anc_ovl = !!(ex->flags & NM_FLAG_OVL_INO);
                    anc_dino = ex->v_dino ? ex->v_dino : ex->v_ino;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                    anc_result_mask = ex->v_result_mask;
                    anc_attributes = ex->v_attributes;
                    anc_attr_mask = ex->v_attr_mask;
#endif
                    anc_ctx_len = ex->v_ctx_len;
                    if (ex->v_ctx_len) memcpy(anc_ctx, ex->v_ctx, ex->v_ctx_len + 1);
                    anc_cap = ex->v_cap;
                    anc_fa = ex->v_fa;
                    have_anc = true;
                }
                err = __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
                if (unlikely(err)) break;
                /* AFTER the inject, not before it. nm_mark_public_up() mutates live state
                 * in place -- rule->flags, child->flags and pd->has_public -- and the
                 * failure path in __nomount_add_rule frees the incoming rule without any
                 * undo. Done first, an -ENOMEM in the inject above left the ancestor
                 * virtual directories permanently PUBLIC: NM_FLAG_PUBLIC is the bit that
                 * makes an entry served to a blocked uid, and has_public is what keeps a
                 * blocked uid on the hijacked lookup path at all, so a failed add handed
                 * the DenyList apps, isolated processes and app_zygotes the exact
                 * visibility the uid gating exists to deny. Nothing read it in between:
                 * the mark decides ancestor visibility on later lookup and readdir, and
                 * __nomount_inject_child_locked does not consult it. */
                if (target_rule->flags & NM_FLAG_PUBLIC)
                    nm_mark_public_up(ex);
                /* A minted directory carries the scope of the rule that minted it. Reused
                 * by a rule scoped differently, it becomes visible to everyone: the union
                 * of two scopes is not a scope, and hiding the directory from one of the
                 * rules' own readers would break that rule. */
                if ((ex->flags & NM_FLAG_VIRTUAL_DIR) &&
                    (ex->target_uid || ex->uid_end || ex->deny_n) &&
                    (ex->target_uid != target_rule->target_uid ||
                     ex->uid_end != target_rule->uid_end ||
                     ex->deny_n != target_rule->deny_n ||
                     memcmp(ex->deny_appid, target_rule->deny_appid,
                            ex->deny_n * sizeof(ex->deny_appid[0])))) {
                    if (nm_widen_scope_up(ex))
                        atomic_inc(&nm_rule_gen);
                }
                found_virtual = true;
                break;
            }
        }

        /* __nomount_add_rule refuses a second rule on a v_path another uid owns, but the
         * intermediates minted below bypass that check (they take the minting rule's scope
         * and widen on reuse, see above). Falling
         * through here used to add one for a path an explicit uid-scoped rule already held,
         * leaving two rules on one v_path with a child slot each: a lookup resolved to
         * whichever the bucket yielded first and the other one's children went dark. */
        if (!found_virtual && !err && uid_clash) {
            nm_debug("refusing to build '%.*s' for uid %u: uid %u already owns that directory\n",
                     (int)parent_len, v_path, target_rule->target_uid, uid_clash->target_uid);
            err = -EEXIST;
        }

        if (unlikely(err)) { if (i > 0) v_path[i] = orig_v_path; break; }

        if (found_virtual) {
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        lookup_path = (parent_len == 1) ? "/" : v_path;
        if (kern_path(lookup_path, LOOKUP_FOLLOW, &p_path) == 0) {
            v_inode = d_backing_inode(p_path.dentry);
            if (S_ISDIR(v_inode->i_mode)) {
                struct kstat akst;

                anc_uid = v_inode->i_uid;
                anc_gid = v_inode->i_gid;
                anc_mode = v_inode->i_mode & 0777;
                if (nm_path_stat(&p_path, &akst) == 0) {
                    anc_ino   = (unsigned long)akst.ino;
                    anc_blksize = akst.blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                    anc_result_mask = akst.result_mask;
#ifdef STATX_DIOALIGN
                    anc_dio_mem = akst.dio_mem_align;
                    anc_dio_off = akst.dio_offset_align;
#endif
                    anc_attr_mask   = akst.attributes_mask;
                    anc_attributes  = akst.attributes & ~(u64)(
#ifdef STATX_ATTR_MOUNT_ROOT
                                          STATX_ATTR_MOUNT_ROOT |
#endif
                                          STATX_ATTR_AUTOMOUNT);
#endif
                    NM_BTIME_COPY(anc_btime, akst.btime);
                    anc_atime = akst.atime;
                    anc_mtime = akst.mtime;
                    anc_ctime = akst.ctime;
                }
                if (nm_read_secctx(v_inode, anc_ctx, &anc_ctx_len) != 0)
                    anc_ctx_len = 0;
                if (v_inode->i_op != &nm_file_iops && v_inode->i_op != &nm_dir_iops)
                {
                    /* erofs directories take O_DIRECT (noop_direct_IO); overlay ones do not. */
                    anc_cap = nm_stock_caps(v_inode) | nm_stock_open_caps(&p_path);
                    nm_fa_sample_path(&p_path, &anc_fa);
                }
#ifdef OVERLAYFS_SUPER_MAGIC
                anc_ovl = p_path.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#endif
                if (!hlist_empty(&pending_list))
                    anc_dpop = nm_dir_ino_pop_cached(lookup_path, true);
                anc_dino = anc_ino;
                if (anc_ovl && !hlist_empty(&pending_list)) {
                    anc_dino = nm_child_dotdot_of(lookup_path);
                    if (!anc_dino)
                        anc_dino = ((u64)h_parent & 0x03FFFFFFULL) | 0x02000000ULL | 1ULL;
                }
                have_anc = true;
            }
            if (unlikely(!S_ISDIR(v_inode->i_mode))) {
                err = -ENOTDIR;
                path_put(&p_path);
                if (i > 0) v_path[i] = orig_v_path;
                break;
            }
            dir_node = nomount_get_dir_node(v_inode);
            fresh_node = !dir_node;
            if (!dir_node) dir_node = __nomount_alloc_dir_node(v_inode);
            if (unlikely(!dir_node)) {
                err = -ENOMEM;
            } else {
                err = nm_sb_supported(p_path.dentry->d_sb) ? 0 : -EOPNOTSUPP;
                if (!err)
                    err = nomount_hijack_virtual_parent(dir_node, v_inode);
                if (!err)
                    err = nomount_hijack_dir_inode(dir_node, v_inode);
                if (!err)
                    err = nomount_hijack_superblock(p_path.dentry->d_sb);
                if (!err)
                    nm_rlist_prime(dir_node, &p_path, v_inode);
                if (likely(!err)) {

                    qname.name = child_name;
                    qname.len = child_len;
                    qname.hash = full_name_hash(p_path.dentry, child_name, child_len);
                    if (p_path.dentry->d_flags & DCACHE_OP_HASH)
                        p_path.dentry->d_op->d_hash(p_path.dentry, &qname);

                    dentry = d_lookup(p_path.dentry, &qname);
                    if (dentry) {
                        if (!nm_dentry_matches_rule(dentry, current_rule))
                            d_drop(dentry);
                        dput(dentry);
                    }
                    err = __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
                }
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
        irule->flags = NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR |
                       (target_rule->flags & NM_FLAG_PUBLIC);
        irule->v_ino = (unsigned long)h_parent;
        /* The scope of the rule it is minted for: an unscoped intermediate showed a
         * scoped-out app an empty directory that does not exist on stock. */
        irule->target_uid = target_rule->target_uid;
        irule->uid_end = target_rule->uid_end;
        irule->deny_n = target_rule->deny_n;
        memcpy(irule->deny_appid, target_rule->deny_appid, sizeof(irule->deny_appid));
        irule->v_uid = GLOBAL_ROOT_UID;
        irule->v_gid = GLOBAL_ROOT_GID;
        irule->v_mode = 0755;
        irule->pending = 1;

        memcpy(nm_get_vpath(irule), v_path, parent_len);
        nm_get_vpath(irule)[parent_len] = '\0';
        nm_get_rpath(irule)[0] = '\0';

        dir_node = __nomount_alloc_dir_node(NULL);
        if (unlikely(!dir_node)) { kfree(irule); err = -ENOMEM; if (i > 0) v_path[i] = orig_v_path; break; }
        dir_node->_tag_ptr = (unsigned long)irule | 1UL;
        irule->this_dir = dir_node;
        err = __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
        if (unlikely(err)) {
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
            if (have_anc) {
                irule->v_uid = anc_uid;
                irule->v_gid = anc_gid;
                irule->v_mode = anc_mode;
                irule->flags |= NM_FLAG_HAVE_TIMES;
                irule->v_atime = anc_atime;
                irule->v_mtime = anc_mtime;
                irule->v_ctime = anc_ctime;
                NM_BTIME_COPY(irule->v_btime, anc_btime);
                irule->v_ctx_len = anc_ctx_len;
                if (anc_ctx_len) memcpy(irule->v_ctx, anc_ctx, anc_ctx_len + 1);
                irule->v_cap = anc_cap;
                irule->v_fa = anc_fa;
                if (!anc_dpop)
                    anc_dpop = nm_real_ancestor_pop(nm_get_vpath(irule));
                irule->v_ino = anc_dpop ?
                        nm_place_dir_ino(anc_dpop, (u64)irule->v_hash) : 0;
                if (!irule->v_ino && anc_ino)
                    irule->v_ino = (anc_ino & ~0xFFFFUL) | (irule->v_hash & 0xFFFF) | 1UL;
                if (anc_ovl) {
                    /* Into the exclusion set at the mint, not only when a slot is seeded:
                     * ancestors are usually minted after their device slot exists. */
                    struct nm_dev_ino *odi = anc_dpop ? nm_dev_ino_get(anc_dpop->dev, NULL) : NULL;
                    u64 dn = ((u64)irule->v_hash & 0x03FFFFFFULL) | 0x02000000ULL | 1ULL;
                    int guard = 256;

                    while (odi && odi->used && nm_used_test(odi->used, dn) && guard-- > 0) {
                        dn += 2;
                        if (dn > 0x03FFFFFFULL)
                            dn = 0x02000001ULL;
                    }
                    if (odi && odi->used)
                        nm_used_add(odi->used, dn);
                    irule->flags |= NM_FLAG_OVL_INO;
                    irule->v_dino = dn;
                } else {
                    irule->v_dino = (u64)irule->v_ino;
                }
                irule->v_pdino = prev_dino;
                prev_dino = irule->v_dino;
                if (irule->parent_dir)
                    nm_restamp_child_ino(irule->parent_dir, irule);
                irule->v_blksize = anc_blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                irule->v_result_mask = anc_result_mask;
                irule->v_dio_mem = anc_dio_mem;
                irule->v_dio_off = anc_dio_off;
                irule->v_attributes  = anc_attributes;
                irule->v_attr_mask   = anc_attr_mask;
#endif
            }
            smp_store_release(&irule->pending, 0);
            hash_add_rcu(nomount_rules_ht, &irule->vpath_node, irule->v_hash);
        }
        if (!target_rule->v_pdino)
            target_rule->v_pdino = prev_dino;
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
        if (!owner || !(owner->flags & NM_FLAG_VIRTUAL_DIR)) break;

        parent = owner->parent_dir;
        parent_virtual = parent && (parent->_tag_ptr & 1UL);

        hash_del_rcu(&owner->vpath_node);
        if (parent) __nomount_delete_child_locked(parent, owner);
        nm_debug("Pruned empty virtual directory: %s\n", nm_get_vpath(owner));
        dir_node = parent_virtual ? parent : NULL;
        hlist_add_head(&owner->victim_node, victims);
    }
}

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
    dev_t dir_dev;
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

/* Both answers a stock inode gives: GETFLAGS asks with flags_valid, FSGETXATTR with
 * fsx_valid, and overlayfs's security check differs between them. Called straight
 * through i_op so the LKM imports nothing new. */
static void nm_fa_sample_path(const struct path *p, struct nm_fa_sample *s)
{
    memset(s, 0, sizeof(*s));
    s->err[0] = s->err[1] = -ENOIOCTLCMD;
#ifdef NM_HAVE_FILEATTR
    {
        struct inode *ino = p && p->dentry ? d_backing_inode(p->dentry) : NULL;
        int k;

        if (ino && ino->i_op && ino->i_op->fileattr_get &&
            ino->i_op != &nm_file_iops && ino->i_op != &nm_dir_iops) {
            for (k = 0; k < 2; k++) {
                memset(&s->fa[k], 0, sizeof(s->fa[k]));
                if (k)
                    s->fa[k].fsx_valid = true;
                else
                    s->fa[k].flags_valid = true;
                s->err[k] = ino->i_op->fileattr_get(p->dentry, &s->fa[k]);
            }
        }
    }
#endif
    s->known = true;
}

/* The fileattr answer of the sibling nm_scan_dir_for_file() last picked. Under
 * nomount_write_mutex, like the sibling cache it travels with. */
static struct nm_fa_sample nm_sib_fa;

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
#ifdef OVERLAYFS_SUPER_MAGIC
    dir_is_overlay = dp.dentry->d_sb->s_magic == OVERLAYFS_SUPER_MAGIC;
#endif
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

    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < sc->n_files; i++) {
            char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->files[i]);
            struct path fp;
            struct kstat fk;

            if (!cp) continue;
            if (nm_path_is_injected(cp, strlen(cp))) {
                kfree(cp);
                continue;
            }
            if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
                int r = nm_path_stat(&fp, &fk);
                struct inode *ci = d_backing_inode(fp.dentry);
                char fctx[NM_CTX_MAX];
                u16 fctxlen = 0;
                dev_t fmapdev = 0;
                u8 fcap = 0;
                struct nm_fa_sample ffa = { 0 };

                if (!ci || ci->i_op == &nm_file_iops || ci->i_op == &nm_dir_iops)
                    r = -EINVAL;

                if (r == 0) {
                    if (nm_read_secctx(d_backing_inode(fp.dentry), fctx, &fctxlen) != 0)
                        fctxlen = 0;
                    fmapdev = nm_stock_map_dev(fp.dentry);
                    fcap = nm_stock_caps(d_backing_inode(fp.dentry)) | nm_stock_open_caps(&fp);
                    nm_fa_sample_path(&fp, &ffa);
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
                    nm_sib_fa = ffa;
                    kfree(cp); ret = 0; goto done;
                }
            }
            kfree(cp);
        }
    }
    for (i = 0; i < sc->n_subdirs; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->subdirs[i]);

        if (!cp) continue;
        if (nm_path_is_injected(cp, strlen(cp))) {
            kfree(cp);
            continue;
        }
        if (nm_scan_dir_for_file(cp, out, octx, octxlen, omapdev, ocap, depth + 1) == 0) { kfree(cp); ret = 0; goto done; }
        kfree(cp);
    }
done:
    kfree(sc);
    return ret;
}

static char nm_sib_cache_dir[PATH_MAX];
static struct kstat nm_sib_cache_kst;
static char nm_sib_cache_ctx[NM_CTX_MAX];
static u16 nm_sib_cache_ctxlen;
static dev_t nm_sib_cache_mapdev;
static u8 nm_sib_cache_cap;
static bool nm_sib_cache_valid;
static struct nm_fa_sample nm_sib_cache_fa;

/* Called under nomount_write_mutex when a hijacked superblock goes away. */
static void nm_forget_dev_caches(dev_t dev)
{
    int i;

    nm_sib_cache_valid = false;
    nm_range_cache_flush();
    for (i = 0; i < NM_DEV_INO_SLOTS; i++)
        if (nm_dev_ino_tab[i].valid && nm_dev_ino_tab[i].dev == dev)
            nm_dev_ino_tab[i].valid = false;
}

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
        *slash = '\0';

    if (nm_sib_cache_valid && strcmp(nm_sib_cache_dir, path) == 0) {
        *out = nm_sib_cache_kst;
        if (octx && octxlen) {
            *octxlen = nm_sib_cache_ctxlen;
            if (nm_sib_cache_ctxlen) memcpy(octx, nm_sib_cache_ctx, nm_sib_cache_ctxlen + 1);
        }
        if (omapdev) *omapdev = nm_sib_cache_mapdev;
        if (ocap) *ocap = nm_sib_cache_cap;
        nm_sib_fa = nm_sib_cache_fa;
        kfree(path);
        return 0;
    }

    for (;;) {
        if (nm_scan_dir_for_file(path, out, octx, octxlen, omapdev, ocap, 0) == 0) { ret = 0; break; }
        slash = strrchr(path, '/');
        if (!slash || slash == path)
            break;
        *slash = '\0';
    }
    if (ret == 0) {
        const char *vslash = strrchr(vpath, '/');

        if (vslash && vslash != vpath && (size_t)(vslash - vpath) < PATH_MAX) {
            size_t plen = vslash - vpath;

            memcpy(nm_sib_cache_dir, vpath, plen);
            nm_sib_cache_dir[plen] = '\0';
            nm_sib_cache_kst = *out;
            nm_sib_cache_ctxlen = (octx && octxlen) ? *octxlen : 0;
            if (nm_sib_cache_ctxlen) memcpy(nm_sib_cache_ctx, octx, nm_sib_cache_ctxlen + 1);
            nm_sib_cache_mapdev = omapdev ? *omapdev : 0;
            nm_sib_cache_cap = ocap ? *ocap : 0;
            nm_sib_cache_fa = nm_sib_fa;
            nm_sib_cache_valid = true;
        }
    }
    kfree(path);
    return ret;
}

static bool nm_vpath_has_slash_run(const char *p, size_t len)
{
    size_t i;

    for (i = 1; i < len; i++)
        if (p[i] == '/' && p[i - 1] == '/')
            return true;
    return false;
}

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

/* For a directory rule: the stock regular file its file children mirror. The sibling scan
 * starts in the directory itself (a stock one, when the rule shadows it) and walks up. */
static void nm_sample_child_file(struct nomount_rule *rule)
{
    char *probe = kasprintf(GFP_KERNEL, "%s/.", nm_get_vpath(rule));
    char *ctx = kmalloc(NM_CTX_MAX, GFP_KERNEL);
    struct kstat k;
    u16 ctxlen = 0;
    dev_t mapdev = 0;
    u8 cap = 0;

    /* Real buffers, not NULLs: the scan caches its answer for this directory, and a later
     * file rule here reads label and map dev back out of that cache. */
    if (!probe || !ctx) {
        kfree(probe);
        kfree(ctx);
        return;
    }
    if (nm_find_sibling_meta(probe, &k, ctx, &ctxlen, &mapdev, &cap) == 0) {
        rule->v_cfile.cap = cap;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        rule->v_cfile.result_mask = k.result_mask;
        rule->v_cfile.attributes = k.attributes;
        rule->v_cfile.attr_mask = k.attributes_mask;
#ifdef STATX_DIOALIGN
        rule->v_cfile.dio_mem = k.dio_mem_align;
        rule->v_cfile.dio_off = k.dio_offset_align;
#endif
#endif
        rule->v_cfile.fa = nm_sib_fa;
        rule->v_cfile.known = true;
    }
    kfree(probe);
    kfree(ctx);
}

static struct nomount_rule *nm_alloc_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, const struct nm_uid_scope *scope)
{
    struct nomount_rule *rule;
    bool is_whiteout = (flags & NM_FLAG_WHITEOUT);
    struct path v_path_struct;

    if (!v_path || v_len == 0 || v_path[0] != '/') return ERR_PTR(-EINVAL);
    if (!r_path && !is_whiteout) return ERR_PTR(-EINVAL);
    while (v_len > 1 && v_path[v_len - 1] == '/') { v_len--; }
    if (!is_whiteout) { while (r_len > 1 && r_path[r_len - 1] == '/') { r_len--; } }

    if (is_whiteout) r_len = 0;
    rule = kzalloc((sizeof(struct nomount_rule) + v_len + 1 + r_len + 1), GFP_KERNEL);
    if (!rule) return ERR_PTR(-ENOMEM);

    INIT_HLIST_NODE(&rule->vpath_node);
    rule->flags = flags & NM_FLAGS_USER_MASK;
    rule->target_uid = scope->uid;
    rule->uid_end    = scope->uid_end;
    rule->deny_n     = (u8)scope->deny_n;
    memcpy(rule->deny_appid, scope->deny,
           scope->deny_n * sizeof(scope->deny[0]));
    rule->v_len = (u16)nm_norm_vpath(nm_get_vpath(rule), v_path, v_len);
    rule->v_hash = full_name_hash(NULL, nm_get_vpath(rule), rule->v_len);

    if (is_whiteout) {
        nm_get_rpath(rule)[0] = '\0';
    } else {
        memcpy(nm_get_rpath(rule), r_path, r_len);
        nm_get_rpath(rule)[r_len] = '\0';
    }

    if (!is_whiteout) {
        if (kern_path(nm_get_rpath(rule), LOOKUP_FOLLOW, &rule->r_path) != 0) {
            kfree(rule);
            return ERR_PTR(-ENOENT);
        }
        if (S_ISDIR(d_backing_inode(rule->r_path.dentry)->i_mode))
            rule->flags |= NM_FLAG_IS_DIR;
    }

    if (kern_path(nm_get_vpath(rule), LOOKUP_FOLLOW, &v_path_struct) == 0) {
        struct kstat kst;
        rule->flags |= NM_FLAG_SHADOWS_STOCK;
        if ((rule->flags & NM_FLAG_WHITEOUT) &&
            S_ISDIR(d_backing_inode(v_path_struct.dentry)->i_mode))
            rule->flags |= NM_FLAG_IS_DIR;
        if (nm_read_secctx(d_backing_inode(v_path_struct.dentry),
                           rule->v_ctx, &rule->v_ctx_len) != 0)
            rule->v_ctx_len = 0;
        rule->v_mapdev = nm_stock_map_dev(v_path_struct.dentry);
        if (nm_path_stat(&v_path_struct, &kst) == 0) {
            rule->v_ino = kst.ino;
            rule->v_dev = kst.dev;
            if (!(rule->flags & NM_FLAG_VIRTUAL_DIR)) {
                rule->v_mode = kst.mode & 07777;
                rule->v_uid = kst.uid;
                rule->v_gid = kst.gid;
                rule->flags |= NM_FLAG_HAVE_VOWN;
            }
            rule->flags |= NM_FLAG_HAVE_TIMES;
            rule->v_atime = kst.atime;
            rule->v_mtime = kst.mtime;
            rule->v_ctime = kst.ctime;
            NM_BTIME_COPY(rule->v_btime, kst.btime);
            rule->v_blksize = kst.blksize;
            rule->v_cratio = nm_size_ratio(kst.size, kst.blocks);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_result_mask = kst.result_mask;
#ifdef STATX_DIOALIGN
            rule->v_dio_mem = kst.dio_mem_align;
            rule->v_dio_off = kst.dio_offset_align;
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_attributes = kst.attributes;
            rule->v_attr_mask = kst.attributes_mask;
#endif
            {
                struct inode *ci = d_backing_inode(v_path_struct.dentry);

                if (ci && ci->i_op != &nm_file_iops && ci->i_op != &nm_dir_iops) {
                    rule->v_cap = nm_stock_caps(ci) | nm_stock_open_caps(&v_path_struct);
                }
            }
        } else {
            rule->v_ino = d_backing_inode(v_path_struct.dentry)->i_ino;
            rule->v_dev = d_backing_inode(v_path_struct.dentry)->i_sb->s_dev;
        }
        {
            struct inode *si = d_backing_inode(v_path_struct.dentry);
            if (si && si->i_op != &nm_file_iops && si->i_op != &nm_dir_iops) {
                rule->s_path = v_path_struct;
            } else {
                /* A live rule already covers the path (a re-add, or under an engine dir):
                 * the stock file is the one that inode stands in for. */
                struct nm_inode_info *ei = si ? si->i_private : NULL;

                if (ei && ei->s_path.dentry) {
                    rule->s_path = ei->s_path;
                    path_get(&rule->s_path);
                }
                path_put(&v_path_struct);
            }
        }
    } else {
        struct kstat sib;

        if (nm_find_sibling_meta(nm_get_vpath(rule), &sib,
                                 rule->v_ctx, &rule->v_ctx_len, &rule->v_mapdev,
                                 &rule->v_cap) == 0) {
            rule->v_dev   = sib.dev;
            rule->flags |= NM_FLAG_HAVE_TIMES;
            rule->v_atime = sib.atime;
            rule->v_mtime = sib.mtime;
            rule->v_ctime = sib.ctime;
            NM_BTIME_COPY(rule->v_btime, sib.btime);
            rule->v_blksize    = sib.blksize;
            rule->v_cratio     = nm_size_ratio(sib.size, sib.blocks);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_result_mask = sib.result_mask;
#ifdef STATX_DIOALIGN
            rule->v_dio_mem = sib.dio_mem_align;
            rule->v_dio_off = sib.dio_offset_align;
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_attributes = sib.attributes;
            rule->v_attr_mask  = sib.attributes_mask;
#endif
            rule->v_fa = nm_sib_fa;
            /* A directory answers like a stock directory: sample its nearest real ancestor. */
            if (rule->flags & NM_FLAG_IS_DIR) {
                char *anc = kstrdup(nm_get_vpath(rule), GFP_KERNEL);
                char *sl;
                struct path ap;

                while (anc && (sl = strrchr(anc, '/')) && sl != anc) {
                    *sl = '\0';
                    if (kern_path(anc, LOOKUP_FOLLOW, &ap) == 0) {
                        nm_fa_sample_path(&ap, &rule->v_fa);
                        path_put(&ap);
                        break;
                    }
                }
                kfree(anc);
            }
            /* A module file left at root:root takes its stock sibling's GROUP -- a binary in
             * /system/bin is root:shell there -- and only where that changes no access: the
             * engine inode's owner is the only DAC check opens get, so the uid never moves,
             * nor anything with set-id bits, nor a mode whose group and other bits differ. */
            {
                struct inode *mi = rule->r_path.dentry ? d_backing_inode(rule->r_path.dentry) : NULL;
                umode_t m = mi ? mi->i_mode : 0;

                if (mi && S_ISREG(m) && uid_eq(mi->i_uid, GLOBAL_ROOT_UID) &&
                    gid_eq(mi->i_gid, GLOBAL_ROOT_GID) && uid_eq(sib.uid, GLOBAL_ROOT_UID) &&
                    !(m & (S_ISUID | S_ISGID)) && ((m >> 3) & 7) == (m & 7)) {
                    rule->v_uid = GLOBAL_ROOT_UID;
                    rule->v_gid = sib.gid;
                    rule->v_mode = m & 07777;
                    rule->flags |= NM_FLAG_HAVE_VOWN;
                }
            }
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
                        bool is_dir = !!(rule->flags & NM_FLAG_IS_DIR);
                        unsigned long placed;

                        pop = nm_dir_ino_pop_cached(parent, is_dir);
                        placed = nm_place_entry_ino(pop, parent, is_dir, spread);
                        if (placed)
                            rule->v_ino = placed;
                        kfree(parent);
                    }
                }
            }
        } else {
            char *vp = nm_get_vpath(rule);
            char *slash = strrchr(vp, '/');

            rule->v_ino = (unsigned long)((u64)rule->v_hash & 0xFFFFFULL) | 1UL;
            rule->v_dev = 0;
            if (slash && slash != vp) {
                char *parent = kstrndup(vp, slash - vp, GFP_KERNEL);

                if (parent) {
                    if (kern_path(parent, LOOKUP_FOLLOW, &v_path_struct) == 0) {
                        struct kstat kst;

                        if (nm_path_stat(&v_path_struct, &kst) == 0) {
                            struct nm_ino_pop *pop;
                            bool is_dir = !!(rule->flags & NM_FLAG_IS_DIR);
                            unsigned long placed = 0;

                            rule->v_dev = kst.dev;
                            pop = nm_dir_ino_pop_cached(parent, is_dir);
                            placed = nm_place_entry_ino(pop, parent, is_dir,
                                                        (u64)rule->v_hash);
                            if (placed)
                                rule->v_ino = placed;
                            else
                                rule->v_ino = (unsigned long)((kst.ino & ~0xFFFFFULL) + 0x100000ULL +
                                                              ((u64)rule->v_hash & 0xFFFFFULL));
                            rule->flags |= NM_FLAG_HAVE_TIMES;
                            rule->v_atime = kst.atime;
                            rule->v_mtime = kst.mtime;
                            rule->v_ctime = kst.ctime;
                            NM_BTIME_COPY(rule->v_btime, kst.btime);
                        }
                        path_put(&v_path_struct);
                    }
                    kfree(parent);
                }
            }
        }
    }

    if ((rule->flags & NM_FLAG_IS_DIR) && !(rule->flags & NM_FLAG_VIRTUAL_DIR))
        nm_sample_child_file(rule);

    return rule;
}
static void nm_free_rule(struct nomount_rule *rule)
{
    if (unlikely(!rule)) return;
    if (rule->r_path.dentry) path_put(&rule->r_path);
    if (rule->s_path.dentry) path_put(&rule->s_path);
    /* Orphan any child this rule still owns, rather than leave it pointing into the
     * dir_node we are about to drop the last reference to.
     *
     * Every caller is supposed to detach a whole subtree before freeing any of it --
     * __nomount_add_rule and __nomount_del_rule return -EBUSY rather than free a rule
     * whose this_dir still has children, and __nomount_clear_all detaches all before
     * freeing any. put_super got that wrong and the cost was a write-capable UAF, so make
     * the wrong order merely leave an orphaned rule instead of a dangling pointer.
     */
    if (rule->this_dir && !idr_is_empty(&rule->this_dir->children_idr)) {
        struct nomount_child_node *child;
        int id;

        idr_for_each_entry(&rule->this_dir->children_idr, child, id)
            if (child->rule && child->rule->parent_dir == rule->this_dir)
                child->rule->parent_dir = NULL;
    }
    nm_dir_node_put(rule->this_dir);
    kfree(rule);
}

static void nm_detach_rule_locked(struct nomount_rule *rule, struct hlist_head *victims, bool prune)
{
    hash_del_rcu(&rule->vpath_node);
    if (rule->parent_dir) {
        struct nomount_dir_node *p_dir = rule->parent_dir;
        bool pinned = atomic_inc_not_zero(&p_dir->refcount);

        __nomount_delete_child_locked(p_dir, rule);
        if (prune && pinned) nomount_prune_empty_virtual_dirs(p_dir, victims);
        if (pinned) nm_dir_node_put(p_dir);
    }
    hlist_add_head(&rule->victim_node, victims);
}

static bool nm_target_too_shallow(const char *p, u16 len)
{
    int comps = 0;
    u16 i = 0;

    while (i < len) {
        u16 start;

        while (i < len && p[i] == '/')
            i++;
        if (i >= len)
            break;
        start = i;
        while (i < len && p[i] != '/')
            i++;
        if (p[start] == '.' && (i - start == 1 || (i - start == 2 && p[start + 1] == '.')))
            return true;
        comps++;
    }
    return comps < 2;
}

static bool nm_vpath_in_pm_scandir(const struct nomount_rule *rule)
{
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
        if (i > start) {
            u16 seglen = i - start;
            const char *const *tab;
            unsigned int n;

            seg++;
            if (seg == 1) {
                tab = roots; n = ARRAY_SIZE(roots);
            } else if (seg == 2) {
                tab = dirs;  n = ARRAY_SIZE(dirs);
            } else {
                return false;
            }
            for (d = 0; d < n; d++)
                if (strlen(tab[d]) == seglen &&
                    memcmp(v + start, tab[d], seglen) == 0)
                    break;
            if (d == n)
                return false;
            if (seg == 2)
                return true;
        }
        start = i + 1;
    }
    return false;
}

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags,
                              const struct nm_uid_scope *scope, struct hlist_head *victims)
{
    struct nomount_rule *rule, *existing, *victim = NULL;
    int err = 0;

    if (unlikely(nm_target_too_shallow(v_path, v_len))) {
        nm_debug("refusing rule on '%.*s': fewer than two path components would mask a whole partition\n",
                 (int)v_len, v_path);
        return -EINVAL;
    }

    mutex_lock(&nomount_write_mutex);

    rule = nm_alloc_rule(v_path, r_path, v_len, r_len, flags, scope);
    if (IS_ERR(rule)) {
        mutex_unlock(&nomount_write_mutex);
        return PTR_ERR(rule);
    }

    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == rule->v_len &&
            !nm_scope_eq(existing, scope) &&
            memcmp(nm_get_vpath(existing), nm_get_vpath(rule), rule->v_len) == 0) {
            nm_debug("refusing rule on '%.*s' for uid %u: uid %u already owns this path\n",
                     (int)rule->v_len, nm_get_vpath(rule), scope->uid, existing->target_uid);
            mutex_unlock(&nomount_write_mutex);
            nm_free_rule(rule);
            return -EEXIST;
        }
    }

    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == rule->v_len &&
             nm_scope_eq(existing, scope) &&
             memcmp(nm_get_vpath(existing), nm_get_vpath(rule), rule->v_len) == 0) {
            if (existing->this_dir &&
                !idr_is_empty(&existing->this_dir->children_idr)) {
                mutex_unlock(&nomount_write_mutex);
                nm_free_rule(rule);
                return -EBUSY;
            }
            rule->flags = (rule->flags & ~NM_FLAG_SHADOWS_STOCK) |
                          (existing->flags & NM_FLAG_SHADOWS_STOCK);
            if (!rule->v_cap)
                rule->v_cap = existing->v_cap;
            if (!rule->s_path.dentry && existing->s_path.dentry) {
                rule->s_path = existing->s_path;
                path_get(&rule->s_path);
            }
            hash_del_rcu(&existing->vpath_node);
            victim = existing;
            nm_debug("Shadowing existing rule for: %s\n", nm_get_vpath(rule));
            break;
        }
    }

    if ((rule->flags & NM_FLAG_SHADOWS_STOCK) && !nm_vpath_in_pm_scandir(rule))
        rule->flags &= ~NM_FLAG_PUBLIC;

    err = nomount_generate_virtual_topology(rule);
    if (err != 0) {
        if (victim) {
            hash_add_rcu(nomount_rules_ht, &victim->vpath_node, victim->v_hash);
            atomic_inc(&nm_rule_gen);
        }
        nm_drop_cached_vpath(nm_get_vpath(rule), rule->v_len, NULL);
        mutex_unlock(&nomount_write_mutex);
        nm_free_rule(rule);
        return err;
    }

    hash_add_rcu(nomount_rules_ht, &rule->vpath_node, rule->v_hash);
    atomic_inc(&nm_rule_gen);
    nm_pin_module();

    nm_drop_cached_vpath(nm_get_vpath(rule), rule->v_len, rule);
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

static int __nomount_del_rule(const char *v_path, size_t v_len, const struct nm_uid_scope *scope, struct hlist_head *r_victims)
{
    struct nomount_rule *rule;
    char *norm = NULL;
    int ret = -ENOENT;
    u32 hash;

    while (v_len > 1 && v_path[v_len - 1] == '/') v_len--;
    if (unlikely(nm_vpath_has_slash_run(v_path, v_len))) {
        norm = kmalloc(v_len + 1, GFP_KERNEL);
        if (!norm) return -ENOMEM;
        v_len = nm_norm_vpath(norm, v_path, v_len);
        v_path = norm;
    }
    hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == v_len && nm_scope_eq(rule, scope) &&
                memcmp(nm_get_vpath(rule), v_path, v_len) == 0) {
            if (rule->this_dir && !idr_is_empty(&rule->this_dir->children_idr)) {
                ret = -EBUSY;
                break;
            }
            nm_detach_rule_locked(rule, r_victims, true);
            nm_sib_cache_valid = false;
            nm_range_cache_flush();
            ret = 0;
            break;
        }
    }
    kfree(norm);
    return ret;
}

static void __nomount_clear_all(bool is_exit)
{
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    HLIST_HEAD(r_victims);

    nm_sib_cache_valid = false;
    nm_range_cache_flush();

    static_branch_disable(&nomount_active_uids);
    hash_for_each_safe(nomount_rules_ht, bkt, tmp, rule, vpath_node) {
        nm_detach_rule_locked(rule, &r_victims, false);
    }
    atomic_inc(&nm_rule_gen);
    synchronize_rcu();
    idr_destroy(&nomount_uid_idr);
    hlist_for_each_entry_safe(rule, tmp, &r_victims, victim_node) {
        nm_free_rule(rule);
    }

    if (is_exit) nomount_restore_superblocks();
}

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
            /* An embedded NUL keys the rule on bytes kern_path never sees: listed under one
             * name, deletable by none. The attribute path strnlen()s for the same reason. */
            if (memchr(v_ptr, 0, vp_len) || (rp_len && memchr(r_ptr, 0, rp_len))) {
                nfail++;
                if (!first_err) first_err = -EINVAL;
                continue;
            }
            {
                /* The batch payload carries no scope fields and keeps its
                 * layout, so a batch entry is always legacy-shaped. Ranges go
                 * through the single-rule attribute form.
                 */
                struct nm_uid_scope scope = { .uid = target_uid };
                err = __nomount_add_rule(v_ptr, r_ptr, vp_len, rp_len, flags, &scope, &a_victims);
            }
            if (err) {
                nm_debug("rule batch entry refused (err: %d)\n", err);
                nfail++;
                if (!first_err) first_err = err;
            }
        }
        if (!hlist_empty(&a_victims)) {
            synchronize_rcu();
            hlist_for_each_entry_safe(v_rule, v_tmp, &a_victims, victim_node)
                nm_free_rule(v_rule);
        }
        if (first_err)
            nm_debug("rule batch: %d entr%s rejected (first err %d)\n",
                     nfail, nfail == 1 ? "y" : "ies", first_err);
        return first_err;

    } else if (attrs[NOMOUNT_ATTR_VIRTUAL_PATH] && attrs[NOMOUNT_ATTR_REAL_PATH]) {
        char *v_str = nla_data(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        char *r_str = nla_data(attrs[NOMOUNT_ATTR_REAL_PATH]);
        int v_len = strnlen(v_str, nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]));
        int r_len = strnlen(r_str, nla_len(attrs[NOMOUNT_ATTR_REAL_PATH]));
        u32 flags = attrs[NOMOUNT_ATTR_FLAGS] ? nla_get_u32(attrs[NOMOUNT_ATTR_FLAGS]) : 0;
        struct nm_uid_scope scope;

        if (v_len == 0) return -EINVAL;
        if (nm_scope_from_attrs(&scope, attrs)) return -EINVAL;
        if (nm_scope_invalid(&scope)) return -EINVAL;
        return __nomount_add_rule(v_str, r_str, v_len, r_len, flags, &scope, NULL);
    }
    return -EINVAL;
}

static int nomount_nl_del_rule(struct nlattr **attrs)
{
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    bool busy = false;
    int first_err = 0;
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

            pos += 6;
            /* Both of these used to `break` and leave the overall result to the
             * victim list, so a batch truncated mid-entry -- or carrying an
             * oversized length -- reported 0 for the entries it HAD deleted and
             * nothing about the ones it silently stopped at. The caller cannot
             * tell a complete delete from a partial one, and the add path already
             * carries a first_err for exactly this reason. Mirrored here. */
            if (vp_len >= PATH_MAX) {
                if (!first_err) first_err = -ENAMETOOLONG;
                break;
            }
            if (pos + vp_len > len) {
                if (!first_err) first_err = -EINVAL;
                break;
            }
            if (memchr(data + pos, 0, vp_len)) {
                if (!first_err) first_err = -EINVAL;
                pos += vp_len;
                continue;
            }
            {
                struct nm_uid_scope scope = { .uid = target_uid };
                if (__nomount_del_rule(data + pos, vp_len, &scope, &r_victims) == -EBUSY)
                    busy = true;
            }
            pos += vp_len;
        }
        atomic_inc(&nm_rule_gen);
        mutex_unlock(&nomount_write_mutex);
    } else if (attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) {
        char *v_path = nla_data(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        int v_len = strnlen(v_path, nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]));
        struct nm_uid_scope scope;

        if (nm_scope_from_attrs(&scope, attrs)) return -EINVAL;
        if (nm_scope_invalid(&scope)) return -EINVAL;

        mutex_lock(&nomount_write_mutex);
        if (__nomount_del_rule(v_path, v_len, &scope, &r_victims) == -EBUSY)
            busy = true;
        atomic_inc(&nm_rule_gen);
        mutex_unlock(&nomount_write_mutex);
    } else {
        return -EINVAL;
    }

    /* first_err outranks the rest: a malformed batch is the caller's bug and it must
     * hear about it even if some entries went through, and even if the rest of the
     * batch happened to match nothing. */
    if (hlist_empty(&r_victims))
        return first_err ? first_err : (busy ? -EBUSY : -ENOENT);
    synchronize_rcu();

    hlist_for_each_entry_safe(rule, tmp, &r_victims, victim_node) {
        nm_debug("Deleted rule for: %s\n", nm_get_vpath(rule));
        nm_free_rule(rule);
    }

    return first_err ? first_err : (busy ? -EBUSY : 0);
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
            /* Emitted only when set, so a legacy rule's list entry keeps its
             * exact size and shape. A reader that wants to DELETE what it lists
             * needs these: the delete key is the whole scope, not the uid.
             */
            if ((rule->uid_end &&
                 nla_put_u32(skb, NOMOUNT_ATTR_UID_END, rule->uid_end)) ||
                (rule->deny_n &&
                 nla_put(skb, NOMOUNT_ATTR_DENY_APPIDS,
                         rule->deny_n * (int)sizeof(rule->deny_appid[0]),
                         rule->deny_appid))) {
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

    uid = nm_appid_of(nla_get_u32(attrs[NOMOUNT_ATTR_UID]));

    mutex_lock(&nomount_write_mutex);
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

    uid = nm_appid_of(nla_get_u32(attrs[NOMOUNT_ATTR_UID]));

    mutex_lock(&nomount_write_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    if (idr_remove(&nomount_uid_idr, uid)) {
#else
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

static int nomount_nl_dump_ghost(struct sk_buff *skb, struct netlink_callback *cb)
{
    char rule[NM_GHOST_RULE_MAX];
    int idx = cb->args[0];
    void *hdr;

    if (!nm_have_ghost())
        return 0;

    while (ghost_get_rule(idx, rule, sizeof(rule)) > 0) {
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

static int nomount_nl_dump_pathhide(struct sk_buff *skb, struct netlink_callback *cb)
{
    char rule[NM_PATHHIDE_RULE_MAX];
    int idx = cb->args[0];
    void *hdr;

    if (!nm_have_pathhide())
        return 0;

    while (pathhide_get_rule(idx, rule, sizeof(rule)) > 0) {
        rule[sizeof(rule) - 1] = '\0';
        hdr = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
                        NM_CMD_TO_TYPE(NM_CMD_GET_PATHHIDE), 0, NLM_F_MULTI);
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

    if (nla_put_string(msg, NOMOUNT_ATTR_MODVER, NM_MODULE_VERSION)) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    /* The knobs are write-only through NM_CMD_SET_KNOB, so nothing could ask what
     * the engine actually holds -- and `nomount doctor` reported uidhide.conf, the
     * value that was REQUESTED, as though it were in effect. A boot sync that never
     * ran then read as agreement. This rides the version reply rather than taking a
     * command of its own, so one round trip answers both. */
    if (nla_put_u32(msg, NOMOUNT_ATTR_KNOBS,
                    (READ_ONCE(nm_hide_isolated) & 3) |
                    (READ_ONCE(nm_vdir_erofs_size) ? 4U : 0U))) {
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
    [NOMOUNT_ATTR_MODVER]       = { .type = NLA_NUL_STRING, .len = 31 },
    [NOMOUNT_ATTR_KNOBS]        = { .type = NLA_U32 },
    [NOMOUNT_ATTR_UID_END]      = { .type = NLA_U32 },
    [NOMOUNT_ATTR_DENY_APPIDS]  = { .type = NLA_BINARY,
                                    .len = NM_DENY_MAX * sizeof(u32) },
};

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

    if (cmd == NM_CMD_GET_LIST || cmd == NM_CMD_GET_UIDS ||
        cmd == NM_CMD_GET_GHOST || cmd == NM_CMD_GET_PATHHIDE) {
        struct netlink_dump_control c = {
            .dump = cmd == NM_CMD_GET_LIST  ? nomount_nl_dump_rules
                  : cmd == NM_CMD_GET_UIDS  ? nomount_nl_dump_uids
                  : cmd == NM_CMD_GET_GHOST ? nomount_nl_dump_ghost
                                            : nomount_nl_dump_pathhide,
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
        if (vlen <= 0)
            return 0;
        /* Validated, like NM_KNOB_HIDE_ISOLATED below. `val[0] == '1'` alone meant any
         * other value set the knob to FALSE and reported success, so a typo -- `nm k d 7`
         * -- silently turned off the thing that makes a synthesized directory report an
         * erofs-shaped size, which is the dir-size tell nm_dir_stat_fix() exists to
         * close. Silently landing on "off" is the worse direction of the two. */
        if (vlen != 1 || (val[0] != '0' && val[0] != '1'))
            return -EINVAL;
        WRITE_ONCE(nm_vdir_erofs_size, val[0] == '1');
        return 0;
    case NM_KNOB_HIDE_ISOLATED: {
        unsigned int pools;

        if (vlen <= 0)
            return 0;
        if (val[0] < '0' || val[0] > '3') return -EINVAL;
        pools = val[0] - '0';
        WRITE_ONCE(nm_hide_isolated, pools);
        nm_info("Isolated-pool hiding set to %u\n", pools);
        return 0;
    }
    case NM_KNOB_GHOST:
        if (!nm_have_ghost())
            return -EINVAL;
        if (vlen == 0)
            return 0;
        return ghost_ctl(val, vlen);
    case NM_KNOB_PATHHIDE:
        if (!nm_have_pathhide())
            return -EINVAL;
        if (vlen == 0)
            return 0;
        return pathhide_ctl(val, vlen);
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

bool nm_inode_hidden_from_caller(const struct inode *inode);
bool nm_inode_hidden_from_caller(const struct inode *inode)
{
    if (unlikely(!inode))
        return false;
    if (inode->i_op != &nm_file_iops && inode->i_op != &nm_dir_iops)
        return false;
    return nm_hidden_from_caller(inode->i_private);
}

/* The fs/ioctl.c FIONREAD hook (hookless/patches/nomount_fionread_*.patch). FIONREAD answers
 * i_size straight off the file's inode, before any of our ops run, and an engine inode is
 * shared by callers served different files: a hidden app reading the stock 56-byte hosts
 * through it was told the module's 2 MB. This is the size of the file this open actually
 * reads. kernel_read_file() is untouched, so .ko and firmware loads keep the module size. */
loff_t nm_fionread_isize(struct file *filp, struct inode *inode);
loff_t nm_fionread_isize(struct file *filp, struct inode *inode)
{
    struct file *real;

    if (unlikely(!inode))
        return 0;
    if (!filp || inode->i_op != &nm_file_iops)
        return i_size_read(inode);
    real = READ_ONCE(filp->private_data);
    if (!real || !file_inode(real))
        return i_size_read(inode);
    return i_size_read(file_inode(real));
}

/* An engine inode or a hijacked directory, whose i_size and i_blocks are not what stat
 * tells this caller. */
static bool nm_stat_for_raw_reader(struct file *filp, struct kstat *st)
{
    struct inode *inode = file_inode(filp);
    bool ours = inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops;

    if (!ours) {
        rcu_read_lock();
        ours = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop,
                        getattr, nomount_hijacked_getattr) != NULL;
        rcu_read_unlock();
    }
    return ours && nm_path_stat(&filp->f_path, st) == 0;
}

/* The fs/locks.c hook: l_whence=SEEK_END reads i_size off the inode, so the lock range is
 * measured against st_size, as stock's is. */
loff_t nm_lock_eof(struct file *filp);
loff_t nm_lock_eof(struct file *filp)
{
    struct kstat st;

    if (unlikely(!filp))
        return 0;
    return nm_stat_for_raw_reader(filp, &st) ? st.size : i_size_read(file_inode(filp));
}

/* The fs/ioctl.c FIOQSIZE hook: st_blocks in bytes, as stock's inode_get_bytes() is. */
loff_t nm_fioqsize_bytes(struct file *filp, struct inode *inode);
loff_t nm_fioqsize_bytes(struct file *filp, struct inode *inode)
{
    struct kstat st;

    if (unlikely(!filp || !inode))
        return inode ? inode_get_bytes(inode) : 0;
    return nm_stat_for_raw_reader(filp, &st) ? (loff_t)st.blocks << 9 : inode_get_bytes(inode);
}

static void __exit nomount_exit(void)
{

    netlink_kernel_release(nm_nl_sk);

    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all(true);
    mutex_unlock(&nomount_write_mutex);

    rcu_barrier();

    {
        int i;

        for (i = 0; i < NM_DEV_INO_SLOTS; i++) {
            kvfree(nm_dev_ino_tab[i].used);
            kfree(nm_dev_ino_tab[i].seed);
        }
    }
    kmem_cache_destroy(nm_dir_cachep);
    kmem_cache_destroy(nm_inode_cachep);
    kmem_cache_destroy(nm_iop_cachep);
    kmem_cache_destroy(nm_fop_cachep);
    put_cred(nm_root_cred);

    nm_info("Unloaded successfully\n");
}

MODULE_LICENSE("GPL");

fs_initcall(nomount_init);
module_exit(nomount_exit);
