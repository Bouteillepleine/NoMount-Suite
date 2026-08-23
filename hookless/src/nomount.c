#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/magic.h>
#include <linux/hash.h>
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static int nomount_hijacked_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat);
#else
static int nomount_hijacked_getattr(IDMAP_ARG const struct path *path, struct kstat *stat,
                                    u32 request_mask, unsigned int query_flags);
#endif
static u64 nm_child_dotdot_of(const char *dirpath);

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
    if (nm_iop && nm_iop->dir_node) return nm_iop->dir_node;

    nm_fop = __get_nm(smp_load_acquire(&inode->i_fop), struct nm_fop, fake_fop, iterate_shared, nomount_hijacked_iterate_dir);
    if (nm_fop && nm_fop->dir_node) return nm_fop->dir_node;
    
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
                rule_info->v_result_mask = rule->v_result_mask;
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
    int emitted;
};

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
                rcu_read_unlock();
                proxy->ctx.pos = offset;
                return NM_ACTOR_CONTINUE;
            }
            break; 
        }
    }
    rcu_read_unlock();

do_real_actor:
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

static inline void nomount_emit_virtual_children(struct dir_context *ctx, struct nomount_dir_node *dir_node)
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
            if (nm_child_visible(child) &&
                !(child->flags & NM_FLAG_WHITEOUT)) {
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
    info->v_ctx_len = rule_info->v_ctx_len;
    if (rule_info->v_ctx_len) memcpy(info->v_ctx, rule_info->v_ctx, rule_info->v_ctx_len + 1);
    /* Own ref for the inode's cached copy: the caller still holds its get_rule_info
     * ref (so the node is live here), and releases it via nm_put_rule_info(). This
     * ref is dropped in nomount_hijacked_destroy_inode(). */
    info->dir_node = rule_info->this_dir;
    if (info->dir_node) atomic_inc(&info->dir_node->refcount);
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
    info->v_result_mask = rule_info->v_result_mask;

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
    pdir = nm_iop ? nm_iop->dir_node : NULL;
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
     * file (no rule) would be needlessly uncached. */
    if (pdir && nomount_is_uid_blocked(current_uid().val) &&
        nomount_get_rule_info(pdir, name, len,
                              full_name_hash(NULL, name, len), &rule_info, false)) {
        nm_install_dentry_ops(dentry);
#ifdef DCACHE_DONTCACHE
        dentry->d_flags |= DCACHE_DONTCACHE;
#endif
        nm_put_rule_info(&rule_info);
    } else if (pdir && nm_name_has_hidden_uid_rule(pdir, name, len,
                                                   full_name_hash(NULL, name, len))) {
        /* Mirror of the above for a UID-scoped rule this reader is not the
         * audience for: it legitimately sees the stock file, but that view must
         * not outlive the call or it becomes the cached answer for the UID the
         * rule names. */
        nm_install_dentry_ops(dentry);
#ifdef DCACHE_DONTCACHE
        dentry->d_flags |= DCACHE_DONTCACHE;
#endif
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
    nm_fop = __get_nm(smp_load_acquire(&file->f_op), struct nm_fop, fake_fop, iterate_shared, nomount_hijacked_iterate_dir);
    orig_fop = nm_fop ? nm_fop->orig_fop : NULL;
    pdir = nm_fop ? nm_fop->dir_node : NULL;
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
        nomount_emit_virtual_children(ctx, pdir);
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
    nomount_emit_virtual_children(ctx, pdir);
    goto out;

do_real_iterate:
    res = orig_fop ? nm_call_iterate(file, ctx, orig_fop) : -ENOTDIR;
out:
    if (pdir) nm_dir_node_put(pdir);
    return res;
}

static void nomount_hijacked_destroy_inode(struct inode *inode)
{
    struct nm_sop *nm_sop;
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        if (inode->i_private) {
            struct nm_inode_info *info = inode->i_private;
            if (info->r_path.dentry) path_put(&info->r_path);
            if (info->s_path.dentry) path_put(&info->s_path);
            if (info->dir_node) nm_dir_node_put(info->dir_node);
            kmem_cache_free(nm_inode_cachep, info);
            inode->i_private = NULL;
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
    return nomount_is_uid_blocked(current_uid().val) ? &info->s_path : NULL;
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
        nm_warn("open of backing file denied for uid %u (relabel the module tree)\n",
                current_uid().val);
        return PTR_ERR(real_file);
    }

    file->private_data = real_file;
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
        case SEEK_END: offset += i_size_read(file_inode(file)); break;
        case SEEK_CUR: offset += file->f_pos; break;
        case SEEK_SET: break;
        default:       return -EINVAL;
        }
        if (offset < 0) return -EINVAL;
        file->f_pos = offset;
        return offset;
    }

    real_file->f_pos = file->f_pos;
    res = vfs_llseek(real_file, offset, whence);
    file->f_pos = real_file->f_pos;

    return res;
}

static ssize_t nm_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct file *file = iocb->ki_filp;
    struct file *real_file = file->private_data;
    ssize_t ret;
    if (!real_file || !real_file->f_op->read_iter) return -EINVAL;

    iocb->ki_filp = real_file;
    ret = real_file->f_op->read_iter(iocb, to);
    /* Do NOT restore on -EIOCBQUEUED. The op is still in flight and the backing
     * filesystem's completion path reads iocb->ki_filp (kiocb_end_write and the
     * iomap/dio completions all do); putting our synthetic file back there hands
     * the completion a file belonging to a different inode with a vtable it never
     * called into. Leaving the backing file is also safe for lifetime: the
     * submitter holds a reference to OUR file for the duration, and real_file is
     * pinned by its ->private_data, so it outlives the completion either way.
     * Synchronous callers (is_sync_kiocb) never see -EIOCBQUEUED and are restored
     * exactly as before. */
    if (ret != -EIOCBQUEUED)
        iocb->ki_filp = file;

    return ret;
}

static ssize_t nm_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct file *real_file = file->private_data;
    ssize_t ret;
    if (!real_file || !real_file->f_op->write_iter) return -EINVAL;

    iocb->ki_filp = real_file;
    ret = real_file->f_op->write_iter(iocb, from);
    /* Same as nm_read_iter: an in-flight (-EIOCBQUEUED) op keeps the backing file
     * on the iocb, because that is what its completion will dereference. */
    if (ret != -EIOCBQUEUED)
        iocb->ki_filp = file;

    return ret;
}

static int nm_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct file *real_file = file->private_data;
    int ret;
    if (!real_file || !real_file->f_op->mmap) return -ENODEV;

    /* Restore on FAILURE too. mmap_region() took its ref on `file` and its error
     * path does fput(vma->vm_file): leaving real_file there over-puts a reference
     * we never took (backing struct file UAF) and leaks the one on `file`. */
    vma->vm_file = real_file;
    ret = real_file->f_op->mmap(real_file, vma);
    if (vma->vm_file == real_file) vma->vm_file = file;

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static int nm_mmap_prepare(struct vm_area_desc *desc)
{
    struct file *file = desc->file;
    struct file *real_file = file->private_data;
    int ret;
    if (!real_file || !real_file->f_op->mmap_prepare) return -ENODEV;

    /* desc->file is const-qualified as of 6.18. The vm_area_desc is a mutable
     * on-stack object on the mmap path, so redirect through a cast (preserving
     * the pre-6.18 behaviour) and restore it afterwards. */
    *(struct file **)&desc->file = real_file;
    ret = real_file->f_op->mmap_prepare(desc);
    if (desc->file == real_file) *(struct file **)&desc->file = file;   /* on failure too */

    return ret;
}
#endif

static long nm_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->unlocked_ioctl) return -ENOTTY;
    return real_file->f_op->unlocked_ioctl(real_file, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long nm_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->compat_ioctl) return -ENOTTY;
    return real_file->f_op->compat_ioctl(real_file, cmd, arg);
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

static int nm_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->fsync) return -EINVAL;
    return real_file->f_op->fsync(real_file, start, end, datasync);
}

static ssize_t nm_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
    static const char nm_selinux_name[] = "security.selinux";
    struct nm_inode_info *info = d_backing_inode(dentry)->i_private;

    if (unlikely(!info)) return -EOPNOTSUPP;
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
 * an inode created part-way through would bake in a count that never updates. */
static unsigned int nm_vdir_nlink(struct nomount_dir_node *d)
{
    struct nomount_child_node *ch;
    unsigned int links = 2;
    int cid = 0;

    if (!d) return links;
    rcu_read_lock();
    idr_for_each_entry(&d->children_idr, ch, cid)
        if (ch->d_type == DT_DIR && !(ch->flags & NM_FLAG_WHITEOUT))
            links++;
    rcu_read_unlock();
    return links;
}

#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xE0F5E1E2
#endif
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

            if (ch->flags & NM_FLAG_WHITEOUT)
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
    d = nm_iop ? nm_iop->dir_node : NULL;
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
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
/* Pre-4.11 inode_operations->getattr signature: (vfsmount, dentry, kstat).
 * vfs_getattr_nosec()/generic_fillattr() are the 2-arg forms here. */
static int nm_file_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
    struct inode *v_inode = d_backing_inode(dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int res;
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
        generic_fillattr(v_inode, stat);
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
         * forwarding getattr to the backing file on /data (which does track
         * atime) sets that bit, so injected files answered statx with a mask no
         * stock sibling produces. Narrow to the stock mask -- never widen. */
        if (info->v_result_mask) stat->result_mask &= info->v_result_mask;
#endif
        stat->nlink = nm_vdir_nlink(info->dir_node);
        /* i_size stays at its 4096 placeholder otherwise; on erofs that is a
         * value no stock directory reports. Recount like nlink. */
        /* The sb here is the PARENT's -- overlayfs on an overlay-backed ROM path,
         * which is why this guard alone left those dirs at 4096. The knob is
         * userspace's measured answer for this device. */
        if (v_inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1 || READ_ONCE(nm_vdir_erofs_size))
            stat->size = nm_vdir_size(info->dir_node,
                                      v_inode->i_sb->s_blocksize);
        return 0;
    }

    res = vfs_getattr_nosec(&info->r_path, stat);
    if (likely(res == 0)) {
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
         * forwarding getattr to the backing file on /data (which does track
         * atime) sets that bit, so injected files answered statx with a mask no
         * stock sibling produces. Narrow to the stock mask -- never widen. */
        if (info->v_result_mask) stat->result_mask &= info->v_result_mask;
#endif
        if (S_ISDIR(stat->mode))
            nm_dir_size_fix(info, stat);
    }
    return res;
}
#else
static int nm_file_getattr(IDMAP_ARG const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    struct inode *v_inode = d_backing_inode(path->dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int res;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        generic_fillattr(IDMAP_CALL request_mask, v_inode, stat);
#else
        generic_fillattr(IDMAP_CALL v_inode, stat);
#endif
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
         * forwarding getattr to the backing file on /data (which does track
         * atime) sets that bit, so injected files answered statx with a mask no
         * stock sibling produces. Narrow to the stock mask -- never widen. */
        if (info->v_result_mask) stat->result_mask &= info->v_result_mask;
#endif
        stat->nlink = nm_vdir_nlink(info->dir_node);
        /* i_size stays at its 4096 placeholder otherwise; on erofs that is a
         * value no stock directory reports. Recount like nlink. */
        /* The sb here is the PARENT's -- overlayfs on an overlay-backed ROM path,
         * which is why this guard alone left those dirs at 4096. The knob is
         * userspace's measured answer for this device. */
        if (v_inode->i_sb->s_magic == EROFS_SUPER_MAGIC_V1 || READ_ONCE(nm_vdir_erofs_size))
            stat->size = nm_vdir_size(info->dir_node,
                                      v_inode->i_sb->s_blocksize);
        return 0;
    }

    res = vfs_getattr_nosec(&info->r_path, stat, request_mask, query_flags);
    if (likely(res == 0)) {
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
         * forwarding getattr to the backing file on /data (which does track
         * atime) sets that bit, so injected files answered statx with a mask no
         * stock sibling produces. Narrow to the stock mask -- never widen. */
        if (info->v_result_mask) stat->result_mask &= info->v_result_mask;
#endif
        if (S_ISDIR(stat->mode))
            nm_dir_size_fix(info, stat);
    }
    return res;
}
#endif

static int nm_setattr(IDMAP_ARG struct dentry *dentry, struct iattr *attr)
{
    struct inode *v_inode = d_inode(dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int err;

    if (unlikely(!info)) return -EIO;
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

    if (unlikely(!info || (info->flags & NM_FLAG_VIRTUAL_DIR) || !info->r_path.dentry))
        return -EOPNOTSUPP;
    real_inode = d_backing_inode(info->r_path.dentry);
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

    if (unlikely(nm_is_virtual_pos(dir_node, ctx->pos))) {
        nomount_emit_virtual_children(ctx, dir_node);
        return 0;
    }

    if (real_file) {
        struct nomount_proxy_ctx proxy_ctx = {
            .ctx.actor = nomount_actor_proxy, .ctx.pos = ctx->pos,
            .orig_ctx = ctx, .dir_node = dir_node, .emitted = 0
        };
        res = nm_call_iterate(real_file, &proxy_ctx.ctx, real_file->f_op);
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

    nomount_emit_virtual_children(ctx, dir_node);
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

    if (r_dir && r_dir->i_op && r_dir->i_op->lookup)
        return r_dir->i_op->lookup(r_dir, dentry, flags);

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

static int nm_xattr_get(const struct xattr_handler *handler, struct dentry *dentry, struct inode *inode, const char *name, void *buffer, size_t size FLAGS_ARG)
{
    struct nm_xattr_proxy *proxy = container_of(handler, struct nm_xattr_proxy, fake);
    if (inode->i_op == &nm_file_iops || inode->i_op == &nm_dir_iops) {
        struct nm_inode_info *info = inode->i_private;
        char *alloc;
        const char *full;
        int r;

        if (unlikely(!info)) return -ENODATA;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int nm_d_revalidate(struct inode *dir, const struct qstr *name, struct dentry *dentry, unsigned int flags)
#else
static int nm_d_revalidate(struct dentry *dentry, unsigned int flags)
#endif
{
    struct inode *parent_dir;
    struct nm_iop *nm_iop;
    struct nomount_dir_node *pdir = NULL;
    struct nm_rule_info rule_info;
    u32 hash;
    bool injected;

    if (flags & LOOKUP_RCU)
        return -ECHILD;

    /* Is this a dentry WE instantiated (an injected file/dir inode)? Used below to
     * drop stale ghosts and to keep the per-UID view consistent. */
    injected = dentry->d_inode &&
        (dentry->d_inode->i_op == &nm_file_iops ||
         dentry->d_inode->i_op == &nm_dir_iops);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
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
        pdir = nm_iop->dir_node;
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
        if (injected)
            return 0;
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
        if (rule_info.flags & NM_FLAG_WHITEOUT) return d_is_negative(dentry) ? 1 : 0;

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
                    return 1;
                return 0;
            }
            return 1;
        }
        return injected ? 1 : nm_reval_stale(dentry);
    }
    nm_dir_node_put(pdir);                                /* pin no longer needed past the lookup */
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
    .fiemap = nm_fiemap,
};

static const struct file_operations nm_dir_fops = {
    .owner = THIS_MODULE,
    .open = nm_open,
    .release = nm_release,
    .llseek = nm_llseek,
    .read = generic_read_dir,
    .iterate_shared = nm_dir_iterate_dir,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    .iterate = nm_dir_iterate_dir,
#endif
};

static const struct inode_operations nm_dir_iops = {
    .permission = nm_inode_permission,
    .lookup = nm_dir_lookup,
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
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

static inline void nomount_hijack_superblock(struct super_block *sb)
{
    struct nm_sop *nm_sop;
    int i, count = 0;
    if (unlikely(!sb || !sb->s_op || __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop, destroy_inode, nomount_hijacked_destroy_inode))) return;

    nm_sop = kzalloc(sizeof(*nm_sop), GFP_KERNEL);
    if (unlikely(!nm_sop)) return;

    nm_sop->fake_sop = *(sb->s_op);
    nm_sop->orig_sop = sb->s_op;
    nm_sop->sb = sb;
    nm_sop->fake_sop.destroy_inode = nomount_hijacked_destroy_inode;
    nm_sop->fake_sop.drop_inode = nomount_hijacked_drop_inode;
    nm_sop->fake_sop.evict_inode = nomount_hijacked_evict_inode;
    nm_sop->fake_sop.put_super = nomount_hijacked_put_super;   /* cure on runtime umount */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    if (!nm_sop->orig_sop->destroy_inode && !nm_sop->orig_sop->free_inode)
        nm_sop->fake_sop.free_inode = free_inode_nonrcu;
#endif

    if (sb->s_xattr && !nm_sop->orig_xattr) {
        const struct xattr_handler **new_array;
        while (sb->s_xattr[count]) count++;
        new_array = kzalloc((count + 1) * sizeof(void *), GFP_KERNEL);
        if (new_array) {
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
}

static inline void nomount_hijack_virtual_parent(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_fop *nm_fop;
    if (unlikely(!inode->i_fop || __get_nm(smp_load_acquire(&inode->i_fop), struct nm_fop, fake_fop, iterate_shared, nomount_hijacked_iterate_dir))) return;

    nm_fop = kmem_cache_zalloc(nm_fop_cachep, GFP_KERNEL);
    if (likely(nm_fop)) {
        nm_fop->fake_fop = *(inode->i_fop);
        nm_fop->orig_fop = inode->i_fop;
        nm_fop->dir_node = dir_node;

        nm_fop->fake_fop.iterate_shared = nomount_hijacked_iterate_dir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        if (nm_fop->fake_fop.iterate)
            nm_fop->fake_fop.iterate = nomount_hijacked_iterate_dir;
#endif

        smp_store_release(&inode->i_fop, &nm_fop->fake_fop);
        nm_debug("i_fop successfully hijacked for virtual parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static inline void nomount_hijack_dir_inode(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_iop *nm_iop;
    if (unlikely(!inode->i_op || __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop, lookup, nomount_hijacked_lookup))) return;

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

#define NM_DEFINE_RCU_FREE(_name, _type, _cache)                \
static void _name(struct rcu_head *head)                        \
{                                                               \
    _type *obj = container_of(head, _type, rcu);                \
    kmem_cache_free(_cache, obj);                               \
}

NM_DEFINE_RCU_FREE(nm_iop_rcu_free, struct nm_iop, nm_iop_cachep)
NM_DEFINE_RCU_FREE(nm_fop_rcu_free, struct nm_fop, nm_fop_cachep)

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
    if (nm_iop && nm_iop->dir_node == dir_node) {
        smp_store_release(&t_inode->i_op, nm_iop->orig_iop);
        nm_debug("Successfully cured i_op for dir %lu\n", t_inode->i_ino);
        call_rcu(&nm_iop->rcu, nm_iop_rcu_free);
    }

    nm_fop = __get_nm(smp_load_acquire(&t_inode->i_fop), struct nm_fop, fake_fop, iterate_shared, nomount_hijacked_iterate_dir);
    if (nm_fop && nm_fop->dir_node == dir_node) {
        smp_store_release(&t_inode->i_fop, nm_fop->orig_fop);
        nm_debug("Successfully cured i_fop for dir %lu\n", t_inode->i_ino);
        call_rcu(&nm_fop->rcu, nm_fop_rcu_free);
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

static void __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule, const char *name, size_t name_len)
{
    struct nomount_child_node *child;
    u32 name_hash;

    if (unlikely(!dir_node)) return;
    name_hash = full_name_hash(NULL, name, name_len);
    rule->parent_dir = dir_node;
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
            child->flags = rule->flags;
            child->rule = rule;
            child->d_type = (rule->flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG;
            WRITE_ONCE(child->fake_ino, rule->v_dino ? rule->v_dino : rule->v_ino);
            if (rule->flags & NM_FLAG_PUBLIC)
                WRITE_ONCE(dir_node->has_public, true);
            return;
        }
    }

    child = kmalloc(sizeof(*child) + name_len + 1, GFP_KERNEL);
    if (unlikely(!child)) return;

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
        return;
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
                    have_anc = true;
                }
                if (target_rule->flags & NM_FLAG_PUBLIC)
                    nm_mark_public_up(ex);
                __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
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
            if (!dir_node) dir_node = __nomount_alloc_dir_node(v_inode);
            if (likely(dir_node)) {
                nomount_hijack_virtual_parent(dir_node, v_inode);
                nomount_hijack_dir_inode(dir_node, v_inode);
                nomount_hijack_superblock(p_path.dentry->d_sb);

                qname.name = child_name;
                qname.len = child_len;
                qname.hash = full_name_hash(p_path.dentry, child_name, child_len);
                if (p_path.dentry->d_flags & DCACHE_OP_HASH)
                    p_path.dentry->d_op->d_hash(p_path.dentry, &qname);

                dentry = d_lookup(p_path.dentry, &qname);
                if (dentry) {
                    d_drop(dentry); 
                    dput(dentry);
                }
                __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
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
        __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
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
        if (!owner) break;

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
                                char *octx, u16 *octxlen, dev_t *omapdev, int depth)
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
                    fmapdev = d_backing_inode(fp.dentry)->i_sb->s_dev;
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
        if (nm_scan_dir_for_file(cp, out, octx, octxlen, omapdev, depth + 1) == 0) { kfree(cp); ret = 0; goto done; }
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
static bool nm_sib_cache_valid;

static int nm_find_sibling_meta(const char *vpath, struct kstat *out,
                                char *octx, u16 *octxlen, dev_t *omapdev)
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
        kfree(path);
        return 0;
    }

    for (;;) {
        if (nm_scan_dir_for_file(path, out, octx, octxlen, omapdev, 0) == 0) { ret = 0; break; }
        slash = strrchr(path, '/');
        if (!slash || slash == path)
            break;
        *slash = '\0';                   /* ascend */
    }
    if (ret == 0) {                      /* cache keyed on vpath's immediate parent */
        strscpy(nm_sib_cache_dir, vpath, PATH_MAX);
        slash = strrchr(nm_sib_cache_dir, '/');
        if (slash && slash != nm_sib_cache_dir) {
            *slash = '\0';
            nm_sib_cache_kst = *out;
            nm_sib_cache_ctxlen = (octx && octxlen) ? *octxlen : 0;
            if (nm_sib_cache_ctxlen) memcpy(nm_sib_cache_ctx, octx, nm_sib_cache_ctxlen + 1);
            nm_sib_cache_mapdev = omapdev ? *omapdev : 0;
            nm_sib_cache_valid = true;
        }
    }
    kfree(path);
    return ret;
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
    rule = kzalloc((sizeof(struct nomount_rule) + v_len + 1 + r_len + 1), GFP_KERNEL);
    if (!rule) return ERR_PTR(-ENOMEM);

    INIT_HLIST_NODE(&rule->vpath_node);
    rule->v_hash = full_name_hash(NULL, v_path, v_len);
    rule->flags = flags & NM_FLAGS_USER_MASK;
    rule->v_len = v_len;
    rule->target_uid = target_uid;
    memcpy(nm_get_vpath(rule), v_path, v_len);
    nm_get_vpath(rule)[v_len] = '\0';

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
        rule->v_mapdev = d_backing_inode(v_path_struct.dentry)->i_sb->s_dev;
        if (nm_path_stat(&v_path_struct, &kst) == 0) {
            rule->v_ino = kst.ino;
            rule->v_dev = kst.dev;
            rule->flags |= NM_FLAG_HAVE_TIMES;
            rule->v_atime = kst.atime;   /* mirror the stock file's times too */
            rule->v_mtime = kst.mtime;
            rule->v_ctime = kst.ctime;
            rule->v_blksize = kst.blksize;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_result_mask = kst.result_mask;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
            rule->v_attributes = kst.attributes;   /* STATX_ATTR_* only exist >= 4.11 */
            rule->v_attr_mask = kst.attributes_mask;
#endif
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
                                 rule->v_ctx, &rule->v_ctx_len, &rule->v_mapdev) == 0) {
            rule->v_dev   = sib.dev;
            rule->flags |= NM_FLAG_HAVE_TIMES;
            rule->v_atime = sib.atime;
            rule->v_mtime = sib.mtime;
            rule->v_ctime = sib.ctime;
            rule->v_blksize    = sib.blksize;
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

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid)
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

    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == v_len &&
             existing->target_uid == target_uid &&
             memcmp(nm_get_vpath(existing), nm_get_vpath(rule), v_len) == 0) {
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
            hash_del_rcu(&existing->vpath_node);
            victim = existing;
            nm_debug("Shadowing existing rule for: %s\n", nm_get_vpath(rule));
            break;
        }
    }

    /* PUBLIC only ever excuses an ADDED name from hiding. On a rule that shadows
     * a stock file the blocked reader is already served the stock bytes from the
     * ops (nm_stock_for_caller), which is consistent on its own; honouring the
     * bit there would hand it the module's copy instead -- a real leak, and one a
     * client could ask for by mislabelling. Decide it HERE rather than in
     * nm_alloc_rule: a replacement re-derives SHADOWS_STOCK from the rule it
     * replaces just above, and measuring it earlier would strip the bit off every
     * re-added rule (a reload resolves the vpath through the live injection, so
     * nm_alloc_rule always concludes "shadowing"). */
    if (rule->flags & NM_FLAG_SHADOWS_STOCK)
        rule->flags &= ~NM_FLAG_PUBLIC;

    err = nomount_generate_virtual_topology(rule);
    if (err != 0) {
        mutex_unlock(&nomount_write_mutex);
        nm_free_rule(rule); 
        if (victim) {
            synchronize_rcu();
            nm_free_rule(victim);
        }
        return err;
    }

    hash_add_rcu(nomount_rules_ht, &rule->vpath_node, rule->v_hash);
    atomic_inc(&nm_rule_gen);
    mutex_unlock(&nomount_write_mutex);

    if (unlikely(victim)) {
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
    u32 hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == v_len && rule->target_uid == target_uid &&
                memcmp(nm_get_vpath(rule), v_path, v_len) == 0) {
            /* Refuse to delete a rule that still owns a populated virtual subtree:
             * nm_free_rule() would free its dir_node while descendant rules keep a
             * parent_dir pointer into it, dangling -> UAF on a later del/clear. The
             * caller must remove the children first. Mirrors the shadow-path guard
             * in __nomount_add_rule(). (nm clear is unaffected: it detaches every
             * rule before any dir_node is freed.) */
            if (rule->this_dir && !idr_is_empty(&rule->this_dir->children_idr))
                return -EBUSY;
            nm_detach_rule_locked(rule, r_victims, true);
            return 0;
        }
    }
    return -ENOENT;
}

/* NB: this drops the blocked-UID set as well as the rules -- per-UID hiding is
 * runtime-only state and CLEAR_ALL is its reset. Any caller that clears in order to
 * rebuild (the Suite's mount pass does exactly that) must re-apply its persistent
 * block list afterwards, or every hidden app is silently unhidden. */
static void __nomount_clear_all(bool is_exit)
{
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    HLIST_HEAD(r_victims);

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
            err = __nomount_add_rule(v_ptr, r_ptr, vp_len, rp_len, flags, target_uid);
            if (err) {
                nm_err("Failed to inject rule batch entry (err: %d)\n", err);
                nfail++;
                if (!first_err) first_err = err;
            }
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
        int v_len = nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) - 1;
        int r_len = nla_len(attrs[NOMOUNT_ATTR_REAL_PATH]) - 1;
        u32 flags = attrs[NOMOUNT_ATTR_FLAGS] ? nla_get_u32(attrs[NOMOUNT_ATTR_FLAGS]) : 0;
        u32 target_uid = attrs[NOMOUNT_ATTR_UID] ? nla_get_u32(attrs[NOMOUNT_ATTR_UID]) : 0;

        return __nomount_add_rule(v_str, r_str, v_len, r_len, flags, target_uid);
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
        int v_len = nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) - 1;
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
    int bkt, node_idx = 0;
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
        }
        skip_nodes = 0;
    }

out:
    rcu_read_unlock();
    cb->args[0] = bkt;
    cb->args[1] = node_idx; 
    return skb->len;
}

static int nomount_nl_add_uid(struct nlattr **attrs)
{
    unsigned int uid;
    int ret;

    if (!attrs[NOMOUNT_ATTR_UID])
        return -EINVAL;

    uid = nla_get_u32(attrs[NOMOUNT_ATTR_UID]) % NM_PER_USER_RANGE; /* store/match appid */

    if (nomount_is_uid_blocked(uid)) 
        return -EEXIST;

    mutex_lock(&nomount_write_mutex);
    idr_preload(GFP_KERNEL);
    ret = idr_alloc(&nomount_uid_idr, (void *)8, uid, uid + 1, GFP_NOWAIT);
    idr_preload_end();

    if (ret >= 0) {
        static_branch_enable(&nomount_active_uids);
        nm_info("Successfully added blocked UID: %u\n", uid);
        ret = 0;
    } else {
        ret = -ENOMEM;
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
 * GET_* commands are streamed via the standard dump machinery. CAP_NET_ADMIN
 * is required on every command (replaces the genl GENL_ADMIN_PERM flag).
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

    if (!netlink_capable(skb, CAP_NET_ADMIN))
        return -EPERM;

    if (cmd == NM_CMD_GET_LIST || cmd == NM_CMD_GET_UIDS) {
        struct netlink_dump_control c = {
            .dump = (cmd == NM_CMD_GET_LIST) ? nomount_nl_dump_rules
                                             : nomount_nl_dump_uids,
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

/*** uname override — write-through into init_uts_ns via /sys/kernel/nomount/ ***/
/* Root-only (0600). A non-empty write that isn't the literal "default" replaces
 * that field in the initial UTS namespace, so every uname()/`/proc/version`
 * reader reflects it (Android apps share init's UTS ns). Empty/"default" = leave.
 * Built-in only (CONFIG_NOMOUNT=y): uts_sem/init_uts_ns are not exported. */

/* ---- /proc/cmdline + /proc/bootconfig spoofing --------------------------------
 * androidboot.* boot state (verifiedbootstate, lock, warranty, vbmeta.digest) lives in
 * /proc/cmdline and, on GKI, /proc/bootconfig. resetprop only moves the derived
 * ro.boot.* props, leaving these procfs sources contradicting them -- a detection tell.
 * A procfs seq-file has no backing inode to vtable-hijack, so on the first write to the
 * sysfs knob we take over the proc entry itself and serve the sanitized string. This
 * happens at post-fs-data (procfs long up), and init's early parse of the real kernel
 * command line is untouched. Empty write => passthrough (the real value). */
static char *nm_fake_cmdline;
static struct proc_dir_entry *nm_cmdline_pde;
static DEFINE_MUTEX(nm_procspoof_mutex);

static int nm_cmdline_show(struct seq_file *m, void *v)
{
    mutex_lock(&nm_procspoof_mutex);
    seq_printf(m, "%s\n", nm_fake_cmdline ? nm_fake_cmdline : saved_command_line);
    mutex_unlock(&nm_procspoof_mutex);
    return 0;
}

#ifdef CONFIG_BOOT_CONFIG
static char *nm_fake_bootconfig, *nm_orig_bootconfig;
static struct proc_dir_entry *nm_bootconfig_pde;

static int nm_bootconfig_show(struct seq_file *m, void *v)
{
    mutex_lock(&nm_procspoof_mutex);
    if (nm_fake_bootconfig)      seq_puts(m, nm_fake_bootconfig);
    else if (nm_orig_bootconfig) seq_puts(m, nm_orig_bootconfig);
    mutex_unlock(&nm_procspoof_mutex);
    return 0;
}

/* Snapshot the real /proc/bootconfig once, before we replace it, so an empty write can
 * fall back to the genuine text (bootconfig is not reproducible from a global). */
static char *nm_snapshot_bootconfig(void)
{
    struct file *f;
    char *buf;
    loff_t pos = 0;
    ssize_t n;

    f = filp_open("/proc/bootconfig", O_RDONLY, 0);
    if (IS_ERR(f)) return NULL;
    buf = kmalloc(SZ_64K, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return NULL; }
    n = kernel_read(f, buf, SZ_64K - 1, &pos);
    filp_close(f, NULL);
    if (n <= 0) { kfree(buf); return NULL; }
    buf[n] = '\0';
    return buf;
}
#endif /* CONFIG_BOOT_CONFIG */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
static int nm_cmdline_open(struct inode *i, struct file *f) { return single_open(f, nm_cmdline_show, NULL); }
static const struct file_operations nm_cmdline_fops = {
    .open = nm_cmdline_open, .read = seq_read, .llseek = seq_lseek, .release = single_release,
};
#ifdef CONFIG_BOOT_CONFIG
static int nm_bootconfig_open(struct inode *i, struct file *f) { return single_open(f, nm_bootconfig_show, NULL); }
static const struct file_operations nm_bootconfig_fops = {
    .open = nm_bootconfig_open, .read = seq_read, .llseek = seq_lseek, .release = single_release,
};
#endif
#endif /* < 4.17 */

/* trim trailing newline/CR then dup; empty => NULL (passthrough) */
static char *nm_dup_trim(const char *buf, size_t count)
{
    while (count && (buf[count - 1] == '\n' || buf[count - 1] == '\r')) count--;
    return count ? kstrndup(buf, count, GFP_KERNEL) : NULL;
}

/* proc has no rename and refuses a duplicate name, so a takeover must
 * remove-then-create. If the create then fails the entry is gone for good, and a
 * MISSING /proc/cmdline is both a louder tell and more breaking than an
 * unsanitised one -- so retry, and report instead of failing silently. */
static struct proc_dir_entry *nm_mk_cmdline_pde(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    return proc_create_single("cmdline", 0444, NULL, nm_cmdline_show);
#else
    return proc_create("cmdline", 0444, NULL, &nm_cmdline_fops);
#endif
}

#ifdef CONFIG_BOOT_CONFIG
static struct proc_dir_entry *nm_mk_bootconfig_pde(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    return proc_create_single("bootconfig", 0444, NULL, nm_bootconfig_show);
#else
    return proc_create("bootconfig", 0444, NULL, &nm_bootconfig_fops);
#endif
}
#endif

static int nm_set_cmdline(const char *buf, size_t c)
{
    char *nb = nm_dup_trim(buf, c);
    mutex_lock(&nm_procspoof_mutex);
    kfree(nm_fake_cmdline);
    nm_fake_cmdline = nb;
    if (!nm_cmdline_pde) {
        remove_proc_entry("cmdline", NULL);
        nm_cmdline_pde = nm_mk_cmdline_pde();
        if (!nm_cmdline_pde) nm_cmdline_pde = nm_mk_cmdline_pde();
        if (!nm_cmdline_pde) {
            kfree(nm_fake_cmdline);
            nm_fake_cmdline = NULL;
            nm_err("procspoof: /proc/cmdline takeover failed, entry lost\n");
            mutex_unlock(&nm_procspoof_mutex);
            return -EIO;
        }
    }
    mutex_unlock(&nm_procspoof_mutex);
    return 0;
}

#ifdef CONFIG_BOOT_CONFIG
static int nm_set_bootconfig(const char *buf, size_t c)
{
    char *nb = nm_dup_trim(buf, c);
    mutex_lock(&nm_procspoof_mutex);
    if (!nm_bootconfig_pde) {
        if (!nm_orig_bootconfig) nm_orig_bootconfig = nm_snapshot_bootconfig();
        /* Never take over into an empty /proc/bootconfig: if we have neither a fake
         * (empty write) nor a snapshot to passthrough, serving nothing is itself a
         * tell (stock is never empty). Leave the genuine entry in place. */
        if (!nb && !nm_orig_bootconfig) {
            mutex_unlock(&nm_procspoof_mutex);
            return 0;
        }
        kfree(nm_fake_bootconfig);
        nm_fake_bootconfig = nb;
        remove_proc_entry("bootconfig", NULL);
        nm_bootconfig_pde = nm_mk_bootconfig_pde();
        if (!nm_bootconfig_pde) nm_bootconfig_pde = nm_mk_bootconfig_pde();
        if (!nm_bootconfig_pde) {
            kfree(nm_fake_bootconfig);
            nm_fake_bootconfig = NULL;
            nm_err("procspoof: /proc/bootconfig takeover failed, entry lost\n");
            mutex_unlock(&nm_procspoof_mutex);
            return -EIO;
        }
    } else {
        kfree(nm_fake_bootconfig);
        nm_fake_bootconfig = nb;
    }
    mutex_unlock(&nm_procspoof_mutex);
    return 0;
}
#endif /* CONFIG_BOOT_CONFIG */

static int nm_uts_store(char *field, size_t fieldsz, const char *buf, size_t count)
{
    char tmp[__NEW_UTS_LEN + 1];
    size_t n = count;

    if (n && buf[n - 1] == '\n') n--;
    if (n > __NEW_UTS_LEN) return -EINVAL;
    memcpy(tmp, buf, n);
    tmp[n] = '\0';
    if (n == 0 || strcmp(tmp, "default") == 0) return 0;

    down_write(&uts_sem);
    memset(field, 0, fieldsz);
    memcpy(field, tmp, n);
    up_write(&uts_sem);
    return 0;
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
    case NM_KNOB_UNAME_RELEASE:
        return nm_uts_store(init_uts_ns.name.release,
                            sizeof(init_uts_ns.name.release), val, vlen);
    case NM_KNOB_UNAME_VERSION:
        return nm_uts_store(init_uts_ns.name.version,
                            sizeof(init_uts_ns.name.version), val, vlen);
    case NM_KNOB_CMDLINE:
        return nm_set_cmdline(val, vlen);
#ifdef CONFIG_BOOT_CONFIG
    case NM_KNOB_BOOTCONFIG:
        return nm_set_bootconfig(val, vlen);
#endif
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
    default:
        return -EINVAL;
    }
}

static void nm_procspoof_exit(void)
{
    struct proc_dir_entry *cpde;
#ifdef CONFIG_BOOT_CONFIG
    struct proc_dir_entry *bpde;
#endif
    /* Detach and free under the lock, but call remove_proc_entry OUTSIDE it:
     * remove_proc_entry blocks until in-flight readers finish, and those readers
     * (nm_cmdline_show/nm_bootconfig_show) take nm_procspoof_mutex themselves --
     * holding it across the removal would be an ABBA deadlock. Once the pointer is
     * NULLed under the lock, show falls back to saved_command_line (never freed). */
    mutex_lock(&nm_procspoof_mutex);
    cpde = nm_cmdline_pde; nm_cmdline_pde = NULL;
    kfree(nm_fake_cmdline); nm_fake_cmdline = NULL;
#ifdef CONFIG_BOOT_CONFIG
    bpde = nm_bootconfig_pde; nm_bootconfig_pde = NULL;
    kfree(nm_fake_bootconfig); nm_fake_bootconfig = NULL;
    kfree(nm_orig_bootconfig); nm_orig_bootconfig = NULL;
#endif
    mutex_unlock(&nm_procspoof_mutex);

    if (cpde) remove_proc_entry("cmdline", NULL);
#ifdef CONFIG_BOOT_CONFIG
    if (bpde) remove_proc_entry("bootconfig", NULL);
#endif

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
     * netlink_capable(CAP_NET_ADMIN)-gated, and for app domains SELinux denies
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
    nm_procspoof_exit();

    netlink_kernel_release(nm_nl_sk);

    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all(true);
    mutex_unlock(&nomount_write_mutex);

    /* Drain pending call_rcu frees (nm_iop / nm_fop / dir_node) before destroying
     * their slab caches, else kmem_cache_destroy races the deferred kmem_cache_free. */
    rcu_barrier();

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
