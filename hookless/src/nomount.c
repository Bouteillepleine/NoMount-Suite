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
#include "nomount.h"

/* Android packs (user_id, appid) into a uid: uid = user_id*NM_PER_USER_RANGE + appid.
 * Matching a blocklist entry on the appid (uid % NM_PER_USER_RANGE) therefore covers
 * the same app across every user, work profile and clone with a single entry. Isolated
 * processes carry a pool-allocated appid in [NM_ISOLATED_START, NM_ISOLATED_END] that is
 * not tied to the parent app, so they are hidden whenever any app is blocked. */
#define NM_PER_USER_RANGE   100000
#define NM_ISOLATED_START   90000
#define NM_ISOLATED_END     99999

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


static __always_inline bool nomount_is_uid_blocked(uid_t uid)
{
    unsigned int appid;
    bool is_blocked;
    if (!static_branch_unlikely(&nomount_active_uids)) return false;
    /* Reaching here means the static branch is on, i.e. at least one appid is blocked. */
    appid = uid % NM_PER_USER_RANGE;
    if (appid >= NM_ISOLATED_START && appid <= NM_ISOLATED_END)
        return true; /* pool-allocated isolated process: hide from all of them */
    rcu_read_lock();
    is_blocked = (idr_find(&nomount_uid_idr, appid) != NULL);
    rcu_read_unlock();
    return is_blocked;
}

#define __get_nm(ptr, type, member, field, hook_func) ({ \
    typeof(ptr) __p = (ptr); \
    (likely(__p) && __p->field == (hook_func)) ? container_of(__p, type, member) : NULL; \
})

/* forward decls: the __get_nm identity checks below reference these hijack ops
 * before their definitions (identity is now by function pointer, not magic sig) */
static struct dentry *nomount_hijacked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags);
static int nomount_hijacked_iterate_dir(struct file *file, struct dir_context *ctx);

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
    if (!(dir_node->bloom_mask & (1ULL << (hash & 63)))) return false;
    rule_info->r_path.dentry = NULL;
    rule_info->r_path.mnt = NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            struct nomount_rule *rule = child->rule;
            if (rule && (rule->target_uid == 0 || rule->target_uid == current_uid().val)) {
                rule_info->flags = rule->flags;
                rule_info->v_ino = rule->v_ino;
                rule_info->v_dev = rule->v_dev;
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
    if (!(proxy->dir_node->bloom_mask & (1ULL << (hash & 63))))
        goto do_real_actor;

    /* By-name lookup: use the per-dir hash table, not an O(children) idr scan.
     * This is the hottest by-name path -- called once per real dirent during a
     * readdir of a hijacked large dir -- so the O(bucket) table is what keeps the
     * "at any fanout" property on the dir that motivates it (/product/overlay). */
    rcu_read_lock();
    hash_for_each_possible_rcu(proxy->dir_node->children_ht, child, hnode, hash) {
        if (child->name_hash == hash && child->name_len == namelen && memcmp(child->name, name, namelen) == 0) {
            if (child->rule && (child->rule->target_uid == 0 || child->rule->target_uid == current_uid().val)) {
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
            if (child->rule &&
                (child->rule->target_uid == 0 || child->rule->target_uid == current_uid().val) &&
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

    info->v_ino = rule_info->v_ino;
    info->v_dev = rule_info->v_dev;
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

            if (nm_read_secctx(real_inode, ctx, &ctxlen) == 0) {
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

    if (unlikely(nomount_is_uid_blocked(current_uid().val) || !pdir))
        goto fallback;

    v_hash = full_name_hash(NULL, name, len);
    if (nomount_get_rule_info(pdir, name, len, v_hash, &rule_info, true)) {
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

    if (unlikely(nomount_is_uid_blocked(current_uid().val) || !orig_fop || !pdir))
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
            if (info->r_path.dentry) {
                path_put(&info->r_path);
            }
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

static int nm_open(struct inode *inode, struct file *file)
{
    struct nm_inode_info *info = inode->i_private;
    struct file *real_file;

    if (unlikely(!info)) return -ENODEV;
    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
        file->private_data = NULL;
        return 0;
    }
    if (unlikely(!info->r_path.dentry)) return -ENODEV;

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
/* Pre-4.11 inode_operations->getattr signature: (vfsmount, dentry, kstat).
 * vfs_getattr_nosec()/generic_fillattr() are the 2-arg forms here. */
static int nm_file_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
    struct inode *v_inode = d_backing_inode(dentry);
    struct nm_inode_info *info = v_inode->i_private;
    int res;
    if (unlikely(!info)) return -EIO;

    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
        generic_fillattr(v_inode, stat);
        stat->ino = info->v_ino;
        stat->dev = info->v_dev ? info->v_dev : v_inode->i_sb->s_dev;
        if (info->v_mtime.tv_sec) {   /* mirror the stock/sibling times (see nm_alloc_rule) */
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
        return 0;
    }

    res = vfs_getattr_nosec(&info->r_path, stat);
    if (likely(res == 0)) {
        stat->ino = info->v_ino;
        stat->dev = info->v_dev ? info->v_dev : v_inode->i_sb->s_dev;
        if (info->v_mtime.tv_sec) {   /* mirror the stock/sibling times (see nm_alloc_rule) */
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

    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        generic_fillattr(IDMAP_CALL request_mask, v_inode, stat);
#else
        generic_fillattr(IDMAP_CALL v_inode, stat);
#endif
        stat->ino = info->v_ino;
        stat->dev = info->v_dev ? info->v_dev : v_inode->i_sb->s_dev;
        if (info->v_mtime.tv_sec) {   /* mirror the stock/sibling times (see nm_alloc_rule) */
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
        return 0;
    }

    res = vfs_getattr_nosec(&info->r_path, stat, request_mask, query_flags);
    if (likely(res == 0)) {
        stat->ino = info->v_ino;
        stat->dev = info->v_dev ? info->v_dev : v_inode->i_sb->s_dev;
        if (info->v_mtime.tv_sec) {   /* mirror the stock/sibling times (see nm_alloc_rule) */
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

    inode_lock(d_backing_inode(info->r_path.dentry));
    err = notify_change(IDMAP_CALL info->r_path.dentry, attr, NULL);
    inode_unlock(d_backing_inode(info->r_path.dentry));

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
    if (unlikely(!info || !info->r_path.dentry)) return ERR_PTR(-ECHILD);

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
        if (ctx->pos < 2 && !dir_emit_dots(file, ctx)) return 0;
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
    bool blocked = nomount_is_uid_blocked(current_uid().val);
    bool have_rule = false;

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
            have_rule = true;
            if (!blocked) {
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
    if (blocked && have_rule) {
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
        if (nomount_is_uid_blocked(current_uid().val))
            return injected ? 0 : 1;
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

static const struct inode_operations nm_file_iops = {
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
    atomic_set(&dir_node->refcount, 1);   /* structural owner ref */
    return dir_node;
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
            child->flags = rule->flags;
            child->rule = rule;
            return;
        }
    }

    child = kmalloc(sizeof(*child) + name_len + 1, GFP_KERNEL);
    if (unlikely(!child)) return;

    child->fake_ino = rule->v_ino;
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
    dir_node->bloom_mask |= (1ULL << (name_hash & 63));
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
                    anc_result_mask = ex->v_result_mask;
                    anc_attributes = ex->v_attributes;
                    anc_attr_mask = ex->v_attr_mask;
#endif
                    anc_ctx_len = ex->v_ctx_len;
                    if (ex->v_ctx_len) memcpy(anc_ctx, ex->v_ctx, ex->v_ctx_len + 1);
                    have_anc = true;
                }
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
        irule->flags = NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR;
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
        hlist_for_each_entry_safe(irule, tmp, &pending_list, vpath_node) {
            hlist_del_init(&irule->vpath_node);
            if (have_anc) {   /* stamp the nearest real ancestor's owner/mode/times/context */
                irule->v_uid = anc_uid;
                irule->v_gid = anc_gid;
                irule->v_mode = anc_mode;
                irule->v_atime = anc_atime;
                irule->v_mtime = anc_mtime;
                irule->v_ctime = anc_ctime;
                irule->v_ctx_len = anc_ctx_len;
                if (anc_ctx_len) memcpy(irule->v_ctx, anc_ctx, anc_ctx_len + 1);
                /* A raw name hash puts a synthesized dir billions away from its
                 * stock siblings (erofs dir inos are small); derive one in the
                 * nearest real ancestor's magnitude band instead. */
                if (anc_ino)
                    irule->v_ino = (anc_ino & ~0xFFFFUL) | (irule->v_hash & 0xFFFF) | 1UL;
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
        hlist_add_head(&owner->vpath_node, victims);
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

static int nm_scan_dir_for_file(const char *dirpath, struct kstat *out, int depth)
{
    struct nm_sib_scan *sc;
    struct path dp;
    struct kstat dkst;
    struct file *dir;
    const struct cred *old;
    int i, ret = -ENOENT;

    if (depth > 2)
        return -ENOENT;
    if (kern_path(dirpath, LOOKUP_FOLLOW, &dp) != 0)
        return -ENOENT;

    sc = kzalloc(sizeof(*sc), GFP_KERNEL);
    if (!sc) { path_put(&dp); return -ENOMEM; }
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

    /* prefer a real file at this level (dev != the overlay-top dir dev) */
    for (i = 0; i < sc->n_files; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->files[i]);
        struct path fp;
        struct kstat fk;

        if (!cp) continue;
        if (kern_path(cp, LOOKUP_FOLLOW, &fp) == 0) {
            int r = nm_path_stat(&fp, &fk);

            path_put(&fp);
            if (r == 0 && fk.dev != sc->dir_dev) { *out = fk; kfree(cp); ret = 0; goto done; }
        }
        kfree(cp);
    }
    /* else descend into a real subdir (bounded) */
    for (i = 0; i < sc->n_subdirs; i++) {
        char *cp = kasprintf(GFP_KERNEL, "%s/%s", dirpath, sc->subdirs[i]);

        if (!cp) continue;
        if (nm_scan_dir_for_file(cp, out, depth + 1) == 0) { kfree(cp); ret = 0; goto done; }
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
static bool nm_sib_cache_valid;

static int nm_find_sibling_meta(const char *vpath, struct kstat *out)
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
        kfree(path);
        return 0;
    }

    for (;;) {
        if (nm_scan_dir_for_file(path, out, 0) == 0) { ret = 0; break; }
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
    rule->flags = flags;
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
    if (!is_whiteout && kern_path(nm_get_rpath(rule), LOOKUP_FOLLOW, &rule->r_path) ==  0 &&
         S_ISDIR(d_backing_inode(rule->r_path.dentry)->i_mode)) rule->flags |= NM_FLAG_IS_DIR;

    if (kern_path(nm_get_vpath(rule), LOOKUP_FOLLOW, &v_path_struct) == 0) {
        struct kstat kst;
        /* Mirror both the dev AND ino a *stock* file at this path reports (what
         * a detector's stat()/maps sees) rather than the raw backing values.
         * On overlay-mounted partitions the raw i_sb->s_dev is the overlay-top
         * dev and the raw i_ino skips overlay xino remapping, so injected
         * inodes become dev/ino outliers vs their stock siblings. */
        if (nm_path_stat(&v_path_struct, &kst) == 0) {
            rule->v_ino = kst.ino;
            rule->v_dev = kst.dev;
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
        path_put(&v_path_struct);
    } else {
        /* Pure injection (no stock file): mirror a real sibling FILE's dev +
         * times, and derive an ino in the sibling's magnitude band. Mirroring
         * the parent *directory* would leak the overlay-top dev, so we hunt for
         * a real file instead (see nm_find_sibling_meta). */
        struct kstat sib;

        if (nm_find_sibling_meta(nm_get_vpath(rule), &sib) == 0) {
            rule->v_dev   = sib.dev;
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
             * breaks anything keying a cache on (dev,ino). A path hash is stable
             * but collides. Magnitude is not the tell it looks like: a clean
             * /system on this device spans ino 334..24.5M, so the band here sits
             * well inside what real filesystems produce. */
            /* r_path is unset for a whiteout, and for a backing path that did not
             * resolve (e.g. a dangling module symlink) -- both reach here when the
             * vpath does not exist either, so this MUST NOT deref it blindly. */
            rule->v_ino   = (unsigned long)((sib.ino & ~0xFFFFFULL) + 0x100000ULL +
                                            (rule->r_path.dentry
                                             ? (u64)d_backing_inode(rule->r_path.dentry)->i_ino
                                             : ((u64)rule->v_hash & 0xFFFFF)));
        } else {
            /* last resort: previous parent-dir dev fallback */
            char *vp = nm_get_vpath(rule);
            char *slash = strrchr(vp, '/');

            rule->v_ino = (unsigned long)rule->v_hash;
            rule->v_dev = 0;
            if (slash && slash != vp) {
                char *parent = kstrndup(vp, slash - vp, GFP_KERNEL);

                if (parent) {
                    if (kern_path(parent, LOOKUP_FOLLOW, &v_path_struct) == 0) {
                        struct kstat kst;

                        if (nm_path_stat(&v_path_struct, &kst) == 0) {
                            rule->v_dev = kst.dev;
                            /* Mirror the parent dir's times too: leaving these 0
                             * makes getattr fall through to the backing file's
                             * (module-install) mtime -- a fresh-timestamp tell. */
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
    hlist_add_head(&rule->vpath_node, victims);
}

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid)
{
    struct nomount_rule *rule, *existing, *victim = NULL;
    int err = 0;

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
            hash_del_rcu(&existing->vpath_node);
            victim = existing;
            nm_debug("Shadowing existing rule for: %s\n", nm_get_vpath(rule));
            break;
        }
    }

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
    hlist_for_each_entry_safe(rule, tmp, &r_victims, vpath_node) {
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
        int pos = 0, err = 0;

        while (pos + 12 <= len) {
            u32 flags      = get_unaligned((const u32 *)(data + pos));
            u32 target_uid = get_unaligned((const u32 *)(data + pos + 4));
            u16 vp_len     = get_unaligned((const u16 *)(data + pos + 8));
            u16 rp_len     = get_unaligned((const u16 *)(data + pos + 10));
            pos += 12;

            if (pos + vp_len + rp_len > len) break;
            if (unlikely(vp_len >= PATH_MAX || rp_len >= PATH_MAX)) break;

            v_ptr = data + pos; pos += vp_len;
            r_ptr = data + pos;  pos += rp_len;
            err = __nomount_add_rule(v_ptr, r_ptr, vp_len, rp_len, flags, target_uid);
            if (err) nm_err("Failed to inject rule batch entry (err: %d)\n", err);
        }
        return 0;

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

    hlist_for_each_entry_safe(rule, tmp, &r_victims, vpath_node) {
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
void nomount_spoof_mmap_metadata(const struct inode *inode, dev_t *dev,
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
    if (info->v_dev)
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
