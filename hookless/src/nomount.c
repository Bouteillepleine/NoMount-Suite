#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/module.h>
#include "nomount.h"

static struct kmem_cache *nm_dir_cachep __read_mostly, *nm_inode_cachep __read_mostly;
static struct kmem_cache *nm_iop_cachep __read_mostly, *nm_fop_cachep __read_mostly;
static const struct cred *nm_root_cred;
static DEFINE_STATIC_KEY_FALSE(nomount_active_uids);

/* P0/P2: dir_node teardown is refcounted + RCU-deferred; used by readers well
 * before the definitions further down. */
static void nm_dir_node_rcu_free(struct rcu_head *head);
static void nomount_dir_node_put(struct nomount_dir_node *dir_node);

/*** Helpers ***/

static __always_inline bool nomount_is_uid_blocked(uid_t uid)
{
    bool is_blocked;
    if (!static_branch_unlikely(&nomount_active_uids)) return false;
    rcu_read_lock();
    is_blocked = (idr_find(&nomount_uid_idr, uid) != NULL);
    rcu_read_unlock();
    return is_blocked;
}

#define __get_nm(ptr, type, member) ({ \
    u64 __sig = 0; \
    type *__o = likely(ptr) ? container_of(ptr, type, member) : NULL; \
    (__o && nm_probe_read(&__sig, &__o->signature, sizeof(__sig)) == 0 && __sig == NOMOUNT_MAGIC_SIG) ? __o : NULL; \
})

static __always_inline struct nomount_dir_node *nomount_get_dir_node(struct inode *inode) 
{
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;

    nm_iop = __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop);
    if (nm_iop && nm_iop->dir_node) return nm_iop->dir_node;

    nm_fop = __get_nm(smp_load_acquire(&inode->i_fop), struct nm_fop, fake_fop);
    if (nm_fop && nm_fop->dir_node) return nm_fop->dir_node;
    
    return NULL;
}

/* Lockless read path: snapshot the needed fields under RCU and path_get() the
 * backing path, so callers never dereference the rule after rcu_read_unlock().
 * Returns true if a rule visible to the current UID was found; on true the caller
 * owns rule_info->r_path and must path_put() it (when r_path.dentry != NULL). */
static __always_inline bool nomount_get_rule_info(struct nomount_dir_node *dir_node, const char *name, size_t len, u32 hash, struct nm_rule_info *rule_info)
{
    struct nomount_child_node *child;
    bool found = false;
    int id;

    if (unlikely(!dir_node)) return false;
    rule_info->r_path.dentry = NULL;
    rule_info->r_path.mnt = NULL;

    rcu_read_lock();
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->name_hash == hash && child->name_len == len && memcmp(child->name, name, len) == 0) {
            struct nomount_rule *rule = child->rule;
            if (rule && (rule->target_uid == 0 || rule->target_uid == current_uid().val)) {
                rule_info->flags = rule->flags;
                rule_info->v_ino = rule->v_ino;
                rule_info->v_dev = rule->v_dev;
                rule_info->v_atime = rule->v_atime;
                rule_info->v_mtime = rule->v_mtime;
                rule_info->v_ctime = rule->v_ctime;
                rule_info->this_dir = rule->this_dir;
                /* P2: pin the snapshot under RCU so it survives being cached in a
                 * synthesized inode past a concurrent teardown. refs==0 => already
                 * being freed, don't hand it out. Caller releases via
                 * nomount_dir_node_put at every exit (mirrors r_path's path_put). */
                if (rule_info->this_dir && !refcount_inc_not_zero(&rule_info->this_dir->refs))
                    rule_info->this_dir = NULL;
                if (rule->r_path.dentry) {
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
    int id;

    proxy->emitted++;
    if (!proxy->dir_node) goto do_real_actor;
    hash = full_name_hash(NULL, name, namelen);
    if (!(proxy->dir_node->bloom_mask & (1ULL << (hash & 63))))
        goto do_real_actor;

    rcu_read_lock();
    idr_for_each_entry(&proxy->dir_node->children_idr, child, id) {
        if (child->name_hash == hash && child->name_len == namelen && memcmp(child->name, name, namelen) == 0) {
            if (child->rule->target_uid == 0 || child->rule->target_uid == current_uid().val) {
                rcu_read_unlock();
                proxy->ctx.pos = offset;
                return NM_ACTOR_CONTINUE;
            }
            break; 
        }
    }
    rcu_read_unlock();

do_real_actor:
    proxy->orig_ctx->pos = proxy->ctx.pos;
    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino, d_type);
    proxy->ctx.pos = proxy->orig_ctx->pos;

    return ret;
}

static inline void nomount_emit_virtual_children(struct dir_context *ctx, struct nomount_dir_node *dir_node)
{
    struct nomount_child_node *child;
    int id;

    if (!dir_node) return;
    if (!nm_is_virtual_pos(ctx->pos)) ctx->pos = nm_pack_pos(0);
    id = nm_unpack_pos(ctx->pos);

    rcu_read_lock();
    idr_for_each_entry_continue(&dir_node->children_idr, child, id) {
        ctx->pos = nm_pack_pos(id);
        if (child->rule->target_uid == 0 || child->rule->target_uid == current_uid().val) {
            if (!(child->flags & NM_FLAG_WHITEOUT) &&
                !dir_emit(ctx, child->name, child->name_len, child->fake_ino, child->d_type)) break;
        }
        ctx->pos = nm_pack_pos(id + 1);
    }
    rcu_read_unlock();
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
    /* P2: the inode's own ref on the cached dir_node (released in destroy_inode).
     * The caller still holds + releases its snapshot ref, so refs>0 -> inc safe. */
    info->dir_node = rule_info->this_dir;
    if (info->dir_node)
        refcount_inc(&info->dir_node->refs);
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

    inode->i_private = info;
    inode->i_ino = rule_info->v_ino;
    if (rule_info->flags & NM_FLAG_VIRTUAL_DIR) {
        inode->i_mode = S_IFDIR | 0755;
        inode->i_size = 4096;
        inode->i_blocks = 8;
        inode->i_uid = GLOBAL_ROOT_UID;
        inode->i_gid = GLOBAL_ROOT_GID;
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
        /* Mirror the backing file's SELinux context onto the synthetic inode.
         * getfilecon()/ls -Z read the label from SELinux's i_security (the SID
         * assigned at new_inode time), NOT via our xattr proxy — on plain erofs
         * that SID is unlabeled ('?'), a detection tell. Overlay copies it for
         * free; erofs does not. (secctx API changed to lsmcontext post-6.12.) */
        {
            void *ctx = NULL;
            u32 ctxlen = 0;

            if (security_inode_getsecctx(real_inode, &ctx, &ctxlen) == 0) {
                security_inode_notifysecctx(inode, ctx, ctxlen);
                security_release_secctx(ctx, ctxlen);
            }
        }
#endif
    }

    inode->i_flags |= S_PRIVATE | S_NOATIME | S_NOCMTIME | S_NOSEC;
    inode->i_opflags |= IOP_XATTR;
    if (!S_ISLNK(inode->i_mode)) inode->i_opflags |= IOP_NOFOLLOW;
    nm_init_private_list(inode);

    return inode;
}

/*** i_op / s_op / f_op Hijacking Hooks ***/

static struct dentry *nomount_hijacked_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    struct nm_iop *nm_iop = __get_nm(smp_load_acquire(&dir->i_op), struct nm_iop, fake_iop);
    struct nm_rule_info rule_info;
    const char *name = dentry->d_name.name;
    size_t len = dentry->d_name.len;
    u32 v_hash;

    if (unlikely(nomount_is_uid_blocked(current_uid().val) || !nm_iop || !nm_iop->dir_node))
        goto fallback;

    v_hash = full_name_hash(NULL, name, len);
    if (nomount_get_rule_info(nm_iop->dir_node, name, len, v_hash, &rule_info)) {
        if (rule_info.flags & NM_FLAG_WHITEOUT) {
            nm_install_dentry_ops(dentry);
            d_add(dentry, NULL);
            if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
            nomount_dir_node_put(rule_info.this_dir);
            return NULL;
        }

        if ((rule_info.flags & NM_FLAG_VIRTUAL_DIR) || rule_info.r_path.dentry) {
            struct inode *new_inode = nomount_create_new_inode(dir->i_sb, &rule_info);
            if (likely(new_inode)) {
                struct dentry *res;
                nm_install_dentry_ops(dentry);
                nm_debug("Lookup hijacked! Splicing inode %lu into dentry '%s'\n", new_inode->i_ino, name);
                if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
                nomount_dir_node_put(rule_info.this_dir);
                /* d_splice_alias may return a DIFFERENT (existing) alias dentry; our
                 * ops must ride on THAT one too, else d_revalidate never runs on the
                 * spliced dentry and the per-UID / ghost-dentry verdict is lost for
                 * it. (Ported from upstream c4fcdac; the DONTCACHE fallback below is
                 * deliberately kept -- upstream's rewrite dropped it.) */
                res = d_splice_alias(new_inode, dentry);
                if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
                return res;
            }
        }
        if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
        nomount_dir_node_put(rule_info.this_dir);
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
    if (nm_iop && nm_iop->dir_node && nomount_is_uid_blocked(current_uid().val) &&
        nomount_get_rule_info(nm_iop->dir_node, name, len,
                              full_name_hash(NULL, name, len), &rule_info)) {
        nm_install_dentry_ops(dentry);
#ifdef DCACHE_DONTCACHE
        dentry->d_flags |= DCACHE_DONTCACHE;
#endif
        if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
        nomount_dir_node_put(rule_info.this_dir);
    }

    if (nm_iop && nm_iop->orig_iop && nm_iop->orig_iop->lookup) {
        return nm_iop->orig_iop->lookup(dir, dentry, flags);
    }

    return ERR_PTR(-EOPNOTSUPP);
}
static int nomount_hijacked_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_fop *nm_fop = __get_nm(smp_load_acquire(&file->f_op), struct nm_fop, fake_fop);
    struct nomount_proxy_ctx proxy_ctx = {
        .ctx.actor = nomount_actor_proxy,
    };
    int res = 0;

    if (unlikely(nomount_is_uid_blocked(current_uid().val) || !nm_fop || !nm_fop->orig_fop || !nm_fop->dir_node))
        goto do_real_iterate;

    if (unlikely(nm_is_virtual_pos(ctx->pos))) {
        nomount_emit_virtual_children(ctx, nm_fop->dir_node);
        return 0;
    }

    proxy_ctx.ctx.pos = ctx->pos;
    proxy_ctx.orig_ctx = ctx;
    proxy_ctx.dir_node = nm_fop->dir_node;
    proxy_ctx.emitted = 0;

    res = nm_call_iterate(file, &proxy_ctx.ctx, nm_fop->orig_fop);
    ctx->pos = proxy_ctx.ctx.pos;
    if (res < 0 || proxy_ctx.emitted > 0) return res;

    ctx->pos = nm_pack_pos(0);
    nomount_emit_virtual_children(ctx, nm_fop->dir_node);
    return res;

do_real_iterate:
    if (nm_fop && nm_fop->orig_fop) return nm_call_iterate(file, ctx, nm_fop->orig_fop);
    return -ENOTDIR;
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
            nomount_dir_node_put(info->dir_node);   /* P2: release cached dir_node ref */
            kmem_cache_free(nm_inode_cachep, info);
            inode->i_private = NULL;
        }
    }
    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop);
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

    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop);
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
    nm_sop = __get_nm(smp_load_acquire(&inode->i_sb->s_op), struct nm_sop, fake_sop);
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
    const struct cred *old_cred;

    if (unlikely(!info)) return -ENODEV;
    if (unlikely(info->flags & NM_FLAG_VIRTUAL_DIR)) {
        file->private_data = NULL;
        return 0;
    }
    if (unlikely(!info->r_path.dentry)) return -ENODEV;

    old_cred = override_creds(nm_root_cred);
    real_file = dentry_open(&info->r_path, file->f_flags, nm_root_cred);
    revert_creds(old_cred);
    if (IS_ERR(real_file)) return PTR_ERR(real_file);

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
    if (!real_file) return -EINVAL;

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

    vma->vm_file = real_file;
    ret = real_file->f_op->mmap(real_file, vma);
    vma->vm_file = file;

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
    *(struct file **)&desc->file = file;

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

static int nm_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct file *real_file = file->private_data;
    if (!real_file || !real_file->f_op->fsync) return -EINVAL;
    return real_file->f_op->fsync(real_file, start, end, datasync);
}

static ssize_t nm_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
    struct nm_inode_info *info = d_backing_inode(dentry)->i_private;
    if (unlikely(!info || (info->flags & NM_FLAG_VIRTUAL_DIR) || !d_backing_inode(info->r_path.dentry)->i_op->listxattr))
        return -EOPNOTSUPP;

    return d_backing_inode(info->r_path.dentry)->i_op->listxattr(info->r_path.dentry, buffer, size);
}

/* Reported (getattr-level) stat of a path — i.e. what a userspace detector
 * sees, not the raw backing inode->i_sb->s_dev. On an overlay mount this yields
 * the underlying layer's dev; on plain erofs it equals the sb dev. We mirror
 * this dev onto injected inodes so they don't stand out as an st_dev outlier
 * against their stock siblings (OnePlus /product is overlay-backed). */
static int nm_path_stat(const struct path *p, struct kstat *st)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    return vfs_getattr_nosec(p, st);
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

static int nm_dir_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct nm_inode_info *info = file_inode(file)->i_private;
    struct nomount_dir_node *dir_node = info ? info->dir_node : NULL;
    struct file *real_file = file->private_data;
    int res = 0;

    if (unlikely(nm_is_virtual_pos(ctx->pos))) {
        nomount_emit_virtual_children(ctx, dir_node);
        return 0;
    }

    if (real_file && real_file->f_op->iterate_shared) {
        struct nomount_proxy_ctx proxy_ctx = {
            .ctx.actor = nomount_actor_proxy, .ctx.pos = ctx->pos,
            .orig_ctx = ctx, .dir_node = dir_node, .emitted = 0
        };
        res = nm_call_iterate(real_file, &proxy_ctx.ctx, real_file->f_op);
        ctx->pos = proxy_ctx.ctx.pos;
        if (res < 0 || proxy_ctx.emitted > 0) return res;
        ctx->pos = nm_pack_pos(0);
    } else if (info && (info->flags & NM_FLAG_VIRTUAL_DIR)) {
        if (ctx->pos < 2 && !dir_emit_dots(file, ctx)) return 0;
        ctx->pos = nm_pack_pos(0);
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
        if (nomount_get_rule_info(info->dir_node, name, len, v_hash, &rule_info)) {
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
                    if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
                    nomount_dir_node_put(rule_info.this_dir);
                    return NULL;
                }
                if ((rule_info.flags & NM_FLAG_VIRTUAL_DIR) || rule_info.r_path.dentry) {
                    struct inode *new_inode = nomount_create_new_inode(dir->i_sb, &rule_info);
                    if (new_inode) {
                        struct dentry *res;
                        nm_install_dentry_ops(dentry);
                        if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
                        nomount_dir_node_put(rule_info.this_dir);
                        /* ops on the spliced-alias result too (same as hijacked_lookup) */
                        res = d_splice_alias(new_inode, dentry);
                        if (!IS_ERR(res) && res) nm_install_dentry_ops(res);
                        return res;
                    }
                }
            }
            if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
            nomount_dir_node_put(rule_info.this_dir);
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

        if (unlikely(!info || !info->r_path.dentry)) return -ENODATA;
        full = nm_full_xattr_name(proxy, name, &alloc);
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
    nm_iop = __get_nm(smp_load_acquire(&parent_dir->i_op), struct nm_iop, fake_iop);
    if (nm_iop) {
        pdir = nm_iop->dir_node;
    } else if (parent_dir->i_op == &nm_dir_iops) {
        struct nm_inode_info *pinfo = parent_dir->i_private;
        if (pinfo) pdir = pinfo->dir_node;
    }
    /* Parent is no longer hijacked (its rule/dir_node was removed by del or clear,
     * and the dir was restored). A cached INJECTED child dentry is now stale --
     * invalidate it so the path re-resolves to the real fs. This kills the
     * "ghost dentry" that otherwise survived del/clear (even drop_caches) until a
     * reboot or a re-hijack of the parent. */
    if (!pdir)
        return injected ? 0 : 1;

    hash = full_name_hash(NULL, dentry->d_name.name, dentry->d_name.len);
    if (nomount_get_rule_info(pdir, dentry->d_name.name, dentry->d_name.len, hash, &rule_info)) {
        if (rule_info.r_path.dentry) path_put(&rule_info.r_path);
        nomount_dir_node_put(rule_info.this_dir);
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
    .fsync = nm_fsync,
};

static const struct inode_operations nm_file_iops = {
    .getattr = nm_file_getattr,
    .setattr = nm_setattr,
    .listxattr = nm_listxattr,
    .get_link = nm_get_link,
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

static inline void nomount_hijack_superblock(struct super_block *sb)
{
    struct nm_sop *nm_sop;
    int i, count = 0;
    if (unlikely(!sb || !sb->s_op || __get_nm(smp_load_acquire(&sb->s_op), struct nm_sop, fake_sop))) return;

    nm_sop = kzalloc(sizeof(*nm_sop), GFP_KERNEL);
    if (unlikely(!nm_sop)) return;

    nm_sop->fake_sop = *(sb->s_op);
    nm_sop->orig_sop = sb->s_op;
    nm_sop->signature = NOMOUNT_MAGIC_SIG;
    nm_sop->sb = sb;
    nm_sop->fake_sop.destroy_inode = nomount_hijacked_destroy_inode;
    nm_sop->fake_sop.drop_inode = nomount_hijacked_drop_inode;
    nm_sop->fake_sop.evict_inode = nomount_hijacked_evict_inode;

    if (sb->s_xattr && !nm_sop->orig_xattr) {
        const struct xattr_handler **new_array;
        while (sb->s_xattr[count]) count++;
        new_array = kzalloc((count + 1) * sizeof(void *), GFP_KERNEL);
        if (new_array) {
            for (i = 0; i < count; i++) {
                struct nm_xattr_proxy *proxy = kzalloc(sizeof(*proxy), GFP_KERNEL);
                if (!proxy) continue;
                proxy->orig = sb->s_xattr[i];
                proxy->fake.name = proxy->orig->name;
                proxy->fake.prefix = proxy->orig->prefix;
                proxy->fake.flags = proxy->orig->flags;
                proxy->fake.list = proxy->orig->list;
                if (proxy->orig->get) proxy->fake.get = nm_xattr_get;
                if (proxy->orig->set) proxy->fake.set = nm_xattr_set;
                new_array[i] = &proxy->fake;
            }
            nm_sop->orig_xattr = (const struct xattr_handler **)sb->s_xattr;
            nm_sop->fake_xattr = new_array;
            smp_store_release((const struct xattr_handler ***)&sb->s_xattr, new_array);
            nm_debug("xattr handlers successfully hijacked for dev: 0x%x\n", sb->s_dev);
        }
    }

    list_add_tail_rcu(&nm_sop->list, &nomount_sb_list);
    smp_store_release(&sb->s_op, &nm_sop->fake_sop);
    nm_debug("Superblock successfully hijacked for dev: 0x%x\n", sb->s_dev);
}

static inline void nomount_hijack_virtual_parent(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_fop *nm_fop;
    if (unlikely(!inode->i_fop || __get_nm(smp_load_acquire(&inode->i_fop), struct nm_fop, fake_fop))) return;

    nm_fop = kmem_cache_zalloc(nm_fop_cachep, GFP_KERNEL);
    if (likely(nm_fop)) {
        nm_fop->fake_fop = *(inode->i_fop);
        nm_fop->orig_fop = inode->i_fop;
        nm_fop->signature = NOMOUNT_MAGIC_SIG;
        nm_fop->dir_node = dir_node;

        if (nm_fop->fake_fop.iterate_shared)
            nm_fop->fake_fop.iterate_shared = nomount_hijacked_iterate_dir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (nm_fop->fake_fop.iterate)
            nm_fop->fake_fop.iterate = nomount_hijacked_iterate_dir;
#endif

        smp_store_release(&inode->i_fop, &nm_fop->fake_fop);
        nm_debug("i_fop successfully hijacked for virtual parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static inline void nomount_hijack_dir_inode(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_iop *nm_iop;
    if (unlikely(!inode->i_op || __get_nm(smp_load_acquire(&inode->i_op), struct nm_iop, fake_iop))) return;

    nm_iop = kmem_cache_zalloc(nm_iop_cachep, GFP_KERNEL);
    if (likely(nm_iop)) {
        nm_iop->fake_iop = *(inode->i_op);
        nm_iop->orig_iop = inode->i_op;
        nm_iop->signature = NOMOUNT_MAGIC_SIG;
        nm_iop->dir_node = dir_node;
        nm_iop->had_private_flag = (inode->i_flags & S_PRIVATE) != 0;

        if (nm_iop->orig_iop->lookup) nm_iop->fake_iop.lookup = nomount_hijacked_lookup;
        smp_store_release(&inode->i_op, &nm_iop->fake_iop);
        inode->i_flags |= S_PRIVATE;
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

/* Drop a dir_node ref; RCU-defer the free once the last ref (topology + any
 * synthesized inode caching it in i_private->dir_node) is gone. NULL-safe. */
static void nomount_dir_node_put(struct nomount_dir_node *dir_node)
{
    if (dir_node && refcount_dec_and_test(&dir_node->refs))
        call_rcu(&dir_node->rcu, nm_dir_node_rcu_free);
}

static void nomount_restore_dir_node(struct nomount_dir_node *dir_node)
{
    struct inode *t_inode = dir_node->_tag_ptr & 1UL ? NULL : dir_node->dir_inode;
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;
 
    if (unlikely(!t_inode)) return;

    spin_lock(&t_inode->i_lock);
    nm_iop = __get_nm(smp_load_acquire(&t_inode->i_op), struct nm_iop, fake_iop);
    if (nm_iop && nm_iop->dir_node == dir_node) {
        smp_store_release(&t_inode->i_op, nm_iop->orig_iop);
        if (!nm_iop->had_private_flag) t_inode->i_flags &= ~S_PRIVATE;
        nm_debug("Successfully cured i_op for dir %lu\n", t_inode->i_ino);
        call_rcu(&nm_iop->rcu, nm_iop_rcu_free);
    }

    nm_fop = __get_nm(smp_load_acquire(&t_inode->i_fop), struct nm_fop, fake_fop);
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
    dir_node->dir_inode = inode ? igrab(inode) : NULL;
    idr_init(&dir_node->children_idr);
    dir_node->bloom_mask = 0;
    refcount_set(&dir_node->refs, 1);   /* topology's own ref */
    return dir_node;
}

static void __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule, const char *name, size_t name_len)
{
    struct nomount_child_node *child;
    int id;

    if (unlikely(!dir_node)) return;
    rule->parent_dir = dir_node;
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->name_len == name_len && memcmp(child->name, name, name_len) == 0) {
            child->flags = rule->flags;
            child->rule = rule;
            return;
        }
    }

    child = kmalloc(sizeof(*child) + name_len + 1, GFP_KERNEL);
    if (unlikely(!child)) return;

    child->fake_ino = rule->v_hash;
    child->name_hash = full_name_hash(NULL, name, name_len);
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

    dir_node->bloom_mask |= (1ULL << (child->name_hash & 63));
}

static void __nomount_delete_child_locked(struct nomount_dir_node *dir_node, unsigned long fake_ino)
{
    struct nomount_child_node *child;
    int id;

    if (unlikely(!dir_node)) return;
    idr_for_each_entry(&dir_node->children_idr, child, id) {
        if (child->fake_ino == fake_ino) {
            idr_remove(&dir_node->children_idr, id);
            kfree_rcu(child, rcu);
            break;
        }
    }
    
    if (idr_is_empty(&dir_node->children_idr)) {
        struct inode *dir_inode = dir_node->_tag_ptr & 1UL ? NULL : dir_node->dir_inode;
        if (dir_inode) {
            nomount_restore_dir_node(dir_node);
            nomount_dir_node_put(dir_node);   /* drop topology ref */
        }
    } else {
        dir_node->bloom_mask = 0;
        idr_for_each_entry(&dir_node->children_idr, child, id) {
            dir_node->bloom_mask |= (1ULL << (child->name_hash & 63));
        }
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

    while (p_len > 1) {
        for (i = p_len - 1; i >= 0; i--) {
            if (v_path[i] == '/') break;
        }

        parent_len = (i == 0) ? 1 : i;
        child_name = v_path + i + 1;
        child_len = p_len - i - 1;
        h_parent = full_name_hash(NULL, v_path, parent_len);
        orig_v_path = v_path[i];
        if (i > 0) v_path[i] = '\0';

        found_virtual = false;
        hash_for_each_possible(nomount_rules_ht, ex, vpath_node, h_parent) {
            if (ex->v_len == parent_len && memcmp(nm_get_vpath(ex), v_path, parent_len) == 0) {
                dir_node = ex->this_dir;
                if (!dir_node) {
                    dir_node = __nomount_alloc_dir_node(NULL);
                    dir_node->owner_rule = ex;
                    dir_node->_tag_ptr = (unsigned long)ex | 1UL;
                    ex->this_dir = dir_node;
                }
                __nomount_inject_child_locked(dir_node, current_rule, child_name, child_len);
                found_virtual = true;
                break;
            }
        }

        if (found_virtual) {
            if (i > 0) v_path[i] = orig_v_path; 
            break;
        }

        lookup_path = (parent_len == 1) ? "/" : v_path;
        if (kern_path(lookup_path, LOOKUP_FOLLOW, &p_path) == 0) {
            v_inode = d_backing_inode(p_path.dentry);
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

        memcpy(nm_get_vpath(irule), v_path, parent_len);
        nm_get_vpath(irule)[parent_len] = '\0';
        nm_get_rpath(irule)[0] = '\0';

        dir_node = __nomount_alloc_dir_node(NULL);
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
        owner = dir_node->_tag_ptr & 1UL ? (struct nomount_rule *)(dir_node->_tag_ptr & ~1UL) : NULL;
        if (!owner) break;

        hash_del_rcu(&owner->vpath_node);
        if (owner->parent_dir) __nomount_delete_child_locked(owner->parent_dir, owner->v_hash);
        nm_debug("Pruned empty virtual directory: %s\n", nm_get_vpath(owner));
        dir_node = owner->parent_dir;
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

    if (!v_path || (!r_path && !is_whiteout)) return ERR_PTR(-EINVAL);
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
            rule->v_ino   = (unsigned long)((sib.ino & ~0xFFFFFULL) |
                                            ((u64)rule->v_hash & 0xFFFFF));
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

                        if (nm_path_stat(&v_path_struct, &kst) == 0)
                            rule->v_dev = kst.dev;
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
    /* Drop the topology's ref on this_dir; it (and its remaining children) is
     * RCU-freed once the last caching inode is gone (P0/P1: lockless readers walk
     * children_idr under RCU; P1: children freed in the callback, not eagerly;
     * P2: refcount defers past a fd-pinned inode). rule itself is kfree_rcu so a
     * cached reader mid-RCU can still deref child->rule. */
    nomount_dir_node_put(rule->this_dir);
    kfree_rcu(rule, rcu);
}

static void nm_detach_rule_locked(struct nomount_rule *rule, struct hlist_head *victims, bool prune)
{
    hash_del_rcu(&rule->vpath_node);
    if (rule->parent_dir) {
        struct nomount_dir_node *p_dir = rule->parent_dir;
        __nomount_delete_child_locked(p_dir, rule->v_hash);
        if (prune) nomount_prune_empty_virtual_dirs(p_dir, victims); 
    }
    hlist_add_head(&rule->vpath_node, victims);
}

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid)
{
    struct nomount_rule *rule, *existing, *victim = NULL;
    int err = 0;

    rule = nm_alloc_rule(v_path, r_path, v_len, r_len, flags, target_uid);
    if (IS_ERR(rule)) return PTR_ERR(rule);

    mutex_lock(&nomount_write_mutex);
    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, rule->v_hash) {
        if (existing->v_hash == rule->v_hash && existing->v_len == v_len &&
             memcmp(nm_get_vpath(existing), nm_get_vpath(rule), v_len) == 0) {
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

static void __nomount_del_rule(const char *v_path, size_t v_len, unsigned int target_uid, struct hlist_head *r_victims)
{
    struct nomount_rule *rule;
    u32 hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == v_len && rule->target_uid == target_uid &&
                memcmp(nm_get_vpath(rule), v_path, v_len) == 0) {
            nm_detach_rule_locked(rule, r_victims, true);
            break;
        }
    }
}

static void __nomount_clear_all(bool is_exit)
{
    struct nomount_rule *rule;
    struct hlist_node *tmp;
    int bkt;
    HLIST_HEAD(r_victims);

    static_branch_disable(&nomount_active_uids);
    idr_destroy(&nomount_uid_idr);
    hash_for_each_safe(nomount_rules_ht, bkt, tmp, rule, vpath_node) {
        nm_detach_rule_locked(rule, &r_victims, false);
    }
    synchronize_rcu();
    hlist_for_each_entry_safe(rule, tmp, &r_victims, vpath_node) {
        nm_free_rule(rule);
    }

    if (is_exit) nomount_restore_superblocks();
}

/*** Netlink control API (private raw netlink) ***/

static struct sock *nm_nl_sk;

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
            __nomount_del_rule(data + pos, vp_len, target_uid, &r_victims);
            pos += vp_len;
        }
        mutex_unlock(&nomount_write_mutex);
    } else if (attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) {
        char *v_path = nla_data(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        int v_len = nla_len(attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) - 1;
        u32 target_uid = attrs[NOMOUNT_ATTR_UID] ? nla_get_u32(attrs[NOMOUNT_ATTR_UID]) : 0;

        mutex_lock(&nomount_write_mutex);
        __nomount_del_rule(v_path, v_len, target_uid, &r_victims);
        mutex_unlock(&nomount_write_mutex);
    } else {
        return -EINVAL;
    }

    if (hlist_empty(&r_victims)) return -ENOENT;
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
    void *hdr;

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

    uid = nla_get_u32(attrs[NOMOUNT_ATTR_UID]);

    if (nomount_is_uid_blocked(uid)) 
        return -EEXIST;

    mutex_lock(&nomount_write_mutex);
    idr_preload(GFP_KERNEL);
    ret = idr_alloc(&nomount_uid_idr, (void *)1, uid, uid + 1, GFP_NOWAIT);
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

    uid = nla_get_u32(attrs[NOMOUNT_ATTR_UID]);

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
    void *ptr;

    if (!static_branch_unlikely(&nomount_active_uids)) return 0;
    rcu_read_lock();
    while ((ptr = idr_get_next(&nomount_uid_idr, &id)) != NULL) {
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
    default:                 return -EINVAL;
    }
}

static void nm_nl_rcv(struct sk_buff *skb)
{
    netlink_rcv_skb(skb, &nm_nl_rcv_msg);
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
    nm_dir_cachep = kmem_cache_create("vext_dnode", sizeof(struct nomount_dir_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_inode_cachep = kmem_cache_create("vext_inode", sizeof(struct nm_inode_info), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_iop_cachep = kmem_cache_create("vext_iop", sizeof(struct nm_iop), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_fop_cachep = kmem_cache_create("vext_fop", sizeof(struct nm_fop), 0, SLAB_HWCACHE_ALIGN, NULL);

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

MODULE_LICENSE("GPL");
MODULE_VERSION(NM_MODULE_VERSION);
MODULE_AUTHOR("XxxY");
MODULE_DESCRIPTION("VFS path helper");

fs_initcall(nomount_init);
module_exit(nomount_exit);
