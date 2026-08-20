#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/file.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jump_label.h>

#define NM_MODULE_VERSION "12.2"
/* Bumped for the directory-size correction: userspace has no other way to tell
 * whether the running engine keeps a managed erofs directory's i_size in step
 * with the listing. The Suite refuses whiteouts on non-overlayfs precisely
 * because an older engine did not, so it must be able to gate that refusal on
 * >= 13 rather than assume. Nothing compares this for equality -- the nm client
 * only parses it for liveness -- so raising it is safe. */
#define NOMOUNT_VERSION    13
#define NOMOUNT_HASH_BITS  12
#define NM_FLAG_IS_DIR      (1 << 0)
#define NM_FLAG_VIRTUAL_DIR (1 << 1)
#define NM_FLAG_WHITEOUT    (1 << 2)
/* Times were captured from a stock source. Needed because mtime 0 is a REAL
 * value -- every file on an apex image and on any reproducible-build erofs
 * reports it -- so "tv_sec != 0" cannot mean "we have a mirrored value". */
#define NM_FLAG_HAVE_TIMES  (1 << 3)
/* This virtual dir hangs under an overlayfs mount, where a real dir's readdir
 * ino and its st_ino diverge (the dirent carries the lower fs's number, stat
 * the one overlayfs allocated). Emitting a single number for both is a
 * zero-permission tell: on OP15, 143/143 real dirs under /product diverge and
 * only a synthesized one matched. Set => serve v_dino to readdir, v_ino to
 * stat; clear => they are the same number, which is what a normal fs does. */
#define NM_FLAG_OVL_INO     (1 << 4)
/* The vpath resolved at rule-creation time, i.e. this rule SHADOWS a stock entry
 * rather than adding a new name. Decides whether the parent directory's entry
 * count changes: a replacement leaves it alone, an addition grows it and a
 * whiteout shrinks it. Set from the kern_path(vpath) that already runs in
 * nm_alloc_rule, so it costs nothing extra. */
#define NM_FLAG_SHADOWS_STOCK (1 << 5)
/* Bits a client may set; anything else is kernel-derived and must be stripped. */
#define NM_FLAGS_USER_MASK  (NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT)
#define NM_CTX_MAX          96   /* inline SELinux context; Android's are ~30B */

/* logs
 *
 * nm_debug is compiled OUT by default. The hijacked lookup path logs once per
 * injected file, so a normal module set produced ~300 lines a boot, and the
 * per-rule messages additionally spelled out every target -> backing mapping in
 * the kernel ring buffer. Build with -DNOMOUNT_DEBUG to get them back.
 * no_printk() keeps the format string and arguments type-checked (so the calls
 * cannot rot) while generating no code. */
#ifdef NOMOUNT_DEBUG
#define nm_debug(fmt, ...) printk(KERN_DEBUG "NoMount: [DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  printk(KERN_INFO "NoMount: " fmt, ##__VA_ARGS__)
#else
/* Production: compile out the message strings entirely (no_printk still
 * type-checks the format but the literal is dead-code-eliminated), so they do
 * not sit in nomount.o naming functions/logic to anyone disassembling the image. */
#define nm_debug(fmt, ...) no_printk("NoMount: [DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  no_printk("NoMount: " fmt, ##__VA_ARGS__)
#endif
#define nm_warn(fmt, ...) printk(KERN_WARNING "NoMount: [WARN] " fmt, ##__VA_ARGS__)
#define nm_err(fmt, ...)  printk(KERN_ERR "NoMount: [ERROR] " fmt, ##__VA_ARGS__)

static DEFINE_HASHTABLE(nomount_rules_ht, NOMOUNT_HASH_BITS);
static LIST_HEAD(nomount_sb_list);
static DEFINE_IDR(nomount_uid_idr);
static DEFINE_MUTEX(nomount_write_mutex);

/* * Helpers to dynamically calculate the memory address of the strings */
#define nm_get_vpath(rule) ((rule)->paths)
#define nm_get_rpath(rule) ((rule)->paths + (rule)->v_len + 1)


struct nm_iop {
    struct inode_operations fake_iop; /* MUST be exactly at offset 0 */
    const struct inode_operations *orig_iop;
    struct nomount_dir_node *dir_node;
    struct rcu_head rcu;
};

struct nm_fop {
    struct file_operations fake_fop;  /* MUST be exactly at offset 0 */
    const struct file_operations *orig_fop;
    struct nomount_dir_node *dir_node;
    struct rcu_head rcu;
};

struct nm_sop {
    struct super_operations fake_sop; /* MUST be exactly at offset 0 */
    const struct super_operations *orig_sop;
    const struct xattr_handler **orig_xattr;
    const struct xattr_handler **fake_xattr;
    struct super_block *sb;
    struct rcu_head rcu;
    struct list_head list;
};

struct nm_inode_info {
    struct path r_path;
    struct nomount_dir_node *dir_node;
    char v_ctx[NM_CTX_MAX];          /* mirrored context for synthesized dirs */
    u16 v_ctx_len;
    unsigned long v_ino;
    u64 v_dino, v_pdino;
    dev_t v_dev, v_mapdev;
    struct timespec64 v_atime, v_mtime, v_ctime;
    u64 v_attributes, v_attr_mask;   /* mirrored statx STATX_ATTR_* of the stock/sibling file */
    u32 v_blksize;                   /* mirrored st_blksize */
    u32 v_result_mask;               /* statx result_mask a STOCK file reports */
    kuid_t v_uid;                    /* virtual-dir owner (mirrored from nearest real ancestor) */
    kgid_t v_gid;
    umode_t v_mode;                  /* virtual-dir mode bits (0 => default 0755) */
    u8 flags;
};

#define nm_get_real_inode(v_inode) \
    (((v_inode)->i_private && ((struct nm_inode_info *)(v_inode)->i_private)->r_path.dentry) ? \
        d_backing_inode(((struct nm_inode_info *)(v_inode)->i_private)->r_path.dentry) : NULL)

/* Per-dir name-lookup hash table: bloom rejects misses, this resolves hits in
 * O(bucket) instead of O(children) so large-fanout dirs (whiteout-heavy
 * /product/overlay etc.) don't linear-scan on every path lookup. The idr stays
 * for stable readdir cookies; this table is only for by-name resolution. */
#define NM_CHILD_HT_BITS 5

struct nomount_child_node {
    struct rcu_head rcu;
    struct hlist_node hnode;   /* link in the owning dir_node's children_ht */
    u32 name_hash;
    u64 fake_ino;
    int id;
    u8 d_type;
    u8 flags;
    u16 name_len;
    struct nomount_rule *rule;

    /* * FLEXIBLE ARRAY MEMBER:
     * Memory Layout: [ struct ] "children_name\0"
     */
    char name[]; 
};

struct nomount_dir_node {
    struct idr children_idr;
    DECLARE_HASHTABLE(children_ht, NM_CHILD_HT_BITS);
    loff_t real_eof;     /* published base; 0 = no full pass observed yet */
    /* Bytes to add to the backing directory's i_size so it matches the listing
     * we actually serve. On erofs a directory's size is exactly
     * 12*(entries incl . and ..) + total name bytes, so adding a name without
     * changing the size leaves a directory that lists N entries while reporting
     * a size that encodes N-1 -- one stat() plus one readdir() apart. Only
     * additions and whiteouts move it; replacements do not. See nm_dir_size_fix. */
    s32 size_delta;
    loff_t max_real_pos; /* running max real dirent offset (not authoritative) */
    u64 bloom_mask;
    atomic_t refcount;   /* owner ref (alloc) + one per synthetic inode caching this node */
    struct rcu_head rcu;
    union {
        struct inode *dir_inode;
        struct nomount_rule *owner_rule;
        unsigned long _tag_ptr;
    };
};

struct nomount_rule {
    struct hlist_node vpath_node;
    struct nomount_dir_node *parent_dir;
    struct nomount_dir_node *this_dir;
    struct path r_path;
    unsigned long v_ino;
    /* Dirent ino, i.e. what readdir reports -- for this dir's own "." and for
     * its entry in the parent's listing. On overlayfs these differ from st_ino
     * (see NM_FLAG_OVL_INO); everywhere else they are equal. */
    u64 v_dino, v_pdino;
    dev_t v_dev;
    /* dev a stock file at this path reports in /proc/<pid>/maps. Differs from
     * v_dev on overlayfs, where the mapping is of the LOWER file. */
    dev_t v_mapdev;
    struct timespec64 v_atime, v_mtime, v_ctime;
    u64 v_attributes, v_attr_mask;   /* mirrored statx STATX_ATTR_* of the stock/sibling file */
    u32 v_blksize;                   /* mirrored st_blksize */
    u32 v_result_mask;               /* statx result_mask a STOCK file reports */
    kuid_t v_uid;                    /* virtual-dir owner (mirrored from nearest real ancestor) */
    kgid_t v_gid;
    umode_t v_mode;                  /* virtual-dir mode bits (0 => default 0755) */
    char v_ctx[NM_CTX_MAX];          /* nearest real ancestor's context, for virtual dirs */
    u16 v_ctx_len;
    u32 v_hash;
    u16 v_len;
    u8  flags;
    unsigned int target_uid;

    /* * FLEXIBLE ARRAY MEMBER: 
     * Memory Layout: [ struct ] "virtual_path\0real_path\0"
     */
    char paths[]; 
};

/*** Operaction Vectors ***/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static const struct file_operations nm_file_fops_mmap_prepare;
#endif
static const struct file_operations nm_file_fops;
static const struct inode_operations nm_file_iops;
static const struct file_operations nm_dir_fops;
static const struct inode_operations nm_dir_iops;
static const struct dentry_operations nm_dops;

/*** Rule Operations ***/
static int nomount_generate_virtual_topology(struct nomount_rule *target_rule);
static struct nomount_rule *nm_alloc_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid);
static void nm_free_rule(struct nomount_rule *rule);
static void nm_detach_rule_locked(struct nomount_rule *rule, struct hlist_head *victims, bool prune);
/* A lockless snapshot of the fields a reader needs from a rule, taken under RCU
 * by nomount_get_rule_info(). The r_path (if any) is path_get()'d into the
 * snapshot, so the caller can use it safely even if the rule is freed
 * concurrently, and MUST path_put() it when done. This replaces returning a bare
 * rule pointer that lockless readers then dereferenced after rcu_read_unlock()
 * -- a use-after-free if a concurrent nm del/clear/COW freed the rule. */
struct nm_rule_info {
    u32 flags;
    unsigned long v_ino;
    u64 v_dino, v_pdino;
    dev_t v_dev, v_mapdev;
    struct timespec64 v_atime, v_mtime, v_ctime;
    u64 v_attributes, v_attr_mask;
    u32 v_blksize;
    u32 v_result_mask;
    kuid_t v_uid;
    kgid_t v_gid;
    umode_t v_mode;
    char v_ctx[NM_CTX_MAX];          /* copied inline: the rule can be freed after the snapshot */
    u16 v_ctx_len;
    struct path r_path;
    struct nomount_dir_node *this_dir;
};

static struct inode *nomount_create_new_inode(struct super_block *virtual_sb, struct nm_rule_info *rule_info);
/* Maps (/proc/<pid>/maps) dev/ino spoof for mapped injected inodes; called from
 * fs/proc/task_mmu.c show_map_vma() via a guarded extern there. */
void nomount_spoof_mmap_metadata(const struct inode *inode, dev_t *dev,
				 unsigned long *ino);

/* =====================================================================
 * NoMount VFS Offset Protocol
 * =====================================================================
 * Virtual dirents CONTINUE the backing directory's own cookie space, starting
 * one past the EOF position that directory reports. The previous scheme tagged
 * every offset with a constant 16-bit signature, which getdents64() then handed
 * to userspace verbatim as d_off -- a single-comparison fingerprint on any
 * injected directory. There is no tag now: an injected entry's d_off is simply
 * the next number after the real ones.
 *
 * real_eof == 0 means no virtual entry has ever been emitted for this dir, so no
 * position can be ours yet. It is recorded at the real->virtual transition, i.e.
 * always before any virtual offset is handed out.
 */
/* Headroom for the virtual entries appended above the base. */
#define NM_POS_HEADROOM 65536

static inline bool nm_is_virtual_pos(const struct nomount_dir_node *d, loff_t pos)
{
    loff_t eof, mx;

    if (!d) return false;
    eof = READ_ONCE(d->real_eof);
    mx  = READ_ONCE(d->max_real_pos);
    /* Also require pos to be above the running max, not just the published base.
     * If the directory GREW since the last completed pass, mx climbs live while
     * real_eof is still the older (lower) base, and a resume position in that
     * gap is a real offset -- treating it as ours would drop the tail of the
     * directory. Residual: a position above BOTH is still ambiguous until the
     * grown dir has been walked to EOF once. Read-only ROM partitions (the
     * injection targets) never grow, so this only bites writable mounts. */
    /* Bound the window. Without an upper edge, ANY position above the base
     * counts as ours -- including a wild fs cookie (ext4 dir_index hands back
     * S64_MAX at EOF), which then unpacks to a nonsense child id and silently
     * ends the listing. */
    return eof && pos > eof && pos > mx && pos <= eof + NM_POS_HEADROOM;
}

static inline loff_t nm_pack_pos(const struct nomount_dir_node *d, int id)
{
    return READ_ONCE(d->real_eof) + 1 + id;
}

static inline int nm_unpack_pos(const struct nomount_dir_node *d, loff_t pos)
{
    loff_t id = pos - READ_ONCE(d->real_eof) - 1;

    if (id < 0 || id > NM_POS_HEADROOM) return -1;
    return (int)id;
}

/* Track the highest REAL dirent offset seen. Deliberately NOT the fs's ctx->pos
 * at EOF: ext4 with dir_index reports EXT4_HTREE_EOF_64BIT (S64_MAX) there, so
 * basing on it overflows loff_t and makes pos > eof never true. */
static inline void nm_note_real_pos(struct nomount_dir_node *d, loff_t pos)
{
    if (!d || pos <= 0 || pos > (loff_t)(S64_MAX - NM_POS_HEADROOM)) return;
    if (pos > READ_ONCE(d->max_real_pos)) WRITE_ONCE(d->max_real_pos, pos);
}

/* Publish the base ONLY once the backing dir has actually reached EOF. Until
 * then the running max is not the maximum, and a mid-pass resume position (which
 * legitimately sits above every offset seen so far) would be mistaken for one of
 * ours -- short-circuiting straight to the virtual entries and dropping the rest
 * of the real directory. Re-published on every completed pass so a dir that grew
 * keeps the invariant that every real offset is <= real_eof. */
static inline void nm_publish_real_eof(struct nomount_dir_node *d, loff_t eof_hint)
{
    loff_t base;

    if (!d) return;
    base = READ_ONCE(d->max_real_pos);
    /* Take the HIGHER of the last real dirent offset and the position the
     * backing dir left at EOF. They coincide on overlayfs (sequential cookies,
     * EOF == last + 1) but not on a byte-offset fs like erofs, where EOF sits
     * PAST the last entry -- basing the window on the dirent offset alone put
     * that EOF position inside the virtual range, so every listing after the
     * first resumed at a child id that does not exist and emitted nothing. The
     * injected file stayed resolvable by name, so it was visible to stat and
     * open but absent from readdir: 90 of 260 rules on OP15. */
    if (eof_hint > 0 && eof_hint <= (loff_t)(S64_MAX - NM_POS_HEADROOM) && eof_hint > base)
        base = eof_hint;
    if (!base) base = 2;                        /* dots-only / purely synthesized */
    WRITE_ONCE(d->real_eof, base);
}

/* ========================================================================= */
/* NETLINK CONTROL PROTOCOL DEFINITIONS (private raw netlink, not generic) */
/* ========================================================================= */

/*
 * Control plane is a PRIVATE raw-netlink protocol, not a named Generic Netlink
 * family. A genl family ("nomount") was enumerable/name-resolvable by any
 * caller via CTRL_CMD_GETFAMILY (an on-device detection oracle). A raw netlink
 * protocol number is neither listed by the genl controller nor resolvable by
 * name, so NoMount's control channel no longer advertises itself.
 *
 * NOMOUNT_NL_PROTO is overridable at build time (e.g. randomize per build);
 * the userspace `nm` client MUST be built with the same value.
 */
#ifndef NOMOUNT_NL_PROTO
#define NOMOUNT_NL_PROTO 29
#endif
#define NOMOUNT_NL_VERSION 1

/* The command travels in nlmsg_type, offset past the reserved control range
 * (0..NLMSG_MIN_TYPE-1). Kernel and client agree on this mapping. */
#define NM_CMD_TO_TYPE(c) (NLMSG_MIN_TYPE + (c))
#define NM_TYPE_TO_CMD(t) ((int)(t) - NLMSG_MIN_TYPE)

/* Commands */
enum {
    NM_CMD_UNSPEC = 0,
    NM_CMD_GET_VERSION,
    NM_CMD_ADD_RULE,
    NM_CMD_DEL_RULE,
    NM_CMD_CLEAR_ALL,
    NM_CMD_ADD_UID,
    NM_CMD_DEL_UID,
    NM_CMD_GET_LIST,
    NM_CMD_GET_UIDS,
    NM_CMD_SET_KNOB,
    __NM_CMD_MAX,
};

/* Boot-identity knobs, formerly sysfs attributes under /sys/kernel/<name>/.
 * That kobject directory was world-traversable (0755), so both its name and its
 * attribute names were readable by any process that could search /sys/kernel --
 * a stock-baseline diff finds it regardless of what it is called. They ride the
 * netlink control plane instead, which is CAP_NET_ADMIN-gated and not
 * enumerable. Payload layout: [u32 knob][value bytes], empty value = clear. */
enum {
    NM_KNOB_UNAME_RELEASE = 0,
    NM_KNOB_UNAME_VERSION,
    NM_KNOB_CMDLINE,
    NM_KNOB_BOOTCONFIG,
    /* "1" => this device's ROM directories are dirent-packed (erofs-shaped), so
     * a synthesized directory must report 12*(entries incl . and ..) + name
     * bytes rather than the 4096 placeholder.
     *
     * Why a knob rather than reading the superblock: a virtual dir inherits its
     * PARENT's sb, and on an overlay-mounted ROM path that is overlayfs, whose
     * magic says nothing about the layer whose shape the stock siblings show.
     * d_real() cannot answer either -- it resolves regular files, and a merged
     * directory has no single real dentry, which is why two attempts to infer
     * this in-kernel both produced no-ops. Userspace CAN answer it: enumerate a
     * real sibling and check whether its size equals the formula. Measure where
     * it is cheap, decide where it is needed. Unset => previous behaviour. */
    NM_KNOB_VDIR_EROFS_SIZE,
    /* Which isolated-process pools per-UID hiding covers, as a decimal bitmask:
     * 1 = app-zygote pool (90000..98999), 2 = platform isolated pool
     * (99000..99999), 3 = both (default). Hiding from them stops a blocked app
     * probing through an isolated helper; leaving them visible stops an UNBLOCKED
     * app spotting the injection by diffing its own view against its own isolated
     * child's. Only meaningful while at least one appid is blocked. */
    NM_KNOB_HIDE_ISOLATED,
    __NM_KNOB_MAX,
};

/* Attributes */
enum {
    NOMOUNT_ATTR_UNSPEC = 0,
    NOMOUNT_ATTR_VIRTUAL_PATH,  /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_REAL_PATH,     /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_FLAGS,         /* u32 (NLA_U32) */
    NOMOUNT_ATTR_UID,           /* u32 (NLA_U32) */
    NOMOUNT_ATTR_VERSION,       /* u32 (NLA_U32) */
    NOMOUNT_ATTR_PAYLOAD,       /* Binary payload for GET_LIST (NLA_BINARY) */
    __NOMOUNT_ATTR_MAX,
};

static const struct nla_policy nomount_genl_policy[__NOMOUNT_ATTR_MAX];

/* * Compat macros * */
/* nlmsg attribute parse: attrs sit directly after nlmsghdr (hdrlen 0). The
 * signature gained an extack arg at 4.12 and split strict/deprecated at 5.2. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    #define NM_NLMSG_PARSE(nlh, tb) \
        nlmsg_parse_deprecated((nlh), 0, (tb), __NOMOUNT_ATTR_MAX - 1, nomount_genl_policy, NULL)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
    #define NM_NLMSG_PARSE(nlh, tb) \
        nlmsg_parse((nlh), 0, (tb), __NOMOUNT_ATTR_MAX - 1, nomount_genl_policy, NULL)
#else
    #define NM_NLMSG_PARSE(nlh, tb) \
        nlmsg_parse((nlh), 0, (tb), __NOMOUNT_ATTR_MAX - 1, nomount_genl_policy)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    #define IDMAP_PATH(path) mnt_idmap((path).mnt),
    #define IDMAP_ARG struct mnt_idmap *idmap,
    #define IDMAP_CALL idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #define IDMAP_PATH(path) mnt_user_ns((path).mnt),
    #define IDMAP_ARG struct user_namespace *mnt_userns,
    #define IDMAP_CALL mnt_userns,
#else
    #define IDMAP_PATH(path)/* Nothing */
    #define IDMAP_ARG /* Nothing */
    #define IDMAP_CALL /* Nothing */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    #define NM_ACTOR_RET bool
    #define NM_ACTOR_CONTINUE true
#else
    #define NM_ACTOR_RET int
    #define NM_ACTOR_CONTINUE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    #define FLAGS_ARG , int flags
    #define FLAGS_VAL , flags
#else
    #define FLAGS_ARG /* Nothing */
    #define FLAGS_VAL /* Nothing */
#endif

static inline void nm_sync_inode_times(struct inode *v_inode, struct inode *r_inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    v_inode->i_atime_sec = r_inode->i_atime_sec;
    v_inode->i_atime_nsec = r_inode->i_atime_nsec;
    v_inode->i_mtime_sec = r_inode->i_mtime_sec;
    v_inode->i_mtime_nsec = r_inode->i_mtime_nsec;
    v_inode->i_ctime_sec = r_inode->i_ctime_sec;
    v_inode->i_ctime_nsec = r_inode->i_ctime_nsec;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    v_inode->i_atime = r_inode->i_atime;
    v_inode->i_mtime = r_inode->i_mtime;
    inode_set_ctime_to_ts(v_inode, inode_get_ctime(r_inode));
#else
    v_inode->i_atime = r_inode->i_atime;
    v_inode->i_mtime = r_inode->i_mtime;
    v_inode->i_ctime = r_inode->i_ctime;
#endif
}

static inline int nm_call_iterate(struct file *file, struct dir_context *ctx, const struct file_operations *fop)
{
    if (fop->iterate_shared)
        return fop->iterate_shared(file, ctx);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    else if (fop->iterate)
        return fop->iterate(file, ctx);
#endif
    return -ENOTDIR;
}

/* Install our dentry ops on a dentry we manage. Setting d_op alone is NOT enough:
 * a dentry allocated on a hijacked sb (e.g. overlayfs, whose s_d_op is
 * ovl_dentry_operations) already has the sb's DCACHE_OP_* flags set, so the VFS
 * would keep calling ops (d_weak_revalidate/d_real/d_release/...) that nm_dops
 * does not provide -> NULL deref (seen as an OOPS in path_lookupat when resolving
 * '..' of a synthesized virtual dir). Clear the inherited op flags and set only
 * the ones nm_dops actually implements (d_revalidate). */
static inline void nm_install_dentry_ops(struct dentry *dentry)
{
    dentry->d_flags &= ~(DCACHE_OP_HASH | DCACHE_OP_COMPARE |
                         DCACHE_OP_REVALIDATE | DCACHE_OP_WEAK_REVALIDATE |
                         DCACHE_OP_DELETE | DCACHE_OP_PRUNE | DCACHE_OP_REAL);
    dentry->d_op = &nm_dops;
    dentry->d_flags |= DCACHE_OP_REVALIDATE;
}

#endif /* _LINUX_NOMOUNT_H */
