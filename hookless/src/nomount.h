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

#define NM_MODULE_VERSION "12"
#define NOMOUNT_VERSION    12
#define NOMOUNT_HASH_BITS  12
#define NM_FLAG_IS_DIR      (1 << 0)
#define NM_FLAG_VIRTUAL_DIR (1 << 1)
#define NM_FLAG_WHITEOUT    (1 << 2)

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

/* Magic signature "NOMOUNT" in hex to safely identify our structures */
#define NOMOUNT_MAGIC_SIG 0x4E4F4D4F554E54ULL

struct nm_iop {
    struct inode_operations fake_iop; /* MUST be exactly at offset 0 */
    const struct inode_operations *orig_iop;
    u64 signature;
    struct nomount_dir_node *dir_node;
    bool had_private_flag;
    struct rcu_head rcu;
};

struct nm_fop {
    struct file_operations fake_fop;  /* MUST be exactly at offset 0 */
    const struct file_operations *orig_fop;
    u64 signature;
    struct nomount_dir_node *dir_node;
    struct rcu_head rcu;
};

struct nm_sop {
    struct super_operations fake_sop; /* MUST be exactly at offset 0 */
    const struct super_operations *orig_sop;
    const struct xattr_handler **orig_xattr;
    const struct xattr_handler **fake_xattr;
    u64 signature;
    struct super_block *sb;
    struct rcu_head rcu;
    struct list_head list;
};

struct nm_inode_info {
    struct path r_path;
    struct nomount_dir_node *dir_node;
    unsigned long v_ino;
    u8 flags;
};

#define nm_get_real_inode(v_inode) \
    (((v_inode)->i_private && ((struct nm_inode_info *)(v_inode)->i_private)->r_path.dentry) ? \
        d_backing_inode(((struct nm_inode_info *)(v_inode)->i_private)->r_path.dentry) : NULL)

struct nomount_child_node {
    struct rcu_head rcu;
    u32 name_hash;
    u32 fake_ino;
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
    u64 bloom_mask;
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
    struct path r_path;
    struct nomount_dir_node *this_dir;
};

static struct inode *nomount_create_new_inode(struct super_block *virtual_sb, struct nm_rule_info *rule_info);

/* =====================================================================
 * NoMount VFS Offset Protocol
 * =====================================================================
 * 64-bit layout: [ 16-bit 'nm' ][ 16-bit 0 ][ 32-bit ID ] 
 * 32-bit layout: [ 16-bit 'nm' ][ 16-bit ID ]
 */
#define NM_SIG_16 0x6E6DULL /* "nm" in hex */
static inline bool nm_is_virtual_pos(loff_t pos) {
#ifdef CONFIG_COMPAT
    if (in_compat_syscall()) return (pos & 0xFFFF0000ULL) == (NM_SIG_16 << 16);
#endif
    return (pos & 0xFFFFFFFF00000000ULL) == (NM_SIG_16 << 48);
}

static inline loff_t nm_pack_pos(int id) {
#ifdef CONFIG_COMPAT
    if (in_compat_syscall()) return (NM_SIG_16 << 16) | (id & 0xFFFF);
#endif
    return (NM_SIG_16 << 48) | (id & 0xFFFFFFFF);
}

static inline int nm_unpack_pos(loff_t pos) {
#ifdef CONFIG_COMPAT
    if (in_compat_syscall()) return (int)(pos & 0xFFFF);
#endif
    return (int)(pos & 0xFFFFFFFF);
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
    __NM_CMD_MAX,
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    #define nm_probe_read(dst, src, size) probe_kernel_read(dst, src, size)
#else
    #define nm_probe_read(dst, src, size) copy_from_kernel_nofault(dst, src, size)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
    #define nm_init_private_list(inode) /* Nothing */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    #define nm_init_private_list(inode) INIT_LIST_HEAD(&(inode)->i_data.i_private_list);
#else
    #define nm_init_private_list(inode) INIT_LIST_HEAD(&(inode)->i_data.private_list);
#endif

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
