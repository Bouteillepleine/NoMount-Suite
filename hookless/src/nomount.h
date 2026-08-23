#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

/* Optional symbol-name cloak. OFF unless built with -DNOMOUNT_STEALTH_SYMS.
 *
 * DECISION (2026-08-21): this stays OFF for the shipped builds. It is kept
 * working, and CI proves it still cloaks cleanly on all ten kernels, so it can
 * be turned on later without archaeology -- but no release should enable it
 * without revisiting the reasoning below. Do not read "off by default" as
 * "not adopted yet".
 *
 * Every identifier in this driver is named nomount_* or nm_*, and /proc/kallsyms
 * lists local text symbols as well as global ones -- so a stock kernel and this
 * one differ by ~100 greppable names. kptr_restrict zeroes the addresses, not the
 * names. The file is mode 0444 with SELinux type proc_kallsyms, which on a stock
 * Android policy keeps app domains out and lets `shell` in; that gate was never
 * verified from an untrusted_app context, so treat app reachability as UNMEASURED
 * rather than as safe.
 *
 * What this buys, and what it does not:
 *   - It removes the PROJECT NAME from the symbol table. Nothing greps for
 *     "nomount" and finds anything.
 *   - It does NOT make the object anonymous. ~100 symbols sharing one invented
 *     prefix is still a distinctive cluster; it just no longer says what it is.
 *     If that distinction does not buy you anything, leave this off.
 *   - It costs real debuggability: a stack trace, a KASAN splat or a
 *     /proc/kallsyms dump from a stealth build names nothing you recognise.
 *     The names are therefore assigned in sorted order and NUMBERED, so mapping
 *     one back is a lookup in this file rather than guesswork:
 *         __vfsx_042  ->  grep -n __vfsx_042 nomount.h
 *
 * The list is derived from every nomount_ or nm_ prefixed identifier in the SOURCE, not
 * from one built object. Which of them survive as symbols varies by kernel
 * version and by what the compiler inlined -- generating it from a single 6.12
 * build left 4.9 leaking its pre-4.17 nm_cmdline_fops/nm_cmdline_open and 6.12
 * itself leaking a dozen more under the matrix flags. A source-derived superset
 * is version-independent by construction; the extra defines for struct tags and
 * inlined helpers cost nothing.
 *
 * Kept INLINE here rather than in its own header on purpose: every consumer of
 * kbuild@hookless copies exactly nomount.c and nomount.h (the compile matrix and
 * all four kernel builders each do `cp nomount.c; cp nomount.h`), so a third file
 * would silently fail to travel and break every one of them at once. It did --
 * that is why this is inline.
 *
 * The one symbol NOT here is the global the maps cloak exports, which
 * fs/proc/task_mmu.c declares by name from the integration patch and therefore
 * cannot be renamed by a header. It was given a neutral name outright
 * (vfs_map_meta_override) so it does not name the project either way.
 *
 * Keeping it honest: the compile matrix builds EVERY version with this defined
 * and fails if any nomount_* or nm_* symbol -- or any "NoMount" string --
 * survives. A half-applied cloak is worse than none: the survivors would be the
 * only thing worth grepping for.
 */

#ifdef NOMOUNT_STEALTH_SYMS

#define __nomount_add_rule                       __vfsx_001
#define __nomount_alloc_dir_node                 __vfsx_002
#define __nomount_clear_all                      __vfsx_003
#define __nomount_del_rule                       __vfsx_004
#define __nomount_delete_child_locked            __vfsx_005
#define __nomount_inject_child_locked            __vfsx_006
#define nm_alloc_rule                            __vfsx_007
#define nm_bootconfig_fops                       __vfsx_008
#define nm_bootconfig_open                       __vfsx_009
#define nm_bootconfig_pde                        __vfsx_010
#define nm_bootconfig_show                       __vfsx_011
#define nm_call_iterate                          __vfsx_012
#define nm_child_dotdot_of                       __vfsx_013
#define nm_child_size_contrib                    __vfsx_014
#define nm_cmdline_fops                          __vfsx_015
#define nm_cmdline_open                          __vfsx_016
#define nm_cmdline_pde                           __vfsx_017
#define nm_cmdline_show                          __vfsx_018
#define nm_compat_ioctl                          __vfsx_019
#define nm_d_revalidate                          __vfsx_020
#define nm_detach_rule_locked                    __vfsx_021
#define nm_dir_cachep                            __vfsx_022
#define nm_dir_deltas                            __vfsx_023
#define nm_dir_fops                              __vfsx_024
#define nm_dir_ino_pop                           __vfsx_025
#define nm_dir_ino_pop_cached                    __vfsx_026
#define nm_dir_iops                              __vfsx_027
#define nm_dir_iterate_dir                       __vfsx_028
#define nm_dir_lookup                            __vfsx_029
#define nm_dir_nlink_delta                       __vfsx_030
#define nm_dir_node_put                          __vfsx_031
#define nm_dir_node_rcu_free                     __vfsx_032
#define nm_dir_size_fix                          __vfsx_033
#define nm_dops                                  __vfsx_034
#define nm_dotdot_actor                          __vfsx_035
#define nm_dotdot_scan                           __vfsx_036
#define nm_dup_trim                              __vfsx_037
#define nm_emit_dots                             __vfsx_038
#define nm_fake_bootconfig                       __vfsx_039
#define nm_fake_cmdline                          __vfsx_040
#define nm_fallocate                             __vfsx_041
#define nm_fiemap                                __vfsx_042
#define nm_file_fops                             __vfsx_043
#define nm_file_fops_mmap_prepare                __vfsx_044
#define nm_file_getattr                          __vfsx_045
#define nm_file_iops                             __vfsx_046
#define nm_find_sibling_meta                     __vfsx_047
#define nm_fop                                   __vfsx_048
#define nm_fop_cachep                            __vfsx_049
#define nm_fop_rcu_free                          __vfsx_050
#define nm_free_rule                             __vfsx_051
#define nm_fsync                                 __vfsx_052
#define nm_full_xattr_name                       __vfsx_053
#define nm_get_link                              __vfsx_054
#define nm_hide_isolated                         __vfsx_055
#define nm_ino_actor                             __vfsx_056
#define nm_ino_pop                               __vfsx_057
#define nm_ino_scan                              __vfsx_058
#define nm_ino_take                              __vfsx_059
#define nm_ino_taken                             __vfsx_060
#define nm_inode_cachep                          __vfsx_061
#define nm_inode_info                            __vfsx_062
#define nm_install_dentry_ops                    __vfsx_063
#define nm_iop                                   __vfsx_064
#define nm_iop_cachep                            __vfsx_065
#define nm_iop_rcu_free                          __vfsx_066
#define nm_is_virtual_pos                        __vfsx_067
#define nm_iter_dotdot                           __vfsx_068
#define nm_listxattr                             __vfsx_069
#define nm_llseek                                __vfsx_070
#define nm_mk_bootconfig_pde                     __vfsx_071
#define nm_mk_cmdline_pde                        __vfsx_072
#define nm_mmap                                  __vfsx_073
#define nm_mmap_prepare                          __vfsx_074
#define nm_nl_rcv                                __vfsx_075
#define nm_nl_rcv_msg                            __vfsx_076
#define nm_nl_sk                                 __vfsx_077
#define nm_note_real_pos                         __vfsx_078
#define nm_open                                  __vfsx_079
#define nm_orig_bootconfig                       __vfsx_080
#define nm_pack_pos                              __vfsx_081
#define nm_path_is_injected                      __vfsx_082
#define nm_path_stat                             __vfsx_083
#define nm_place_ino                             __vfsx_084
#define nm_pop_insert                            __vfsx_085
#define nm_procspoof_exit                        __vfsx_086
#define nm_procspoof_mutex                       __vfsx_087
#define nm_publish_real_eof                      __vfsx_088
#define nm_put_rule_info                         __vfsx_089
#define nm_range_cache                           __vfsx_090
#define nm_range_cache_next                      __vfsx_091
#define nm_range_slot                            __vfsx_092
#define nm_read_iter                             __vfsx_093
#define nm_read_secctx                           __vfsx_094
#define nm_real_ancestor_pop                     __vfsx_095
#define nm_release                               __vfsx_096
#define nm_restamp_child_ino                     __vfsx_097
#define nm_reval_stale                           __vfsx_098
#define nm_root_cred                             __vfsx_099
#define nm_rule_gen                              __vfsx_100
#define nm_rule_info                             __vfsx_101
#define nm_rule_visible                          __vfsx_102
#define nm_scan_dir_for_file                     __vfsx_103
#define nm_scan_path                             __vfsx_104
#define nm_selinux_name                          __vfsx_105
#define nm_set_bootconfig                        __vfsx_106
#define nm_set_cmdline                           __vfsx_107
#define nm_setattr                               __vfsx_108
#define nm_sib_actor                             __vfsx_109
#define nm_sib_cache_ctx                         __vfsx_110
#define nm_sib_cache_ctxlen                      __vfsx_111
#define nm_sib_cache_dir                         __vfsx_112
#define nm_sib_cache_kst                         __vfsx_113
#define nm_sib_cache_mapdev                      __vfsx_114
#define nm_sib_cache_valid                       __vfsx_115
#define nm_sib_scan                              __vfsx_116
#define nm_snapshot_bootconfig                   __vfsx_117
#define nm_sop                                   __vfsx_118
#define nm_splice_read                           __vfsx_119
#define nm_splice_write                          __vfsx_120
#define nm_sync_inode_times                      __vfsx_121
#define nm_unlocked_ioctl                        __vfsx_122
#define nm_unpack_pos                            __vfsx_123
#define nm_uts_store                             __vfsx_124
#define nm_vdir_erofs_size                       __vfsx_125
#define nm_vdir_nlink                            __vfsx_126
#define nm_vdir_size                             __vfsx_127
#define nm_write_iter                            __vfsx_128
#define nm_xattr_get                             __vfsx_129
#define nm_xattr_proxy                           __vfsx_130
#define nm_xattr_set                             __vfsx_131
#define nomount_active_uids                      __vfsx_132
#define nomount_actor_proxy                      __vfsx_133
#define nomount_child_node                       __vfsx_134
#define nomount_create_new_inode                 __vfsx_135
#define nomount_dir_node                         __vfsx_136
#define nomount_emit_virtual_children            __vfsx_137
#define nomount_exit                             __vfsx_138
#define nomount_generate_virtual_topology        __vfsx_139
#define nomount_genl_policy                      __vfsx_140
#define nomount_get_dir_node                     __vfsx_141
#define nomount_get_rule_info                    __vfsx_142
#define nomount_hijack_dir_inode                 __vfsx_143
#define nomount_hijack_superblock                __vfsx_144
#define nomount_hijack_virtual_parent            __vfsx_145
#define nomount_hijacked_destroy_inode           __vfsx_146
#define nomount_hijacked_drop_inode              __vfsx_147
#define nomount_hijacked_evict_inode             __vfsx_148
#define nomount_hijacked_getattr                 __vfsx_149
#define nomount_hijacked_iterate_dir             __vfsx_150
#define nomount_hijacked_lookup                  __vfsx_151
#define nomount_hijacked_put_super               __vfsx_152
#define nomount_init                             __vfsx_153
#define nomount_is_uid_blocked                   __vfsx_154
#define nomount_nl_add_rule                      __vfsx_155
#define nomount_nl_add_uid                       __vfsx_156
#define nomount_nl_clear_rules                   __vfsx_157
#define nomount_nl_del_rule                      __vfsx_158
#define nomount_nl_del_uid                       __vfsx_159
#define nomount_nl_dump_rules                    __vfsx_160
#define nomount_nl_dump_uids                     __vfsx_161
#define nomount_nl_get_version                   __vfsx_162
#define nomount_nl_set_knob                      __vfsx_163
#define nomount_proxy_ctx                        __vfsx_164
#define nomount_prune_empty_virtual_dirs         __vfsx_165
#define nomount_restore_dir_node                 __vfsx_166
#define nomount_restore_superblocks              __vfsx_167
#define nomount_rule                             __vfsx_168
#define nomount_rules_ht                         __vfsx_169
#define nomount_sb_list                          __vfsx_170
#define nomount_uid_idr                          __vfsx_171
#define nomount_write_mutex                      __vfsx_172
#define nm_inode_permission                      __vfsx_173
#define nm_uid_hidden                            __vfsx_174
#define nm_child_visible                         __vfsx_175
#define nm_mark_public_up                        __vfsx_176

#endif /* NOMOUNT_STEALTH_SYMS */



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

#define NM_MODULE_VERSION "15.0"
/* Bumped for the directory-size correction: userspace has no other way to tell
 * whether the running engine keeps a managed erofs directory's i_size in step
 * with the listing. The Suite refuses whiteouts on non-overlayfs precisely
 * because an older engine did not, so it must be able to gate that refusal on
 * >= 13 rather than assume. Nothing compares this for equality -- the nm client
 * only parses it for liveness -- so raising it is safe.
 *
 * 14: three behaviour changes userspace can otherwise not detect.
 *  - A replaced rule now refreshes the parent's child node completely (d_type
 *    and fake_ino). On 13 and earlier a reload that shadowed a rule left a
 *    directory whose link count contradicted its contents -- measured as nlink 2
 *    on a dir that had gained a subdirectory.
 *  - The parent's size correction is now derived per-caller from the live child
 *    flags (nm_dir_deltas) instead of a cached counter, so a --uid-scoped rule no
 *    longer shifts the reported directory SIZE for callers it does not target
 *    while moving the link count only for the one it does.
 *  - NM_CMD_ADD_RULE's batch form returns the first rejection instead of an
 *    unconditional 0, so a refused rule is no longer indistinguishable from an
 *    applied one. The Suite's per-entry failure counters become meaningful only
 *    against >= 14.
 *
 * 15: NM_FLAG_PUBLIC exists (see below). An engine below this strips the bit
 *    with every other unknown one, so a Suite that sets it gets the old
 *    behaviour silently -- an added ROM APK stays hidden from a blocked reader
 *    and the PackageManager keeps advertising a path that app cannot open.
 *    Userspace can only warn about that if it can tell the two apart. */
#define NOMOUNT_VERSION    15
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
/* This rule stays visible to a reader on the block list.
 *
 * Per-UID hiding is otherwise all-or-nothing: a blocked reader gets the stock
 * filesystem, and for an ADDED name that means -ENOENT. That is right for a
 * module file nothing else advertises, and wrong for one the system has already
 * told the reader about. The PackageManager scans /product/overlay (and every
 * other ROM APK directory) as system_server, which is not blocked, so it parses
 * and REGISTERS an injected APK -- then hands its path to every app that asks
 * about the package. A blocked app therefore holds a path the PM says exists and
 * open() answers ENOENT for, which is a far louder inconsistency than the
 * injection it was hiding: measured on OP15, IBM Trusteer (La Banque Postale)
 * walks the package list at startup, calls getResourcesForApplication() on each
 * entry, and SIGSEGVs on the IOException from 139 unopenable overlay APKs.
 *
 * So a rule the PM already advertises opts out of hiding. Set by userspace for
 * an added ROM APK; STRIPPED by the kernel whenever the rule turns out to shadow
 * a stock file, because there the blocked reader is served the stock bytes and
 * revealing the module's copy instead would be a real leak. */
#define NM_FLAG_PUBLIC      (1 << 6)
/* Bits a client may set; anything else is kernel-derived and must be stripped.
 * NB: nomount_child_node.flags is a u8, so a client-settable bit must be < 8. */
#define NM_FLAGS_USER_MASK  (NM_FLAG_IS_DIR | NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT |                              NM_FLAG_PUBLIC)
#define NM_CTX_MAX          96   /* inline SELinux context; Android's are ~30B */

/* logs
 *
 * nm_debug is compiled OUT by default. The hijacked lookup path logs once per
 * injected file, so a normal module set produced ~300 lines a boot, and the
 * per-rule messages additionally spelled out every target -> backing mapping in
 * the kernel ring buffer. Build with -DNOMOUNT_DEBUG to get them back.
 * no_printk() keeps the format string and arguments type-checked (so the calls
 * cannot rot) while generating no code. */
/* The log tag is part of the symbol cloak, not decoration. nm_warn/nm_err are
 * real printks, so their format literals sit in .rodata and survive into the
 * image: a stealth build with 0 nomount_* symbols still answered
 * `strings vmlinux | grep NoMount` with 7 hits, which makes the cloak worse than
 * useless -- the survivors become the only thing worth grepping for. Tag and
 * symbols move together.
 * Known cost when cloaked: `nomount export` dumps `dmesg | grep -i nomount`
 * (health.rs), which then only catches the module's own lowercase "nomount:"
 * lines from the shell, not the kernel's. Diagnostics only, nothing decides on it. */
#ifdef NOMOUNT_STEALTH_SYMS
#define NM_LOG_TAG "vfs: "
#else
#define NM_LOG_TAG "NoMount: "
#endif

#ifdef NOMOUNT_DEBUG
#define nm_debug(fmt, ...) printk(KERN_DEBUG NM_LOG_TAG "[DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  printk(KERN_INFO NM_LOG_TAG fmt, ##__VA_ARGS__)
#else
/* Production: compile out the message strings entirely (no_printk still
 * type-checks the format but the literal is dead-code-eliminated), so they do
 * not sit in nomount.o naming functions/logic to anyone disassembling the image. */
#define nm_debug(fmt, ...) no_printk(NM_LOG_TAG "[DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  no_printk(NM_LOG_TAG fmt, ##__VA_ARGS__)
#endif
#define nm_warn(fmt, ...) printk(KERN_WARNING NM_LOG_TAG "[WARN] " fmt, ##__VA_ARGS__)
#define nm_err(fmt, ...)  printk(KERN_ERR NM_LOG_TAG "[ERROR] " fmt, ##__VA_ARGS__)

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
    /* The STOCK file this injection shadows, pinned at rule creation. A hidden
     * reader is entitled to see it, and serving it from here means we never have
     * to invalidate the shared dentry to arrange that. Empty for an ADDED name
     * (nothing underneath) and for a whiteout. */
    struct path s_path;
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
    /* NB: there is deliberately no size_delta counter here any more. See
     * nm_dir_deltas(): the parent's size correction is derived from the live
     * child flags on the same walk that computes the link-count correction, so
     * it stays in step with a replaced rule AND is filtered by the caller's uid.
     * A single cached number could do neither. */
    loff_t max_real_pos; /* running max real dirent offset (not authoritative) */
    u64 bloom_mask;
    /* Does any child here carry NM_FLAG_PUBLIC? Conservative summary in the same
     * spirit as bloom_mask: set when such a child is injected and never cleared,
     * because a stale true only costs a blocked reader the slow path through a
     * directory where it then sees nothing, while a stale false would hide a
     * child that must stay visible. Read on the hot gate in
     * nomount_hijacked_lookup/iterate so that a device with no public rule keeps
     * the exact bail-out it has today. */
    bool has_public;
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
    /* Teardown list link, kept SEPARATE from vpath_node on purpose.
     * hlist_del_rcu() deliberately leaves ->next intact so an RCU reader already
     * standing on the node can still walk off it; the victims list used to reuse
     * vpath_node, whose hlist_add_head() overwrote exactly that pointer. Since
     * nomount_nl_dump_rules() walks the rule table under rcu_read_lock() ALONE
     * (it does not take nomount_write_mutex), a `nm list` concurrent with a
     * del/clear could follow ->next out of its hash bucket and into the victims
     * list -- emitting deleted or duplicated rules into the reload delta. */
    struct hlist_node victim_node;
    struct nomount_dir_node *parent_dir;
    struct nomount_dir_node *this_dir;
    struct path r_path;
    struct path s_path;              /* stock file this rule shadows; see nm_inode_info */
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
    struct path s_path;              /* stock file behind a shadowing rule (may be empty) */
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
void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
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
