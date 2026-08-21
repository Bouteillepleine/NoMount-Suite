#ifndef _LINUX_NOMOUNT_SYMS_H
#define _LINUX_NOMOUNT_SYMS_H

/* Optional symbol-name cloak. OFF unless built with -DNOMOUNT_STEALTH_SYMS.
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
 *   - It does NOT make the object anonymous. 100 symbols sharing one invented
 *     prefix is still a distinctive cluster; it just no longer says what it is.
 *     If that distinction does not buy you anything, leave this off.
 *   - It costs real debuggability: a stack trace, a KASAN splat or a
 *     /proc/kallsyms dump from a stealth build names nothing you recognise.
 *     The names are therefore assigned in sorted order and NUMBERED, so mapping
 *     one back is a lookup in this file rather than guesswork:
 *         __vfsx_042  ->  grep -n __vfsx_042 nomount_syms.h
 *
 * The one symbol NOT here is the global the maps cloak exports, which
 * fs/proc/task_mmu.c declares by name from the integration patch and therefore
 * cannot be renamed by a header. It was given a neutral name outright
 * (vfs_map_meta_override) so it does not name the project either way.
 *
 * Keeping it honest: the compile matrix builds one version with this defined and
 * fails if ANY nomount_* or nm_* symbol survives, so a function added later cannot
 * silently escape the cloak and leave it half-applied -- which would be worse
 * than not having it, since the survivors would be the only thing to grep for.
 */

#ifdef NOMOUNT_STEALTH_SYMS

#define __nomount_add_rule                     __vfsx_001
#define __nomount_alloc_dir_node               __vfsx_002
#define __nomount_clear_all                    __vfsx_003
#define __nomount_del_rule                     __vfsx_004
#define __nomount_delete_child_locked          __vfsx_005
#define __nomount_inject_child_locked          __vfsx_006
#define nm_alloc_rule                          __vfsx_007
#define nm_bootconfig_pde                      __vfsx_008
#define nm_bootconfig_show                     __vfsx_009
#define nm_cmdline_pde                         __vfsx_010
#define nm_cmdline_show                        __vfsx_011
#define nm_compat_ioctl                        __vfsx_012
#define nm_d_revalidate                        __vfsx_013
#define nm_detach_rule_locked                  __vfsx_014
#define nm_dir_cachep                          __vfsx_015
#define nm_dir_deltas                          __vfsx_016
#define nm_dir_fops                            __vfsx_017
#define nm_dir_ino_pop                         __vfsx_018
#define nm_dir_ino_pop_cached                  __vfsx_019
#define nm_dir_iops                            __vfsx_020
#define nm_dir_iterate_dir                     __vfsx_021
#define nm_dir_lookup                          __vfsx_022
#define nm_dir_node_put                        __vfsx_023
#define nm_dir_node_rcu_free                   __vfsx_024
#define nm_dops                                __vfsx_025
#define nm_dotdot_actor                        __vfsx_026
#define nm_fake_bootconfig                     __vfsx_027
#define nm_fake_cmdline                        __vfsx_028
#define nm_fallocate                           __vfsx_029
#define nm_fiemap                              __vfsx_030
#define nm_file_fops                           __vfsx_031
#define nm_file_getattr                        __vfsx_032
#define nm_file_iops                           __vfsx_033
#define nm_fop_cachep                          __vfsx_034
#define nm_fop_rcu_free                        __vfsx_035
#define nm_fsync                               __vfsx_036
#define nm_full_xattr_name                     __vfsx_037
#define nm_get_link                            __vfsx_038
#define nm_hide_isolated                       __vfsx_039
#define nm_ino_actor                           __vfsx_040
#define nm_inode_cachep                        __vfsx_041
#define nm_iop_cachep                          __vfsx_042
#define nm_iop_rcu_free                        __vfsx_043
#define nm_iter_dotdot                         __vfsx_044
#define nm_listxattr                           __vfsx_045
#define nm_llseek                              __vfsx_046
#define nm_mmap                                __vfsx_047
#define nm_nl_rcv                              __vfsx_048
#define nm_nl_rcv_msg                          __vfsx_049
#define nm_nl_sk                               __vfsx_050
#define nm_open                                __vfsx_051
#define nm_orig_bootconfig                     __vfsx_052
#define nm_path_is_injected                    __vfsx_053
#define nm_place_ino                           __vfsx_054
#define nm_procspoof_mutex                     __vfsx_055
#define nm_range_cache                         __vfsx_056
#define nm_range_cache_next                    __vfsx_057
#define nm_read_iter                           __vfsx_058
#define nm_read_secctx                         __vfsx_059
#define nm_release                             __vfsx_060
#define nm_root_cred                           __vfsx_061
#define nm_rule_gen                            __vfsx_062
#define nm_scan_dir_for_file                   __vfsx_063
#define nm_setattr                             __vfsx_064
#define nm_sib_actor                           __vfsx_065
#define nm_sib_cache_ctx                       __vfsx_066
#define nm_sib_cache_ctxlen                    __vfsx_067
#define nm_sib_cache_dir                       __vfsx_068
#define nm_sib_cache_kst                       __vfsx_069
#define nm_sib_cache_mapdev                    __vfsx_070
#define nm_sib_cache_valid                     __vfsx_071
#define nm_splice_read                         __vfsx_072
#define nm_splice_write                        __vfsx_073
#define nm_unlocked_ioctl                      __vfsx_074
#define nm_uts_store                           __vfsx_075
#define nm_vdir_erofs_size                     __vfsx_076
#define nm_write_iter                          __vfsx_077
#define nm_xattr_get                           __vfsx_078
#define nm_xattr_set                           __vfsx_079
#define nomount_active_uids                    __vfsx_080
#define nomount_actor_proxy                    __vfsx_081
#define nomount_create_new_inode               __vfsx_082
#define nomount_emit_virtual_children          __vfsx_083
#define nomount_exit                           __vfsx_084
#define nomount_generate_virtual_topology      __vfsx_085
#define nomount_genl_policy                    __vfsx_086
#define nomount_hijacked_destroy_inode         __vfsx_087
#define nomount_hijacked_drop_inode            __vfsx_088
#define nomount_hijacked_evict_inode           __vfsx_089
#define nomount_hijacked_getattr               __vfsx_090
#define nomount_hijacked_iterate_dir           __vfsx_091
#define nomount_hijacked_lookup                __vfsx_092
#define nomount_hijacked_put_super             __vfsx_093
#define nomount_init                           __vfsx_094
#define nomount_nl_dump_rules                  __vfsx_095
#define nomount_nl_dump_uids                   __vfsx_096
#define nomount_rules_ht                       __vfsx_097
#define nomount_sb_list                        __vfsx_098
#define nomount_uid_idr                        __vfsx_099
#define nomount_write_mutex                    __vfsx_100

#endif /* NOMOUNT_STEALTH_SYMS */
#endif /* _LINUX_NOMOUNT_SYMS_H */
