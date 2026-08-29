// SPDX-License-Identifier: GPL-2.0
/*
 * The symbols a stock GKI kernel trims away.
 *
 * WHY THESE SIX AND NO OTHERS
 *
 * Every function the engine calls is EXPORT_SYMBOL'd in the kernel source --
 * the compile gate across all ten versions established that, and it is why
 * nm_oot.h's redirect list is empty. But a released GKI kernel is built with
 * CONFIG_TRIM_UNUSED_KSYMS and an allow-list: only the symbols named in
 * android/abi_gki_aarch64* keep their exports, and everything else is dropped
 * even though the source exports it.
 *
 * Checked against the union of all 36 abi_gki_aarch64* lists for android15-6.6
 * (9366 symbols): 89 of the engine's 98 are in the KMI. Of the nine that are
 * not, three are not kernel symbols at all -- __this_module, and the engine's
 * own weak ghost_ctl/ghost_get_rule. These six are the real remainder.
 *
 * WHY TRAMPOLINES RATHER THAN TYPED WRAPPERS
 *
 * nm_oot.h's NM_SYM() takes a return type and a parameter list, which means
 * writing each signature out and keeping it right across ten kernels. Three of
 * these six changed shape inside that range: vfs_getxattr and vfs_setxattr each
 * gained an idmap argument twice (a user_namespace at 5.12, an mnt_idmap at
 * 6.3), and netlink_rcv_skb's callback gained a netlink_ext_ack.
 *
 * A naked trampoline needs no signature at all. It is an ordinary definition of
 * the symbol, so the engine's calls bind to it at link time with whatever
 * prototype the headers declare, and the arguments pass through untouched in
 * their registers. x16 is the intra-procedure-call scratch register, so
 * clobbering it is architecturally safe.
 *
 * On a kernel that does NOT trim, these definitions simply win over the
 * kernel's exported ones and the indirection costs one load and one branch.
 * Nothing has to know which kind of kernel it is running on.
 */
#include <linux/kernel.h>
#include "nm_oot.h"

void *nm_oot_sym[NM_OOT_SYM_COUNT];

/* Keep the asm indices and the enum from drifting apart. The asm cannot see the
 * enum, so the index is spelled as a literal; these are what make that safe. */
_Static_assert(NM_OOT_vfs_getxattr == 0, "nm_oot_sym index drift");
_Static_assert(NM_OOT_vfs_setxattr == 1, "nm_oot_sym index drift");
_Static_assert(NM_OOT_free_inode_nonrcu == 2, "nm_oot_sym index drift");
_Static_assert(NM_OOT_netlink_rcv_skb == 3, "nm_oot_sym index drift");
_Static_assert(NM_OOT_security_inode_getsecctx == 4, "nm_oot_sym index drift");
_Static_assert(NM_OOT_security_inode_notifysecctx == 5, "nm_oot_sym index drift");

#define NM_OOT_TRAMP(name, idx)					\
	asm(".globl " #name "\n"				\
	    ".type " #name ", %function\n"			\
	    #name ":\n"						\
	    "  adrp x16, nm_oot_sym\n"				\
	    "  add  x16, x16, :lo12:nm_oot_sym\n"		\
	    "  ldr  x16, [x16, #(8*" #idx ")]\n"		\
	    "  br   x16\n")

NM_OOT_TRAMP(vfs_getxattr, 0);
NM_OOT_TRAMP(vfs_setxattr, 1);
NM_OOT_TRAMP(free_inode_nonrcu, 2);
NM_OOT_TRAMP(netlink_rcv_skb, 3);
NM_OOT_TRAMP(security_inode_getsecctx, 4);
NM_OOT_TRAMP(security_inode_notifysecctx, 5);
