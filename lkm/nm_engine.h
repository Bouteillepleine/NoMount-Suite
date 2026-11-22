/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NM_ENGINE_H
#define _NM_ENGINE_H

/* The engine's surface to this module, in ONE place.
 *
 * These three functions live in hookless/src/nomount.c and are called from here. They
 * used to be declared by hand, separately, in each .c that wanted one -- nm_uid_blocked()
 * in nm_mount_filter.c, nm_inode_hidden_from_caller() in nm_xattr_guard.c,
 * vfs_map_meta_override() in nm_maps_spoof.c -- which is the one arrangement that cannot
 * fail loudly. Each declaration is self-consistent, so every translation unit still
 * compiles; C has no name mangling, so the module still links; and the first sign of a
 * signature that no longer matches the engine's is an argument read from the wrong
 * register at runtime. That is the same failure shape as the fs_initcall clobber: green
 * on every board, wrong on the device.
 *
 * nomount.h is NOT the place for this and this header is not a workaround. That file
 * declares a `static` function at :262 (nomount_create_new_inode), so it is a private
 * header for nomount.c rather than an interface: a TU that includes it and cannot define
 * that static is already in trouble, before counting net/genetlink.h and jump_label.h.
 *
 * Pinned against the definitions by src/mount.rs, which is what makes this more than a
 * tidier version of the same hope -- the engine and this header are in different build
 * systems and nothing else compares them.
 *
 * ghost.c deliberately does NOT use this header. It is vendored byte-identical into the
 * kernel tree (hookless/README.md:118), and its nm_uid_blocked is reached through the
 * #ifdef MODULE weak/pointer shim that exists because arm64 emits R_AARCH64_ADR_GOT_PAGE
 * for a weak undefined symbol and the module loader does not apply it. Leave it alone.
 */

#include <linux/types.h>

struct inode;

bool nm_uid_blocked(uid_t uid);
bool nm_inode_hidden_from_caller(const struct inode *inode);
void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
			   unsigned long *ino);

#endif /* _NM_ENGINE_H */
