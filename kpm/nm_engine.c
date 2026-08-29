// SPDX-License-Identifier: GPL-2.0
/*
 * The NoMount engine, compiled for a KernelPatch module.
 *
 * Built against the REAL kernel headers (K_FLAGS in the Makefile), not the
 * KernelPatch SDK: the engine dereferences struct inode, dentry and super_block,
 * so their layouts must be the target KMI's actual ones. nm_kpm_entry.c is the
 * mirror image -- SDK headers, no kernel headers. Two include worlds, joined by
 * `ld -r`.
 *
 * The engine is INCLUDED, not copied: ../hookless/src/nomount.c is the one copy
 * in this repository, shared with the in-tree build and the LKM variant, so this
 * port cannot silently drift from what the Suite ships.
 *
 * INCLUDE ORDER IS LOad-BEARING. The shim defines function-like macros named
 * after kernel functions, and such a macro expands anywhere the name is followed
 * by '(' -- including inside the header that DECLARES it. Defining the shim
 * before <linux/string.h> would rewrite string.h's own declaration of memcpy and
 * break the compile. So: engine headers first, then the shim, then the engine.
 * nomount.c's own #includes are then no-ops behind their include guards.
 */

/* LSE atomics expand to inline asm relying on in-tree alternative patching this
 * object never goes through. The old port did the same. */
#undef CONFIG_ARM64_LSE_ATOMICS

/* Exactly the headers nomount.c includes, pulled in ahead of the shim. */
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/hash.h>
#include <linux/sort.h>
#include "../hookless/src/nomount.h"

/*
 * A .kpm has no struct module. The MODULE macros in the engine reference
 * __this_module, so give them one to point at rather than patching the engine.
 */
struct module __this_module;

/*
 * generic_read_dir is used as a VALUE in a static initializer:
 *
 *     .read = generic_read_dir,
 *
 * A redirect macro cannot serve that -- a static initializer needs a constant,
 * and a table lookup is not one. A real function under the same name can: the
 * initializer gets a genuine address, and the indirection happens when called.
 * Declared before the shim so the shim does not rewrite this definition.
 */
static ssize_t (*nm_real_generic_read_dir)(struct file *, char __user *, size_t, loff_t *);

ssize_t generic_read_dir(struct file *f, char __user *b, size_t n, loff_t *o)
{
	return nm_real_generic_read_dir(f, b, n, o);
}

#include "nm_kpm_shim.h"
#include "../hookless/src/nomount.c"

/*
 * The string and memory routines cannot be redirected by macro: the compiler
 * emits calls to them on its own -- a struct assignment becomes a memcpy that no
 * macro ever sees -- so they need real definitions in this object. Freestanding
 * implementations, deliberately simple; none is on a hot path in this engine.
 *
 * Defined after the engine so the shim's macros (which do not cover these) and
 * the kernel's declarations have both been seen.
 */
#undef memcpy
#undef memset
#undef memcmp
#undef strlen
#undef strcmp
#undef strncmp
#undef strnlen
#undef strrchr

void *memcpy(void *d, const void *s, size_t n)
{
	char *dp = d;
	const char *sp = s;

	while (n--)
		*dp++ = *sp++;
	return d;
}

void *memset(void *d, int c, size_t n)
{
	char *dp = d;

	while (n--)
		*dp++ = (char)c;
	return d;
}

int memcmp(const void *a, const void *b, size_t n)
{
	const unsigned char *x = a, *y = b;

	while (n--) {
		if (*x != *y)
			return *x - *y;
		x++; y++;
	}
	return 0;
}

size_t strlen(const char *s)
{
	const char *p = s;

	while (*p)
		p++;
	return p - s;
}

size_t strnlen(const char *s, size_t n)
{
	size_t i = 0;

	while (i < n && s[i])
		i++;
	return i;
}

int strcmp(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++; b++;
	}
	return *(const unsigned char *)a - *(const unsigned char *)b;
}

int strncmp(const char *a, const char *b, size_t n)
{
	while (n && *a && *a == *b) {
		a++; b++; n--;
	}
	if (!n)
		return 0;
	return *(const unsigned char *)a - *(const unsigned char *)b;
}

char *strrchr(const char *s, int c)
{
	const char *last = NULL;

	do {
		if (*s == (char)c)
			last = s;
	} while (*s++);
	return (char *)last;
}

/*
 * nomount_init/nomount_exit are static in the engine and reached there by
 * fs_initcall()/module_exit(), neither of which a .kpm goes through --
 * KernelPatch calls KPM_INIT directly. These two wrappers are the only glue,
 * giving the entry half (which cannot see kernel headers) a plain symbol.
 */
/*
 * The weak optional externs, as pointers. nomount.c's own declarations of
 * ghost_ctl/ghost_get_rule expand through the shim into declarations of these,
 * so the engine's `if (!ghost_ctl)` probe reads whatever they hold. They stay
 * NULL when no ghost module is loaded, which is exactly what that probe means.
 */
int (*nm_w_ghost_ctl)(const char *buf, size_t count);
int (*nm_w_ghost_get_rule)(int idx, char *out, size_t outsz);

long nm_engine_init(void)
{
	/* Bind everything that is reached by address rather than by call, now
	 * that nm_kpm_entry.c has populated the table. */
	nm_real_generic_read_dir = (typeof(nm_real_generic_read_dir))
				   nm_kpm_sym[NMS_generic_read_dir];
	nm_w_ghost_ctl = (typeof(nm_w_ghost_ctl))nm_kpm_sym[NMS_ghost_ctl];
	nm_w_ghost_get_rule = (typeof(nm_w_ghost_get_rule))nm_kpm_sym[NMS_ghost_get_rule];

	return nomount_init();
}

void nm_engine_exit(void)
{
	nomount_exit();
}
