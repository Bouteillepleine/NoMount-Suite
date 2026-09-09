// SPDX-License-Identifier: GPL-2.0

#undef CONFIG_ARM64_LSE_ATOMICS

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

struct module __this_module;

#include "nm_kpm_shim.h"
#include "../hookless/src/nomount.c"

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

int (*nm_w_ghost_ctl)(const char *buf, size_t count);
int (*nm_w_ghost_get_rule)(int idx, char *out, size_t outsz);

long nm_engine_init(void)
{
	nm_w_ghost_ctl = (typeof(nm_w_ghost_ctl))nm_kpm_sym[NMS_ghost_ctl];
	nm_w_ghost_get_rule = (typeof(nm_w_ghost_get_rule))nm_kpm_sym[NMS_ghost_get_rule];

	return nomount_init();
}

void nm_engine_exit(void)
{
	nomount_exit();
}
