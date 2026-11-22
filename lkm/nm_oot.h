#ifndef _NM_OOT_H
#define _NM_OOT_H

#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

/* Loud: logs when the symbol is absent. One caller -- nm_hide.c, for module_mutex. */
unsigned long nm_oot_lookup(const char *name);

/* Same lookup, without the error log: for a symbol a guard can do without.
 * Two callers -- pagemap_pte_hole and __arm64_sys_statmount, both NULL-guarded. */
unsigned long nm_oot_lookup_opt(const char *name);

/* Two declarations used to live here that nothing used.
 *
 *   nm_oot_resolve_all()  -- named as if it resolved a set of symbols at init. It only
 *                            bootstrapped the kallsyms lookup and returned 0; no caller,
 *                            ever, in this tree or the kernel one.
 *   NM_SYM(name,...)      -- declared `extern ret (*nm_p_<name>)` plus an inline wrapper,
 *                            for a table of pre-resolved function pointers. No file ever
 *                            invoked it and nm_oot.c defines no nm_p_* pointer, so the
 *                            first use would have been a link error naming a symbol that
 *                            was never going to exist -- with nothing here to say the
 *                            mechanism was only ever a sketch.
 *
 * Deleted rather than kept "in case": the two lookups above ARE the boundary, and
 * declarations implying a resolver that does not exist made this header read like more
 * than it is. If a pre-resolved table is ever wanted, write it then, against a caller.
 */

#endif
