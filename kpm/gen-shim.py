#!/usr/bin/env python3
"""Generate the KPM symbol table, trampolines and shim from a measured list.

WHY ANY OF THIS IS NEEDED

A .kpm cannot call kernel functions directly. KernelPatch's loader resolves
undefined symbols only against its own table (kernel/patch/module/module.c,
simplify_symbols), and the kallsyms fallback there is commented out with the
reason:

    // kernel symbol cause overflow in relocation

An AArch64 `bl` reaches +/-128 MB; a kallsyms address is far outside that from
wherever the module was allocated. Every kernel call therefore has to become an
indirect call through a pointer resolved at load time. nm_kpm_sym[] is that
table, and this script writes the plumbing around it.

The input is measured, never invented:

    make -C kpm undefined TARGET_COMPILE=... KP_DIR=... KERNEL_DIR=...

run against each supported kernel, unioned.

TRAMPOLINES, NOT MACROS

The obvious approach is a macro per symbol that calls through the table. It does
not work, and the way it fails is worth recording so nobody tries it again.

A macro only rewrites calls written in nomount.c's own text. Much of what the
engine calls it reaches through STATIC INLINES in the kernel headers -- kmalloc
lands on __kmalloc and kmalloc_caches, spin_lock on _raw_spin_lock, nlmsg_put on
__nlmsg_put. Those inline bodies are parsed with the headers, long before any
shim macro exists, so their references survive untouched. A macro shim covering
all 102 symbols was built and measured: it still left 27 undefined, all of them
reached through header inlines.

So instead each symbol gets a real definition under its own name -- a naked
trampoline that tail-calls through the table:

        adrp x16, nm_kpm_sym
        add  x16, x16, :lo12:nm_kpm_sym
        ldr  x16, [x16, #(8*IDX)]
        br   x16

That satisfies references from anywhere -- engine text, header inlines, function
pointers stored in vtables -- because it is an ordinary symbol definition. It
needs no prototype, so nothing has to track signatures across the supported
range (vfs_getxattr and vfs_setxattr each gained an argument twice inside it).
Arguments stay in their registers untouched; x16 is the designated
intra-procedure-call scratch register, so clobbering it is safe. And `br` has no
range limit, which is the constraint that defeated the direct call.

The relocations this needs -- ADR_PREL_PG_HI21, ADD_ABS_LO12_NC,
LDST64_ABS_LO12_NC -- are all handled by KernelPatch's relocator in
kernel/patch/module/relo.c.

WHAT STILL NEEDS A MACRO

Data, and the weak optional pair. Neither is a call, so no trampoline helps:

  init_net        taken by address in the engine's own text, which a macro reaches
  slab entries    kmalloc/kzalloc/kmalloc_array are inlines that index the
                  kmalloc_caches ARRAY. A trampoline cannot stand in for an array
                  object, so these are redirected to __kmalloc instead, which
                  stops the inline being instantiated at all
  ghost_ctl       the engine tests their ADDRESS as a feature probe, so a
  ghost_get_rule  trampoline would be non-NULL and falsely advertise ghost support
"""

import argparse
import io
import os

# ---------------------------------------------------------------- special cases

# Data objects. A trampoline is a function; these are not, so they keep a macro.
# kmalloc_caches is handled by SLAB_REDIRECT below instead of appearing here:
# it is only ever reached from slab.h's inlines, never from the engine's text,
# so a macro on it would rewrite nothing.
DATA = {'init_net'}

# Reached only through kernel-header inlines that also touch kmalloc_caches.
# Redirecting the entry points to __kmalloc (which does get a trampoline) stops
# those inlines being instantiated, and takes kmalloc_caches, kmalloc_trace and
# kmalloc_large out of the undefined set with them.
SLAB_REDIRECT = {
    'kmalloc': '__kmalloc((__VA_ARGS__))',
    'kzalloc': None,          # spelled out below; needs __GFP_ZERO
    'kmalloc_array': None,
}

# Declared __attribute__((weak)) by the engine, and legitimately absent: it
# tests the address before calling, and that test is a feature probe. They also
# matter because KernelPatch's loader does not special-case weak undefined
# symbols -- leaving them undefined fails the whole load with "unknown symbol".
WEAK = {'ghost_ctl', 'ghost_get_rule'}

# Provided as real code by nm_engine.c rather than redirected: the compiler emits
# calls to these on its own (a struct assignment becomes a memcpy), so nothing
# that works at the source level can intercept them.
LOCAL = {
    'memcpy', 'memset', 'memcmp',
    'strlen', 'strcmp', 'strncmp', 'strnlen', 'strrchr',
    '__this_module',
}

# Supplied by KernelPatch to the entry half, not by the kernel. They appear
# undefined in the linked .kpm and that is correct -- the loader resolves them.
KP_PROVIDED = {'kallsyms_lookup_name', 'printk'}

# Renamed across the supported range; resolution tries name then alt.
ALT = {
    '_printk': 'printk',
    'kvfree_call_rcu': 'kfree_call_rcu',
    'kfree_call_rcu': 'kvfree_call_rcu',
    'kfree_skb_reason': 'kfree_skb',
    'kfree_skb': 'kfree_skb_reason',
    '__kmalloc': '__kmalloc_noprof',
    'kmem_cache_alloc': 'kmem_cache_alloc_noprof',
    'kmem_cache_create': '__kmem_cache_create_args',
}

VERSIONS = ['5.4', '5.10', '5.15', '6.1', '6.6']


def read_per_version(d):
    lists = {}
    for v in VERSIONS:
        p = os.path.join(d, v + '.txt')
        if os.path.exists(p):
            with io.open(p, encoding='utf-8') as fh:
                lists[v] = {ln.strip() for ln in fh if ln.strip()}
    return lists


def optional_set(lists):
    if not lists:
        return set()
    return set.union(*lists.values()) - set.intersection(*lists.values())


def enum_name(sym):
    return 'NMS_' + sym


def gen_syms_h(symbols):
    out = [
        '/* SPDX-License-Identifier: GPL-2.0 */',
        '/*',
        ' * GENERATED by kpm/gen-shim.py -- do not edit by hand.',
        ' *',
        ' * The index space shared by the two halves of the .kpm: nm_kpm_entry.c',
        ' * fills the table in, nm_kpm_tramp.c jumps through it. They are compiled',
        ' * against different headers and this is the one thing they share.',
        ' */',
        '#ifndef _NM_KPM_SYMS_H',
        '#define _NM_KPM_SYMS_H',
        '',
        'enum nm_kpm_sym {',
    ]
    out += ['\t%s,' % enum_name(s) for s in symbols]
    out += [
        '\tNM_KPM_SYM_COUNT',
        '};',
        '',
        'extern void *nm_kpm_sym[NM_KPM_SYM_COUNT];',
        '',
        '#endif /* _NM_KPM_SYMS_H */',
        '',
    ]
    return '\n'.join(out)


def gen_table(symbols, optional):
    rows = []
    for s in symbols:
        alt = ALT.get(s)
        rows.append('\t{ %s, "%s", %s, %d },'
                    % (enum_name(s), s, ('"%s"' % alt) if alt else '0',
                       1 if (s in optional or s in WEAK) else 0))
    return '\n'.join(rows)


def gen_tramp_c(symbols, tramp, lists):
    """One naked trampoline per callable symbol."""
    out = [
        '// SPDX-License-Identifier: GPL-2.0',
        '/*',
        ' * GENERATED by kpm/gen-shim.py -- do not edit by hand.',
        ' *',
        ' * A definition for every kernel function the engine references, each one a',
        ' * tail-call through nm_kpm_sym[]. See gen-shim.py for why these are',
        ' * trampolines and not macros -- in short, a macro cannot reach the calls',
        ' * that kernel-header inlines make on the engine\'s behalf.',
        ' *',
        ' * Compiled against the kernel headers only for the enum; it uses no kernel',
        ' * types and no prototypes, which is the point.',
        ' */',
        '#include "nm_kpm_syms.h"',
        '',
        '/* x16 is the intra-procedure-call scratch register: free to clobber in a',
        ' * trampoline, and argument registers are left exactly as the caller set',
        ' * them. `br` is used rather than `bl` because it has no range limit -- the',
        ' * +/-128 MB reach of a direct call is precisely what rules out calling the',
        ' * kernel from a .kpm at all. */',
        '#define NM_TRAMP(name, idx)\t\t\t\t\t\\',
        '\tasm(".globl " #name "\\n"\t\t\t\t\\',
        '\t    ".type " #name ", %function\\n"\t\t\t\\',
        '\t    #name ":\\n"\t\t\t\t\t\\',
        '\t    "  adrp x16, nm_kpm_sym\\n"\t\t\t\t\\',
        '\t    "  add  x16, x16, :lo12:nm_kpm_sym\\n"\t\t\\',
        '\t    "  ldr  x16, [x16, #(8*" #idx ")]\\n"\t\t\t\\',
        '\t    "  br   x16\\n")',
        '',
        '/* The asm above cannot see the enum, so the index is written as a literal.',
        ' * These assertions are what keep the two in step: change the symbol list',
        ' * and regenerate, or the build stops here rather than dispatching through',
        ' * the wrong table slot at runtime. */',
    ]
    for s in tramp:
        idx = symbols.index(s)
        out.append('_Static_assert(%s == %d, "table index drift: %s");'
                   % (enum_name(s), idx, s))
    out.append('')
    for s in tramp:
        out.append('NM_TRAMP(%s, %d);' % (s, symbols.index(s)))
    out.append('')
    return '\n'.join(out)


def gen_shim_h(symbols, lists):
    out = [
        '/* SPDX-License-Identifier: GPL-2.0 */',
        '/*',
        ' * GENERATED by kpm/gen-shim.py -- do not edit by hand.',
        ' *',
        ' * The small residue that trampolines cannot cover: data taken by address,',
        ' * the slab inlines, and the weak optional pair. Everything callable is',
        ' * handled by nm_kpm_tramp.c instead.',
        ' *',
        ' * Include AFTER the kernel headers. A function-like macro named after a',
        ' * kernel function expands inside that function\'s own declaration too.',
        ' */',
        '#ifndef _NM_KPM_SHIM_H',
        '#define _NM_KPM_SHIM_H',
        '',
        '#include "nm_kpm_syms.h"',
        '',
        '/* KernelPatch does not come up on 6.12+ -- it hangs in its own pagetable',
        ' * bring-up, so a module built for it could never load. Fail the compile',
        ' * rather than ship something that bootloops. See kpm/README.md. */',
        '#include <linux/version.h>',
        '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)',
        '#error "KPM targets kernel 6.6 and older: KernelPatch does not boot on 6.12+."',
        '#endif',
        '',
        '/* Data taken by address in the engine\'s own text. */',
    ]
    for s in [x for x in symbols if x in DATA]:
        out.append('#define %s (*(typeof(&%s))nm_kpm_sym[%s])' % (s, s, enum_name(s)))

    out += [
        '',
        '/*',
         ' * The slab entry points are static inlines that index the kmalloc_caches',
         ' * ARRAY, which no trampoline can stand in for. Redirecting them to',
         ' * __kmalloc -- which does have one -- stops those inlines being',
         ' * instantiated, and takes kmalloc_caches, kmalloc_trace and kmalloc_large',
         ' * out of the undefined set along with them.',
         ' */',
        '#undef kmalloc',
        '#undef kzalloc',
        '#undef kmalloc_array',
        '#define kmalloc(sz, fl)\t\t__kmalloc((sz), (fl))',
        '#define kzalloc(sz, fl)\t\t__kmalloc((sz), (fl) | __GFP_ZERO)',
        '#define kmalloc_array(n, sz, fl)\t__kmalloc((n) * (sz), (fl))',
        '',
        '/*',
        ' * Optional, and legitimately NULL: the engine tests the address before',
        ' * calling and that test is a real feature probe, so a trampoline would be',
        ' * non-NULL and falsely advertise ghost support.',
        ' *',
        ' * They expand to a POINTER rather than a lookup because the engine DECLARES',
        ' * them as well as calling them:',
        ' *',
        ' *     extern int ghost_ctl(const char *, size_t) __attribute__((weak));',
        ' *',
        ' * and a macro whose name is followed by "(" expands inside that declaration',
        ' * too. (*nm_w_ghost_ctl) leaves it well-formed -- it becomes a weak function',
        ' * POINTER -- while calls and the !ghost_ctl test both still mean what the',
        ' * engine intended. nm_engine.c defines them and binds them at init.',
        ' */',
    ]
    for s in [x for x in symbols if x in WEAK]:
        out.append('#define %s (*nm_w_%s)' % (s, s))

    out += ['', '#endif /* _NM_KPM_SHIM_H */', '']
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--syms', required=True)
    ap.add_argument('--per-version')
    ap.add_argument('--outdir', default=os.path.dirname(os.path.abspath(__file__)))
    a = ap.parse_args()

    with io.open(a.syms, encoding='utf-8') as fh:
        symbols = sorted({ln.strip() for ln in fh
                          if ln.strip() and not ln.startswith('#')})

    bad = [s for s in symbols if not s.replace('_', 'a').replace('.', 'a').isalnum()]
    if bad:
        raise SystemExit('not identifiers, the list is contaminated: %r' % bad[:5])

    lists = read_per_version(a.per_version) if a.per_version else {}
    optional = optional_set(lists)

    table_syms = [s for s in symbols if s not in LOCAL and s not in KP_PROVIDED]
    # Everything callable gets a trampoline. Data, the weak pair and anything
    # handled locally do not.
    tramp = [s for s in table_syms if s not in DATA and s not in WEAK]

    def w(name, text):
        with io.open(os.path.join(a.outdir, name), 'w',
                     encoding='utf-8', newline='\n') as fh:
            fh.write(text)

    w('nm_kpm_syms.h', gen_syms_h(table_syms))
    w('nm_kpm_shim.h', gen_shim_h(table_syms, lists))
    w('nm_kpm_tramp.c', gen_tramp_c(table_syms, tramp, lists))
    w('nm_kpm_table.h', '/* GENERATED by kpm/gen-shim.py -- do not edit. */\n'
                        + gen_table(table_syms, optional) + '\n')

    print('%d measured: %d in table, %d trampolines, %d data, %d weak, '
          '%d local, %d KernelPatch-provided, %d optional'
          % (len(symbols), len(table_syms), len(tramp),
             len([s for s in table_syms if s in DATA]),
             len([s for s in table_syms if s in WEAK]),
             len([s for s in symbols if s in LOCAL]),
             len([s for s in symbols if s in KP_PROVIDED]),
             len([s for s in table_syms if s in optional or s in WEAK])))


if __name__ == '__main__':
    main()
