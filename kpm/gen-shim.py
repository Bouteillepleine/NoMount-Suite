#!/usr/bin/env python3
"""Generate the KPM symbol table and redirect shim from a measured symbol list.

WHY THIS IS GENERATED

A .kpm cannot call kernel functions directly. KernelPatch's loader resolves
undefined symbols only against its own table (kernel/patch/module/module.c,
simplify_symbols), and its kallsyms fallback is commented out with the reason:

    // kernel symbol cause overflow in relocation

An AArch64 `bl` reaches +/-128 MB; a kallsyms address is far outside that from
wherever the module was allocated. So every kernel call has to become an
INDIRECT call through a pointer resolved at load time. That is what nm_kpm_sym[]
is, and this script writes the plumbing.

The input is measured, never invented:

    make -C kpm undefined TARGET_COMPILE=... KP_DIR=... KERNEL_DIR=...

Run this against the union of those lists across the supported kernels.

WHY typeof() RATHER THAN HAND-WRITTEN SIGNATURES

Each redirect needs the function's exact prototype for the target KMI, and
several changed inside the supported range (vfs_getxattr and vfs_setxattr gained
a user_namespace/mnt_idmap argument at 5.12 and again at 6.3). Writing ~100
signatures five times over would be both laborious and a standing source of
silent breakage.

Instead each macro reads the prototype back out of the kernel's own header:

    #define kern_path(...) ((typeof(&kern_path))nm_kpm_sym[NMS_kern_path])(__VA_ARGS__)

The preprocessor does not re-expand a macro inside its own expansion, so the
`kern_path` inside `typeof(&kern_path)` is the real declaration from
<linux/namei.h>. The signature is therefore correct by construction on every
kernel, and a mismatch is a compile error rather than a runtime fault.

ORDERING CONSTRAINT

These macros must be defined AFTER the kernel headers are parsed. A function-like
`#define memcpy(...)` expands inside string.h's own declaration of memcpy and
breaks it. nm_engine.c therefore includes the engine's headers first, then this
shim, then the engine body.
"""

import argparse
import io
import os

# ---------------------------------------------------------------- special cases
#
# Everything not listed here becomes a plain function redirect.

# Data objects, not functions: the macro dereferences the table entry rather
# than calling it, so `&sym` and `sym[i]` both still mean the real kernel object.
#
# typeof(&sym) carries the whole type, which matters more than it looks:
# kmalloc_caches is a two-dimensional array whose extents are configuration
# dependent (NR_KMALLOC_TYPES x KMALLOC_SHIFT_HIGH+1), and writing that cast out
# by hand would be both unreadable and wrong on some configs.
DATA = {'init_net', 'kmalloc_caches'}

# Declared __attribute__((weak)) in the engine and legitimately absent: the
# engine tests `if (!ghost_ctl)` before calling. These resolve to NULL when the
# ghost module is not loaded, which is exactly what that test wants.
#
# They matter here for a second reason: KernelPatch's loader does not special-
# case weak undefined symbols, so leaving them undefined fails the whole load
# with "unknown symbol" rather than resolving them to zero.
WEAK = {'ghost_ctl', 'ghost_get_rule'}

# Used as a VALUE in a static initializer (`.read = generic_read_dir`), where a
# macro cannot help: a static initializer needs a constant, and a table lookup is
# not one. nm_engine.c defines a real forwarding function under this name
# instead, so the initializer keeps a genuine address and the forwarding happens
# at call time.
FORWARD = {'generic_read_dir'}

# Provided locally by nm_engine.c rather than redirected.
#
#   mem*/str*     the compiler emits calls to these on its own -- a struct
#                 assignment becomes memcpy -- and a macro cannot intercept what
#                 the compiler generates. They need real definitions.
#   __this_module the MODULE macros reference it; a KPM has no module struct.
LOCAL = {
    'memcpy', 'memset', 'memcmp',
    'strlen', 'strcmp', 'strncmp', 'strnlen', 'strrchr',
    '__this_module',
}

# Renamed across the supported range. Resolution tries the primary name, then the
# alternate, so one table serves every KMI.
ALT = {
    '_printk': 'printk',            # renamed at 5.15
    'printk': '_printk',
    'kvfree_call_rcu': 'kfree_call_rcu',
    'kfree_call_rcu': 'kvfree_call_rcu',
    'kfree_skb_reason': 'kfree_skb',
    'kfree_skb': 'kfree_skb_reason',
    '__kmalloc': '__kmalloc_noprof',
    'kmem_cache_alloc': 'kmem_cache_alloc_noprof',
    'kmem_cache_create': '__kmem_cache_create_args',
}

# The supported kernels, in order. Used both for optionality and for the version
# guards around symbols that do not exist on every one of them.
VERSIONS = ['5.4', '5.10', '5.15', '6.1', '6.6']


def read_per_version(per_version_dir):
    """{version: set(symbols)} from the measured lists."""
    lists = {}
    for v in VERSIONS:
        p = os.path.join(per_version_dir, v + '.txt')
        if not os.path.exists(p):
            continue
        with io.open(p, encoding='utf-8') as fh:
            lists[v] = {ln.strip() for ln in fh if ln.strip()}
    return lists


def optional_set(lists):
    """Symbols absent from at least one supported kernel."""
    if not lists:
        return set()
    return set.union(*lists.values()) - set.intersection(*lists.values())


def kv(ver):
    major, minor = ver.split('.')
    return 'KERNEL_VERSION(%s, %s, 0)' % (major, minor)


def version_guard(sym, lists):
    """(#if line, #endif line) for a symbol that does not exist on every kernel.

    A macro like

        #define printk(...) ((typeof(&printk))...)

    only compiles where printk is actually declared. printk became _printk at
    5.15, so on 6.6 that macro is a hard error rather than dead code. The guard
    is derived from where the symbol was MEASURED, not from memory of when it
    was renamed.
    """
    if not lists:
        return None, None
    present = [v for v in VERSIONS if v in lists and sym in lists[v]]
    if not present or len(present) == len(lists):
        return None, None

    idx = [VERSIONS.index(v) for v in present]
    contiguous = idx == list(range(idx[0], idx[-1] + 1))

    conds = []
    if idx[0] > 0:
        conds.append('LINUX_VERSION_CODE >= %s' % kv(VERSIONS[idx[0]]))
    if idx[-1] < len(VERSIONS) - 1:
        conds.append('LINUX_VERSION_CODE < %s' % kv(VERSIONS[idx[-1] + 1]))
    if not conds:
        return None, None

    note = '' if contiguous else '  /* NOTE: measured presence is not contiguous */'
    return '#if ' + ' && '.join(conds) + note, '#endif'


def enum_name(sym):
    return 'NMS_' + sym


def gen_syms_h(symbols):
    out = [
        '/* SPDX-License-Identifier: GPL-2.0 */',
        '/*',
        ' * GENERATED by kpm/gen-shim.py -- do not edit by hand.',
        ' *',
        ' * Index space shared by nm_kpm_entry.c (which fills the table in) and',
        ' * nm_kpm_shim.h (which calls through it). Both halves of the .kpm are',
        ' * compiled against different headers and this is the one thing they share.',
        ' */',
        '#ifndef _NM_KPM_SYMS_H',
        '#define _NM_KPM_SYMS_H',
        '',
        'enum nm_kpm_sym {',
    ]
    for s in symbols:
        out.append('\t%s,' % enum_name(s))
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
    """The nm_syms[] rows for nm_kpm_entry.c."""
    rows = []
    for s in symbols:
        alt = ALT.get(s)
        alt_s = '"%s"' % alt if alt else '0'
        opt = 1 if (s in optional or s in WEAK) else 0
        rows.append('\t{ %s, "%s", %s, %d },' % (enum_name(s), s, alt_s, opt))
    return '\n'.join(rows)


def gen_shim_h(symbols, lists):
    out = [
        '/* SPDX-License-Identifier: GPL-2.0 */',
        '/*',
        ' * GENERATED by kpm/gen-shim.py -- do not edit by hand.',
        ' *',
        ' * Every kernel call in the engine becomes an indirect call through',
        ' * nm_kpm_sym[]. See gen-shim.py for why a .kpm cannot call the kernel',
        ' * directly, and why these signatures are read back out of the kernel',
        ' * headers with typeof() instead of being written down.',
        ' *',
        ' * MUST be included AFTER the kernel headers -- a function-like macro for',
        ' * memcpy expands inside string.h\'s declaration of memcpy otherwise.',
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
    ]

    data = [s for s in symbols if s in DATA]
    weak = [s for s in symbols if s in WEAK]
    funcs = [s for s in symbols
             if s not in DATA and s not in WEAK and s not in LOCAL and s not in FORWARD]

    if data:
        out += ['/* Data objects: dereference the entry so &sym and sym[i] both still',
                ' * denote the real kernel object. */']
        for s in data:
            pre, post = version_guard(s, lists)
            if pre:
                out.append(pre)
            out.append('#define %s (*(typeof(&%s))nm_kpm_sym[%s])' % (s, s, enum_name(s)))
            if post:
                out.append(post)
        out.append('')

    if weak:
        out += ['/* Optional, may legitimately be NULL; the engine tests before calling. */']
        for s in weak:
            pre, post = version_guard(s, lists)
            if pre:
                out.append(pre)
            out.append('#define %s ((typeof(&%s))nm_kpm_sym[%s])' % (s, s, enum_name(s)))
            if post:
                out.append(post)
        out.append('')

    out += ['/* Calls. typeof(&f) reads f\'s real prototype for this KMI: the',
            ' * preprocessor does not re-expand f inside f\'s own expansion. */']
    for s in funcs:
        pre, post = version_guard(s, lists)
        if pre:
            out.append(pre)
        out.append('#define %s(...) ((typeof(&%s))nm_kpm_sym[%s])(__VA_ARGS__)'
                   % (s, s, enum_name(s)))
        if post:
            out.append(post)

    out += ['', '#endif /* _NM_KPM_SHIM_H */', '']
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--syms', required=True, help='union symbol list, one per line')
    ap.add_argument('--per-version', help='directory of per-version lists, for optionality')
    ap.add_argument('--outdir', default=os.path.dirname(os.path.abspath(__file__)))
    a = ap.parse_args()

    with io.open(a.syms, encoding='utf-8') as fh:
        symbols = sorted({ln.strip() for ln in fh if ln.strip() and not ln.startswith('#')})

    bad = [s for s in symbols if not s.replace('_', 'a').replace('.', 'a').isalnum()]
    if bad:
        raise SystemExit('not identifiers, list is contaminated: %r' % bad[:5])

    lists = read_per_version(a.per_version) if a.per_version else {}
    optional = optional_set(lists)

    # Symbols provided locally are not table entries at all.
    table_syms = [s for s in symbols if s not in LOCAL]

    w = lambda n, t: io.open(os.path.join(a.outdir, n), 'w', encoding='utf-8', newline='\n').write(t)
    w('nm_kpm_syms.h', gen_syms_h(table_syms))
    w('nm_kpm_shim.h', gen_shim_h(table_syms, lists))
    w('nm_kpm_table.h', '/* GENERATED by kpm/gen-shim.py -- do not edit. */\n'
                        + gen_table(table_syms, optional) + '\n')

    print('%d symbols: %d redirected, %d data, %d weak, %d local, %d optional'
          % (len(symbols), len(table_syms), len([s for s in table_syms if s in DATA]),
             len([s for s in table_syms if s in WEAK]),
             len([s for s in symbols if s in LOCAL]),
             len([s for s in table_syms if s in optional or s in WEAK])))


if __name__ == '__main__':
    main()
