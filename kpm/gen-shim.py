#!/usr/bin/env python3

import argparse
import io
import os

DATA = {'init_net'}

WEAK = {'ghost_ctl', 'ghost_get_rule'}

LOCAL = {
    'memcpy', 'memset', 'memcmp',
    'strlen', 'strcmp', 'strncmp', 'strnlen', 'strrchr',
    '__this_module',
    'nm_kpm_sym',
    'vfs_map_meta_override',
}

KP_PROVIDED = {'kallsyms_lookup_name', 'printk'}

SLAB = [
    ('kmalloc', 'kmalloc(sz, fl)\t\t__kmalloc((sz), (fl))'),
    ('kzalloc', 'kzalloc(sz, fl)\t\t__kmalloc((sz), (fl) | __GFP_ZERO)'),
    ('kmalloc_array', 'kmalloc_array(n, sz, fl)\t__kmalloc((n) * (sz), (fl))'),
    ('kcalloc', 'kcalloc(n, sz, fl)\t__kmalloc((n) * (sz), (fl) | __GFP_ZERO)'),
]

ALT = {
    '__list_add_valid': '__list_add_valid_or_report',
    '__list_add_valid_or_report': '__list_add_valid',
    '__list_del_entry_valid': '__list_del_entry_valid_or_report',
    '__list_del_entry_valid_or_report': '__list_del_entry_valid',
    '_printk': 'printk',
    'kvfree_call_rcu': 'kfree_call_rcu',
    'kfree_call_rcu': 'kvfree_call_rcu',
    'kfree_skb_reason': 'kfree_skb',
    'kfree_skb': 'kfree_skb_reason',
    '__kmalloc': '__kmalloc_noprof',
    'kmem_cache_alloc': 'kmem_cache_alloc_noprof',
    'kmem_cache_create': '__kmem_cache_create_args',
}

def read_per_version(d):
    lists = {}
    for f in sorted(os.listdir(d)):
        if not f.endswith('.txt'):
            continue
        with io.open(os.path.join(d, f), encoding='utf-8') as fh:
            syms = {ln.strip() for ln in fh if ln.strip()}
        if not syms:
            raise SystemExit('%s is empty: that survey did not build' % f)
        lists[f[:-4]] = syms
    return lists

def optional_set(lists):
    if not lists:
        return set()
    return set.union(*lists.values()) - set.intersection(*lists.values())

def enum_name(sym):
    return 'NMS_' + sym

def gen_syms_h(symbols):
    out = [
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
        '#endif',
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

def gen_tramp_c(symbols, tramp):
    out = [
        '#include "nm_kpm_syms.h"',
        '',
        '#define NM_TRAMP(name, idx)\t\t\t\t\t\\',
        '\tasm(".globl " #name "\\n"\t\t\t\t\\',
        '\t    ".type " #name ", %function\\n"\t\t\t\\',
        '\t    #name ":\\n"\t\t\t\t\t\\',
        '\t    "  adrp x16, nm_kpm_sym\\n"\t\t\t\t\\',
        '\t    "  add  x16, x16, :lo12:nm_kpm_sym\\n"\t\t\\',
        '\t    "  ldr  x16, [x16, #(8*" #idx ")]\\n"\t\t\t\\',
        '\t    "  br   x16\\n")',
        '',
    ]
    for s in tramp:
        out.append('_Static_assert(%s == %d, "table index drift: %s");'
                   % (enum_name(s), symbols.index(s), s))
    out.append('')
    for s in tramp:
        out.append('NM_TRAMP(%s, %d);' % (s, symbols.index(s)))
    out.append('')
    return '\n'.join(out)

def gen_shim_h(symbols):
    out = [
        '#ifndef _NM_KPM_SHIM_H',
        '#define _NM_KPM_SHIM_H',
        '',
        '#include "nm_kpm_syms.h"',
        '',
        '#include <linux/version.h>',
        '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)',
        '#error "KPM targets kernel 6.6 and older: KernelPatch does not boot on 6.12+."',
        '#endif',
        '',
    ]
    for s in [x for x in symbols if x in DATA]:
        out.append('#define %s (*(typeof(&%s))nm_kpm_sym[%s])' % (s, s, enum_name(s)))

    out.append('')
    out += ['#undef %s' % name for name, _ in SLAB]
    out += ['#define %s' % body for _, body in SLAB]
    out.append('')

    for s in [x for x in symbols if x in WEAK]:
        out.append('#define %s (*nm_w_%s)' % (s, s))

    out += ['', '#endif', '']
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

    measured = set(symbols) | DATA | WEAK
    table_syms = [s for s in sorted(measured)
                  if s not in LOCAL and s not in KP_PROVIDED]
    tramp = [s for s in table_syms if s not in DATA and s not in WEAK]

    def w(name, text):
        with io.open(os.path.join(a.outdir, name), 'w',
                     encoding='utf-8', newline='\n') as fh:
            fh.write(text)

    w('nm_kpm_syms.h', gen_syms_h(table_syms))
    w('nm_kpm_shim.h', gen_shim_h(table_syms))
    w('nm_kpm_tramp.c', gen_tramp_c(table_syms, tramp))
    w('nm_kpm_table.h', gen_table(table_syms, optional) + '\n')

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
