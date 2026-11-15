/* Host check of nm's --uid-excluded parsing, the contract integrators written
 * against upstream's CLI rely on. Morphe sends
 *   nm rule add|del --uid-range all --uid-excluded 1000-1000 <v> [<r>]
 * and a parse failure there leaves its "NoMount only" installs with nothing.
 *
 *   zig cc -target x86_64-linux -Oz -static -nostdlib -ffreestanding \
 *     -fno-unwind-tables -Wno-invalid-noreturn -Wl,--entry=_start \
 *     tests/nm-parse-check.c -o nm-parse-check && ./nm-parse-check
 */
#include "../userspace/src/nm.h"

static int failures;

static void expect(const char *arg, int ok, int n, const unsigned int *want) {
    unsigned int got[NM_DENY_MAX];
    int got_n = 0, rc = parse_appid_list(arg, got, NM_DENY_MAX, &got_n), bad = 0;

    if (ok ? rc != 0 : rc == 0) bad = 1;
    if (ok && !rc) {
        if (got_n != n) bad = 1;
        for (int i = 0; !bad && i < n; i++) if (got[i] != want[i]) bad = 1;
    }
    if (bad) { print_err("FAIL --uid-excluded "); print_err(arg); print_err("\n"); failures++; }
}

__attribute__((noreturn, used))
void c_main(long *sp) {
    (void)sp;
    static const unsigned int a1000[] = { 1000 };
    static const unsigned int pair[] = { 10170, 10397 };
    static const unsigned int run[] = { 10000, 10001, 10002 };
    static const unsigned int top[] = { 99998, 99999 };

    /* upstream's C-D form */
    expect("1000-1000", 1, 1, a1000);           /* Morphe */
    expect("10002-10000", 1, 3, run);           /* reversed, as upstream accepts */
    expect("99998-99999", 1, 2, top);
    expect("10000-10008", 0, 0, 0);             /* 9 appids: over NM_DENY_MAX */
    expect("99999-100000", 0, 0, 0);            /* not an appid */
    expect("1010397-1010397", 0, 0, 0);         /* a raw uid, as in the list form */
    expect("all", 0, 0, 0);
    expect("1000-", 0, 0, 0);
    expect("-1000", 0, 0, 0);

    /* our appid list, unchanged */
    expect("10397,10170", 1, 2, pair);
    expect("1000", 1, 1, a1000);
    expect("10397,10397", 0, 0, 0);
    expect("100000", 0, 0, 0);
    expect("10397,", 0, 0, 0);

    if (!failures) print_err("nm-parse-check: ok\n");
    sys1(SYS_EXIT, failures != 0);
    __builtin_unreachable();
}
