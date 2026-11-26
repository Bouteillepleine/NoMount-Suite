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
    /* One slot past NM_DENY_MAX with a canary in it: a parser that writes past the
     * bound fails here instead of quietly damaging the stack. */
    unsigned int got[NM_DENY_MAX + 1];
    got[NM_DENY_MAX] = 0xC0FFEE01u;
    int got_n = 0, rc = parse_appid_list(arg, got, NM_DENY_MAX, &got_n), bad = 0;

    if (got[NM_DENY_MAX] != 0xC0FFEE01u) bad = 1;
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
    /* NM_DENY_MAX exactly: the largest input both forms must still ACCEPT. Only the
     * over-limit side was pinned, so tightening the bound by one would have passed every
     * case here while the error text and the engine's attribute both promise eight. */
    static const unsigned int eight[] = {
        10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007
    };

    /* upstream's C-D form */
    expect("1000-1000", 1, 1, a1000);           /* Morphe */
    expect("10002-10000", 1, 3, run);           /* reversed, as upstream accepts */
    expect("99998-99999", 1, 2, top);
    expect("10000-10007", 1, 8, eight);         /* 8 appids: NM_DENY_MAX exactly */
    expect("10000-10008", 0, 0, 0);             /* 9 appids: over NM_DENY_MAX */
    expect("99999-100000", 0, 0, 0);            /* not an appid */
    expect("1010397-1010397", 0, 0, 0);         /* a raw uid, as in the list form */
    expect("all", 0, 0, 0);
    expect("1000-", 0, 0, 0);
    expect("-1000", 0, 0, 0);

    /* our appid list, unchanged */
    expect("10397,10170", 1, 2, pair);
    expect("10000,10001,10002,10003,10004,10005,10006,10007", 1, 8, eight);
    expect("10000,10001,10002,10003,10004,10005,10006,10007,10008", 0, 0, 0); /* 9: over */
    expect("1000", 1, 1, a1000);
    expect("10397,10397", 0, 0, 0);
    expect("100000", 0, 0, 0);
    expect("10397,", 0, 0, 0);

    /* --uid-range, the other scope form. parse_range() is only the parser; the
     * reason nm.c now REFUSES an end of 0 is this: on the wire uid_end 0 IS the
     * absent-marker (nomount.h, NOMOUNT_ATTR_UID), so a `0-0` that reached the
     * engine would be read as "this appid under every user" -- a globally visible
     * rule. These pin the two facts that argument rests on: that `0-0` parses to
     * an end of 0, and that `all` does not. */
    {
        unsigned int lo = 7, hi = 7;

        if (parse_range("0-0", &lo, &hi) || lo != 0 || hi != 0) {
            print_err("FAIL --uid-range 0-0 must parse to 0,0\n"); failures++; }
        lo = hi = 7;
        if (parse_range("all", &lo, &hi) || lo != 0 || hi != 0xFFFFFFFFu) {
            print_err("FAIL --uid-range all must parse to 0,0xFFFFFFFF\n"); failures++; }
        lo = hi = 7;
        if (parse_range("5-0", &lo, &hi) || lo != 5 || hi != 0) {
            print_err("FAIL --uid-range 5-0 must parse to 5,0 for nm.c to refuse\n");
            failures++; }
        lo = hi = 7;
        if (parse_range("1000-1000", &lo, &hi) || lo != 1000 || hi != 1000) {
            print_err("FAIL --uid-range 1000-1000 must still parse\n"); failures++; }
        if (!parse_range("1000", &lo, &hi)) {
            print_err("FAIL --uid-range needs an explicit A-B\n"); failures++; }
    }

    /* do_nm_cmd's single-attribute bound. It memcpy'd len caller-supplied bytes to
     * tx_buf + 20 with no check at all, while do_nm_cmd_multi ten lines above checked
     * `off + padded > TX_BUF_SIZE`; the only thing keeping it in bounds was the
     * MAX_PAYLOAD convention, re-derived at three call sites with 68 bytes of slack.
     *
     * fd is -1 on purpose: SYS_WRITE fails with -EBADF and do_nm_cmd returns it, so an
     * accepted length is distinguishable from a refused one (NM_ERR_PROTO) without a
     * socket. Removing the bound makes the over-length cases stop being refused -- and
     * the last two then overflow the buffer for real, which is the point.
     */
    {
        static struct nm_mem mem;
        static char big[MAX_PAYLOAD + 64];
        struct { int len; int refuse; } cases[] = {
            { 0, 0 }, { 1, 0 }, { MAX_PAYLOAD, 0 },
            { MAX_PAYLOAD + 1, 1 }, { TX_BUF_SIZE, 1 }, { -1, 1 },
        };

        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            int rc = do_nm_cmd(-1, 1, 1, big, cases[i].len, 0, &mem);

            if ((rc == NM_ERR_PROTO) != cases[i].refuse) {
                print_err("FAIL do_nm_cmd len=");
                print_uint((unsigned)cases[i].len);
                print_err(cases[i].refuse ? " must be refused\n"
                                          : " must be accepted\n");
                failures++;
            }
        }
    }

    if (!failures) print_err("nm-parse-check: ok\n");
    sys1(SYS_EXIT, failures != 0);
    __builtin_unreachable();
}
