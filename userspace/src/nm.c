/*
 * nm.c - NoMount CLI Userspace Tool
 */
#include "nm.h"

/* --- MAIN --- */
__attribute__((noreturn, used))
void c_main(long *sp) {
    struct nm_mem mem __attribute__((aligned(16)));
    long argc = *sp;
    char **argv = (char **)(sp + 1);
    int exit_code = 1;

    if (argc < 2) {
        print_str("nm <command>\n");
        goto do_exit;
    }

    int fd = sys3(SYS_SOCKET, AF_NETLINK, SOCK_RAW, NOMOUNT_NL_PROTO);
    if (fd < 0) { exit_code = 2; goto do_exit; }
    /* Before the FIRST read, and covering every later one: a kernel that takes
     * the message and never replies must not hang us, because nm runs during
     * post-fs-data and a hang there hangs boot. See NM_RECV_TIMEOUT_SEC. */
    set_recv_timeout(fd);

    /* No family resolution: the private raw-netlink protocol is addressed
     * directly (kernel is portid 0); the command rides in nlmsg_type. */

    /* Exact command WORDS, not a first-character match.
     *
     * This used to be `argv[1][0]`, so any word beginning with the right letter
     * ran the command. `nm check`, `nm count` and `nm config` all executed CLEAR
     * -- which drops every rule AND the blocked-UID set (see __nomount_clear_all:
     * per-UID hiding is runtime-only state and CLEAR_ALL is its reset). A typo at
     * a root shell was a silent, total wipe with a success exit code.
     *
     * The table carries every spelling the Suite actually uses -- nm.rs, the
     * module scripts and the WebUI between them issue add/del/w/block/unblock/
     * clear/list/l/v/k -- plus the obvious long forms. Anything else is refused
     * rather than guessed at. */
    static const struct { const char *name; char op; } nm_cmds[] = {
        { "add", 'a' },      { "del", 'd' },     { "w", 'w' },
        { "whiteout", 'w' }, { "block", 'b' },   { "unblock", 'u' },
        { "clear", 'c' },    { "list", 'l' },    { "l", 'l' },
        { "v", 'v' },        { "version", 'v' }, { "k", 'k' },
        { "knob", 'k' },
    };
    char cmd = 0;
    for (unsigned int ci = 0; ci < sizeof(nm_cmds) / sizeof(nm_cmds[0]); ci++) {
        if (strcmp(argv[1], nm_cmds[ci].name) == 0) { cmd = nm_cmds[ci].op; break; }
    }
    if (!cmd) {
        print_str("nm: unknown command\n");
        exit_code = 3; goto do_exit;
    }
    unsigned int target_uid = 0;
    /* NM_FLAG_PUBLIC: this rule stays visible to a UID on the hide list. Only
     * meaningful on `add`, and only correct for a path the system already
     * advertises to that UID anyway -- a ROM APK the PackageManager has scanned
     * and now names to every app that asks. The kernel refuses it on a rule that
     * shadows a stock file, so a wrong `--public` cannot leak module bytes. */
    unsigned int add_flags = 0;
    const char *p_args[64];
    int p_count = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
            const char *s = argv[++i];
            /* Validate: the old loop turned any non-digit into arithmetic, so a
             * typo silently targeted a garbage uid instead of failing. */
            if (!*s) { exit_code = 3; goto do_exit; }
            while (*s) {
                if (*s < '0' || *s > '9') { exit_code = 3; goto do_exit; }
                target_uid = (target_uid << 3) + (target_uid << 1) + (*s++ - '0');
            }
        } else if (strcmp(argv[i], "--public") == 0) {
            add_flags |= 64;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            /* Anything else spelled like an option is a mistake, and taking it for
             * a PATH is the worst way to handle one: a typo ("--publik") would be
             * accepted as the virtual path of the very rule it was meant to flag,
             * and `--uid` with no value (which fails the branch above) as a path
             * of its own. Both applied a wrong rule and exited 0. */
            print_str("nm: unknown option\n");
            exit_code = 3; goto do_exit;
        } else if (p_count < 64) {
            p_args[p_count++] = argv[i];
        } else {
            /* Silently dropping the tail meant a batch `nm add` past 64 arguments
             * applied part of its work and still exited 0, so the caller recorded
             * every pair as applied. Refuse the whole command instead. */
            print_str("nm: too many arguments (max 64)\n");
            exit_code = 3; goto do_exit;
        }
    }

    if (cmd == 'a' || cmd == 'd' || cmd == 'w') {
        int step = 1 + (cmd == 'a');
        /* Was exit 0: `nm add` with no operands reported success and did nothing,
         * so a caller that built an empty argument list saw its work "applied". */
        if (p_count < step) { print_str("nm: missing operand\n"); exit_code = 3; goto do_exit; }

        const char *cwd = (sys3(SYS_GETCWD, (long)mem.cwd_buf, PATH_MAX, 0) > 0) ? mem.cwd_buf : "/";
        char *cursor = mem.payload;

        int target_cmd = 2 + (cmd == 'd');
        exit_code = 0;

        for (int i = 0; i + step - 1 < p_count; i += step) {
            char *v_end = resolve_path(mem.v_resolved, cwd, p_args[i]);
            int v_len = v_end ? (int)(v_end - mem.v_resolved) : 0; /* NULL = overran PATH_MAX */
            if (!v_len) { exit_code = 3; continue; }

            int r_len = 0;
            if (cmd == 'a') {
                char *r_end = resolve_path(mem.r_resolved, cwd, p_args[i+1]);
                r_len = r_end ? (int)(r_end - mem.r_resolved) : 0;
                if (!r_len) { exit_code = 3; continue; }
            }

            int header_size = (target_cmd == 2) ? 12 : 6;
            if ((cursor - mem.payload) + header_size + v_len + r_len > MAX_PAYLOAD) {
                int rc = do_nm_cmd(fd,target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem);
                /* A silent kernel will not answer the NEXT batch either, and
                 * grinding through the rest of a large `nm add` at five seconds
                 * a batch is the boot-time stall this bound exists to prevent. */
                if (nm_timed_out(rc)) goto do_timeout;
                exit_code |= (rc < 0);
                cursor = mem.payload;
            }

            if (target_cmd == 2) { /* ADD / WHITEOUT */
                *(unsigned int*)cursor = (cmd == 'w') ? 4 : add_flags;
                *(unsigned int*)(cursor + 4) = target_uid;
                *(unsigned short*)(cursor + 8) = v_len;
                *(unsigned short*)(cursor + 10) = r_len;
                memcpy(cursor + 12, mem.v_resolved, v_len);
                if (r_len > 0) memcpy(cursor + 12 + v_len, mem.r_resolved, r_len);
                cursor += 12 + v_len + r_len;
            } else { /* DEL */
                *(unsigned int*)cursor = target_uid;
                *(unsigned short*)(cursor + 4) = v_len;
                memcpy(cursor + 6, mem.v_resolved, v_len);
                cursor += 6 + v_len;
            }
        }

        if (cursor > mem.payload) {
            int rc = do_nm_cmd(fd,target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem);
            if (nm_timed_out(rc)) goto do_timeout;
            exit_code |= (rc < 0);
        }

        goto do_exit;

    } else if (cmd == 'b' || cmd == 'u') {
        if (p_count < 1) goto do_exit;
        unsigned int uid = 0; const char *s = p_args[0];
        if (!*s) { exit_code = 3; goto do_exit; }
        while (*s) {
            if (*s < '0' || *s > '9') { exit_code = 3; goto do_exit; }
            uid = (uid << 3) + (uid << 1) + (*s++ - '0');
        }
        int rc = do_nm_cmd(fd,6 - (cmd == 'b'), 4, &uid, 4, 5, &mem);
        if (nm_timed_out(rc)) goto do_timeout;
        exit_code = (rc < 0);
        goto do_exit;

    } else if (cmd == 'k') {
        /* k <r|v|c|b> <value> -- boot-identity knob, formerly a sysfs attribute.
         * Payload: [u32 knob][value bytes]; an empty value clears the override. */
        int knob = -1;
        const char *val;
        int vlen = 0;

        /* Exact knob WORDS, for the reason the command table above matches words
         * (see the note at `nm_cmds`): this was `p_args[0][0]`, so any token
         * beginning with the right letter selected that knob. `nm k cold` rewrote
         * /proc/cmdline, `nm k dir` flipped the directory-shape knob, `nm k boot
         * ...` rewrote /proc/bootconfig -- each from a word that was never a knob
         * name, and each exiting 0. Every caller in the tree passes the bare
         * letter (spoof.sh's nm_knob r|v|c|b, service.sh / customize.sh / the
         * WebUI's `nm k p`, nm.rs's `k i` and `k d`), so the letters are the whole
         * vocabulary; anything else is refused rather than guessed at.
         *
         *   r/v -- uname release / version override
         *   c/b -- sanitized /proc/cmdline / /proc/bootconfig
         *   d <0|1> -- this device's ROM dirs are dirent-packed (erofs-shaped),
         *     so a synthesized dir must report the formula rather than 4096.
         *     Measured by the Suite; see NM_KNOB_VDIR_EROFS_SIZE.
         *   i <0..3> -- which isolated-process pools per-UID hiding covers:
         *     1 = app-zygote, 2 = platform, 3 = both (default), 0 = neither.
         *     See NM_KNOB_HIDE_ISOLATED for the trade this expresses.
         *   p <cmd> -- one _pathhide control command: "+needle" adds, "~needle"
         *     removes, "-" clears. `nm k p` with NO value is a presence probe
         *     that exits 0 only when the pathhide patch set is compiled in; it is
         *     not a clear. See NM_KNOB_PATHHIDE.
         *   g <cmd> -- one _ghost control command: "p+/abs/path" / "p~/abs/path"
         *     / "p-" for the hidden-path table, "u+<uid>" / "u~<uid>" / "u-" for
         *     the hidden-uid table. Same presence-probe rule as p: `nm k g` with
         *     NO value exits 0 only when _ghost is compiled in AND the engine is
         *     >= v26 (below that the knob does not exist and the kernel answers
         *     -EINVAL). _ghost's guards are dead code until BOTH tables are
         *     populated, so this knob is what makes them live. */
        static const struct { const char *name; int knob; } nm_knobs[] = {
            { "r", 0 }, { "v", 1 }, { "c", 2 }, { "b", 3 },
            { "d", 4 }, { "i", 5 }, { "p", 6 }, { "g", 7 },
        };
        if (p_count < 1) goto do_exit;
        for (unsigned int ki = 0; ki < sizeof(nm_knobs) / sizeof(nm_knobs[0]); ki++) {
            if (strcmp(p_args[0], nm_knobs[ki].name) == 0) { knob = nm_knobs[ki].knob; break; }
        }
        if (knob < 0) {
            print_str("nm: unknown knob\n");
            exit_code = 3; goto do_exit;
        }
        val = (p_count > 1) ? p_args[1] : "";
        while (val[vlen]) vlen++;
        if (4 + vlen > MAX_PAYLOAD) { exit_code = 3; goto do_exit; }
        *(unsigned int *)mem.payload = (unsigned int)knob;
        if (vlen) memcpy(mem.payload + 4, val, vlen);
        int rc = do_nm_cmd(fd, 9, 6, mem.payload, 4 + vlen, 5, &mem);
        if (nm_timed_out(rc)) goto do_timeout;
        exit_code = (rc < 0);
        goto do_exit;

    } else if (cmd == 'c') {
        int rc = do_nm_cmd(fd,4, 0, (void *)0, 0, 5, &mem);
        if (nm_timed_out(rc)) goto do_timeout;
        exit_code = (rc < 0);
        goto do_exit;

    } else if (cmd == 'v') {
        int vlen_rx = do_nm_cmd(fd, 1, 0, (void *)0, 0, 1, &mem);
        if (nm_timed_out(vlen_rx)) goto do_timeout;
        struct nlmsghdr *vh = (struct nlmsghdr *)mem.rx_buf;
        /* Bound the header's own length claim by what was actually READ before
         * walking attributes off it. The list path below already does this per
         * message; this one trusted nlmsg_len outright, so a short or malformed
         * reply sent get_attr walking past rx_buf. */
        if (vlen_rx >= 16 && vh->nlmsg_len <= (unsigned int)vlen_rx) {
            unsigned int *ver = get_attr(mem.rx_buf, 5);
            if (ver) {
                /* print_uint handles any width; the old two-digit routine printed
                 * "02" for 2 and garbage for >= 100. */
                print_uint(*ver);
                print_str("\n");
                exit_code = 0; goto do_exit;
            }
        }

    } else if (cmd == 'l') {
        int is_json = 0, is_uids = 0, is_ph = 0;
        for (int i = 0; i < p_count; i++) {
            if (p_args[i][0] == 'j') is_json = 1;
            if (p_args[i][0] == 'u') is_uids = 1;
            /* `nm l p` -- the _pathhide rule list. Plain one-per-line by
             * default so it drops straight into the shell loops that used to
             * `cat /proc/pathhide`. */
            if (p_args[i][0] == 'p') is_ph = 1;
        }
        if (is_uids) is_json = 1;

        int target_cmd = is_ph ? 10 : is_uids ? 8 : 7;
        /* signed: a negative errno from do_nm_cmd()/read() must fail the while(len>0)
         * guard, not wrap to a huge unsigned length that walks rx_buf out of bounds. */
        int len = do_nm_cmd(fd,target_cmd, 0, (void *)0, 0, 0x301, &mem);
        int offset = 2;
        /* A dump that aborts mid-stream (kernel returns -EAGAIN when the rule
         * table mutated under the cursor) must NOT look like success: callers
         * feed this list straight into the reload delta, so a silently truncated
         * list is acted on as if it were the whole live set.
         *
         * That guard used to cover only this FIRST read. A dump of any real size
         * spans several -- and the continuation read at the foot of the loop had
         * no guard at all: an -ENOBUFS, a receive timeout or a premature EOF
         * simply failed `while (len > 0)` and fell through to list_done with
         * exit_code still 0. The Suite then pruned every rule the dump had not
         * reached yet. See the loop's tail. */
        if (nm_timed_out(len)) goto do_timeout;
        if (len < 0) { exit_code = 4; goto list_fail; }
        exit_code = 0;
        if (is_json) print_str("[\n");

        while (len > 0) {
            for (struct nlmsghdr *msg = (void *)mem.rx_buf; msg->nlmsg_len && msg->nlmsg_len <= (unsigned int)len;
                    len -= msg->nlmsg_len, msg = (void *)((char *)msg + msg->nlmsg_len)) {
                if (msg->nlmsg_type == 3) goto list_done;          /* NLMSG_DONE */
                if (msg->nlmsg_type == 2) {                        /* NLMSG_ERROR */
                    if (*(int *)((char *)msg + 16)) exit_code = 4; /* err 0 == plain ACK */
                    goto list_done;
                }

                if (is_ph) {
                    /* The needle rides in NOMOUNT_ATTR_VIRTUAL_PATH -- see the
                     * kernel dump for why that attribute is reused. */
                    char *rule = get_attr(msg, 1);
                    if (rule) {
                        if (is_json) {
                            print_str((const char *)",\n  \"" + offset); offset = 0;
                            print_json(rule);
                            print_str("\"");
                        } else {
                            print_str(rule); print_str("\n");
                        }
                    }
                } else if (is_uids) {
                    unsigned int *uid = get_attr(msg, 4); /* NOMOUNT_ATTR_UID */
                    if (uid) {
                        if (offset == 0) print_str(",\n");
                        print_str("  "); print_uint(*uid);
                        offset = 0;
                    }
                } else {
                    char *v = get_attr(msg, 1); 
                    char *r = get_attr(msg, 2); 
                    unsigned int *flags = get_attr(msg, 3);
                    unsigned int *uid = get_attr(msg, 4);

                    if (v && r) {
                        int is_whiteout    = (flags && (*flags & 4));
                        int is_virtual_dir = (flags && (*flags & 2)); 
                        /* Reported so `nomount doctor` can tell an added ROM APK
                         * that opted out of hiding from one that did not -- the
                         * kernel may have stripped the bit (a shadowing rule), so
                         * what was asked for is not always what is live. */
                        int is_public      = (flags && (*flags & 64));

                        if (is_json) {
                            print_str((const char *)",\n  {\n    \"virtual\": \"" + offset); offset = 0;
                            print_json(v);
                            if (is_whiteout) print_str("\",\n    \"whiteout\": true");
                            else if (is_virtual_dir) print_str("\",\n    \"virtual_dir\": true");
                            else { print_str("\",\n    \"real\": \""); print_json(r); print_str("\""); }
                            if (is_public) print_str(",\n    \"public\": true");
                            if (uid && *uid != 0) { print_str(",\n    \"uid\": "); print_uint(*uid); }
                            print_str("\n  }");
                        } else {
                            print_str(v);
                            if (is_whiteout) print_str(" (whiteout)");
                            else if (is_virtual_dir) print_str(" (virtual dir)");
                            else { print_str(" -> "); print_str(r); }
                            if (is_public) print_str(" (public)");
                            if (uid && *uid != 0) { print_str(" [UID: "); print_uint(*uid); print_str("]"); }
                            print_str("\n");
                        }
                    }
                }
            }
            len = nm_read(fd, &mem);
            if (nm_timed_out(len)) goto do_timeout;
        }
        /* Reaching HERE means the loop ran out of input without ever seeing
         * NLMSG_DONE or NLMSG_ERROR -- those are the only two exits, and both
         * jump to list_done. So the stream ended early: read() failed (-ENOBUFS
         * is the realistic one on a large raw-netlink dump) or returned 0.
         * Whatever was printed is a PREFIX of the rule set, and the reload delta
         * cannot tell a prefix from the whole set. Fail. */
        exit_code = 4;
list_fail:
        /* Deliberately NOT closing the JSON array. Exit code 4 is the contract
         * (nm.rs's Nm::run bails on any non-zero status, which is how every Rust
         * caller sees this), but a truncated `nm l j` also has to be unparseable
         * for anyone who forgets to check, and an unterminated array is. The
         * diagnostic goes to stderr so it cannot be read back as a rule. */
        print_err("nm: rule dump ended early - list is incomplete\n");
        goto do_exit;
list_done:
        if (is_json) print_str("\n]\n");
    }
    goto do_exit;

do_timeout:
    /* Distinct from every other failure: the kernel took the message and never
     * answered within NM_RECV_TIMEOUT_SEC. Before the SO_RCVTIMEO bound this
     * blocked forever, and because metamount.sh and post-fs-data.sh run nm during
     * post-fs-data, forever meant the device never finished booting. */
    print_err("nm: no answer from the kernel (timed out)\n");
    exit_code = NM_EXIT_TIMEOUT;

do_exit:
    sys1(SYS_EXIT, exit_code);
    __builtin_unreachable();
}
