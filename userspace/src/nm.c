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

    /* No family resolution: the private raw-netlink protocol is addressed
     * directly (kernel is portid 0); the command rides in nlmsg_type. */

    char cmd = argv[1][0];
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
                exit_code |= (do_nm_cmd(fd,target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem) < 0);
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

        if (cursor > mem.payload)
            exit_code |= (do_nm_cmd(fd,target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem) < 0);

        goto do_exit;

    } else if (cmd == 'b' || cmd == 'u') {
        if (p_count < 1) goto do_exit;
        unsigned int uid = 0; const char *s = p_args[0];
        if (!*s) { exit_code = 3; goto do_exit; }
        while (*s) {
            if (*s < '0' || *s > '9') { exit_code = 3; goto do_exit; }
            uid = (uid << 3) + (uid << 1) + (*s++ - '0');
        }
        exit_code = (do_nm_cmd(fd,6 - (cmd == 'b'), 4, &uid, 4, 5, &mem) < 0);
        goto do_exit;

    } else if (cmd == 'k') {
        /* k <r|v|c|b> <value> -- boot-identity knob, formerly a sysfs attribute.
         * Payload: [u32 knob][value bytes]; an empty value clears the override. */
        unsigned int knob;
        const char *val;
        int vlen = 0;

        if (p_count < 1) goto do_exit;
        switch (p_args[0][0]) {
        case 'r': knob = 0; break;
        case 'v': knob = 1; break;
        case 'c': knob = 2; break;
        case 'b': knob = 3; break;
        /* d <0|1> -- this device's ROM dirs are dirent-packed (erofs-shaped), so
         * a synthesized dir must report the formula rather than 4096. Measured
         * by the Suite; see NM_KNOB_VDIR_EROFS_SIZE. */
        case 'd': knob = 4; break;
        /* i <0..3> -- which isolated-process pools per-UID hiding covers:
         * 1 = app-zygote, 2 = platform, 3 = both (default), 0 = neither.
         * See NM_KNOB_HIDE_ISOLATED for the trade this expresses. */
        case 'i': knob = 5; break;
        default: exit_code = 3; goto do_exit;
        }
        val = (p_count > 1) ? p_args[1] : "";
        while (val[vlen]) vlen++;
        if (4 + vlen > MAX_PAYLOAD) { exit_code = 3; goto do_exit; }
        *(unsigned int *)mem.payload = knob;
        if (vlen) memcpy(mem.payload + 4, val, vlen);
        exit_code = (do_nm_cmd(fd, 9, 6, mem.payload, 4 + vlen, 5, &mem) < 0);
        goto do_exit;

    } else if (cmd == 'c') {
        exit_code = (do_nm_cmd(fd,4, 0, (void *)0, 0, 5, &mem) < 0);
        goto do_exit;

    } else if (cmd == 'v') {
        if (do_nm_cmd(fd,1, 0, (void *)0, 0, 1, &mem) > 0) {
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
        int is_json = 0, is_uids = 0;
        for (int i = 0; i < p_count; i++) {
            if (p_args[i][0] == 'j') is_json = 1;
            if (p_args[i][0] == 'u') is_uids = 1;
        }
        if (is_uids) is_json = 1;

        int target_cmd = is_uids ? 8 : 7;
        /* signed: a negative errno from do_nm_cmd()/read() must fail the while(len>0)
         * guard, not wrap to a huge unsigned length that walks rx_buf out of bounds. */
        int len = do_nm_cmd(fd,target_cmd, 0, (void *)0, 0, 0x301, &mem);
        int offset = 2;
        /* A dump that aborts mid-stream (kernel returns -EAGAIN when the rule
         * table mutated under the cursor) must NOT look like success: callers
         * feed this list straight into the reload delta, so a silently truncated
         * list is acted on as if it were the whole live set. */
        if (len < 0) { exit_code = 4; goto do_exit; }
        exit_code = 0;
        if (is_json) print_str("[\n");

        while (len > 0) {
            for (struct nlmsghdr *msg = (void *)mem.rx_buf; msg->nlmsg_len && msg->nlmsg_len <= len;
                    len -= msg->nlmsg_len, msg = (void *)((char *)msg + msg->nlmsg_len)) {
                if (msg->nlmsg_type == 3) goto list_done;          /* NLMSG_DONE */
                if (msg->nlmsg_type == 2) {                        /* NLMSG_ERROR */
                    if (*(int *)((char *)msg + 16)) exit_code = 4; /* err 0 == plain ACK */
                    goto list_done;
                }

                if (is_uids) {
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
                            print_str(v);
                            if (is_whiteout) print_str("\",\n    \"whiteout\": true");
                            else if (is_virtual_dir) print_str("\",\n    \"virtual_dir\": true");
                            else { print_str("\",\n    \"real\": \""); print_str(r); print_str("\""); }
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
            len = sys3(SYS_READ, fd, (long)mem.rx_buf, RX_BUF_SIZE);
        }
list_done:
        if (is_json) print_str("\n]\n");
    }

do_exit:
    sys1(SYS_EXIT, exit_code);
    __builtin_unreachable();
}
