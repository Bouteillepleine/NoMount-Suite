/* nm.c - NoMount CLI Userspace Tool */
#include "nm.h"

__attribute__((noreturn, used))
void c_main(long *sp) {
    struct nm_mem mem __attribute__((aligned(16)));
    long argc = *sp;
    char **argv = (char **)(sp + 1);
    int exit_code = 1;

    if (argc < 2) {
        print_err("nm <command>\n");
        goto do_exit;
    }

    int fd = sys3(SYS_SOCKET, AF_NETLINK, SOCK_RAW, NOMOUNT_NL_PROTO);
    if (fd < 0) {
        print_err("nm: cannot open the NoMount netlink socket - this kernel has no NoMount "
                  "engine (CONFIG_NOMOUNT), or nm and the kernel were built with different "
                  "NOMOUNT_NL_PROTO values\n");
        exit_code = 2; goto do_exit;
    }
    set_recv_timeout(fd);

    static const struct { const char *name; char op; } nm_cmds[] = {
        { "add", 'a' },   { "del", 'd' },     { "w", 'w' },
        { "block", 'b' }, { "unblock", 'u' },  { "clear", 'c' },
        { "list", 'l' },  { "l", 'l' },        { "v", 'v' },
        { "k", 'k' },
    };
    char cmd = 0;
    for (unsigned int ci = 0; ci < sizeof(nm_cmds) / sizeof(nm_cmds[0]); ci++) {
        if (strcmp(argv[1], nm_cmds[ci].name) == 0) { cmd = nm_cmds[ci].op; break; }
    }
    if (!cmd) {
        print_err("nm: unknown command\n");
        exit_code = 3; goto do_exit;
    }
    const unsigned int target_uid = 0;
    unsigned int add_flags = 0;
    const char *p_args[64];
    int p_count = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--public") == 0) {
            add_flags |= 64;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            print_err("nm: unknown option\n");
            exit_code = 3; goto do_exit;
        } else if (p_count < 64) {
            p_args[p_count++] = argv[i];
        } else {
            print_err("nm: too many arguments (max 64)\n");
            exit_code = 3; goto do_exit;
        }
    }

    if (cmd == 'a' || cmd == 'd' || cmd == 'w') {
        int step = 1 + (cmd == 'a');
        if (p_count < step) { print_err("nm: missing operand\n"); exit_code = 3; goto do_exit; }
        if (p_count % step) { print_err("nm: odd number of add operands\n"); exit_code = 3; goto do_exit; }

        const char *cwd = (sys3(SYS_GETCWD, (long)mem.cwd_buf, PATH_MAX, 0) > 0) ? mem.cwd_buf : "/";
        char *cursor = mem.payload;

        int target_cmd = 2 + (cmd == 'd');
        exit_code = 0;

        for (int i = 0; i + step - 1 < p_count; i += step) {
            char *v_end = resolve_path(mem.v_resolved, cwd, p_args[i]);
            int v_len = v_end ? (int)(v_end - mem.v_resolved) : 0;
            if (!v_len) { print_err("nm: path too long: "); print_err(p_args[i]); print_err("\n");
                          exit_code = 3; continue; }

            int r_len = 0;
            if (cmd == 'a') {
                char *r_end = resolve_path(mem.r_resolved, cwd, p_args[i+1]);
                r_len = r_end ? (int)(r_end - mem.r_resolved) : 0;
                if (!r_len) { print_err("nm: path too long: "); print_err(p_args[i+1]); print_err("\n");
                              exit_code = 3; continue; }
            }

            int header_size = (target_cmd == 2) ? 12 : 6;
            if ((cursor - mem.payload) + header_size + v_len + r_len > MAX_PAYLOAD) {
                int rc = do_nm_cmd(fd,target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem);
                if (nm_timed_out(rc)) goto do_timeout;
                if (rc < 0) print_refused("this batch", rc);
                exit_code |= (rc < 0);
                cursor = mem.payload;
            }

            if (target_cmd == 2) {
                unsigned int hdr_flags = (cmd == 'w') ? 4u : add_flags;
                unsigned short hv = (unsigned short)v_len, hr = (unsigned short)r_len;
                memcpy(cursor + 0, &hdr_flags, 4);
                memcpy(cursor + 4, &target_uid, 4);
                memcpy(cursor + 8, &hv, 2);
                memcpy(cursor + 10, &hr, 2);
                memcpy(cursor + 12, mem.v_resolved, v_len);
                if (r_len > 0) memcpy(cursor + 12 + v_len, mem.r_resolved, r_len);
                cursor += 12 + v_len + r_len;
            } else {
                unsigned short hv = (unsigned short)v_len;
                memcpy(cursor + 0, &target_uid, 4);
                memcpy(cursor + 4, &hv, 2);
                memcpy(cursor + 6, mem.v_resolved, v_len);
                cursor += 6 + v_len;
            }
        }

        if (cursor > mem.payload) {
            int rc = do_nm_cmd(fd,target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem);
            if (nm_timed_out(rc)) goto do_timeout;
            if (rc < 0) print_refused("this batch", rc);
            exit_code |= (rc < 0);
        }

        goto do_exit;

    } else if (cmd == 'b' || cmd == 'u') {
        if (p_count < 1) { print_err("nm: missing uid\n"); exit_code = 3; goto do_exit; }
        unsigned int uid = 0; const char *s = p_args[0];
        int ndig = 0;
        if (!*s) goto bad_uid;
        while (*s) {
            if (*s < '0' || *s > '9') goto bad_uid;
            if (++ndig > 10 || uid > 429496729u ||
                (uid == 429496729u && *s > '5')) goto bad_uid;
            uid = (uid << 3) + (uid << 1) + (*s++ - '0');
        }
        int rc = do_nm_cmd(fd,6 - (cmd == 'b'), 4, &uid, 4, 5, &mem);
        if (nm_timed_out(rc)) goto do_timeout;
        if (rc < 0) print_refused((cmd == 'b') ? "block" : "unblock", rc);
        exit_code = (rc < 0);
        goto do_exit;

    } else if (cmd == 'k') {
        int knob = -1;
        const char *val;
        int vlen = 0;

        static const struct { const char *name; int knob; } nm_knobs[] = {
            { "d", 4 }, { "i", 5 }, { "g", 7 },
        };
        if (p_count < 1) { print_err("nm: missing knob\n"); exit_code = 3; goto do_exit; }
        for (unsigned int ki = 0; ki < sizeof(nm_knobs) / sizeof(nm_knobs[0]); ki++) {
            if (strcmp(p_args[0], nm_knobs[ki].name) == 0) { knob = nm_knobs[ki].knob; break; }
        }
        if (knob < 0) {
            print_err("nm: unknown knob\n");
            exit_code = 3; goto do_exit;
        }
        val = (p_count > 1) ? p_args[1] : "";
        while (val[vlen]) vlen++;
        if (4 + vlen > MAX_PAYLOAD) { print_err("nm: knob value too long\n"); exit_code = 3; goto do_exit; }
        *(unsigned int *)mem.payload = (unsigned int)knob;
        if (vlen) memcpy(mem.payload + 4, val, vlen);
        int rc = do_nm_cmd(fd, 9, 6, mem.payload, 4 + vlen, 5, &mem);
        if (nm_timed_out(rc)) goto do_timeout;
        if (rc < 0) print_refused("this knob", rc);
        exit_code = (rc < 0);
        goto do_exit;

    } else if (cmd == 'c') {
        int rc = do_nm_cmd(fd,4, 0, (void *)0, 0, 5, &mem);
        if (nm_timed_out(rc)) goto do_timeout;
        if (rc < 0) print_refused("clear", rc);
        exit_code = (rc < 0);
        goto do_exit;

    } else if (cmd == 'v') {
        int vlen_rx = do_nm_cmd(fd, 1, 0, (void *)0, 0, 1, &mem);
        if (nm_timed_out(vlen_rx)) goto do_timeout;
        struct nlmsghdr *vh = (struct nlmsghdr *)mem.rx_buf;
        if (vlen_rx >= 16 && vh->nlmsg_len <= (unsigned int)vlen_rx) {
            unsigned int *ver = get_attr(mem.rx_buf, 5, 4);
            if (ver) {
                print_uint(*ver);
                print_str("\n");
                exit_code = 0; goto do_exit;
            }
        }
        if (vlen_rx < 0) print_refused("the version query", vlen_rx);
        else print_err("nm: the engine did not answer with a version - it may be too old, or "
                       "built with a different NOMOUNT_NL_PROTO\n");
        exit_code = 1; goto do_exit;

    } else if (cmd == 'l') {
        int is_uids = 0, is_gh = 0;
        for (int i = 0; i < p_count; i++) {
            const char *a = p_args[i];
            if (a[0] && !a[1]) {
                if (a[0] == 'u') { is_uids = 1; continue; }
                if (a[0] == 'g') { is_gh = 1; continue; }
            }
            print_err("nm: unknown list option\n");
            exit_code = 3; goto do_exit;
        }

        int target_cmd = is_gh ? 11 : is_uids ? 8 : 7;
        int len = do_nm_cmd(fd,target_cmd, 0, (void *)0, 0, 0x301, &mem);
        int first = 1;
        if (nm_timed_out(len)) goto do_timeout;
        if (len < 0) goto list_refused;
        exit_code = 0;
        if (is_uids) print_str("[\n");

        while (len > 0) {
            for (struct nlmsghdr *msg = (void *)mem.rx_buf;
                    len >= 16 && msg->nlmsg_len >= 16 && msg->nlmsg_len <= (unsigned int)len;
                    len -= msg->nlmsg_len, msg = (void *)((char *)msg + msg->nlmsg_len)) {
                if (msg->nlmsg_type == 3) {
                    /* NLMSG_DONE carries an int status, and discarding it meant a dump
                     * the kernel had to cut short - ENOBUFS on a large rule table, or a
                     * dump callback that failed partway - was printed as a SHORT LIST
                     * WITH EXIT 0. Nothing downstream could tell an incomplete rule
                     * table from a complete one, and the Suite decides what is served
                     * from exactly this output. Older kernels send a bare DONE header
                     * with no payload, hence the length test rather than assuming one. */
                    if (msg->nlmsg_len >= 20 && *(int *)((char *)msg + 16)) {
                        print_refused("this dump at its end", *(int *)((char *)msg + 16));
                        print_err("nm: the rule list above is INCOMPLETE\n");
                        exit_code = 4;
                    }
                    goto list_done;
                }
                if (msg->nlmsg_type == 2) {
                    if (msg->nlmsg_len < 20) {
                        print_err("nm: the kernel ended this dump with a truncated error reply\n");
                        exit_code = 4;
                    } else if (*(int *)((char *)msg + 16)) {
                        print_refused("this dump partway through", *(int *)((char *)msg + 16));
                        exit_code = 4;
                    }
                    goto list_done;
                }

                if (is_gh) {
                    char *rule = get_attr_str(msg, 1);
                    if (rule) { print_str(rule); print_str("\n"); }
                } else if (is_uids) {
                    unsigned int *uid = get_attr(msg, 4, 4);
                    if (uid) {
                        if (!first) print_str(",\n");
                        print_str("  "); print_uint(*uid);
                        first = 0;
                    }
                } else {
                    char *v = get_attr_str(msg, 1);
                    char *r = get_attr_str(msg, 2);
                    unsigned int *flags = get_attr(msg, 3, 4);
                    unsigned int *uid = get_attr(msg, 4, 4);

                    if (v && r) {
                        int is_whiteout    = (flags && (*flags & 4));
                        int is_virtual_dir = (flags && (*flags & 2)); 
                        int is_public      = (flags && (*flags & 64));

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
            len = nm_read(fd, &mem);
            if (nm_timed_out(len)) goto do_timeout;
        }
        exit_code = 4;
        print_err("nm: rule dump ended early - list is incomplete\n");
        goto do_exit;
list_refused:
        exit_code = 4;
        print_err("nm: the kernel refused this dump - unsupported command, or an engine "
                  "too old to have it\n");
        goto do_exit;
list_done:
        if (is_uids) print_str("\n]\n");
    }
    goto do_exit;

bad_uid:
    print_err("nm: uid must be 1-10 digits and fit in 32 bits\n");
    exit_code = 3;
    goto do_exit;

do_timeout:
    print_err("nm: no answer from the kernel (timed out)\n");
    exit_code = NM_EXIT_TIMEOUT;

do_exit:
    sys1(SYS_EXIT, exit_code);
    __builtin_unreachable();
}
