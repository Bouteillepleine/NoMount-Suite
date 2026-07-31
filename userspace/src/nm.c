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

    int fd = sys3(SYS_SOCKET, AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) { exit_code = 2; goto do_exit; }

    int nm_family = -1;
    if (do_nm_cmd(fd, 16, 3, 2, "nomount", 8, 1, &mem) > 0) {
        unsigned short *fam_id = get_attr(mem.rx_buf, 1);
        if (fam_id) nm_family = *fam_id;
    }
    if (nm_family < 0) { exit_code = 3; goto do_exit; }

    char cmd = argv[1][0];
    unsigned int target_uid = 0;
    const char *p_args[64];
    int p_count = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
            const char *s = argv[++i];
            while (*s) target_uid = (target_uid << 3) + (target_uid << 1) + (*s++ - '0');
        } else if (p_count < 64) {
            p_args[p_count++] = argv[i];
        }
    }

    if (cmd == 'a' || cmd == 'd' || cmd == 'w') {
        int step = 1 + (cmd == 'a');
        if (p_count < step) { exit_code = 0; goto do_exit; }

        const char *cwd = (sys3(SYS_GETCWD, (long)mem.cwd_buf, PATH_MAX, 0) > 0) ? mem.cwd_buf : "/";
        char *cursor = mem.payload;

        int target_cmd = 2 + (cmd == 'd');
        exit_code = 0;

        for (int i = 0; i + step - 1 < p_count; i += step) {
            char *v_end = resolve_path(mem.v_resolved, cwd, p_args[i]);
            int v_len = v_end - mem.v_resolved;
            if (!v_len) { exit_code = 3; continue; }

            int r_len = 0;
            if (cmd == 'a') {
                char *r_end = resolve_path(mem.r_resolved, cwd, p_args[i+1]);
                r_len = r_end - mem.r_resolved;
                if (!r_len) { exit_code = 3; continue; }
            }

            int header_size = (target_cmd == 2) ? 12 : 6;
            if ((cursor - mem.payload) + header_size + v_len + r_len > MAX_PAYLOAD) {
                exit_code |= (do_nm_cmd(fd, nm_family, target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem) < 0);
                cursor = mem.payload;
            }

            if (target_cmd == 2) { /* ADD / WHITEOUT */
                *(unsigned int*)cursor = (cmd == 'w') ? 4 : 0; 
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
            exit_code |= (do_nm_cmd(fd, nm_family, target_cmd, 6, mem.payload, cursor - mem.payload, 5, &mem) < 0);

        goto do_exit;

    } else if (cmd == 'b' || cmd == 'u') {
        if (p_count < 1) goto do_exit;
        unsigned int uid = 0; const char *s = p_args[0];
        while (*s) uid = (uid << 3) + (uid << 1) + (*s++ - '0');
        exit_code = (do_nm_cmd(fd, nm_family, 6 - (cmd == 'b'), 4, &uid, 4, 5, &mem) < 0);
        goto do_exit;

    } else if (cmd == 'c') {
        exit_code = (do_nm_cmd(fd, nm_family, 4, 0, (void *)0, 0, 5, &mem) < 0);
        goto do_exit;

    } else if (cmd == 'v') {
        if (do_nm_cmd(fd, nm_family, 1, 0, (void *)0, 0, 1, &mem) > 0) {
            unsigned int *ver = get_attr(mem.rx_buf, 5);
            if (ver) {
                unsigned int v = *ver; char v_str[4] = {0};
                unsigned char tens = ((v << 7) + (v << 6) + (v << 3) + (v << 2) + v) >> 11;
                v = v - ((tens << 3) + (tens << 1));
                v_str[0] = tens + '0'; v_str[1] = v + '0'; v_str[2] = '\n';
                print_str(v_str);
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
        unsigned int len = do_nm_cmd(fd, nm_family, target_cmd, 0, (void *)0, 0, 0x301, &mem);
        int offset = 2;
        if (is_json) print_str("[\n");

        while (len > 0) {
            for (struct nlmsghdr *msg = (void *)mem.rx_buf; msg->nlmsg_len && msg->nlmsg_len <= len;
                    len -= msg->nlmsg_len, msg = (void *)((char *)msg + msg->nlmsg_len)) {
                if (msg->nlmsg_type == 3 || msg->nlmsg_type == 2) goto list_done; 

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

                        if (is_json) {
                            print_str((const char *)",\n  {\n    \"virtual\": \"" + offset); offset = 0;
                            print_str(v);
                            if (is_whiteout) print_str("\",\n    \"whiteout\": true");
                            else if (is_virtual_dir) print_str("\",\n    \"virtual_dir\": true");
                            else { print_str("\",\n    \"real\": \""); print_str(r); print_str("\""); }
                            if (uid && *uid != 0) { print_str(",\n    \"uid\": "); print_uint(*uid); }
                            print_str("\n  }");
                        } else {
                            print_str(v);
                            if (is_whiteout) print_str(" (whiteout)");
                            else if (is_virtual_dir) print_str(" (virtual dir)");
                            else { print_str(" -> "); print_str(r); }
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
        exit_code = 0;
    }

do_exit:
    sys1(SYS_EXIT, exit_code);
    __builtin_unreachable();
}
