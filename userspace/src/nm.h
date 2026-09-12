/* --- arch --- */
#if defined(__aarch64__)
    #define SYS_GETCWD     17
    #define SYS_READ       63
    #define SYS_WRITE      64
    #define SYS_EXIT       93
    #define SYS_SOCKET     198
    #define SYS_SETSOCKOPT 208

    __attribute__((always_inline)) static inline long sys1(long n, long a) {
        register long x8 asm("x8") = n; register long x0 asm("x0") = a;
        __asm__ __volatile__("svc 0" : "+r"(x0) : "r"(x8) : "memory", "cc");
        return x0;
    }
    __attribute__((always_inline)) static inline long sys3(long n, long a, long b, long c) {
        register long x8 asm("x8") = n; register long x0 asm("x0") = a; register long x1 asm("x1") = b; register long x2 asm("x2") = c;
        __asm__ __volatile__("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
        return x0;
    }
    __attribute__((always_inline)) static inline long sys5(long n, long a, long b, long c, long d, long e) {
        register long x8 asm("x8") = n; register long x0 asm("x0") = a; register long x1 asm("x1") = b;
        register long x2 asm("x2") = c; register long x3 asm("x3") = d; register long x4 asm("x4") = e;
        __asm__ __volatile__("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory", "cc");
        return x0;
    }
    __asm__( ".global _start\n" ".type _start, %function\n" "_start:\n" "mov x0, sp\n" "b c_main\n" );

#elif defined(__arm__)
    #define SYS_EXIT       1
    #define SYS_READ       3
    #define SYS_WRITE      4
    #define SYS_GETCWD     183
    #define SYS_SOCKET     281
    #define SYS_SETSOCKOPT 294

    __attribute__((always_inline)) static inline long sys1(long n, long a) {
        register long r7 asm("r7") = n; register long r0 asm("r0") = a;
        __asm__ __volatile__("svc 0" : "+r"(r0) : "r"(r7) : "memory", "cc");
        return r0;
    }
    __attribute__((always_inline)) static inline long sys3(long n, long a, long b, long c) {
        register long r7 asm("r7") = n; register long r0 asm("r0") = a; register long r1 asm("r1") = b; register long r2 asm("r2") = c;
        __asm__ __volatile__("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory", "cc");
        return r0;
    }
    __attribute__((always_inline)) static inline long sys5(long n, long a, long b, long c, long d, long e) {
        register long r7 asm("r7") = n; register long r0 asm("r0") = a; register long r1 asm("r1") = b;
        register long r2 asm("r2") = c; register long r3 asm("r3") = d; register long r4 asm("r4") = e;
        __asm__ __volatile__("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4) : "memory", "cc");
        return r0;
    }
    __asm__( ".global _start\n" ".type _start, %function\n" "_start:\n" "mov r0, sp\n" "b c_main\n");

#elif defined(__x86_64__)
    #define SYS_READ       0
    #define SYS_WRITE      1
    #define SYS_SOCKET     41
    #define SYS_SETSOCKOPT 54
    #define SYS_EXIT       60
    #define SYS_GETCWD     79

    __attribute__((always_inline)) static inline long sys1(long n, long a) {
        long ret; __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a) : "rcx", "r11", "memory", "cc");
        return ret;
    }
    __attribute__((always_inline)) static inline long sys3(long n, long a, long b, long c) {
        long ret; __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory", "cc");
        return ret;
    }
    __attribute__((always_inline)) static inline long sys5(long n, long a, long b, long c, long d, long e) {
        long ret;
        register long r10 asm("r10") = d; register long r8 asm("r8") = e;
        __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8) : "rcx", "r11", "memory", "cc");
        return ret;
    }
    __asm__( ".global _start\n" ".type _start, @function\n" "_start:\n" "mov %rsp, %rdi\n" "jmp c_main\n" );

#else
    #error "Arch not supported"
#endif

#define AF_NETLINK 16
#define SOCK_RAW 3
#define NETLINK_GENERIC 16
#ifndef NOMOUNT_NL_PROTO
#define NOMOUNT_NL_PROTO 29
#endif
#define NM_TYPE_BASE 0x10

#define SOL_SOCKET   1
#define SO_RCVTIMEO  20
#define NM_EAGAIN    11

#define NM_RECV_TIMEOUT_SEC 5

#define NM_ERR_TIMEOUT (-4096)

#define NM_EXIT_TIMEOUT 5

struct nm_timeval { long tv_sec; long tv_usec; };

struct nlmsghdr {
    unsigned int   nlmsg_len;
    unsigned short nlmsg_type;
    unsigned short nlmsg_flags;
    unsigned int   nlmsg_seq;
    unsigned int   nlmsg_pid;
};

#define PATH_MAX  4096
#define RX_BUF_SIZE 32768
#define TX_BUF_SIZE 16384
#define MAX_PAYLOAD (TX_BUF_SIZE - 88)

struct nm_mem {
    char rx_buf[RX_BUF_SIZE];
    char tx_buf[TX_BUF_SIZE];
    char v_resolved[PATH_MAX];
    char r_resolved[PATH_MAX];
    char cwd_buf[PATH_MAX];
    char payload[MAX_PAYLOAD];
} __attribute__((aligned(16)));

#define noinline __attribute__((noinline))
#if defined(__x86_64__)
static noinline void *memcpy(void *dst, const void *src, unsigned long n) {
    void *ret = dst;
    __asm__ __volatile__("rep movsb" : "+D"(dst), "+S"(src), "+c"(n) : : "memory");
    return ret;
}
#else
static noinline void *memcpy(void *dst, const void *src, unsigned long n) {
    char *d = dst;
    const char *s = src;
    while (n--) { *d++ = *s++; }
    return dst;
}
#endif

static noinline int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static noinline void print_str(const char *s) {
    long len = 0;
    while (s[len]) len++;
    sys3(SYS_WRITE, 1, (long)s, len);
}

static noinline void print_err(const char *s) {
    long len = 0;
    while (s[len]) len++;
    sys3(SYS_WRITE, 2, (long)s, len);
}

static noinline void print_num(int fd, unsigned int n) {
    char buf[12];
    int i = 11;
    buf[i] = '\0';

    do {
        buf[--i] = (n % 10) + '0';
        n /= 10;
    } while (n > 0);
    long len = 0;
    while (buf[i + len]) len++;
    sys3(SYS_WRITE, fd, (long)&buf[i], len);
}

static noinline void print_uint(unsigned int n) { print_num(1, n); }

static noinline void print_refused(const char *what, int rc) {
    print_err("nm: the kernel refused ");
    print_err(what);
    print_err(" (errno ");
    print_num(2, rc < 0 ? -(unsigned int)rc : (unsigned int)rc);
    print_err(")\n");
}

static noinline char* resolve_path(char *p, const char *cwd, const char *rel) {
    char *end = p + PATH_MAX - 1;
    if (cwd && *rel != '/') {
        while (*cwd && p < end) *p++ = *cwd++;
        if (*cwd) return (char *)0;
        if (p < end) *p++ = '/';
    }
    while (*rel && p < end) *p++ = *rel++;
    if (*rel) return (char *)0;
    *p = '\0';
    return p;
}

static noinline void *get_attr(const void *nh, int type, unsigned int min_payload) {
    unsigned int max_len = ((struct nlmsghdr *)nh)->nlmsg_len;
    char *attr = (char *)nh + 16;
    while ((attr - (char *)nh) + 4 <= max_len) {
        unsigned short alen = *(unsigned short *)attr;
        if (alen < 4 || (attr - (char *)nh) + alen > max_len) break;
        if (*(unsigned short *)(attr + 2) == type)
            return (alen >= 4 + min_payload) ? attr + 4 : (void *)0;
        attr += (alen + 3) & -4;
    }
    return (void *)0;
}

static noinline char *get_attr_str(const void *nh, int type) {
    char *s = get_attr(nh, type, 1);
    if (!s) return (char *)0;
    unsigned int alen = *(unsigned short *)(s - 4);
    for (unsigned int p = 0; 4 + p < alen; p++)
        if (!s[p]) return s;
    return (char *)0;
}

static noinline void set_recv_timeout(int fd) {
    struct nm_timeval tv;
    tv.tv_sec = NM_RECV_TIMEOUT_SEC;
    tv.tv_usec = 0;
    sys5(SYS_SETSOCKOPT, fd, SOL_SOCKET, SO_RCVTIMEO, (long)&tv, (long)sizeof(tv));
}

static noinline int nm_read(int fd, struct nm_mem *mem) {
    int res = sys3(SYS_READ, fd, (long)mem->rx_buf, RX_BUF_SIZE);
    return (res == -NM_EAGAIN) ? NM_ERR_TIMEOUT : res;
}

static noinline int nm_timed_out(int res) { return res == NM_ERR_TIMEOUT; }

static noinline int do_nm_cmd(int fd, int cmd, int atype, const void *data, int len, int flags, struct nm_mem *mem) {
    struct nlmsghdr *nlh = (void *)mem->tx_buf;
    nlh->nlmsg_type = NM_TYPE_BASE + cmd;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_len = 16;

    if (data) {
        unsigned short *nla = (void *)(mem->tx_buf + 16);
        nla[0] = 4 + len; nla[1] = atype;
        memcpy(nla + 2, data, len);
        nlh->nlmsg_len = 16 + nla[0];
    }

    int res = sys3(SYS_WRITE, fd, (long)nlh, nlh->nlmsg_len);
    if (res < 0) return res;
    res = nm_read(fd, mem);
    if (res >= 20 && ((struct nlmsghdr *)mem->rx_buf)->nlmsg_type == 2) res = *(int *)(mem->rx_buf + 16);

    return res;
}
