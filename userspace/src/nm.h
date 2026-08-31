/* --- ARCH --- */
#if defined(__aarch64__)
    #define SYS_GETCWD     17
    #define SYS_READ       63
    #define SYS_WRITE      64
    #define SYS_EXIT       93
    #define SYS_SOCKET     198
    /* uapi/asm-generic/unistd.h: `#define __NR_setsockopt 208`. arm64 has no
     * syscall table of its own -- every other number in this block is the
     * asm-generic one too (17/63/64/93/198), which is what pins the numbering. */
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
    /* setsockopt() takes five arguments; nothing else here needs more than three.
     * Args 4 and 5 ride in x3/x4 -- same shape as sys3, two more registers. */
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
    /* arch/arm/tools/syscall.tbl: `294  common  setsockopt  sys_setsockopt`. */
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
    /* arch/x86/entry/syscalls/syscall_64.tbl: `54  64  setsockopt  sys_setsockopt`. */
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
    /* arg4 rides in r10 (not rcx) and arg5 in r8 -- the SYSCALL ABI, not the
     * function-call ABI; rcx/r11 are destroyed by the instruction itself. */
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

/* --- NETLINK DEFS --- */
#define AF_NETLINK 16
#define SOCK_RAW 3
#define NETLINK_GENERIC 16
/* Private raw-netlink protocol — MUST match kernel nomount.h NOMOUNT_NL_PROTO.
 * Replaces the old genl family "nomount" (enumerable via CTRL_CMD_GETFAMILY).
 * The command now travels in nlmsg_type as NM_TYPE_BASE + cmd (no genlmsghdr). */
/* #ifndef, so -DNOMOUNT_NL_PROTO=<n> on the build line actually works. The
 * kernel header guards its own definition the same way and documents
 * randomising the number per build; with an unguarded #define here that was a
 * redefinition, so the documented mitigation could not be used without editing
 * this file -- and a kernel built with a different number would simply never
 * answer, with no diagnostic beyond `nm v` printing nothing. Kernel and client
 * MUST be built with the same value. */
#ifndef NOMOUNT_NL_PROTO
#define NOMOUNT_NL_PROTO 29
#endif
#define NM_TYPE_BASE 0x10

/* --- RECEIVE TIMEOUT ---
 *
 * Every read on this socket used to be an UNBOUNDED blocking read: a kernel that
 * accepted the message and never answered hung the caller forever. metamount.sh
 * and post-fs-data.sh shell out to nm during post-fs-data, so "forever" means the
 * device never finishes booting. The shell callers wrap nm in `timeout` (60-90s),
 * but a hang is the client's bug, and the bound belongs where the socket is.
 *
 * SOL_SOCKET and SO_RCVTIMEO come from uapi/asm-generic/socket.h, which is the
 * header all three arches here use -- arm64's uapi/asm/Kbuild lists only
 * unistd_64.h and kvm_para.h, so socket.h arrives from the mandatory-generic set
 * verbatim. That header takes the `__BITS_PER_LONG == 64` branch on aarch64 and
 * x86_64 ("on 64-bit and x32, avoid the ?: operator"), where SO_RCVTIMEO is
 * SO_RCVTIMEO_OLD == 20; the _OLD option is the one that takes a `struct
 * __kernel_old_timeval` (two __kernel_long_t == two `long`), so one struct and
 * one constant serve every target here. On 32-bit arm the same 20 is what a
 * `long`-pair means: sock_copy_user_timeval() takes its in_compat_syscall()
 * branch and reads `struct old_timeval32`, also two 32-bit fields. optlen is
 * sizeof the struct in both cases and the kernel only requires optlen >= its own.
 *
 * SOL_SOCKET is dispatched by do_sock_setsockopt() to sock_setsockopt(), NOT to
 * netlink_setsockopt() (which returns -ENOPROTOOPT for anything but SOL_NETLINK),
 * and netlink_recvmsg -> skb_recv_datagram -> __skb_recv_datagram takes
 * sock_rcvtimeo(sk, ...) and returns -EAGAIN when it expires. So this really does
 * bound a plain read() on a netlink socket. */
#define SOL_SOCKET   1
#define SO_RCVTIMEO  20   /* == SO_RCVTIMEO_OLD */
#define NM_EAGAIN    11   /* uapi/asm-generic/errno-base.h; == EWOULDBLOCK */

/* Generous for a round-trip against an in-kernel rule table (the whole control
 * plane is a spinlock and a list walk) and an order of magnitude below the
 * shells' own `timeout`, so nm reports the failure itself instead of being killed
 * and leaving the caller to guess why. */
#define NM_RECV_TIMEOUT_SEC 5

/* The receive timeout, mapped to a value no kernel answer can collide with.
 *
 * It CANNOT stay -EAGAIN: do_nm_cmd() also decodes an NLMSG_ERROR body into the
 * same return value, and -EAGAIN is exactly what the kernel replies when a dump
 * aborts because the rule table mutated under the cursor (see the dump loop in
 * nm.c). Conflating the two would report a live, answering kernel as silent.
 * netlink errors are -errno and MAX_ERRNO is 4095, so -4096 is unreachable. */
#define NM_ERR_TIMEOUT (-4096)

/* Exit status reserved for "the kernel never answered", distinct from the generic
 * failure (1), socket creation (2), argument errors (3) and the truncated-dump
 * failure (4): a caller deciding whether to retry needs to tell "the kernel
 * refused" from "the kernel went silent". */
#define NM_EXIT_TIMEOUT 5

/* struct __kernel_old_timeval -- two __kernel_long_t, i.e. two `long`. */
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

/* Diagnostics for the commands that STREAM their result to stdout go to fd 2, so
 * a failure message can never be read back as a rule, nor land inside the JSON
 * array the same run is emitting. */
static noinline void print_err(const char *s) {
    long len = 0;
    while (s[len]) len++;
    sys3(SYS_WRITE, 2, (long)s, len);
}

static noinline void print_uint(unsigned int n) {
    char buf[12];
    int i = 11;
    buf[i] = '\0';

    do {
        buf[--i] = (n % 10) + '0';
        n /= 10;
    } while (n > 0);    
    print_str(&buf[i]);
}

/* path resolution */
static noinline char* resolve_path(char *p, const char *cwd, const char *rel) {
    char *end = p + PATH_MAX - 1; /* leave room for the terminating NUL */
    if (cwd && *rel != '/') {
        while (*cwd && p < end) *p++ = *cwd++;
        if (*cwd) return (char *)0;        /* cwd alone overran the buffer */
        if (p < end) *p++ = '/'; /* Linux VFS treats "//" exactly as "/" */
    }
    while (*rel && p < end) *p++ = *rel++;
    if (*rel) return (char *)0;            /* path too long -> refuse, do not truncate */
    *p = '\0';
    return p; /* Points exactly to '\0' */
}

static noinline void *get_attr(const void *nh, int type) {
    unsigned int max_len = ((struct nlmsghdr *)nh)->nlmsg_len;
    /* attrs sit directly after the nlmsghdr (16B) — no genlmsghdr (was +20) */
    char *attr = (char *)nh + 16;
    while ((attr - (char *)nh) + 4 <= max_len) {
        unsigned short alen = *(unsigned short *)attr;
        /* The payload must also FIT: without this a truncated attribute yields a
         * pointer running past the message, which print_str() then walks to a NUL. */
        if (alen < 4 || (attr - (char *)nh) + alen > max_len) break;
        if (*(unsigned short *)(attr + 2) == type) return attr + 4;
        attr += (alen + 3) & -4;
    }
    return (void *)0;
}

/* Bound every read on this socket. Called once, right after socket(), so it
 * covers do_nm_cmd()'s reply read AND the dump loop's continuation reads.
 *
 * Best-effort by design: a kernel that refuses the option is a kernel that is
 * answering, which is no reason to refuse the command. It would leave that build
 * with the old unbounded behaviour, which the shells' `timeout` still backstops. */
static noinline void set_recv_timeout(int fd) {
    struct nm_timeval tv;
    tv.tv_sec = NM_RECV_TIMEOUT_SEC;
    tv.tv_usec = 0;
    sys5(SYS_SETSOCKOPT, fd, SOL_SOCKET, SO_RCVTIMEO, (long)&tv, (long)sizeof(tv));
}

/* The only read() on this socket. The socket is blocking and never gets
 * O_NONBLOCK, so -EAGAIN from it can only be the receive timeout expiring --
 * a kernel-side EAGAIN arrives as an NLMSG_ERROR body, not as a read error. */
static noinline int nm_read(int fd, struct nm_mem *mem) {
    int res = sys3(SYS_READ, fd, (long)mem->rx_buf, RX_BUF_SIZE);
    return (res == -NM_EAGAIN) ? NM_ERR_TIMEOUT : res;
}

/* True when the kernel took the message and never answered. Takes an int because
 * that is what do_nm_cmd() and the dump loop hold. */
static noinline int nm_timed_out(int res) { return res == NM_ERR_TIMEOUT; }

/* init_msg + add_attr + send_and_recv unified (raw netlink: command in
 * nlmsg_type = NM_TYPE_BASE + cmd, attrs directly after the nlmsghdr) */
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
    /* >= 20, not >= 16: the nlmsgerr error field sits at offset 16 (directly
     * after the 16-byte nlmsghdr) and is FOUR bytes wide, so a 16..19-byte reply
     * passed the old test and was then read past its end. A timeout is
     * NM_ERR_TIMEOUT here, which is negative and so skips this decode untouched:
     * every caller's existing `< 0` test still fails the command, and
     * nm_timed_out() lets the call site report it as itself. */
    if (res >= 20 && ((struct nlmsghdr *)mem->rx_buf)->nlmsg_type == 2) res = *(int *)(mem->rx_buf + 16);

    return res;
}
