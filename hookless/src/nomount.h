#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/file.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jump_label.h>

/* The PUBLISHED label, and nothing else. Nothing in the driver reads it; the
 * BUILDERS scrape it out of this header to name the kernel they release.
 *
 * Shaped 1.<NOMOUNT_VERSION>.0 on purpose. The product line is 1.x -- an engine
 * label of "18.0" read like a major version eighteen releases along, next to a
 * Suite at 1.3.x. But the middle field is still NOMOUNT_VERSION, the capability
 * counter userspace actually gates on, so the label cannot drift away from what
 * the engine really speaks: the last time these were maintained as two
 * independent numbers the engine went to 16 while this still said "15.0" and the
 * build summary announced a version the kernel did not implement.
 *
 * Do NOT collapse this to a bare "1.0", and do NOT renumber NOMOUNT_VERSION to
 * match it. That counter is monotonic capability, not marketing: the Suite gates
 * on `< 13`, `< 15`, `15..18` and `>= 17`, and an older kernel reporting a HIGHER
 * number than a newer one inverts every one of those silently. */
#define NM_MODULE_VERSION "1.30.0"
/* Bumped for the directory-size correction: userspace has no other way to tell
 * whether the running engine keeps a managed erofs directory's i_size in step
 * with the listing. The Suite refuses whiteouts on non-overlayfs precisely
 * because an older engine did not, so it must be able to gate that refusal on
 * >= 13 rather than assume. Nothing compares this for equality -- the nm client
 * only parses it for liveness -- so raising it is safe.
 *
 * 14: three behaviour changes userspace can otherwise not detect.
 *  - A replaced rule now refreshes the parent's child node completely (d_type
 *    and fake_ino). On 13 and earlier a reload that shadowed a rule left a
 *    directory whose link count contradicted its contents -- measured as nlink 2
 *    on a dir that had gained a subdirectory.
 *  - The parent's size correction is now derived per-caller from the live child
 *    flags (nm_dir_deltas) instead of a cached counter, so a --uid-scoped rule no
 *    longer shifts the reported directory SIZE for callers it does not target
 *    while moving the link count only for the one it does.
 *  - NM_CMD_ADD_RULE's batch form returns the first rejection instead of an
 *    unconditional 0, so a refused rule is no longer indistinguishable from an
 *    applied one. The Suite's per-entry failure counters become meaningful only
 *    against >= 14.
 *
 * 15: NM_FLAG_PUBLIC exists (see below). An engine below this strips the bit
 *    with every other unknown one, so a Suite that sets it gets the old
 *    behaviour silently -- an added ROM APK stays hidden from a blocked reader
 *    and the PackageManager keeps advertising a path that app cannot open.
 *    Userspace can only warn about that if it can tell the two apart.
 *
 * 16: RETRACTED. This announced that the engine could carry the _pathhide
 *    cloak's configuration. It no longer can: the knob and the dump command are
 *    both retired (slots reserved, see below), because no builder applies that
 *    patch set and the forwarder therefore answered -EINVAL on every kernel
 *    that shipped. An engine reporting >= 16 does NOT imply pathhide support;
 *    nothing in the Suite asks, and the version is not lowered because 17 and
 *    above make claims that still hold.
 *
 * 17: NM_FLAG_PUBLIC now SURVIVES on a rule that shadows a stock APK, where 16
 *    and earlier stripped it unconditionally. Below 17 a blocked reader opening
 *    a replaced ROM APK gets the STOCK bytes while the PackageManager -- which
 *    parsed the module's copy as system_server -- advertises the module's version
 *    and signature for that same path, a disagreement any app can measure.
 *    Measured on OP15 against a 16 engine: PM reported com.android.contacts
 *    16.80.0 from a 74641847-byte /product/priv-app/Contacts/Contacts.apk while a
 *    blocked uid read the 64249089-byte stock APK there. Userspace sets the bit
 *    identically either way, so this is invisible without a version to gate on.
 *
 * 18: 17 kept the bit but nothing acted on it -- nm_stock_for_caller() decided
 *    with the raw blocked-uid test, so open/getattr/xattr still handed a blocked
 *    reader the stock file and 17 was observationally identical to 16. It now
 *    asks nm_uid_hidden(), so a PUBLIC shadowing rule really does serve OUR bytes.
 *    The exemption also widened from "*.apk" to "anything under a directory the
 *    PackageManager scans", because PM publishes a package's nativeLibraryDir as
 *    well as its APK: measured on OP15, a blocked uid got ENOENT for all 25
 *    shared libraries under /product/priv-app/Mms/lib/arm64 while PM advertised
 *    that directory to every app. Below 18 a Suite cannot tell whether the bit it
 *    set is honoured, so `doctor` cannot report the difference.
 *
 * 19: directories answer fsync() the way a real directory at that path does.
 *    nm_dir_fops carried no .fsync, so every directory we serve returned -EINVAL
 *    regardless of what it sat on -- and on an overlay-backed ROM dir that is a
 *    one-syscall, baseline-free oracle. Measured on OP15 /product/priv-app: the
 *    three synthesized dirs (Mms, Mms/lib, Mms/lib/arm64) returned EINVAL while
 *    all six stock package dirs beside them, at every depth, returned 0. A
 *    synthesized dir now replays the nearest real ANCESTOR DIRECTORY's answer,
 *    the same v_cap mechanism 18 introduced for files. Userspace cannot set or
 *    observe this, so the bump exists purely so `doctor` can tell a flashed
 *    engine from the one it replaced.
 *
 * 20: two fixes found by exercising a DIR-TARGET rule on-device for the first
 *    time (no rule of that shape had ever run). NM_CAP_KNOWN splits "we sampled
 *    stock and it has no ->fsync" from "we never sampled": the two used to share
 *    the encoding v_cap == 0, and the ops read that as never-sampled and
 *    forwarded to the f2fs backing file -- so on an erofs path fsync() answered
 *    0 where every stock sibling answers -EINVAL, reopening the oracle 19
 *    closed, for any rule whose caps came from a sibling scan. And nm_child_ino
 *    now scales its band to the parent instead of stepping a fixed 1 MB, which
 *    only preserved magnitude when the parent ino already exceeded 1 MB;
 *    measured at /product/etc (dir ino 15018, siblings 7166..20309) minting
 *    children at 1226252..2181515. Neither is userspace-settable; the bump
 *    exists so `doctor` can tell this engine from v19.
 *
 * 22: an adversarial re-read of 20/21 found two lifetime bugs in that work and a
 *    set of wrong version guards. nomount_hijacked_destroy_inode armed call_rcu
 *    BEFORE clearing i_private -- call_rcu only waits for readers already in
 *    progress, so a reader entering after the arm (nm_d_revalidate's own RCU fast
 *    path does exactly this read) could load a pointer the callback was free to
 *    release; it now unpublishes first. nm_rule_gen was sampled AFTER reading the
 *    rule table while writers publish-then-increment, so an add/del landing in
 *    that window stamped an inode with the NEW generation although it had been
 *    validated against the OLD topology -- an `nm del` racing a revalidate kept
 *    serving the deleted rule from the cached dentry; sampling before makes the
 *    error one-directional (a stamp can only be staler, costing one ref-walk).
 *    Userspace-observable, and the reason for the bump: .readlink is now on
 *    nm_dir_iops too, so a hidden DIRECTORY answers -ENOENT rather than the
 *    -EINVAL-vs--ENOENT discriminator (21 fixed only nm_file_iops), and
 *    __nomount_clear_all now resets the inode-placement caches, so injected
 *    st_ino is stable across reload passes instead of drifting and eventually
 *    re-creating the dense consecutive run nm_place_ino exists to avoid.
 *
 * 23: ioctl() no longer pays for an open it cannot need. nm_ioctl_as_stock
 *    always did dentry_open + dispatch + fput on the stock path, even when that
 *    inode carries neither ->unlocked_ioctl nor ->compat_ioctl and the dispatch
 *    was therefore guaranteed to reach -ENOTTY. Both sides returned the same
 *    errno, so only the COST separated them -- and it did, cleanly. Measured on
 *    OP15 with an unknown cmd on erofs-backed paths, n=12 per side, 3000 reps
 *    per file, per-file median: injected 938..1823ns against stock siblings
 *    521..781ns. Disjoint, so one threshold classified every file, unprivileged,
 *    with each file its own baseline. Now short-circuited to -ENOTTY when stock
 *    could not have answered otherwise; overlay-backed paths still open and
 *    forward, because ovl_file_operations DOES implement ->unlocked_ioctl.
 *
 * 24: the mmap path no longer installs the BACKING filesystem's vm_ops over our
 *    file. It used to point vma->vm_file at the backing file, call its ->mmap,
 *    and restore vm_file -- leaving f2fs_file_vm_ops behind, whose .fault and
 *    .page_mkwrite begin with F2FS_I_SB(file_inode(vma->vm_file)) on what is now
 *    an erofs or overlayfs inode. Measured from the device's own BTF:
 *    f2fs_sb_info.iostat_enable at +4376 and iostat_lock at +3676 against a
 *    472-byte erofs_sb_info (176 for ovl_fs), i.e. a ~4KB out-of-bounds read on
 *    every faulted page of every injected mapping, surviving only because that
 *    byte read zero. Now generic_file_readonly_mmap(), which is exactly what
 *    erofs_file_mmap is -- so an injected file gets the same generic_file_vm_ops
 *    as its stock siblings, and a shared+maywrite mapping is refused with
 *    -EINVAL as stock refuses it, instead of being allowed by f2fs.
 *
 * 25: readdir cookies. A SYNTHESIZED directory emitted d_off as a plain counter
 *    (1, 3, 4 ... 28) where erofs emits each dirent at its byte offset in the
 *    directory -- 12*(j+1) within a block, ending on i_size. Measured on OP15:
 *    /product/priv-app/Mms/lib/arm64 gave 1,3,4..28 against its stock peer
 *    /product/priv-app/AIUnit/lib/arm64 at 12,24,36..314. i_size was already
 *    right, so only the cookies betrayed it. The emitter now replays the same
 *    block walk nm_vdir_size() uses, so the terminal cookie and the reported
 *    size are one computation rather than two that happen to agree; the model
 *    was checked against four real erofs dirs (190/432/942/1284 entries, up to
 *    12 blocks) with zero mismatches. st_blocks now follows st_size for those
 *    dirs too -- it was stamped at 8 sectors and never updated, which was only
 *    correct while the size fit in one block.
 *
 *    A DIR-TARGET rule (backing directory on /data) additionally reported the
 *    f2fs directory's own size and hash-ordered children: measured 3452 bytes
 *    and out-of-order=3 where stock erofs dirs on the same path are the closed
 *    form and fully sorted. Both now come from one bounded, cached, sorted
 *    snapshot of the backing directory, so size, blocks and cookies agree by
 *    construction. Narrowly gated to the pure "serve a /data dir as a ROM dir"
 *    shape; a directory that also has injected children keeps the existing
 *    merge semantics.
 *
 * 26: NM_KNOB_GHOST and NM_CMD_GET_GHOST exist, i.e. this engine can forward
 *    control commands to the _ghost existence cloak and dump its tables. Same
 *    shape as the retired pathhide pair (slot 6), including the empty-value
 *    presence probe.
 *
 *    This matters more than a usual capability bump. _ghost's guards are INERT
 *    until its two tables are populated -- ghost_hidden_path() short-circuits to
 *    false on an empty table -- so a kernel carrying the patches without this
 *    forwarder behaves exactly like an unpatched one. Measured on OP15: a v25
 *    kernel built WITH _ghost still leaked all four oracles (O_PATH returned the
 *    path, getxattr the label, a trailing component ENOTDIR, link EXDEV) because
 *    nothing could reach ghost_ctl(). Below 26 a Suite cannot populate them and
 *    cannot tell that it cannot.
 *
 * 27: a PASSTHROUGH child of a dir-target rule that shadows a real directory now
 *    carries its OWN s_path. 26 and earlier inherited NM_FLAG_SHADOWS_STOCK down
 *    to such a child without inheriting anything for it to point at, and the two
 *    halves of the per-UID pair then disagreed: nm_hidden_from_caller() saw the
 *    flag and declined to answer -ENOENT, while nm_stock_for_caller() found no
 *    s_path and returned NULL -- so a blocked reader was served the MODULE's
 *    bytes for every name under that directory, while its nm_open() of the
 *    PARENT handed it the pinned stock directory. readdir listed stock names,
 *    lookup resolved module content, and per-UID hiding leaked precisely what it
 *    exists to hide. nm_dir_child_lookup() now resolves the same name under the
 *    parent's stock directory: found -> pinned and served; genuinely absent ->
 *    the flag is stripped so the child is hidden like any other added name;
 *    unresolvable -> flags untouched, because "could not ask" is not "not there".
 *
 *    Reachable only through a hand-issued `nm add <existing-dir> <dir>`: the
 *    Suite's own plan refuses a target that resolves to a live directory
 *    (mount.rs::inject_would_mask_dir) and its CLI refuses a directory source, so
 *    no shipped configuration builds that rule shape and no device measured here
 *    carried one. Userspace can neither set nor observe the difference, so the
 *    bump exists so `doctor` can tell a flashed engine from the one it replaced --
 *    the same reason 19, 20, 22 and 25 have one.
 *
 *    MEASURED, and the first build of it did nothing -- see 28.
 *
 * 28: 27's stock-child lookup ran under override_creds(nm_root_cred), whose SID
 *    is the KERNEL's rather than root's (prepare_creds() at fs_initcall), and
 *    lookup_one_len_unlocked() ends in inode_permission(), which runs the LSM.
 *    Asked of the live policy through /sys/fs/selinux/access on an OP15:
 *        kernel_t -> system_file       dir:search  ALLOWED (0x11140053)
 *        kernel_t -> system_data_file  dir:search  ALLOWED
 *        kernel_t -> shell_data_file   dir:search  DENIED  (0x0)
 *        kernel_t -> adb_data_file     dir:search  DENIED  (0x0)
 *    so on any /data-labelled target the lookup returned -EACCES, took the error
 *    arm, pinned nothing, and left 26's behaviour in place -- silently, because
 *    that denial is dontaudit'd and logs no AVC. Same rule shape, blocked reader,
 *    two labels:
 *        shell_data_file        both.txt = MODULE  modonly = MODULE   (inert)
 *        system_data_root_file  both.txt = STOCK   modonly = <ENOENT> (works)
 *    The other nm_root_cred users in this file never noticed because they only
 *    ever scan ROM paths, where kernel_t is allowed -- which is also why 27 would
 *    have worked on every case the Suite can actually produce. (NOT QUITE: see
 *    29, which found the one that does not scan a ROM path.)
 *
 *    It uses the CALLER's creds now, matching the module-side lookup beside it.
 *
 *    THE BUMP IS THE POINT, not the fix. Two builds answered `nm v` with 27 and
 *    behaved differently: the one flashed from the first commit is inert on
 *    /data labels, this one is not. A capability counter exists so `doctor` can
 *    tell a flashed engine from the one it replaced, and 27 can no longer do
 *    that for itself.
 *
 * 29: 28's closing claim was wrong about one caller. nm_dsnap_make() opens the
 *    rule's BACKING directory -- /data, by construction -- and it is the only
 *    nm_root_cred user in the file that is not a ROM scan, so it lands on exactly
 *    the labels 28 measured kernel_t as denied on. The failure was then CACHED:
 *    the descriptor was published with ok = false, which is the encoding for
 *    "walked it, does not qualify", so the v25 dir-target correction (erofs
 *    closed-form size, sorted children, matching cookies) stayed off for that
 *    rule until the backing directory's size or mtime moved -- and silently,
 *    because the denial is dontaudit'd there too. "Could not ask" is not a
 *    verdict: the open failure now publishes nothing and retries, and says so
 *    once. The caller's creds are deliberately NOT used here, unlike 28's fix --
 *    an app reading an injected ROM directory cannot search a module tree, so
 *    that would disable the correction for precisely the readers it exists for.
 *
 *    Also in 29, neither userspace-observable but both changing what a flashed
 *    engine does on a failure path: nomount_hijack_superblock() can now report
 *    -ENOMEM instead of returning void, so a rule is refused rather than served
 *    on a superblock whose ->destroy_inode we never installed (which leaked every
 *    injected inode's nm_inode_info and the path/dir_node refs it owns, for the
 *    life of the boot); and nm_file_getattr's two signature arms are one body
 *    behind two wrappers, which changes no behaviour at all but is where a fix
 *    applied to the 4.11+ arm and not the 4.9 one would previously have hidden.
 *
 *    Same reason 19, 20, 22, 25 and 27 have a bump: userspace cannot see any of
 *    it, so `doctor` needs a number to tell this engine from the one before it.
 *
 * 30: the control plane now demands CAP_SYS_ADMIN instead of CAP_NET_ADMIN, and
 *    nm_dsnap_make() stops publishing its remaining failures as verdicts.
 *
 *    The capability is the one change here a user can be locked out by, so it
 *    needs a number: CAP_NET_ADMIN was the faithful translation of the genl
 *    GENL_ADMIN_PERM flag this protocol replaced, and a bad fit for an interface
 *    whose ADD_RULE can serve a chosen file at any path on any ROM partition --
 *    root-equivalent power behind a capability that netd and system_server hold
 *    and root-equivalence does not follow from. Every caller in the tree is uid 0
 *    with a full capability set, so nothing legitimate loses access; a kernel
 *    below 30 simply keeps the looser gate.
 *
 *    The dsnap fix is 29's, finished. 29 split "could not ask" from "walked it
 *    and it does not qualify" for the dentry_open arm and left the other three
 *    exits sharing one `goto out`, which publishes ok = false -- so a GFP_NOFS
 *    failure, or an iterate_dir() error, still cached a not-answer that
 *    nm_dsnap_fresh() then kept until the backing directory's size or mtime
 *    moved. Only b.overflow (more entries or name bytes than the model carries,
 *    a property of the directory) leaves as a cacheable negative now. */
#define NOMOUNT_VERSION    30
#define NOMOUNT_HASH_BITS  12
#define NM_FLAG_IS_DIR      (1 << 0)
#define NM_FLAG_VIRTUAL_DIR (1 << 1)
#define NM_FLAG_WHITEOUT    (1 << 2)
/* Times were captured from a stock source. Needed because mtime 0 is a REAL
 * value -- every file on an apex image and on any reproducible-build erofs
 * reports it -- so "tv_sec != 0" cannot mean "we have a mirrored value". */
#define NM_FLAG_HAVE_TIMES  (1 << 3)
/* This virtual dir hangs under an overlayfs mount, where a real dir's readdir
 * ino and its st_ino diverge (the dirent carries the lower fs's number, stat
 * the one overlayfs allocated). Emitting a single number for both is a
 * zero-permission tell: on OP15, 143/143 real dirs under /product diverge and
 * only a synthesized one matched. Set => serve v_dino to readdir, v_ino to
 * stat; clear => they are the same number, which is what a normal fs does. */
#define NM_FLAG_OVL_INO     (1 << 4)
/* The vpath resolved at rule-creation time, i.e. this rule SHADOWS a stock entry
 * rather than adding a new name. Decides whether the parent directory's entry
 * count changes: a replacement leaves it alone, an addition grows it and a
 * whiteout shrinks it. Set from the kern_path(vpath) that already runs in
 * nm_alloc_rule, so it costs nothing extra. */
#define NM_FLAG_SHADOWS_STOCK (1 << 5)
/* This rule stays visible to a reader on the block list.
 *
 * Per-UID hiding is otherwise all-or-nothing: a blocked reader gets the stock
 * filesystem, and for an ADDED name that means -ENOENT. That is right for a
 * module file nothing else advertises, and wrong for one the system has already
 * told the reader about. The PackageManager scans /product/overlay (and every
 * other ROM APK directory) as system_server, which is not blocked, so it parses
 * and REGISTERS an injected APK -- then hands its path to every app that asks
 * about the package. A blocked app therefore holds a path the PM says exists and
 * open() answers ENOENT for, which is a far louder inconsistency than the
 * injection it was hiding: measured on OP15, IBM Trusteer (La Banque Postale)
 * walks the package list at startup, calls getResourcesForApplication() on each
 * entry, and SIGSEGVs on the IOException from 139 unopenable overlay APKs.
 *
 * So a rule the PM already advertises opts out of hiding. Set by userspace for a
 * file under a PM-scanned codePath; STRIPPED by the kernel when the rule shadows
 * a stock file OUTSIDE such a directory, because there the blocked reader is
 * served the stock bytes and revealing the module's copy would be a real leak.
 *
 * A shadowing rule inside a PM scan dir keeps the bit (engine >= 18), and from 18
 * the bit is actually honoured on the read paths -- nm_stock_for_caller() asks
 * nm_uid_hidden() rather than the raw blocked-uid test, which is what makes the
 * flag change any observable byte. "Served the stock bytes" is only consistent
 * while nothing else has described the file; for a PM-scanned path the PM has,
 * having parsed the module's copy as system_server, so a blocked reader handed
 * the stock bytes (or ENOENT for an added lib) disagrees with the version,
 * signature and nativeLibraryDir the PM publishes. Hiding the module's copy there
 * conceals nothing PM has not announced and adds a mismatch that was not
 * there before. */
#define NM_FLAG_PUBLIC      (1 << 6)
/* Bits a client may set; anything else is kernel-derived and must be stripped.
 * NB: nomount_child_node.flags is a u8, so a client-settable bit must be < 8.
 * NM_FLAG_IS_DIR is NOT here on purpose: it is always derived from the backing
 * path (S_ISDIR in nm_alloc_rule) or, for a whiteout, from the shadowed path, so
 * a client value only ever mislabels -- a regular file with a client IS_DIR gets
 * DT_DIR in getdents() while stat() reports S_IFREG, a one-syscall-pair tell. */
#define NM_FLAGS_USER_MASK  (NM_FLAG_VIRTUAL_DIR | NM_FLAG_WHITEOUT | NM_FLAG_PUBLIC)
#define NM_CTX_MAX          96   /* inline SELinux context; Android's are ~30B */

/* Answers a STOCK file at this path gives to file ops whose result depends on
 * which FILESYSTEM backs it rather than on the file's contents.
 *
 * The injected file is backed by /data (f2fs) while its neighbours are erofs, so
 * these diverge by default and each one is a baseline-free, one-syscall oracle:
 * measured on OP15, fsync() returned 0 on the single injected file in
 * /system/etc/permissions and -EINVAL on all 24 stock siblings, because erofs has
 * no ->fsync and f2fs does. Captured from the shadowed file (or, for a pure
 * addition, from the sibling already sampled for st_blksize and STATX_ATTR_*) and
 * replayed by the ops, the same "mirror the stock answer" rule as v_dev/v_ino. */
#define NM_CAP_FSYNC        (1 << 0)   /* stock fops has ->fsync */
#define NM_CAP_ODIRECT      (1 << 1)   /* stock mapping's a_ops has ->direct_IO */
/* "We actually sampled a stock file for this rule." Without it, v_cap == 0 is
 * ambiguous -- it means BOTH "never sampled" and "sampled, and stock supports
 * nothing" -- and the ops treat the ambiguous zero as never-sampled and fall
 * through to the /data backing file. On an erofs path that is exactly wrong:
 * erofs has no ->fsync, so the correct sampled answer IS zero, and falling
 * through to f2fs made fsync() return 0 where every stock sibling returns
 * -EINVAL. Measured on OP15 via a dir-target rule at /product/etc/mk10test --
 * the directory, its nested child and its files all answered 0 against stock
 * /product/etc answering EINVAL. Set by nm_stock_caps() on every real sample. */
#define NM_CAP_KNOWN        (1 << 7)

/* logs
 *
 * nm_debug is compiled OUT by default. The hijacked lookup path logs once per
 * injected file, so a normal module set produced ~300 lines a boot, and the
 * per-rule messages additionally spelled out every target -> backing mapping in
 * the kernel ring buffer. Build with -DNOMOUNT_DEBUG to get them back.
 * no_printk() keeps the format string and arguments type-checked (so the calls
 * cannot rot) while generating no code. */
#define NM_LOG_TAG "NoMount: "

#ifdef NOMOUNT_DEBUG
#define nm_debug(fmt, ...) printk(KERN_DEBUG NM_LOG_TAG "[DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  printk(KERN_INFO NM_LOG_TAG fmt, ##__VA_ARGS__)
#else
/* Production: compile out the message strings entirely (no_printk still
 * type-checks the format but the literal is dead-code-eliminated), so they do
 * not sit in nomount.o naming functions/logic to anyone disassembling the image. */
#define nm_debug(fmt, ...) no_printk(NM_LOG_TAG "[DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...)  no_printk(NM_LOG_TAG fmt, ##__VA_ARGS__)
#endif
#define nm_warn(fmt, ...) printk(KERN_WARNING NM_LOG_TAG "[WARN] " fmt, ##__VA_ARGS__)
#define nm_err(fmt, ...)  printk(KERN_ERR NM_LOG_TAG "[ERROR] " fmt, ##__VA_ARGS__)
/* For a warning an UNPRIVILEGED caller can drive: printing it per attempt lets an
 * app emit the tag at will and push everything else out of the ring buffer. */
#define nm_warn_once(fmt, ...) printk_once(KERN_WARNING NM_LOG_TAG "[WARN] " fmt, ##__VA_ARGS__)

static DEFINE_HASHTABLE(nomount_rules_ht, NOMOUNT_HASH_BITS);
static LIST_HEAD(nomount_sb_list);
static DEFINE_IDR(nomount_uid_idr);
static DEFINE_MUTEX(nomount_write_mutex);

/* * Helpers to dynamically calculate the memory address of the strings */
#define nm_get_vpath(rule) ((rule)->paths)
#define nm_get_rpath(rule) ((rule)->paths + (rule)->v_len + 1)


/* A hijack vtable is installed ONCE per inode and never freed or uninstalled.
 *
 * It cannot be freed: the VFS caches the pointer outside any RCU read-side
 * section. do_dentry_open() copies i_fop into file->f_op once, and iterate_dir()
 * then dispatches through that copy for the fd's whole lifetime, so an RCU grace
 * period says nothing about whether a reader still holds it. call_rcu-freeing
 * these meant any process holding an open DIR* across a `nm clear` -- which the
 * Suite runs on every mount/reload pass -- called a function pointer out of
 * recycled slab on its next getdents64(). i_op has a narrower version of the same
 * hole (the VFS loads inode->i_op and makes the indirect call outside RCU).
 *
 * Nor is it worth deferring the free to module exit: this driver is obj-y on
 * every target, so __exit code is discarded at link time and a graveyard list has
 * no reachable consumer -- measured on OP15 as 125 live nm_iop/nm_fop against 105
 * dir_nodes, i.e. 20 of each already orphaned, growing with every reload.
 *
 * So teardown NEUTERS instead: `dir_node` is set to NULL and the vtable stays
 * installed. Every hijacked handler already treats a NULL dir_node as
 * "unhijacked" and falls through to orig_*, so behaviour matches a restored
 * inode; a cached file->f_op stays valid forever; and a later hijack of the same
 * inode RE-ARMS this object instead of allocating another.
 *
 * ⚠ The re-arm does NOT bound the total. Teardown also iputs the inode, dropping
 * the igrab that pinned it, so between a clear and the next add the directory
 * inode can be reclaimed -- taking the only pointer to its pair with it -- and
 * the next add on that path allocates a fresh one. The real bound is "one pair
 * per hijacked directory per reload IN WHICH THE INODE WAS RECLAIMED", not one
 * for the life of the boot. Reuse is an optimisation here; the reason this design
 * is correct is the cached f_op, not the accounting. */
struct nm_iop {
    struct inode_operations fake_iop; /* MUST be exactly at offset 0 */
    const struct inode_operations *orig_iop;
    struct nomount_dir_node *dir_node;
};

struct nm_fop {
    struct file_operations fake_fop;  /* MUST be exactly at offset 0 */
    const struct file_operations *orig_fop;
    struct nomount_dir_node *dir_node;
};

struct nm_sop {
    struct super_operations fake_sop; /* MUST be exactly at offset 0 */
    const struct super_operations *orig_sop;
    const struct xattr_handler **orig_xattr;
    const struct xattr_handler **fake_xattr;
    struct super_block *sb;
    struct rcu_head rcu;
    struct list_head list;
};

struct nm_dsnap;

struct nm_inode_info {
    struct path r_path;
    /* The STOCK file this injection shadows, pinned at rule creation. A hidden
     * reader is entitled to see it, and serving it from here means we never have
     * to invalidate the shared dentry to arrange that. Empty for an ADDED name
     * (nothing underneath) and for a whiteout. */
    struct path s_path;
    struct nomount_dir_node *dir_node;
    char v_ctx[NM_CTX_MAX];          /* mirrored context for synthesized dirs */
    u16 v_ctx_len;
    unsigned long v_ino;
    u64 v_dino, v_pdino;
    dev_t v_dev, v_mapdev;
    struct timespec64 v_atime, v_mtime, v_ctime;
    u64 v_attributes, v_attr_mask;   /* mirrored statx STATX_ATTR_* of the stock/sibling file */
    u32 v_blksize;                   /* mirrored st_blksize */
    /* Stock allocated-size RATIO in 1/1024 units (0 = never sampled).
     * Stock ROM files are erofs-compressed while injected ones are served from
     * f2fs uncompressed, so the predicate st_blocks*512 >= st_size held for
     * 41/41 injected files >=64KiB and 0/191 stock ones -- one stat(), no root,
     * no baseline device, fully disjoint per directory. Replaying a sampled
     * ratio puts the injected file back inside the population. */
    u16 v_cratio;
    u32 v_result_mask;               /* statx result_mask a STOCK file reports */
    u8  v_cap;                       /* NM_CAP_*: file-op answers a STOCK file gives */
    kuid_t v_uid;                    /* virtual-dir owner (mirrored from nearest real ancestor) */
    kgid_t v_gid;
    umode_t v_mode;                  /* virtual-dir mode bits (0 => default 0755) */
    u8 flags;
    /* Rule-topology generation this inode was last fully validated against. Read
     * LOCKLESS by nm_d_revalidate()'s RCU fast path: a mismatch means an add/del/
     * clear has happened since, so that path bails to the ref-walk which re-runs
     * the full verdict and re-stamps. See nomount_generation. */
    u32 gen;
    /* Cached sorted snapshot of a dir-target rule's BACKING directory, and
     * the lock that publishes it. NULL until the first qualifying
     * stat()/readdir(); see the nm_dsnap block in nomount.c for what it is
     * for, how it is bounded and when it is invalidated. */
    struct nm_dsnap *dsnap;
    spinlock_t dsnap_lock;
    /* Freed via call_rcu, NOT immediately. destroy_inode() runs synchronously
     * (fs/inode.c), so a plain kmem_cache_free here would pull this struct out
     * from under the RCU fast path, which reads i_private with no reference. The
     * INODE itself is already RCU-safe on both backing filesystems we hijack
     * (erofs and overlayfs each provide ->free_inode), so this payload was the
     * only piece left unprotected. */
    struct rcu_head rcu;
};

#define nm_get_real_inode(v_inode) \
    (((v_inode)->i_private && ((struct nm_inode_info *)(v_inode)->i_private)->r_path.dentry) ? \
        d_backing_inode(((struct nm_inode_info *)(v_inode)->i_private)->r_path.dentry) : NULL)

/* Per-dir name-lookup hash table: bloom rejects misses, this resolves hits in
 * O(bucket) instead of O(children) so large-fanout dirs (whiteout-heavy
 * /product/overlay etc.) don't linear-scan on every path lookup. The idr stays
 * for stable readdir cookies; this table is only for by-name resolution. */
#define NM_CHILD_HT_BITS 5

struct nomount_child_node {
    struct rcu_head rcu;
    struct hlist_node hnode;   /* link in the owning dir_node's children_ht */
    u32 name_hash;
    u64 fake_ino;
    int id;
    u8 d_type;
    u8 flags;
    u16 name_len;
    struct nomount_rule *rule;

    /* * FLEXIBLE ARRAY MEMBER:
     * Memory Layout: [ struct ] "children_name\0"
     */
    char name[]; 
};

struct nomount_dir_node {
    struct idr children_idr;
    DECLARE_HASHTABLE(children_ht, NM_CHILD_HT_BITS);
    loff_t real_eof;     /* published base; 0 = no full pass observed yet */
    /* NB: there is deliberately no size_delta counter here any more. See
     * nm_dir_deltas(): the parent's size correction is derived from the live
     * child flags on the same walk that computes the link-count correction, so
     * it stays in step with a replaced rule AND is filtered by the caller's uid.
     * A single cached number could do neither. */
    loff_t max_real_pos; /* running max real dirent offset (not authoritative) */
    u64 bloom_mask;
    /* Does any child here carry NM_FLAG_PUBLIC? Conservative summary in the same
     * spirit as bloom_mask: set when such a child is injected and never cleared,
     * because a stale true only costs a blocked reader the slow path through a
     * directory where it then sees nothing, while a stale false would hide a
     * child that must stay visible. Read on the hot gate in
     * nomount_hijacked_lookup/iterate so that a device with no public rule keeps
     * the exact bail-out it has today. */
    bool has_public;
    atomic_t refcount;   /* owner ref (alloc) + one per synthetic inode caching this node */
    struct rcu_head rcu;
    union {
        struct inode *dir_inode;
        struct nomount_rule *owner_rule;
        unsigned long _tag_ptr;
    };
};

struct nomount_rule {
    struct hlist_node vpath_node;
    /* Teardown list link, kept SEPARATE from vpath_node on purpose.
     * hlist_del_rcu() deliberately leaves ->next intact so an RCU reader already
     * standing on the node can still walk off it; the victims list used to reuse
     * vpath_node, whose hlist_add_head() overwrote exactly that pointer. Since
     * nomount_nl_dump_rules() walks the rule table under rcu_read_lock() ALONE
     * (it does not take nomount_write_mutex), a `nm list` concurrent with a
     * del/clear could follow ->next out of its hash bucket and into the victims
     * list -- emitting deleted or duplicated rules into the reload delta. */
    struct hlist_node victim_node;
    struct nomount_dir_node *parent_dir;
    struct nomount_dir_node *this_dir;
    struct path r_path;
    struct path s_path;              /* stock file this rule shadows; see nm_inode_info */
    unsigned long v_ino;
    /* Dirent ino, i.e. what readdir reports -- for this dir's own "." and for
     * its entry in the parent's listing. On overlayfs these differ from st_ino
     * (see NM_FLAG_OVL_INO); everywhere else they are equal. */
    u64 v_dino, v_pdino;
    dev_t v_dev;
    /* dev a stock file at this path reports in /proc/<pid>/maps. Differs from
     * v_dev on overlayfs, where the mapping is of the LOWER file. */
    dev_t v_mapdev;
    struct timespec64 v_atime, v_mtime, v_ctime;
    u64 v_attributes, v_attr_mask;   /* mirrored statx STATX_ATTR_* of the stock/sibling file */
    u32 v_blksize;                   /* mirrored st_blksize */
    /* Stock allocated-size RATIO in 1/1024 units (0 = never sampled).
     * Stock ROM files are erofs-compressed while injected ones are served from
     * f2fs uncompressed, so the predicate st_blocks*512 >= st_size held for
     * 41/41 injected files >=64KiB and 0/191 stock ones -- one stat(), no root,
     * no baseline device, fully disjoint per directory. Replaying a sampled
     * ratio puts the injected file back inside the population. */
    u16 v_cratio;
    u32 v_result_mask;               /* statx result_mask a STOCK file reports */
    u8  v_cap;                       /* NM_CAP_*: file-op answers a STOCK file gives */
    kuid_t v_uid;                    /* virtual-dir owner (mirrored from nearest real ancestor) */
    kgid_t v_gid;
    umode_t v_mode;                  /* virtual-dir mode bits (0 => default 0755) */
    char v_ctx[NM_CTX_MAX];          /* nearest real ancestor's context, for virtual dirs */
    u16 v_ctx_len;
    u32 v_hash;
    u16 v_len;
    u8  flags;
    unsigned int target_uid;

    /* * FLEXIBLE ARRAY MEMBER: 
     * Memory Layout: [ struct ] "virtual_path\0real_path\0"
     */
    char paths[]; 
};

/*** Operaction Vectors ***/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
static const struct file_operations nm_file_fops_mmap_prepare;
#endif
static const struct file_operations nm_file_fops;
static const struct inode_operations nm_file_iops;
static const struct file_operations nm_dir_fops;
static const struct inode_operations nm_dir_iops;
static const struct dentry_operations nm_dops;

/*** Rule Operations ***/
static int nomount_generate_virtual_topology(struct nomount_rule *target_rule);
static struct nomount_rule *nm_alloc_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags, unsigned int target_uid);
static void nm_free_rule(struct nomount_rule *rule);
static void nm_detach_rule_locked(struct nomount_rule *rule, struct hlist_head *victims, bool prune);
/* A lockless snapshot of the fields a reader needs from a rule, taken under RCU
 * by nomount_get_rule_info(). The r_path (if any) is path_get()'d into the
 * snapshot, so the caller can use it safely even if the rule is freed
 * concurrently, and MUST path_put() it when done. This replaces returning a bare
 * rule pointer that lockless readers then dereferenced after rcu_read_unlock()
 * -- a use-after-free if a concurrent nm del/clear/COW freed the rule. */
struct nm_rule_info {
    u32 flags;
    struct path s_path;              /* stock file behind a shadowing rule (may be empty) */
    unsigned long v_ino;
    u64 v_dino, v_pdino;
    dev_t v_dev, v_mapdev;
    struct timespec64 v_atime, v_mtime, v_ctime;
    u64 v_attributes, v_attr_mask;
    u32 v_blksize;
    /* Stock allocated-size RATIO in 1/1024 units (0 = never sampled).
     * Stock ROM files are erofs-compressed while injected ones are served from
     * f2fs uncompressed, so the predicate st_blocks*512 >= st_size held for
     * 41/41 injected files >=64KiB and 0/191 stock ones -- one stat(), no root,
     * no baseline device, fully disjoint per directory. Replaying a sampled
     * ratio puts the injected file back inside the population. */
    u16 v_cratio;
    u32 v_result_mask;
    u8  v_cap;
    kuid_t v_uid;
    kgid_t v_gid;
    umode_t v_mode;
    char v_ctx[NM_CTX_MAX];          /* copied inline: the rule can be freed after the snapshot */
    u16 v_ctx_len;
    struct path r_path;
    struct nomount_dir_node *this_dir;
    /* Rule generation sampled BEFORE the snapshot was taken, carried through to
     * nm_inode_info.gen. Sampling on this side is what keeps the stamp from ever
     * being newer than the topology the inode was built from -- see the note in
     * nomount_get_rule_info(). */
    u32 gen;
};

static struct inode *nomount_create_new_inode(struct super_block *virtual_sb, struct nm_rule_info *rule_info);
/* Maps (/proc/<pid>/maps) dev/ino spoof for mapped injected inodes; called from
 * fs/proc/task_mmu.c show_map_vma() via a guarded extern there. */
void vfs_map_meta_override(const struct inode *inode, dev_t *dev,
				 unsigned long *ino);

/* =====================================================================
 * NoMount VFS Offset Protocol
 * =====================================================================
 * Virtual dirents CONTINUE the backing directory's own cookie space, starting
 * one past the EOF position that directory reports. The previous scheme tagged
 * every offset with a constant 16-bit signature, which getdents64() then handed
 * to userspace verbatim as d_off -- a single-comparison fingerprint on any
 * injected directory. There is no tag now: an injected entry's d_off is simply
 * the next number after the real ones.
 *
 * real_eof == 0 means no virtual entry has ever been emitted for this dir, so no
 * position can be ours yet. It is recorded at the real->virtual transition, i.e.
 * always before any virtual offset is handed out.
 */
/* Headroom for the virtual entries appended above the base. */
#define NM_POS_HEADROOM 65536

static inline bool nm_is_virtual_pos(const struct nomount_dir_node *d, loff_t pos)
{
    loff_t eof, mx;

    if (!d) return false;
    eof = READ_ONCE(d->real_eof);
    mx  = READ_ONCE(d->max_real_pos);
    /* Also require pos to be above the running max, not just the published base.
     * If the directory GREW since the last completed pass, mx climbs live while
     * real_eof is still the older (lower) base, and a resume position in that
     * gap is a real offset -- treating it as ours would drop the tail of the
     * directory. Residual: a position above BOTH is still ambiguous until the
     * grown dir has been walked to EOF once. Read-only ROM partitions (the
     * injection targets) never grow, so this only bites writable mounts. */
    /* Bound the window. Without an upper edge, ANY position above the base
     * counts as ours -- including a wild fs cookie (ext4 dir_index hands back
     * S64_MAX at EOF), which then unpacks to a nonsense child id and silently
     * ends the listing. */
    return eof && pos > eof && pos > mx && pos <= eof + NM_POS_HEADROOM;
}

static inline loff_t nm_pack_pos(const struct nomount_dir_node *d, int id)
{
    return READ_ONCE(d->real_eof) + 1 + id;
}

static inline int nm_unpack_pos(const struct nomount_dir_node *d, loff_t pos)
{
    loff_t id = pos - READ_ONCE(d->real_eof) - 1;

    if (id < 0 || id > NM_POS_HEADROOM) return -1;
    return (int)id;
}

/* Track the highest REAL dirent offset seen. Deliberately NOT the fs's ctx->pos
 * at EOF: ext4 with dir_index reports EXT4_HTREE_EOF_64BIT (S64_MAX) there, so
 * basing on it overflows loff_t and makes pos > eof never true. */
static inline void nm_note_real_pos(struct nomount_dir_node *d, loff_t pos)
{
    if (!d || pos <= 0 || pos > (loff_t)(S64_MAX - NM_POS_HEADROOM)) return;
    if (pos > READ_ONCE(d->max_real_pos)) WRITE_ONCE(d->max_real_pos, pos);
}

/* Publish the base ONLY once the backing dir has actually reached EOF. Until
 * then the running max is not the maximum, and a mid-pass resume position (which
 * legitimately sits above every offset seen so far) would be mistaken for one of
 * ours -- short-circuiting straight to the virtual entries and dropping the rest
 * of the real directory. Re-published on every completed pass so a dir that grew
 * keeps the invariant that every real offset is <= real_eof. */
static inline void nm_publish_real_eof(struct nomount_dir_node *d, loff_t eof_hint)
{
    loff_t base;

    if (!d) return;
    base = READ_ONCE(d->max_real_pos);
    /* Take the HIGHER of the last real dirent offset and the position the
     * backing dir left at EOF. They coincide on overlayfs (sequential cookies,
     * EOF == last + 1) but not on a byte-offset fs like erofs, where EOF sits
     * PAST the last entry -- basing the window on the dirent offset alone put
     * that EOF position inside the virtual range, so every listing after the
     * first resumed at a child id that does not exist and emitted nothing. The
     * injected file stayed resolvable by name, so it was visible to stat and
     * open but absent from readdir: 90 of 260 rules on OP15. */
    if (eof_hint > 0 && eof_hint <= (loff_t)(S64_MAX - NM_POS_HEADROOM) && eof_hint > base)
        base = eof_hint;
    if (!base) base = 2;                        /* dots-only / purely synthesized */
    WRITE_ONCE(d->real_eof, base);
}

/* ========================================================================= */
/* NETLINK CONTROL PROTOCOL DEFINITIONS (private raw netlink, not generic) */
/* ========================================================================= */

/*
 * Control plane is a PRIVATE raw-netlink protocol, not a named Generic Netlink
 * family. A genl family ("nomount") was enumerable/name-resolvable by any
 * caller via CTRL_CMD_GETFAMILY (an on-device detection oracle). A raw netlink
 * protocol number is neither listed by the genl controller nor resolvable by
 * name, so NoMount's control channel no longer advertises itself.
 *
 * NOMOUNT_NL_PROTO is overridable at build time (e.g. randomize per build);
 * the userspace `nm` client MUST be built with the same value.
 */
#ifndef NOMOUNT_NL_PROTO
#define NOMOUNT_NL_PROTO 29
#endif

/* The command travels in nlmsg_type, offset past the reserved control range
 * (0..NLMSG_MIN_TYPE-1). Kernel and client agree on this mapping. */
#define NM_CMD_TO_TYPE(c) (NLMSG_MIN_TYPE + (c))
#define NM_TYPE_TO_CMD(t) ((int)(t) - NLMSG_MIN_TYPE)

/* Commands */
enum {
    NM_CMD_UNSPEC = 0,
    NM_CMD_GET_VERSION,
    NM_CMD_ADD_RULE,
    NM_CMD_DEL_RULE,
    NM_CMD_CLEAR_ALL,
    NM_CMD_ADD_UID,
    NM_CMD_DEL_UID,
    NM_CMD_GET_LIST,
    NM_CMD_GET_UIDS,
    NM_CMD_SET_KNOB,
    /* 10: RETIRED. Dumped the _pathhide rule list. The command travels in
     * nlmsg_type as NLMSG_MIN_TYPE + cmd, so the slot is reserved rather than
     * deleted -- removing it would shift NM_CMD_GET_GHOST under every nm binary
     * already installed. */
    NM_CMD_RESERVED_10,
    NM_CMD_GET_GHOST,
    __NM_CMD_MAX,
};

/* Boot-identity knobs, formerly sysfs attributes under /sys/kernel/<name>/.
 * That kobject directory was world-traversable (0755), so both its name and its
 * attribute names were readable by any process that could search /sys/kernel --
 * a stock-baseline diff finds it regardless of what it is called. They ride the
 * netlink control plane instead, which is CAP_SYS_ADMIN-gated and not
 * enumerable. Payload layout: [u32 knob][value bytes], empty value = clear. */
enum {
    /* 0..3: RETIRED boot-identity knobs -- uname release/version and the
     * /proc/cmdline + /proc/bootconfig takeover. The Suite never drove them
     * automatically once spoof.sh was removed, and it now provides no
     * boot-identity spoofing at all, so the implementations are gone.
     *
     * The SLOTS stay. A knob is a raw u32 at payload offset 0, so deleting
     * these would renumber every knob below and silently remap the knobs of any
     * nm binary already on a device -- `nm k d 1` would arrive as a different
     * knob entirely. Reserved, never reused. */
    NM_KNOB_RESERVED_0 = 0,
    NM_KNOB_RESERVED_1,
    NM_KNOB_RESERVED_2,
    NM_KNOB_RESERVED_3,
    /* "1" => this device's ROM directories are dirent-packed (erofs-shaped), so
     * a synthesized directory must report 12*(entries incl . and ..) + name
     * bytes rather than the 4096 placeholder.
     *
     * Why a knob rather than reading the superblock: a virtual dir inherits its
     * PARENT's sb, and on an overlay-mounted ROM path that is overlayfs, whose
     * magic says nothing about the layer whose shape the stock siblings show.
     * d_real() cannot answer either -- it resolves regular files, and a merged
     * directory has no single real dentry, which is why two attempts to infer
     * this in-kernel both produced no-ops. Userspace CAN answer it: enumerate a
     * real sibling and check whether its size equals the formula. Measure where
     * it is cheap, decide where it is needed. Unset => previous behaviour. */
    NM_KNOB_VDIR_EROFS_SIZE,
    /* Which isolated-process pools per-UID hiding covers, as a decimal bitmask:
     * 1 = app-zygote pool (90000..98999), 2 = platform isolated pool
     * (99000..99999), 3 = both (default). Hiding from them stops a blocked app
     * probing through an isolated helper; leaving them visible stops an UNBLOCKED
     * app spotting the injection by diffing its own view against its own isolated
     * child's. Only meaningful while at least one appid is blocked. */
    NM_KNOB_HIDE_ISOLATED,
    /* 6: RETIRED. Forwarded one _pathhide control command to its parser. No
     * builder applies that patch set, so pathhide_ctl was a NULL weak symbol on
     * every kernel these builders produce and this answered -EINVAL to every
     * call -- including the empty-value presence probe, because the NULL test
     * ran first. Reserved for the same wire reason as 0..3. */
    NM_KNOB_RESERVED_6,
    /* One _ghost control command, forwarded verbatim to its parser:
     * "p+/abs/path" / "p~/abs/path" / "p-" for the hidden-path table,
     * "u+<uid>" / "u~<uid>" / "u-" for the hidden-uid table.
     *
     * An EMPTY value is a presence probe (returns 0 iff _ghost is compiled
     * in), not "clear" as it is for the knobs above -- clearing is the explicit
     * "-" command. Userspace needs it because NM_CMD_GET_GHOST answers empty
     * both for "not built" and for "built, no rules".
     *
     * _ghost is INERT until both tables are populated: ghost_hidden_path()
     * short-circuits to false on an empty table, so a kernel carrying the
     * patches but no forwarder behaves exactly like an unpatched one. This knob
     * is the forwarder. Ship both, or ship neither. */
    NM_KNOB_GHOST,
    __NM_KNOB_MAX,
};

/* Attributes */
enum {
    NOMOUNT_ATTR_UNSPEC = 0,
    NOMOUNT_ATTR_VIRTUAL_PATH,  /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_REAL_PATH,     /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_FLAGS,         /* u32 (NLA_U32) */
    NOMOUNT_ATTR_UID,           /* u32 (NLA_U32) */
    NOMOUNT_ATTR_VERSION,       /* u32 (NLA_U32) */
    NOMOUNT_ATTR_PAYLOAD,       /* Binary payload for GET_LIST (NLA_BINARY) */
    __NOMOUNT_ATTR_MAX,
};

static const struct nla_policy nomount_genl_policy[__NOMOUNT_ATTR_MAX];

/* * Compat macros * */
/* nlmsg attribute parse: attrs sit directly after nlmsghdr (hdrlen 0). The
 * signature gained an extack arg at 4.12 and split strict/deprecated at 5.2. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    #define NM_NLMSG_PARSE(nlh, tb) \
        nlmsg_parse_deprecated((nlh), 0, (tb), __NOMOUNT_ATTR_MAX - 1, nomount_genl_policy, NULL)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
    #define NM_NLMSG_PARSE(nlh, tb) \
        nlmsg_parse((nlh), 0, (tb), __NOMOUNT_ATTR_MAX - 1, nomount_genl_policy, NULL)
#else
    #define NM_NLMSG_PARSE(nlh, tb) \
        nlmsg_parse((nlh), 0, (tb), __NOMOUNT_ATTR_MAX - 1, nomount_genl_policy)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    #define IDMAP_PATH(path) mnt_idmap((path).mnt),
    #define IDMAP_ARG struct mnt_idmap *idmap,
    #define IDMAP_CALL idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #define IDMAP_PATH(path) mnt_user_ns((path).mnt),
    #define IDMAP_ARG struct user_namespace *mnt_userns,
    #define IDMAP_CALL mnt_userns,
#else
    #define IDMAP_PATH(path)/* Nothing */
    #define IDMAP_ARG /* Nothing */
    #define IDMAP_CALL /* Nothing */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    #define NM_ACTOR_RET bool
    #define NM_ACTOR_CONTINUE true
#else
    #define NM_ACTOR_RET int
    #define NM_ACTOR_CONTINUE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    #define FLAGS_ARG , int flags
    #define FLAGS_VAL , flags
#else
    #define FLAGS_ARG /* Nothing */
    #define FLAGS_VAL /* Nothing */
#endif

static inline void nm_sync_inode_times(struct inode *v_inode, struct inode *r_inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    v_inode->i_atime_sec = r_inode->i_atime_sec;
    v_inode->i_atime_nsec = r_inode->i_atime_nsec;
    v_inode->i_mtime_sec = r_inode->i_mtime_sec;
    v_inode->i_mtime_nsec = r_inode->i_mtime_nsec;
    v_inode->i_ctime_sec = r_inode->i_ctime_sec;
    v_inode->i_ctime_nsec = r_inode->i_ctime_nsec;
/* 6.7 renamed i_atime/i_mtime to __i_atime/__i_mtime (v6.6 include/linux/fs.h
 * still spells them i_atime/i_mtime; v6.7 does not) and added the accessors that
 * replace them. Naming the fields directly therefore only compiles on 6.6
 * itself, which is why 6.7..6.11 gets its own arm. The >= 6.12 arm above stays
 * on the discrete second/nanosecond fields it was written for. */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    inode_set_atime_to_ts(v_inode, inode_get_atime(r_inode));
    inode_set_mtime_to_ts(v_inode, inode_get_mtime(r_inode));
    inode_set_ctime_to_ts(v_inode, inode_get_ctime(r_inode));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    v_inode->i_atime = r_inode->i_atime;
    v_inode->i_mtime = r_inode->i_mtime;
    inode_set_ctime_to_ts(v_inode, inode_get_ctime(r_inode));
#else
    v_inode->i_atime = r_inode->i_atime;
    v_inode->i_mtime = r_inode->i_mtime;
    v_inode->i_ctime = r_inode->i_ctime;
#endif
}

/* Read a directory's mtime for the dir-target snapshot's validity stamp.
 * inode_get_mtime() arrives at v6.7, which is also where the field became
 * __i_mtime -- verified against the trees, not from memory: v6.6
 * include/linux/fs.h:675 declares `struct timespec64 i_mtime` and has no
 * inode_get_mtime; v6.7 fs.h:675 declares __i_mtime and fs.h:1559 defines
 * inode_get_mtime(). Same split nm_sync_inode_times() above uses. */
static inline struct timespec64 nm_inode_mtime(struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    return inode_get_mtime(inode);
#else
    return inode->i_mtime;
#endif
}

static inline int nm_call_iterate(struct file *file, struct dir_context *ctx, const struct file_operations *fop)
{
    if (fop->iterate_shared)
        return fop->iterate_shared(file, ctx);
/* ->iterate was removed at 6.5, not 6.6 (v6.4 fs.h has it, v6.5 does not). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
    else if (fop->iterate)
        return fop->iterate(file, ctx);
#endif
    return -ENOTDIR;
}

/* Recover our nm_fop from a (possibly hijacked) file_operations.
 *
 * The hijack mirrors whichever readdir op the filesystem itself implements, so
 * the identity probe has to check both: before 6.5 the VFS picks the SHARED or
 * EXCLUSIVE inode lock by whether ->iterate_shared is set, and installing it on a
 * filesystem that only implements ->iterate silently downgrades the exclusion
 * that split exists to express. From 6.5 ->iterate is gone (v6.4 fs.h declares
 * it, v6.5 does not) and only the first probe can match. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
#define nm_get_fop(p) ({                                                        \
    const struct file_operations *__nf = (p);                                   \
    struct nm_fop *__nr = __get_nm(__nf, struct nm_fop, fake_fop,               \
                                   iterate_shared, nomount_hijacked_iterate_dir);\
    if (!__nr)                                                                  \
        __nr = __get_nm(__nf, struct nm_fop, fake_fop,                          \
                        iterate, nomount_hijacked_iterate_dir);                 \
    __nr; })
#else
#define nm_get_fop(p) \
    __get_nm((p), struct nm_fop, fake_fop, iterate_shared, nomount_hijacked_iterate_dir)
#endif

/* Install our dentry ops on a dentry we manage. Setting d_op alone is NOT enough:
 * a dentry allocated on a hijacked sb (e.g. overlayfs, whose s_d_op is
 * ovl_dentry_operations) already has the sb's DCACHE_OP_* flags set, so the VFS
 * would keep calling ops (d_weak_revalidate/d_real/d_release/...) that nm_dops
 * does not provide -> NULL deref (seen as an OOPS in path_lookupat when resolving
 * '..' of a synthesized virtual dir). Clear the inherited op flags and set only
 * the ones nm_dops actually implements (d_revalidate). */
static inline void nm_install_dentry_ops(struct dentry *dentry)
{
    dentry->d_flags &= ~(DCACHE_OP_HASH | DCACHE_OP_COMPARE |
                         DCACHE_OP_REVALIDATE | DCACHE_OP_WEAK_REVALIDATE |
                         DCACHE_OP_DELETE | DCACHE_OP_PRUNE | DCACHE_OP_REAL);
    dentry->d_op = &nm_dops;
    dentry->d_flags |= DCACHE_OP_REVALIDATE;
}

/* Tag a dentry we are about to hand BACK to the real filesystem's ->lookup.
 *
 * nm_install_dentry_ops() REPLACES d_op wholesale. That is right for a dentry we
 * instantiate ourselves -- its d_fsdata is still NULL and the fs's hooks must not
 * run against our synthetic inode -- and wrong for one the fs is about to
 * populate, because the fs's own ops go with it.
 *
 * overlayfs is the case that bites, and /product/overlay and /product/priv-app
 * are overlay mounts on the devices this engine targets. ovl_lookup() stores its
 * per-dentry ovl_entry in d_fsdata on every kernel from 4.9 to 6.4 -- including
 * for a NEGATIVE result, where oe is allocated and assigned all the same
 * (v5.10 fs/overlayfs/namei.c:1055-1057) -- and only .d_release =
 * ovl_dentry_release frees it, dput()ing every lower-layer dentry in the stack on
 * the way (v5.10 fs/overlayfs/super.c:69-77). Clobbering d_op before ovl_lookup
 * runs therefore leaked one ovl_entry per fallback lookup and pinned the whole
 * lowerdir stack (8 deep on OP15 /product/overlay) until reboot. It also dropped
 * .d_real, which on 4.9/4.14 is how the VFS reaches the real file at all
 * (vfs_open() -> d_real()), since overlayfs had no file_operations of its own
 * before 4.19.
 *
 * 6.5 moved the ovl_entry into the inode (OVL_E() is OVL_I(inode)->oe) and
 * dropped .d_release entirely -- v6.5 fs/overlayfs/super.c:135-139 vs
 * v6.4:170-177 -- which is why a 6.12 device never showed any of it.
 *
 * Nor did the install buy anything on overlayfs: from 5.10 ovl_lookup ends with
 * ovl_dentry_update_reval(), which CLEARS DCACHE_OP_REVALIDATE unless a layer
 * asked for it, so nm_d_revalidate would not have run on that dentry anyway.
 *
 * So: DCACHE_DONTCACHE (5.13+) does the eviction and needs no d_op at all, and
 * our ops go on only when the filesystem has none to lose -- s_d_op NULL, i.e.
 * erofs/ext4/f2fs without casefolding, which is exactly where the pre-DONTCACHE
 * nm_reval_stale() fallback matters and where nothing is given up by taking it.
 * The dentry is freshly allocated by d_alloc_parallel() at this point, so d_op is
 * still whatever __d_alloc() copied out of sb->s_d_op. */
static inline void nm_tag_passthrough_dentry(struct dentry *dentry)
{
#ifdef DCACHE_DONTCACHE
    dentry->d_flags |= DCACHE_DONTCACHE;
#endif
    if (!dentry->d_op)
        nm_install_dentry_ops(dentry);
}

#endif /* _LINUX_NOMOUNT_H */
