# NoMount pre-release audit — hookless / kbuild / Suite module

**Date:** 2026-08-21
**Targets:**
- `kbuild@hookless` — `hookless/src/nomount.c` (4080 L) + `nomount.h` (518 L), 10 integration patches, CI matrix
- `nomount-suite@feat/hide-patterns-presets` — module scripts, WebUI, Rust CLI, C netlink client

**Method:** full read of the kernel engine; cross-compile of `fs/nomount.o` against a real GKI 6.12 tree
(gcc `W=1`, gcc `W=2`, clang plain, clang `W=1`); patch/CI differential; live testing on OP15 (CPH2747,
`6.12.23-android16-5`, engine **v13**, 260 rules, 24 blocked UIDs, verdict healthy).

**Device left unchanged:** rule count 260 before and after, no leftover rules or files.
**WSL kernel tree left unchanged:** `git status` clean, build dirs removed.

## Status — fixed in this pass (2026-08-21)

| ID | Fix | Verification |
|---|---|---|
| **A1** | `__nomount_inject_child_locked()` replacement branch now subtracts the old `nm_child_size_contrib()`, refreshes `d_type` and `fake_ino`, and re-adds on the new flags | builds clean; needs a kernel flash to re-run the nlink test |
| **A2** | `nomount_rule` gained a dedicated `victim_node`; the teardown list no longer reuses `vpath_node` | builds clean |
| **A3** | Batch `NM_CMD_ADD_RULE` returns the first rejection instead of `0`; every entry is still attempted | builds clean; consumers audited (see below) |
| **A7** | dead `nstat` deleted | **clang `W=1` now 0 diagnostics** (was `-Werror` fail) |
| **B1** | CI asserts the `fs/Makefile` and `fs/Kconfig` hunks and `CONFIG_NOMOUNT=y` in `.config` | assertions tested against the good case and both broken cases |
| **B2** | CI prefers `gki_defconfig`, enables `BOOT_CONFIG`, and asserts it on every kernel ≥ 5.10 | `gki_defconfig` confirmed to carry `CONFIG_BOOT_CONFIG=y` |
| **B3** | W=1 is now a **gate** (baseline 0) rather than a discarded `::notice::`; sparse stays advisory | — |
| **C1** | `spoof.sh` moved inside the bootloop guard in both `metamount.sh` and `post-fs-data.sh` | `sh -n` clean on all three scripts |
| **B5** | `hookless/AUDIT.md` marked historical, with what changed and a pointer here | — |

Engine version bumped **13 → 14** so userspace can gate on A1/A3. Safe: the only comparison in the
Suite is `version() < 13` (`whiteout.rs:72`), a `>=` gate.

**A3 consumer audit** — the new error path was checked against every caller before changing the
contract. `mount.rs` (both sites) already had `Err(_) => failed += 1` arms that a kernel rejection
could never previously reach; `whiteout.rs:295` matches; `absorb.rs` propagates with `?` into a
per-candidate handler that logs, counts, and *still records the rules already created*. Nothing
aborts a boot pass on a single bad rule. In `absorb` the fix closes a silent data-visibility hole:
the bind is unmounted **before** the re-serve, so a rejected `nm.add` previously made the file
vanish while absorb reported success.

### Second pass — the remainder

| ID | Fix |
|---|---|
| **A4** | `size_delta` counter **deleted**. `nm_dir_deltas()` derives the size *and* link corrections from the live child flags in one visibility-filtered walk, so a `--uid` rule no longer moves the reported size for callers it does not target. Costs nothing — the nlink walk was already O(children) on that path — and makes the replacement-staleness class unexpressible. |
| **A5** | `nm_get_link()` returns `-EIO` on the ref-walk call (`dentry != NULL`) and `-ECHILD` only on the RCU-walk call, where it is a retry request rather than an error. |
| **A6** | `nm_setattr()` forwards a **copy** of the `iattr` with `ATTR_FILE`/`ia_file` stripped, so the backing fs never receives our `struct file`. Also keeps `notify_change`'s `ia_valid` mutations off the caller's struct. |
| **A8** | `bloom_mask` reads use `READ_ONCE`; the add-side update uses `WRITE_ONCE`, matching the delete side. |
| **A9** | Superblock-hijack persistence documented as a deliberate **invariant** (restoring `s_op` while a synthetic inode is still pinned would hand it to a teardown that knows nothing about `i_private`). kallsyms residual recorded in-source as an accepted risk — **not** code-fixed; see below. |
| **A10** | `ki_filp` is no longer restored when the backing op returns `-EIOCBQUEUED`; the in-flight completion keeps the backing file, which is what it dereferences. Synchronous callers are unaffected. |
| **B4** | `NOMOUNT_NL_PROTO` in the client is `#ifndef`-guarded, so `-DNOMOUNT_NL_PROTO=n` works and the documented per-build randomisation is actually reachable. |
| **C2** | ksud's immutable flag is **recorded with `lsattr` and restored only if it was set**. The clear is kept (the `mv` unlinks a hardlink to that inode, which `+i` refuses) but no longer *adds* immutability that would break the next ksud update with `EPERM`. Both sites. |
| **C3** | A `doctor` that times out or crashes now yields `health unknown — doctor did not finish` instead of `healthy`. |
| **C4** | All **eight** WebUI call sites route through the existing `shq()`, including `nm()` itself and the pathhide rule writer. Zero raw interpolations into a root shell remain. |
| **C5** | One `nm list` per script, reused. Was 16 full netlink dumps of ~260 rules during post-fs-data on this device. The per-module count also uses `grep -F`, fixing a regex-metachar miscount. |
| **C6** | `service.sh` no longer wipes `/proc/pathhide` at boot (the list is empty then; the wipe only ever destroyed another module's rules — PathHideManager drives the same shared interface identically). The WebUI still clears for live removal but **preserves foreign rules**, using `cat`'s exit status to tell "readable and empty" from "write-only", and says so in the toast when it cannot. |
| **C7** | `exec 8>&2; exec 9>"$LOCK" 2>/dev/null; exec 2>&8 8>&-` — stderr is silenced for the redirection only, not for the rest of the boot pass. |
| **C8** | `umask 077` in all three scripts and in the Rust `main()`, plus a one-time `chmod 0600` of pre-existing state files. `uidhide` is the hiding policy and no longer relies on its parent directory alone. |
| **C9** | The install integrity-check comment now says what it is: corruption detection, not authenticity (the manifest ships in the same zip). |
| **C10** | `scan.sh` uses `tr '\n' '\0' \| xargs -0`, disabling `xargs` quote processing so a quoted APK path cannot mangle or abort the scan. |

**Deliberately not code-fixed — A9's kallsyms half.** All 67 function symbols in the object are
named `nomount_*`/`nm_*`, and kallsyms lists local text symbols. Closing it needs either renaming
every identifier or a build-time mangling layer. Both cost real debuggability (a stack trace from
such a build names nothing), both must be kept in step as functions are added, and neither makes the
object anonymous — 67 symbols under one invented prefix is still a distinctive cluster, just one
that does not name the project. The exposure is also unmeasured for app domains: the file is `0444`
but SELinux-typed `proc_kallsyms`, and an `untrusted_app`-context read could not be executed here.
Recorded in-source as an accepted risk rather than churned. Say the word and it becomes an opt-in
`NOMOUNT_STEALTH_SYMS` header with a CI gate that fails if any symbol leaks.

> The pre-existing `hookless/AUDIT.md` was **stale** — it describes a 1768-line, Generic-Netlink,
> `S_PRIVATE`-setting engine at `eb9587b`. Now marked historical (B5).

---

## Build verification (new evidence)

| Build | Result |
|---|---|
| GKI 6.12 · aarch64 gcc-13 · `W=1` | **clean — 0 warnings from `nomount.c`** |
| GKI 6.12 · aarch64 gcc-13 · `W=2` | 0 warnings from `nomount.c` (only kernel-header `type-limits` noise) |
| GKI 6.12 · clang 18 · plain | **passes** |
| GKI 6.12 · clang 18 · `W=1` | **fails**: `nomount.c:2213: variable 'nstat' set but not used [-Werror,-Wunused-but-set-variable]` |

The `gki_defconfig` build used here had `CONFIG_BOOT_CONFIG=y`, `CONFIG_COMPAT=y`, `CONFIG_OVERLAY_FS=y`,
`CONFIG_EROFS_FS=y`, so the clean result does cover the bootconfig paths. **The CI's config does not** — see K2.

---

## A. Kernel engine (hookless)

### A1 — HIGH — Rule replacement leaves the parent's child node half-updated ✅ *confirmed on device*

`__nomount_inject_child_locked()` (`nomount.c:1970`), when a child with the same name already exists,
updates **only** two fields:

```c
child->flags = rule->flags;
child->rule  = rule;
return;
```

It does **not** refresh `child->d_type`, `child->fake_ino`, or the parent's `dir_node->size_delta`
(whose contribution via `nm_child_size_contrib()` depends on the very flags just changed).

This branch is reached on the shadow path in `__nomount_add_rule()` — re-adding a rule for a vpath that
already has one, which is what `nomount reload` does on a module update.

Consequences:
- `d_type` stale → `nm_dir_nlink_delta()` mis-counts, so the parent directory's link count contradicts
  its contents.
- `fake_ino` stale → readdir and stat can disagree on the entry's inode.
- `size_delta` stale → on erofs, `nm_dir_size_fix()` applies the *old* rule's byte contribution
  (whiteout→addition is a `2 × (12 + namelen)` error).

**Live proof** (`/data/local/tmp`, f2fs, control vs case):

```
CONTROL  fresh DIR rule, never shadowed : x=directory  parent nlink=3   ✓
CASE     FILE rule shadowed by DIR rule : x=directory  parent nlink=2   ✗
CONTROL  real on-disk dir with 1 subdir :              parent nlink=3   ✓
```

`x` stats as a directory and is descendable (`ls` returns `inner`), yet the parent reports 2 links.
No real filesystem produces that — it is precisely the one-stat tell the engine exists to remove.

Note the `fake_ino` half is usually *masked*: the replacement rule resolves its vpath through the
still-live injection, so it inherits the old `v_ino`. It stops being masked when the old rule is a
whiteout (vpath no longer resolves → fresh sibling-derived ino).

**Fix:** in the overwrite branch, subtract the old contribution, refresh `d_type`/`fake_ino`, add the
new contribution — or just delete and re-add the child.

### A2 — HIGH — RCU list-node reuse corrupts a concurrent `nm list`

`nm_detach_rule_locked()` (`nomount.c:3283`):

```c
hash_del_rcu(&rule->vpath_node);      /* leaves ->next intact, by design, for RCU readers */
...
hlist_add_head(&rule->vpath_node, victims);   /* overwrites ->next */
```

`hlist_del_rcu()` deliberately preserves `n->next` so a reader already positioned on the node can walk
off it. Linking the same `hlist_node` onto the victims list immediately clobbers that pointer.

`nomount_nl_dump_rules()` (`nomount.c:3525`) traverses `nomount_rules_ht[bkt]` under
`rcu_read_lock()` **only** — it does not take `nomount_write_mutex`. So a `nm list` concurrent with an
`nm del` / `nm reload` can follow `->next` out of the hash bucket and into the victims list.

Not a use-after-free (the `synchronize_rcu()` before the frees covers the reader), but the dump can
emit deleted rules, duplicate rules, or mis-set `cb->args`. That output feeds the reload delta and
`selfcheck`. `nomount_prune_empty_virtual_dirs()` has the same pattern.

**Fix:** give `nomount_rule` a separate `struct hlist_node victim_node` for the teardown list, or defer
the victim linking until after a grace period.

### A3 — MEDIUM — A failed rule add reports success ✅ *confirmed on device*

`nomount_nl_add_rule()` batch path logs each `__nomount_add_rule()` error and then
`return 0;` unconditionally (`nomount.c:3428`). The bundled `nm` client uses the batch path for
`nm a`, so its exit code cannot reflect per-entry failure either.

```
$ nm a /data/local/tmp/nmt/dir/ghost /data/local/tmp/nmt/DOES_NOT_EXIST
  nm exit code = 0
  rules live for that path: 0
  rule count before/after: 260 / 260
```

`nm_alloc_rule()` correctly rejects an unresolvable backing path with `-ENOENT` (that reject is a good
fix — it removes the "lists but ENOENTs" tell). The problem is only that the rejection never reaches
the caller. Combined with `metamount.sh` discarding stderr and not checking the exit code, **a module
whose files fail to inject is indistinguishable from one that injected fine**, and `reload`'s delta
records them as applied.

**Fix:** return the first error (or a count) from the batch loop and have the client propagate it.

### A4 — MEDIUM — `size_delta` is not UID-scoped but `nlink` delta is

In `nomount_hijacked_getattr()`, the link-count correction filters children through
`nm_rule_visible()` (`nm_dir_nlink_delta()`), but the size correction reads `d->size_delta` raw.
A `--uid`-scoped rule therefore shifts the reported directory **size** for every caller while moving
the **link count** only for the targeted one. On erofs that is a stat divergence visible to any
untargeted process.

### A5 — LOW/MEDIUM — `nm_get_link()` returns `-ECHILD` in ref-walk

`nm_get_link()` returns `ERR_PTR(-ECHILD)` when `info`/`r_path.dentry` is missing, regardless of
whether `dentry` is NULL (RCU-walk) or not. On the ref-walk call the VFS propagates it, so userspace
sees `ECHILD` ("No child processes") from a path operation — an errno no filesystem produces there.
Should be `-EIO` when `dentry != NULL`. Currently unreachable (the header notes `LOOKUP_FOLLOW` means
`S_ISLNK` never holds), but it is a latent tell if symlink resolution ever changes.

### A6 — LOW/MEDIUM — `nm_setattr()` forwards `ATTR_FILE` pointing at the synthetic file

`nm_setattr()` passes the caller's `struct iattr` straight to `notify_change()` on the backing dentry.
On `ftruncate()`, `do_truncate()` sets `ATTR_FILE` with `ia_file` = **our** `struct file` (whose
`f_op` is `nm_file_fops`), not the backing one held in `private_data`. A backing fs that consults
`attr->ia_file` gets the wrong file. Read-only ROM targets mask this today.

### A7 — LOW — `nstat` is set but never read (breaks `W=1` clang)

`nomount.c:2213` `int i, nstat = 0;` — incremented at `:2261`, never read. Confirmed to fail a
`W=1` clang build with `-Werror`. Dead code; delete it.

### A8 — LOW — `bloom_mask` read without `READ_ONCE`

`nomount_get_rule_info()` reads `dir_node->bloom_mask` with a plain load while writers use
`WRITE_ONCE`. `__nomount_delete_child_locked()` was deliberately fixed to publish the rebuilt mask in
one store — the reader side should match it.

### A9 — INFO — Residual identity surface

The engine goes to real lengths to drop identity tells (no `/sys/kernel/<name>` kobject, no genl family
name, no `MODULE_VERSION` so no `/sys/module/<name>/version`, innocuous slab-cache names). Verified on
device: `/sys/module/nomount` **does not exist** ✓. What remains:

- **`/proc/kallsyms` leaks 55 `nomount_*` symbol names.** Mode `-r--r--r--`, context `proc_kallsyms`.
  Addresses are zeroed by `kptr_restrict`, but the *names* are plain text
  (`nomount_spoof_mmap_metadata`, `__nomount_clear_all`, `nomount_create_new_inode`, …). Reachable by
  any domain sepolicy permits to read `proc_kallsyms` — on stock Android that excludes app domains but
  includes `shell`. I could not get an `untrusted_app`-domain read to execute on this device to settle
  the app-reachability question either way, so treat this as *DAC-open, SELinux-gated, unmeasured for
  app domains*. Static function names could be shortened/genericised the same way the slab caches were.
- **`/proc/slabinfo`** shows `vfs_dnode` / `vfs_ninfo` / `vfs_iops` / `vfs_fops` — well disguised, and
  the file is `0440 root:log`.
- **Superblock hijack is never undone at runtime.** `nm clear` restores hijacked directory inodes but
  leaves `s_op`/`s_xattr` swapped for the lifetime of the mount (`nomount_restore_superblocks()` is
  only called from `nomount_exit`, which is `__exit` on a `bool` Kconfig symbol and therefore dead
  code). Functionally harmless — the handlers fall through — but the partition stays hijacked after a
  clear.

### A10 — INFO — `ki_filp` swap is not async-safe

`nm_read_iter()`/`nm_write_iter()` swap `iocb->ki_filp` to the backing file, call through, then restore.
If the backing `read_iter` returns `-EIOCBQUEUED` (io_uring/AIO), completion runs later against the
restored — wrong — `ki_filp`. Read-only ROM targets and the current call pattern make this latent.

---

## B. kbuild

### B1 — HIGH — CI cannot detect a misapplied `fs/Makefile` / `fs/Kconfig` hunk ✅ *confirmed by experiment*

The workflow applies patches with `patch -p1 --forward --fuzz=3` — very permissive placement — then
verifies wiring with:

```yaml
grep -n 'CONFIG_NOMOUNT' fs/Makefile fs/Kconfig || true    # never fails
```

I removed the `obj-$(CONFIG_NOMOUNT) += nomount.o` line from `fs/Makefile` and ran the CI's own build
step:

```
NO-MAKEFILE-ENTRY-RC=0
-rw-r--r-- 1 steve steve 763136 out/fs/nomount.o
```

`make fs/nomount.o` builds the object from the single-target rule **whether or not it is in `obj-y`**.
So a fuzzed or misplaced Makefile hunk produces a green matrix and a kernel that never links the engine.

This is the same failure class already hardened for `task_mmu.c` (which asserts both presence *and*
that the call landed inside `show_map_vma` — good, and all 10 patches do carry that hunk, verified).
The Makefile/Kconfig hunks deserve the same assertion:

```bash
grep -q 'obj-$(CONFIG_NOMOUNT) += nomount.o' fs/Makefile || { echo FATAL; exit 1; }
grep -q '^config NOMOUNT'                    fs/Kconfig  || { echo FATAL; exit 1; }
grep -q '^CONFIG_NOMOUNT=y'                  out/.config || { echo FATAL; exit 1; }
```

### B2 — MEDIUM/HIGH — The bootconfig spoof is never compiled by the matrix ✅ *confirmed*

The workflow configures with `make defconfig`. Running the CI's exact recipe on the 6.12 tree:

```
$ make ARCH=arm64 O=out3 defconfig && ./scripts/config --file out3/.config -e NOMOUNT && make olddefconfig
# CONFIG_BOOT_CONFIG is not set
CONFIG_NOMOUNT=y
```

`CONFIG_BOOT_CONFIG` is present in `gki_defconfig` but **absent from arm64 `defconfig`**. Everything
under `#ifdef CONFIG_BOOT_CONFIG` — `nm_snapshot_bootconfig()`, `nm_bootconfig_show()`,
`nm_set_bootconfig()`, `nm_mk_bootconfig_pde()`, and the `NM_KNOB_BOOTCONFIG` dispatch — therefore has
**zero compile coverage on all ten versions**. That is load-bearing code for the verifiedbootstate
cloak. (It does compile clean under `gki_defconfig`, as this audit's builds show.)

**Fix:** use `gki_defconfig` where it exists, or explicitly `-e BOOT_CONFIG` alongside `-e NOMOUNT`.

### B3 — MEDIUM — Warning signal is generated and then discarded

`KCFLAGS=-Wno-error` is set for every build **and is inherited by the advisory step** (MAKEOPTS is
persisted via `$GITHUB_ENV`). The `W=1` + sparse step is additionally `continue-on-error: true` and
ends by emitting a count into a `::notice::`. There is no threshold and no baseline, so a regression
from 0 → N warnings changes nothing observable. The `nstat` warning (A7) is exactly what this step
exists to catch and exactly what it will not act on.

**Fix:** fail the advisory step when the `nomount.[ch]`-only warning count exceeds a checked-in
baseline (0 today).

### B4 — LOW — The per-build netlink-proto randomisation cannot actually be used

`nomount.h` documents `NOMOUNT_NL_PROTO` as "overridable at build time (e.g. randomize per build); the
userspace `nm` client MUST be built with the same value" and guards it with `#ifndef`. The client
hardcodes it unguarded:

```c
/* userspace/src/nm.h:68 */
#define NOMOUNT_NL_PROTO 29
```

`-DNOMOUNT_NL_PROTO=…` on the client is a redefinition. The documented mitigation is unreachable
without editing the header. Add the `#ifndef` guard on the client side too.

### B5 — LOW — `hookless/AUDIT.md` is stale (see header note).

---

## C. Suite module

### C1 — MEDIUM — The bootloop guard cannot protect against `spoof.sh`

In both `metamount.sh` and `post-fs-data.sh`, the spoof add-on runs **before** the guard is evaluated
and is **not gated on `$NMDIR/disabled`**:

```sh
[ -f "$MODDIR/spoof.sh" ] && sh "$MODDIR/spoof.sh" 2>/dev/null   # metamount.sh:76
# --- bootloop guard ---                                          # :78
if   [ -f "$NMDIR/disabled" ]; then ...
elif [ "$COUNT" -ge "$GUARD_MAX" ]; then : > "$NMDIR/disabled"
elif [ -x "$BIN" ]; then timeout 60 "$BIN" mount ...
```

`disabled` only ever suppresses the mount pass. `spoof.sh` is 628 lines that manipulates `resetprop`
properties, `uname`, `/proc/cmdline` and `/proc/bootconfig` — a higher bootloop risk surface than the
injection pass — and it keeps running on every boot even after the guard has tripped. A user whose
device is bootlooping on a spoof setting has no self-recovery path.

**Fix:** move the `spoof.sh` call below the guard, inside the same `elif` that gates the mount pass
(or at least gate it on `! -f "$NMDIR/disabled"`).

### C2 — MEDIUM — `chattr +i "$KSUD"` sets immutability rather than restoring it

`metamount.sh:58/69` and `service.sh:67/78`:

```sh
chattr -i "$KSUD" 2>/dev/null
... cp "$KSUD" "$SUSFS_BIN.nm_new" ...
chattr +i "$KSUD" 2>/dev/null   # comment: "Restore ksud's immutable flag"
```

Nothing records whether `+i` was set beforehand. If it was not, this **adds** immutability that the
system did not have, on every boot — the opposite of the stated intent. A subsequent legitimate ksud
update then fails with `EPERM`. Capture the prior state (`lsattr`) and only restore it, or drop the
`+i` entirely (the copy only needs read access, which `-i` was not required for in the first place).

### C3 — MEDIUM — A timed-out `doctor` is reported as "healthy"

`service.sh:182`:

```sh
_doc=$(timeout 30 "$BIN" doctor 2>/dev/null | sed -n 's/^summary: \([0-9]*\) errors, \([0-9]*\) warnings.*$/\1 \2/p')
_err=$(echo "$_doc" | awk '{print $1+0}')
```

If `doctor` times out or fails, `_doc` is empty, `_err`/`_wrn` become `0`, and the module card reads
**"healthy"**. Same shape as A3: a failure is coerced into a success value. Distinguish "0 problems"
from "could not be determined" and say so on the card.

### C4 — LOW/MEDIUM — Two WebUI call sites build a root shell command without `shq()`

`index.html` defines the correct helper and uses it in `setConf`:

```js
function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }   // :2226
```

but six `nm(...)` call sites interpolate raw. Four are safely guarded by input regexes —
`UID_TARGET_RE = /^[A-Za-z0-9._*]+$/` for `uidOp`, and
`WO_PATH_RE = /^\/[^\s'"`;|&$<>()*?\[\]{}\\]*$/` for both whiteout paths. **Two are not:**

```js
async function unblockOne(target) { await nm(`uid unblock '${target}'`); }   // :2142
async function saveOne(target)    { await nm(`uid block   '${target}'`); }   // :2149
```

`target` comes from the row's `data-nmt`, derived from `nomount uid list` output and ultimately from
`/data/adb/nomount/uidhide`. A single quote in that value escapes the quoting and the KSU WebUI
`exec()` runs it as root.

This is **not** a privilege boundary crossing — writing `uidhide` already requires root, and package
names cannot contain quotes. It is defence-in-depth against a malformed or future non-validated
writer (a preset/scan path that emits an odd entry), and the fix is to call the helper that is already
in the file. Same for the `uspick` row at `:2100`.

### C5 — LOW — `nm list` is re-run once per module in the boot path

`metamount.sh:170` calls `"$NM_BIN" list` inside the per-module tagging loop, plus twice more at
`:185`/`:186`. On this device that is **16 full netlink dumps of 260 rules** during post-fs-data. Hoist
one `nm list` into a variable and count from it — the OPlus boot watchdog is the reason the kernel-side
scan was optimised in the first place.

### C6 — LOW — `echo - > /proc/pathhide` wipes every rule, not just ours

`service.sh:32` clears the global pathhide list before re-applying `pathhide.conf`. Any other module
using the same interface (PathHideManager, a standalone cloak) loses its rules whenever the Suite's
service runs.

### C7 — LOW — `exec 9>"$LOCK" 2>/dev/null` silences stderr for the rest of `metamount.sh`

`metamount.sh:20` — the `2>/dev/null` is part of the `exec`, so it applies to the whole remaining
script, not just the fd-9 redirection. Every diagnostic written to stderr by anything the boot pass
calls is discarded. Reinforces the A3/C3 theme.

### C8 — LOW — State files in `/data/adb/nomount` are `0666`

Observed on device: `absorbed.list`, `binds.lock`, `uidhide`, `uidhide.cache` are `-rw-rw-rw-`. The
directory is `0700 root:root`, so this is not exploitable today — but `uidhide` is the hiding policy,
and the scripts already take care to `chmod 0600` `.mount.lock` for exactly this reason. Make the
writers use a `0600` umask.

### C9 — INFO — The install integrity check detects corruption, not tampering

`customize.sh` verifies `nomount.sha256sums` — a manifest bundled **inside the same zip**. Anyone who
modifies a file modifies the manifest. The behaviour is right; the comment ("Catches a corrupted
download or a tampered zip before we run a root binary") oversells it. Reword to "corrupted download".

### C10 — nit — `scan.sh` `xargs` quote handling

`pm list packages -3 -f | ... | xargs -P "$J" -n1 sh -c '...'` — `xargs` without `-d`/`-0` applies
quote processing, so an APK path containing `'` or `"` mangles or aborts the scan. Unlikely on Android
paths; `xargs -d '\n'` removes the class.

---

## What is in good shape

Worth recording, because several of these are the hard parts:

- **Lifetime discipline in the hot paths is sound.** Every hijacked handler recovers its vtable and
  pins `dir_node` with `atomic_inc_not_zero` under one `rcu_read_lock`, then never dereferences the
  `nm_iop`/`nm_fop` again — the sleeping-alloc window is correctly handled.
- **`nm_rule_info` snapshotting** removes the class of bug where lockless readers dereferenced a rule
  after `rcu_read_unlock()`.
- **The four `destroy_inode`/`free_inode` combinations** in `nomount_hijack_superblock()` are all
  handled correctly, including the `free_inode_nonrcu` case for filesystems that define neither.
- **`__nomount_add_rule` / `__nomount_del_rule` both refuse (`-EBUSY`) to free a rule that still owns a
  populated virtual subtree** — the descendant-`parent_dir`-dangling UAF is closed on both paths.
- **`get_attr()` in the C client bounds-checks properly** (`alen < 4`, payload-fits), and `MAX_PAYLOAD`
  (16296) genuinely exceeds the largest single batch entry (12 + 4096 + 4096 = 8204), so the flush
  logic cannot overflow.
- **The `task_mmu.c` hunk is present in all 10 patches** and CI asserts both its presence and that it
  landed inside `show_map_vma`.
- **`S_PRIVATE` is gone** and contexts are mirrored instead — the LSM bypass called out in the old
  audit is genuinely fixed.
- **`/sys/module/nomount` does not exist on the running device** — the `MODULE_VERSION` reasoning holds.

---

## Suggested order

1. **A1** — half-updated child node (confirmed live tell, small localised fix)
2. **B1** — assert the Makefile/Kconfig hunks in CI (cheap, prevents a silent no-op ship)
3. **A2** — separate `hlist_node` for the victims list
4. **C1** — move `spoof.sh` behind the bootloop guard
5. **A3 / C3 / C7** — stop coercing failures into success (batch return code, doctor timeout, stderr)
6. **B2** — `gki_defconfig` (or `-e BOOT_CONFIG`) in CI
7. **A7 / B3** — delete `nstat`, then make the W=1 count a gate
8. **A4, C2, C4, C5** — the rest
