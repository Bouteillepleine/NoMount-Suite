# NoMount **hookless** — full audit & review (kernels 4.9 → 6.18)

Source: `maxsteeel/nomount@experimental/hookless` (head `eb9587b`, 2026‑07‑25).
Module artifact reviewed: `NoMount-v1.1.0-196-77432e9.zip`.
Reviewer: static analysis only — **no kernel was compiled** (needs the kbuild CI).
Compile-viability verdicts below are predictions to be confirmed by the CI matrix.

---

## 1. What "hookless" is

- **Kernel patch = 2 files only** (`fs/Kconfig`, `fs/Makefile`, 29 lines, identical
  across all 10 versions, `default y`). All logic lives in the module source
  `fs/nomount.c` (1768 L) + `include/linux/nomount.h` (300 L), compiled as
  `obj-$(CONFIG_NOMOUNT) += nomount.o`.
- **Mechanism = per-object ops-vtable hijacking.** For a targeted directory inode
  it heap-allocates a *copy* of that inode's `inode_operations`
  (`nm_iop.fake_iop = *inode->i_op`), stores the original pointer, patches only
  `lookup`/`unlink`/`rename`, then `smp_store_release(&inode->i_op, &fake_iop)`.
  Same for `i_fop` (dir iterate) and `s_op` (destroy/drop/evict_inode + the whole
  `s_xattr` handler array). **The shared `const` rodata ops structs are never
  mutated** — the one thing this technique must get right, and it does.
- **Type recovery** = `container_of` + fault-safe read (`copy_from_kernel_nofault`,
  or `probe_kernel_read` < 5.8) of a 64-bit `signature == NOMOUNT_MAGIC_SIG`. Safe
  even against arbitrary rodata pointers.
- **Control plane = Generic Netlink** (family `"nomount"`, `GENL_ADMIN_PERM`),
  driven by the `nm` binary (zip: `bin/nm-arm`, `bin/nm-arm64`). **No `/dev` node,
  no ioctl, no char device.** Different ABI from the hooks line's `/dev/nomount`.
- **Loads at `fs_initcall`** but hijacks **nothing until userspace adds a rule** →
  zero-rule boot is inert. No `task_struct` fields touched → the OP15
  `android_oem_data1` bootloop class is structurally absent; **no recursion guard
  needed** (interception is per-inode, not per-call-site global).
- **Value over the redirect/hooks line:** real `whiteout` + `rename`/COW semantics
  (can *hide* stock files), which getname-redirect could not do.
- **No SUSFS integration** (hooks line had 21 `#ifdef CONFIG_KSU_SUSFS`; this has 0)
  and **no self-hiding** story; the netlink family name is visible in `genl-ctrl`.

---

## 2. Per-version guard coverage matrix

Version-sensitive APIs and how the source gates them (✔ = handled correctly for
the target set; ⚠ = imprecise boundary but harmless for the built versions):

| API / concern | Guard in source | 4.9 | 4.14 | 4.19 | 5.4 | 5.10 | 5.15 | 6.1 | 6.6 | 6.12 | 6.18 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `unaligned.h` include | `>=6.12 linux/` else `asm/` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| fault-safe read | `<5.8 probe_kernel_read` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| idmap arg (`IDMAP_*`) | `>=6.3 idmap / >=5.12 userns / none` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `filldir`/actor return | `>=6.1 bool else int` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| genl policy location | `<5.2 per-op else per-family` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| xattr `.get` flags arg | `5.2..<5.12 FLAGS_ARG` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `.iterate` vs `_shared` | `<6.6 also .iterate` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| inode time fields | `>=6.12 sec/nsec / >=6.6 set_ctime / else` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `d_revalidate` sig | `>=6.11 (dir,name,dentry,flags)` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `mmap` vs `mmap_prepare` | `>=6.16 mmap_prepare` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `generic_fillattr` args | `>=6.3 request_mask` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ⚠¹ |
| addr_space private_list | `>=6.8 i_private_list else private_list` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| **`vfs_getattr_nosec`** | **unconditional 4-arg** | **✗²** | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |

¹ `generic_fillattr` `request_mask` actually landed in 6.6, guard says `>=6.3`; only
affects 6.3–6.5 (not in the set), so harmless here — but wrong in principle.
² see Finding **F1**.

---

## 3. Findings (ranked)

### F1 — HIGH — `vfs_getattr_nosec` 4-arg breaks the 4.9 build
`nm_file_getattr()` calls `vfs_getattr_nosec(&info->r_path, stat, request_mask,
query_flags)` **unconditionally**. The 4-arg signature (adds `request_mask`,
`query_flags`) landed in **4.11**; kernel **4.9 has the 2-arg form**. There is no
`LINUX_VERSION_CODE` guard around this call → **4.9 will fail to compile**
(4.14/4.19/5.4+ are fine). Fix: guard the call, or `#if <4.11` fall back to
`vfs_getattr(path, stat)` / 2-arg `vfs_getattr_nosec`.

### F2 — MED — `S_PRIVATE` set on live production inodes
`nomount_hijack_dir_inode()` sets `inode->i_flags |= S_PRIVATE` on the real
`/system`-family directory inode (restored via `had_private_flag`). On a
user-visible directory this suppresses fsnotify/LSM-inode paths for that dir.
Low crash risk, but a genuine behavioural change on production inodes and a
possible interaction source. Applies to all versions.

### F3 — MED — superblock-wide `s_op`+`s_xattr` swap; unload-time proxy UAF
Hijacking one dir on erofs `/system` swaps the **whole** superblock's `s_op` and
proxies the **entire** `s_xattr` array → every `getxattr` on that sb (SELinux hits
`security.selinux` constantly) takes an extra indirection. On teardown,
`nomount_restore_superblocks()` `kfree`s the xattr proxies **immediately after**
the `smp_store_release`, with **no `synchronize_rcu`** → an in-flight xattr op can
UAF the proxy. **Only triggers on module unload → build `CONFIG_NOMOUNT=y`
(built-in), never `=m`.** Applies to all versions.

### F4 — LOW — `i_mapping` aliasing + duplicate assignment
`nomount_create_new_inode()` sets `inode->i_mapping = real_inode->i_mapping`
(line duplicated, harmless). Fine for read-only payloads (normal case);
questionable writeback/accounting for writable files. All versions.

### F5 — LOW — `CONFIG_NOMOUNT default y`
All 10 integration patches set `default y`, i.e. the driver is built into every
kernel by default. Inert without rules, but it's a policy choice; prefer
`default n` and enable per-build via fragment.

### F6 — INFO — detectability / hygiene
No `/dev` node (nothing to `sus_path`), truly mountless (no overlay mounts to
umount-hide), but the netlink family `"nomount"` is enumerable (`genl-ctrl list`),
`MODULE_AUTHOR("maxsteeel")`/`MODULE_DESCRIPTION` strings are in the image, and
injected inodes remain globally visible (UID-gated only) — integrity checks over
redirected `/system` files still see them. No self-hiding by design.

### F8 — HIGH — `d_revalidate` guard breaks the 6.12 build (found during real-tree verification)
`nm_d_revalidate` switches to the 4-arg signature `(inode *dir, const qstr *name,
dentry *, unsigned int)` at `>= KERNEL_VERSION(6, 11, 0)`. Verified against real
trees: **android15-6.6 and android16-6.12 both still declare the 2-arg**
`d_revalidate(struct dentry *, unsigned int)`; only **6.18** (`linux-6.18.y`) has the
4-arg form. So on 6.12 — the **primary target** — the 4-arg function is assigned to
a 2-arg `dentry_operations.d_revalidate` slot → incompatible-pointer-type build
error. The original audit's "6.12 ✔ confirmed" was wrong (it trusted the guard).
**Fixed in the vendored copy: guard moved to `>= KERNEL_VERSION(6, 13, 0)`** (boundary
lies in (6.12, 6.18]; 6.12 verified 2-arg, 6.18 verified 4-arg). Both the function
signature and the `parent_dir = dir` guard were updated.

### F7 — DESIGN — RRO/idmap theming still unresolved
Still mountless: no overlayfs, no real mount. The documented OxygenCustomizer wall
(idmap2/OMS needs the overlay APK on a real mount to reach `STATE_ENABLED`) is not
obviously cleared. Hookless presents the injected APK as a genuine dentry+inode on
the real erofs sb (closer to "real" than getname-redirect) so it *might* reach
idmap generation — unproven. Assume RRO theming still needs `magic_mount_rs`;
hookless replaces only the file-injection role (mutually exclusive metamodule).

---

## 4. Per-kernel compile-viability prediction (confirm via CI)

| Kernel | Prediction | Notes |
|---|---|---|
| 4.9  | ❌ likely FAIL | F1 `vfs_getattr_nosec` 4-arg; also oldest genl/xattr surface |
| 4.14 | ⚠ probable | 4-arg getattr OK; verify xattr `.get`/`.set` handler sig, genl |
| 4.19 | ⚠ probable | as 4.14 |
| 5.4  | ✔ likely | pre-idmap path (`IDMAP_*` empty), mature APIs |
| 5.10 | ✔ likely | GKI 1; well-trodden |
| 5.15 | ✔ likely | GKI |
| 6.1  | ✔ likely | GKI; `userns` idmap path |
| 6.6  | ✔ likely | GKI; `.iterate` gone, `set_ctime` |
| 6.12 | ✔ after F8 fix | primary target; **would have broken pre-fix** on `d_revalidate` (see F8) |
| 6.18 | ⚠ bleeding edge | `mmap_prepare`/`vm_area_desc` + 4-arg `d_revalidate` + `linux/unaligned.h` all verified present |

Headline: **the modern GKI band (5.4–6.12) should compile; 4.9 needs a getattr fix;
4.14/4.19 and 6.18 are the "watch" ends of the range.**

---

## 5. Build/test plan for `Bouteillepleine/kbuild` (branch `hookless`)

Reality: the existing `kbuild` builder (branch `nomount`) is a **GKI OnePlus device
builder** covering exactly 5 versions (android12-5.10 … android16-6.12). It
**cannot** build 4.9/4.14/4.19/5.4/6.18 (no OnePlus device / no GKI branch). So
validating "all 10" requires a **compile-test matrix** against each version's
canonical AOSP common kernel — a new, lighter workflow than the device builder.

Proposed layout on branch `hookless`:
- `kernel_patches/hookless/nomount_<ver>_kernel_integration.patch` ×10 + `src/{nomount.c,nomount.h}` (vendored, or cloned from `maxsteeel/nomount@experimental/hookless`).
- `.github/workflows/hookless-compile-matrix.yml` — matrix over the 10 versions:
  fetch matching `common-android*`/stable source + matching clang, apply patch +
  drop `src/*` into `fs/`, `CONFIG_NOMOUNT=y`, `make fs/nomount.o` (or a minimal
  `olddefconfig && make -j fs/`), upload logs. This is the "test/build" that proves
  each patch across all 10 and will confirm/deny F1 and the ⚠ rows above.
- Keep (optionally) a device-build path reusing the existing builder for the GKI-5
  subset when a bootable OnePlus image is wanted.

---

## 6. Verification log (signatures checked against real kernel trees)

Fetched the actual headers from `android.googlesource.com/kernel/common` (and
`git.kernel.org` for 6.18) and confirmed each version-sensitive API rather than
relying on memory:

| Check | Result |
|---|---|
| 4.9 `getattr` = `(vfsmount,dentry,kstat)`; `vfs_getattr_nosec`/`generic_fillattr` 2-arg | ✔ confirmed → **F1 fix correct** |
| 4.14 `getattr` = 4-arg path form; `vfs_getattr_nosec` 4-arg | ✔ confirmed (uses `>=4.11` branch) |
| 4.9 `genl_family` has `.ops`/`.n_ops`/`.module`; single-arg `genl_register_family` | ✔ present — no genl break on 4.9 |
| 5.4 `probe_kernel_read` exists (`<5.8` path) | ✔ confirmed |
| 6.1 `filldir_t` returns `bool` (`>=6.1` actor) | ✔ confirmed |
| 6.6 `generic_fillattr(mnt_idmap,u32,inode,kstat)` matches `>=6.3` 4-arg call | ✔ confirmed |
| 6.6 `.iterate` removed (only `iterate_shared`) | ✔ confirmed |
| 6.6 / 6.12 `d_revalidate` = **2-arg**; 6.18 = **4-arg** | ✔ → **F8 found & fixed (`>=6.13`)** |
| 6.12 has `.mmap`, no `mmap_prepare` | ✔ (uses `.mmap`; `mmap_prepare` gated `>=6.16`) |
| 6.18 has `mmap_prepare`, 4-arg `d_revalidate`, `linux/unaligned.h` | ✔ confirmed |

Toolchain reality also corrected: the 4.x AOSP-common branches now live under
`deprecated/` (`deprecated/android-4.9-q`, `.../android-4.14-stable`,
`.../android-4.19-stable`) — the CI matrix branch names were fixed accordingly.

**Userspace + module reviewed too:** `nm.c` is a freestanding nolibc netlink client
whose wire format (12-byte add / 6-byte del headers, whiteout flag `4`) matches the
kernel's `nomount_genl_add_rule`/`del_rule` exactly. `metamount.sh` has a `.booting`
bootloop semaphore (self-disables on the next boot after a hang), `.replace`/char-dev
whiteout handling, and batched `xargs -0` netlink calls; `service.sh` replays UID
exclusions. No blocking issues.

### Net: two real compile-blockers fixed before CI
1. **F1** — 4.9 `getattr`/`vfs_getattr_nosec` (guarded to the pre-4.11 signature).
2. **F8** — 6.12 `d_revalidate` (guard moved `6.11`→`6.13`).
Everything else in the guard set verified correct for all 10 target versions.
