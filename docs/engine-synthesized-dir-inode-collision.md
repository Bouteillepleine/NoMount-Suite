# Engine: two ways a synthesized directory gives itself away

**Status:** measured and reproduced on an OP15 running engine v30; fixed in v31,
which is what that device runs now. Detection shipped in Suite v1.3.164 as the
`synthesized dir inode collision` check.

**The fix is written, compile-verified and boot-verified.** Clean at `W=1` on all
ten pinned kernels (4.9 ... 6.18), same as the unpatched baseline; then built for
OP15 by `OnePlus-ReSukiSu_NMS` with `nomount_ref=prerelease` and flashed
(2026-09-07).

Result on the device that showed all three collisions:

    before   Mms=101  Mms/lib=77   Mms/lib/arm64=89    -- 3 collisions
    after    Mms=187  Mms/lib=188  Mms/lib/arm64=189   -- 0 collisions

Stock maximum on that filesystem is 186, so the three land immediately above it:
free by construction, and the same digit count as their neighbours. An
independent scan (188 directories, inodes 2..189) reports no duplicated inode at
all, and `nomount check` goes from WARN to PASS with the whole report clean.
Re-read on the live v31 device (2026-09-08): `[PASS] synthesized dir inode
collision ... 3 director(ies) the engine synthesized checked against 429 on the
same partition(s); no shared inode`.

---

## The oracle

`(st_dev, st_ino)` identifies a file uniquely, and directories cannot be
hardlinked. So two directory paths reporting the same pair is **impossible on a
real filesystem**. Finding them costs one `stat` per directory and no root:

```
walk a ROM partition
group directories by (st_dev, st_ino)
any group larger than one contains a directory the engine invented
```

Measured on an OP15, `/product`, all 1232 entries across all 24 mounted devices:

| device | entries | inodes used more than once |
|---|---|---|
| dev 56 (`/product/priv-app`, overlay) | 188 | **3** |
| every other device (23 of them) | 1044 | 0 |

All three groups on dev 56 pair a synthesized directory with a stock one:

```
/product/priv-app/Mms           == /product/priv-app/OplusScreenRecorder/oat/arm64   (ino 101)
/product/priv-app/Mms/lib       == /product/priv-app/GmsCore/m/independent/oat       (ino 77)
/product/priv-app/Mms/lib/arm64 == /product/priv-app/Wallpapers/oat/arm64            (ino 89)
```

Perfect precision and perfect recall on this device: every synthesized directory
collides, and nothing else does.

**Injected files do not collide.** The gap-interleaving in `nm_place_ino` works -
139 APKs under `/product/overlay` produce zero collisions. This is a
directory-only defect and the file path must not be touched.

The stock partner changes between boots (overlayfs assigns `st_ino` at mount
time) but the collision itself is deterministic.

## Why it happens

It is arithmetic, not bad luck. `/product/priv-app` holds **188 directories in
inode range 2..186** - 185 available values. By pigeonhole at least three must
collide, and the three excess are exactly the three the engine added. Adding N
synthesized directories to a saturated inode space guarantees N collisions.

`nm_place_ino()` searches for a free gap between the target's **siblings**, and
`nm_ino_taken()` consults only `pop->v[]` (up to `NM_INO_SAMPLES` = 64 immediate
subdirectories of the nearest real ancestor) plus `pop->mine[]` (its own
handouts). On this device the siblings occupy 3..71 while the **nested**
directories two and three levels down occupy 72..186 - and the engine never sees
them. 77, 89 and 101 all came from the gap search's last-element branch, where
`room` defaults to 64 above the top sampled sibling.

So it is not the "past the top" fallback that is wrong; widening only that would
not help.

## Why `overlay dir inode range` passed it

`audit.rs::check_overlay_dir_ino` tests **magnitude**: it flags an inode only if
it exceeds the stock sibling maximum by 8x. 101 against a sibling maximum of 71
is well inside that. The number is plausible and impossible at the same time.
The new `check_dir_ino_collision` tests the impossibility directly.

## The design constraint

The three properties cannot all hold at once:

1. the inode must be of a **plausible magnitude** (this is why the 1 MB step was
   replaced - a dir at `/product/etc` was minting children at 1226252..2181515
   against stock siblings of 7166..20309, and one stat separated them);
2. it must be **collision-free**;
3. it must be chosen **without knowing which inodes the filesystem already uses**.

A plausible magnitude means "inside or just above the used range". On a saturated
range that means colliding. Dropping (3) is the only escape: the allocator has to
know the used set, or at least the true maximum, for the whole device - not for
one directory level.

## The fix as written

The shape is clear:

- **directories only** - leave `nm_place_ino`'s gap search for files exactly as
  it is;
- allocate at `max(device_subtree_max, pop->hw) + 1`. On this device that is
  187+: free, and adjacent to the top, so magnitude stays plausible;
- **fail safe** - if the walk cannot establish that maximum, fall back to today's
  behaviour unchanged, so the patch is never worse than the current code.

`nm_subtree_dir_ino_max()` establishes the ceiling. What it has to get right:

- it needs a **bounded recursive** directory walk (the collisions here are three
  levels down), not the single-level `nm_dir_ino_pop` scan;
- `nm_dir_ino_pop` returns inodes but not child **names**, so a second actor is
  needed to collect them;
- a depth-first walk needs the child names of every level held simultaneously.
  At `NAME_MAX + 1` per name that is tens of KB per level - too much for
  `kmalloc` at several levels, so it needs either `kvmalloc`, a re-scan-by-index
  strategy, or a bounded bfs queue;
- it must be right on **ten kernel versions**, 4.9 through 6.18, where the
  `iterate_dir`/`filldir_t` signatures differ (the existing `NM_ACTOR_RET`
  machinery handles this and should be reused);
- the value becomes a live inode's `i_ino`, so an error here is not a leak, it is
  a VFS-visible defect.

Two details worth knowing about the implementation:

- **It climbs to the mount root before walking down.** Walking only the caller's
  ancestor would place a dir under `/product/priv-app/Foo` above Foo's little
  subtree while the rest of the mount sits far higher - and the collision would
  survive the fix. It climbs while `st_dev` holds, which lands on the mount root.
- **Directories are never sampled if we invented them.** Feeding a synthesized
  inode back into the ceiling would ratchet it upward on every boot.
- **It only runs when there is a synthesized directory to place.** The walk is
  the expensive half of this fix - up to 2048 directories, each with a
  `dentry_open` + `iterate_dir`, plus a `kasprintf` + `kern_path` +
  `vfs_getattr_nosec` per subdirectory child - and its only consumer is
  `nm_place_dir_ino`. The sample sits in `nomount_generate_virtual_topology`'s
  "nearest real ancestor" branch, which is reached by **every** rule, while the
  overwhelmingly common rule (a file into a ROM directory that already exists)
  synthesizes nothing and never reads the answer. On a system-as-root partition
  it is worse than unread: the climb reaches `/`, the bfs spends the whole
  2048-directory budget and returns `-E2BIG`, so there was never an answer to
  give. That branch *ends* the walk, so `pending_list` already holds every
  directory this call invented - `!hlist_empty(&pending_list)` is therefore an
  exact test for "am I about to place one", and the sample is gated on it.

  It cannot instead be deferred to the lazy `nm_real_ancestor_pop()` in the
  stamping loop below, even though that climbs to the same directory: by then
  the hijack and the child injection have linked the synthesized directory into
  that parent, while its rule does not reach `nomount_rules_ht` until the end of
  the loop - so `nm_path_is_injected()` would not recognise it and the scan would
  take our own raw-hash inode as population. Sampling before the hijack is what
  keeps the directory pristine.

  This is a redundancy fix, not a latency one. Measured on the OP15 with the walk
  running on every rule, the whole mount pass is ~2 s for 257 rules across 93
  directories over four consecutive boots, against a 60 s bound - nowhere near
  the 250 s OPlus watchdog that the per-child `kern_path()+stat()` pass in
  `nm_ino_actor` once tripped.

Refusal cases, all of which fall back to the shipped behaviour: allocation
failure, a directory with more than 128 subdirectories, a filesystem answering
`DT_UNKNOWN` (the walk could then skip a subtree and return a ceiling that is too
low), and a 2048-directory visit cap.

## How to verify a fix

`nomount check` reports it directly. Before:

```
[WARN] synthesized dir inode collision (device)
       measured: 3 synthesized directory(ies) share an inode with a stock one: ...
```

After the fix that row must read `PASS`, with the evidence naming how many
synthesized directories were checked against how many on the partition. The
check walks up to 20,000 directories and reports `unmeasured` rather than a pass
if it hits that cap.


---

# 2. `lseek(SEEK_DATA)` on a synthesized directory returns einval

**Status:** measured, fixed, compile-verified on all ten kernels, and
boot-verified on an OP15 (2026-09-07).

    before   Mms  data=-1 EINVAL  hole=-1 EINVAL     stock 67/67 answered
    after    Mms  data=0  hole=61 (== st_size)       stock 67/67 answered

Re-running the separation test after the flash: **68 of 68 directories answer,
0 EINVAL** - the synthesized one is no longer distinguishable from its stock
siblings, and `HOLE` equals the size `stat` reports, as it does for every real
directory on that filesystem.

A real directory answers `SEEK_DATA` and `SEEK_HOLE`: erofs uses
`generic_file_llseek`, which returns the offset itself for `SEEK_DATA` and eof
for `SEEK_HOLE`, and `-ENXIO` at or past the end. `nm_llseek` handled
`SEEK_SET`/`CUR`/`END` for synthesized directories - the `SEEK_END` arm exists
because `stat().st_size` and `lseek(fd,0,SEEK_END)` used to disagree on the same
fd, which is its own one-syscall-pair tell - and sent everything else to
`default: return -EINVAL`.

So two `lseek` calls, no root, separated a synthesized directory from a stock
one. Measured on an OP15 across `/product/priv-app`:

| | answers | EINVAL |
|---|---|---|
| stock subdirectories | **67** | 0 |
| synthesized | 0 | **1** |

Perfect precision and perfect recall, on the same filesystem, with no reference
image needed.

The fix mirrors `generic_file_llseek_size()` and computes the size the way the
`SEEK_END` arm does - from what `nm_file_getattr` reports, not the raw 4096
placeholder, since answering from the placeholder would just move the divergence
that arm was written to remove.

### The same oracle, one argument over (found in review, not yet on a device)

The v31 fix added `if (offset < 0) return -EINVAL;` ahead of the enxio test, on
both directory kinds. That is the one line that does not mirror generic.
`must_set_pos()` compares `(unsigned long long)*offset >= eof`, and the cast is
deliberate: a negative offset becomes a huge unsigned value and takes the enxio
arm. `ksys_lseek()` validates only `whence` (and `SEEK_HOLE` is `SEEK_MAX`), so a
negative offset reaches `->llseek` unfiltered, and erofs and f2fs both route it
through `generic_file_llseek`. So on v31:

| | `lseek(fd, 0, SEEK_DATA)` | `lseek(fd, -1, SEEK_DATA)` |
|---|---|---|
| stock dir | `0` | `ENXIO` |
| NoMount dir (both kinds) | `0` (fixed in v31) | **`EINVAL`** |

Both arms now use the unsigned compare instead. Written, **not compiled and not
flashed** -- it needs the next builder run. The negative-offset column was never
measured on the device: no probe there passes a negative offset, and pushing one
is a device mutation. Narrow - it needs a detector that thinks to pass a
negative offset - but the project cut a release for this oracle at offset 0, and
the variant is a one-character change for whoever wrote that probe.

The `SEEK_END` arms keep their `offset < 0` check. Those are correct: there the
test guards the computed result, which `vfs_setpos()` does reject with `EINVAL`.

---

# 3. Two further arms of the same two fixes

**Status: shipped.** Both arms are in engine v31, built for OP15 by
`OnePlus-ReSukiSu_NMS` (run 34225323493) and flashed; the device is running them.
Compile-verified at `W=1` on all ten pinned kernels (4.9 ... 6.18) with zero
diagnostics.

What is *measured* differs by arm, and the two are not equal:

* **`nm_scan_dir_for_file()` self-sampling** - flashed and serving, but the
  fsync-consistency measurement has not been re-run, and nothing in
  `nomount check` probes it. What was re-read on the device (read-only,
  2026-09-08): `fprobe` over all 25 `/product/priv-app/Mms/lib/arm64/*.so` and
  over stock `/product/priv-app/AIUnit/lib/arm64/libaiunit_framework.so` agrees
  on `fsync ok(0)`, `fdatasync ok(0)`, `fadvise ok(0)`, `readahead ok(0)`,
  `fallocate Bad file descriptor` and `open O_DIRECT Invalid argument` - no
  divergence. On *this* directory stock answers `fsync` `0` too, so that run
  confirms consistency, not the erofs-`EINVAL` mechanism the oracle was about.
* **`SEEK_DATA`/`SEEK_HOLE` on a dir-target directory** - unmeasured **by
  construction**, not unverified: the Suite builds no dir-target rule, so there
  is nothing on the device to probe (see the last paragraph of this section).
  The synthesized half of the same five lines is measured: `oprobe` on
  `/product/priv-app/Mms` gives `SEEK_DATA(0)=0 SEEK_HOLE(0)=61` against
  `st_size=61`, and stock `/product/priv-app/AIUnit` gives `0`/`79` against
  `st_size=79`.

**`nm_scan_dir_for_file()` could sample our own injections.** It was the only
sampler in the engine without the "never sample ourselves" guard that eight other
sites carry. It reads the directory through the **hijacked** ops, so its actor
sees injected names, and `nm_stock_caps()` on one of our inodes returns
`NM_CAP_FSYNC` - `nm_file_fops` always carries `.fsync` - which puts `nm_fsync`
back to forwarding to the f2fs backing file and answering 0 where every erofs
sibling answers `-EINVAL`. That is exactly the one-syscall, baseline-free oracle
v20 was cut to close, reopened through the sampler. The worked case is the 25
`.so` files under a synthesized `.../Mms/lib/arm64`: rule 1 synthesizes the chain
and samples a real ancestor, but from rule 2 on that directory resolves, and a
miss on the one-entry sibling cache makes the scan list it and sample one of
ours. On kernels < 6.8 it also mis-answered `nm_stock_map_dev()`, since our
dentries carry `nm_dops`, which has no `.d_real`.

The guard is the same pair the other sites use - `nm_path_is_injected()` before
`kern_path` (so resolving does not instantiate one of our inodes) and the vtable
identity test after it (which also catches a passthrough child of a dir-target
rule, which has no rule of its own). Skipping a candidate makes
`nm_find_sibling_meta()` ascend to the next real parent, which is where rule 1
already sampled - so the 25 libs become consistent with each other rather than
diverging.

**`SEEK_DATA`/`SEEK_HOLE` on a dir-target directory.** Section 2 above fixed the
*synthesized* directory. The dir-target branch intercepted only `SEEK_END`, so
everything else forwarded to `vfs_llseek` on the f2fs backing **directory**,
whose `generic_file_llseek` answers `SEEK_HOLE` with the f2fs `i_size` while
`stat()`, `SEEK_END` and the terminal readdir cookie all report the erofs closed
form. One `lseek` pair against one `stat`, on the same fd. It now answers from
`nm_dsnap_dir_size()` with the identical five lines the synthesized-dir arm uses,
so both directory kinds agree.

Narrower than the sampler defect, and recorded as an unfinished arm of a shipped
feature rather than new capability: the Suite builds no dir-target rule
(`mount.rs::inject_would_mask_dir` refuses the target), so it is reachable only
through a hand-issued `nm add <dir> <dir>`.

## Oracles measured and found closed

Worth recording so they are not re-opened from a code reading:

- **`getxattr("security.selinux")` returning the `/data` copy's label.** Injected
  files and synthesized directories both report `u:object_r:system_file:s0`, the
  same as their stock siblings.
- **`d_ino` vs `st_ino` on a synthesized directory.** They agree.
- **readdir ordering for pure additions.** All 87 erofs parents holding
  injections come back byte-sorted, and no injected name is out of order - the
  engine inserts at the correct sort position. (Note that "is the listing sorted"
  is not a reference-free oracle anyway: stock multi-block erofs directories are
  not globally sorted.)
- **The post-reload `s_path` loss.** A shadowing rule re-added over a live one
  still serves the hidden reader the stock bytes while root gets the module's.
- **Multi-block erofs `st_size` after a whiteout.** Real, but already known,
  already surfaced at plan time, and not fixable in the engine: erofs pads each
  block by an amount that depends on where the names fall, so there is no closed
  form to correct. `whiteout::measurable_hole` declines these and says so.
