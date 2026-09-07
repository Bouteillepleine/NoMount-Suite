# Engine: two ways a synthesized directory gives itself away

**Status:** measured and reproduced on an OP15 (engine v30). Detection shipped in
Suite v1.3.164 as the `synthesized dir inode collision` check.

**The fix is written, compile-verified and BOOT-VERIFIED.** Clean at `W=1` on all
ten pinned kernels (4.9 … 6.18), same as the unpatched baseline; then built for
OP15 by `OnePlus-ReSukiSu_NMS` with `nomount_ref=prerelease` and flashed
(2026-09-07).

Result on the device that showed all three collisions:

    before   Mms=101  Mms/lib=77   Mms/lib/arm64=89    -- 3 collisions
    after    Mms=187  Mms/lib=188  Mms/lib/arm64=189   -- 0 collisions

Stock maximum on that filesystem is 186, so the three land immediately above it:
free by construction, and the same digit count as their neighbours. An
independent scan (188 directories, inodes 2..189) reports no duplicated inode at
all, and `nomount check` goes from WARN to PASS with the whole report clean.

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

**Injected files do NOT collide.** The gap-interleaving in `nm_place_ino` works —
139 APKs under `/product/overlay` produce zero collisions. This is a
directory-only defect and the file path must not be touched.

The stock partner changes between boots (overlayfs assigns `st_ino` at mount
time) but the collision itself is deterministic.

## Why it happens

It is arithmetic, not bad luck. `/product/priv-app` holds **188 directories in
inode range 2..186** — 185 available values. By pigeonhole at least three must
collide, and the three excess are exactly the three the engine added. Adding N
synthesized directories to a saturated inode space guarantees N collisions.

`nm_place_ino()` searches for a free gap between the target's **siblings**, and
`nm_ino_taken()` consults only `pop->v[]` (up to `NM_INO_SAMPLES` = 64 immediate
subdirectories of the nearest real ancestor) plus `pop->mine[]` (its own
handouts). On this device the siblings occupy 3..71 while the **nested**
directories two and three levels down occupy 72..186 — and the engine never sees
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
   replaced — a dir at `/product/etc` was minting children at 1226252..2181515
   against stock siblings of 7166..20309, and one stat separated them);
2. it must be **collision-free**;
3. it must be chosen **without knowing which inodes the filesystem already uses**.

A plausible magnitude means "inside or just above the used range". On a saturated
range that means colliding. Dropping (3) is the only escape: the allocator has to
know the used set, or at least the true maximum, for the whole device — not for
one directory level.

## The fix as written

The shape is clear:

- **directories only** — leave `nm_place_ino`'s gap search for files exactly as
  it is;
- allocate at `max(device_subtree_max, pop->hw) + 1`. On this device that is
  187+: free, and adjacent to the top, so magnitude stays plausible;
- **fail safe** — if the walk cannot establish that maximum, fall back to today's
  behaviour unchanged, so the patch is never worse than the current code.

`nm_subtree_dir_ino_max()` establishes the ceiling. What it has to get right:

- it needs a **bounded recursive** directory walk (the collisions here are three
  levels down), not the single-level `nm_dir_ino_pop` scan;
- `nm_dir_ino_pop` returns inodes but not child **names**, so a second actor is
  needed to collect them;
- a depth-first walk needs the child names of every level held simultaneously.
  At `NAME_MAX + 1` per name that is tens of KB per level — too much for
  `kmalloc` at several levels, so it needs either `kvmalloc`, a re-scan-by-index
  strategy, or a bounded BFS queue;
- it must be right on **ten kernel versions**, 4.9 through 6.18, where the
  `iterate_dir`/`filldir_t` signatures differ (the existing `NM_ACTOR_RET`
  machinery handles this and should be reused);
- the value becomes a live inode's `i_ino`, so an error here is not a leak, it is
  a VFS-visible defect.

Two details worth knowing about the implementation:

- **It climbs to the mount root before walking down.** Walking only the caller's
  ancestor would place a dir under `/product/priv-app/Foo` above Foo's little
  subtree while the rest of the mount sits far higher — and the collision would
  survive the fix. It climbs while `st_dev` holds, which lands on the mount root.
- **Directories are never sampled if we invented them.** Feeding a synthesized
  inode back into the ceiling would ratchet it upward on every boot.

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

# 2. `lseek(SEEK_DATA)` on a synthesized directory returns EINVAL

**Status:** measured, fixed, compile-verified on all ten kernels, and
BOOT-VERIFIED on an OP15 (2026-09-07).

    before   Mms  DATA=-1 EINVAL  HOLE=-1 EINVAL     stock 67/67 answered
    after    Mms  DATA=0  HOLE=61 (== st_size)       stock 67/67 answered

Re-running the separation test after the flash: **68 of 68 directories answer,
0 EINVAL** — the synthesized one is no longer distinguishable from its stock
siblings, and `HOLE` equals the size `stat` reports, as it does for every real
directory on that filesystem.

A real directory answers `SEEK_DATA` and `SEEK_HOLE`: erofs uses
`generic_file_llseek`, which returns the offset itself for `SEEK_DATA` and EOF
for `SEEK_HOLE`, and `-ENXIO` at or past the end. `nm_llseek` handled
`SEEK_SET`/`CUR`/`END` for synthesized directories -- the `SEEK_END` arm exists
because `stat().st_size` and `lseek(fd,0,SEEK_END)` used to disagree on the same
fd, which is its own one-syscall-pair tell -- and sent everything else to
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
`SEEK_END` arm does -- from what `nm_file_getattr` REPORTS, not the raw 4096
placeholder, since answering from the placeholder would just move the divergence
that arm was written to remove.

## Oracles measured and found CLOSED

Worth recording so they are not re-opened from a code reading:

- **`getxattr("security.selinux")` returning the `/data` copy's label.** Injected
  files and synthesized directories both report `u:object_r:system_file:s0`, the
  same as their stock siblings.
- **`d_ino` vs `st_ino` on a synthesized directory.** They agree.
- **readdir ordering for pure additions.** All 87 erofs parents holding
  injections come back byte-sorted, and no injected name is out of order — the
  engine inserts at the correct sort position. (Note that "is the listing sorted"
  is not a reference-free oracle anyway: stock multi-block erofs directories are
  not globally sorted.)
- **The post-reload `s_path` loss.** A shadowing rule re-added over a live one
  still serves the hidden reader the STOCK bytes while root gets the module's.
- **Multi-block erofs `st_size` after a whiteout.** Real, but already known,
  already surfaced at plan time, and not fixable in the engine: erofs pads each
  block by an amount that depends on where the names fall, so there is no closed
  form to correct. `whiteout::measurable_hole` declines these and says so.
