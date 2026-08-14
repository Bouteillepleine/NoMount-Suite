# Changelog

## v1.1.2

Hookless `/my_*` (opt-in) + self-manage detection across variables.

### Added
- **Hookless `/my_*` serving (opt-in, `NM_MY_HOOKLESS`).** `/my_*` targets can now be served by the same mountless hookless VFS injection as every other partition instead of a real bind — zero mounts. Enable with `NM_MY_HOOKLESS=1` (metamount env) or a `/data/adb/nomount/my_hookless` marker; the default stays bind. Cold-boot validated on OP15 (6.12): a `/my_product` framework feature-config served hookless survived the real init→zygote `forkSystemServer` FD-allowlist with no bootloop — refuting the long-held "my_* hookless bootloops" assumption for this case. Guarded by the existing `GUARD_MAX` self-disable. NOT yet validated for preloaded overlay APKs / framework jars / fonts under `/my_*`, so the safe default remains bind while multi-device data is gathered.

### Fixed
- **Self-manage detection matches across the script and resolves simple vars.** `self_binds_my` no longer requires `my_` and `mount`/`bind` on one line: it collects vars assigned a `my_*` value (`DST=/my_product/…`) and flags any `mount`/`bind` line that reaches a `my_*` path directly *or* through such a var (`mount "$DST"`). This catches the real-world pattern used by `op15_3d_lockscreen_wp`, `OxygenCustomizer` and `OnePlus_Dialer_Universal` that the one-line heuristic missed — which, under hookless `/my_*`, would otherwise double-handle the same target. Still precise: an unrelated `mount` plus an unrelated `my_` mention elsewhere does not trip it. 6 unit tests added.

## v1.1.1

Follow-up audit cleanup of two v1.1.0 P2s.

### Fixed
- **Self-manage detection no longer trips on comments.** `self_binds_my` now requires `my_` and `mount`/`bind` on the *same non-comment line* (an actual bind), instead of matching those tokens anywhere in a boot script -- a commented-out `my_` mention next to an unrelated `mount` no longer causes a module's my_* overrides to be dropped.
- **reload re-binds a my_* backing whose source changed.** binds.list now records `target\tsource`, so a hot `reload` detects a bind whose backing file moved and re-binds it, instead of only reconciling added/removed targets (source changes previously waited for a full mount). Legacy target-only rows are backfilled on first reload.

## v1.1.0

Audit fix pass over the v1.0.11-1.0.13 additions (dynamic resolver, my_* bind hybrid, gap-free reload).

### Fixed
- **reload reconciles changed source/kind, not just presence.** A target that moves between modules, or flips inject<->whiteout on the same path, is now re-applied (`~changed`) instead of frozen at the old rule until a full mount. `parse_live` captures source+kind; `reload` diffs them.
- **my_* bind hardening.** Aborts the bind if the SELinux relabel fails (never exposes a mislabeled `adb_data_file` override -> avc + tell); unbinds if the mount can't be recorded (no untracked-leak/stacking); and skips a target another module already mounted. binds.list read-modify-write is now flock-serialized against a concurrent mount/reload.
- **Self-manage detection narrowed.** A module's my_* content is left to it only if one of its boot scripts actually mounts/binds a my_* path -- previously *any* `service.sh`/`post-fs-data.sh` (very common) wrongly caused its my_* overrides to be dropped. Also checks `post-mount.sh`.
- **Partition discovery follows symlinks again.** Split from canonicalization after v1.0.13: discovery walks a symlinked top-level root (so `system_ext/` etc. isn't dropped where that root is a symlink), while `system/<X>` canonicalization keeps lstat.
- **reload safety + robustness.** Propagates an `nm list` failure instead of silently mass-re-adding; parses live rules by suffix/rsplit so paths with spaces/parens/arrows aren't mis-split; excludes `/data_mirror` from partition detection.

## v1.0.13

### Fixed
- **Dynamic resolver mistook `/system`-symlinks for partitions.** `/etc -> /system/etc` (and `/bin`) are symlinks, and the resolver's `is_dir()` check followed them, so classic-layout `system/etc/...` wrongly canonicalized to `/etc/...` (a harmless-but-wrong target on the same inode, which tripped doctor's zygote FD-allowlist warning). Now uses `symlink_metadata` (lstat) so only a real partition mount (`/vendor`, `/product`, `/odm`, `/my_product`, …) canonicalizes; `system/etc` correctly stays `/system/etc`.

## v1.0.12

### Added
- **Gap-free hot load / unload** (`nomount reload`, WebUI **Reload** button). Reconciles the live rule set to the currently installed modules and applies only the delta — no `clear`, so injections never drop mid-reload. Install a module and tap Reload: just its files go live. Remove one and Reload: just its files go away. No reboot. Also reconciles my_* binds incrementally (umount removed, bind new). The old full-rebuild pass still runs at boot; the WebUI's "Re-apply" button is now the gap-free "Reload".

## v1.0.11

### Added
- **my_* partition support via a scoped bind hybrid.** OnePlus/Oppo `my_*` partitions are in zygote's FD allowlist, so hookless injection there bootloops (`CreateFromFd` rejects the spoofed inode). Those files were silently dropped before; now a module's `my_*` content is served by a real file-over-file bind (which keeps the true inode and passes the check), with the source SELinux-relabeled to the partition's context and the mount tracked for teardown on the next pass. **Scoped:** a module that ships its own `post-fs-data.sh`/`service.sh` already binds its `my_*` content, so those are left to it (no double-mount). Everything hookless can reach stays mountless.
- **`nomount plan`** — read-only: prints exactly what the mount pass would do (resolved target, kind, source) without applying. `doctor` now also reports the my_* bind count.

### Changed
- **`system/<X>` resolution is now dynamic.** The classic layout maps `system/<X>/…` to `/<X>/…` for any real separate partition on the device (`/vendor`, `/product`, `/odm`, `/system_ext`, `/system_dlkm`, `/oem`, `/my_product`, …), matching magic-mount — replacing a hardcoded four-partition list that mis-targeted `system/system_dlkm`, `system/oem`, etc. to a literal `/system/<X>`. Plain `/system` subdirs (`system/app`, `system/bin`) are unaffected.

## v1.0.10

### Changed
- **Procfs boot-state spoof now rides on the Boot-state toggle.** The `/proc/cmdline` + `/proc/bootconfig` sanitizer (previously the config-only `spoof_cmdline`) now follows `spoof_props`, so enabling **Boot-state (props + procfs)** in Tools › Spoofing normalizes the raw procfs boot-state alongside the props in one switch. It always required props to be on anyway, so a separate toggle was just a footgun. The procfs half is a no-op when the kernel has no `/sys/kernel/nomount` knobs. Advanced: set `spoof_cmdline=0` in `spoof.conf` to keep procfs untouched while still spoofing props.

## v1.0.9

### Added
- **`/proc/cmdline` + `/proc/bootconfig` boot-state sanitizer** (`spoof_cmdline`, opt-in, off by default). `resetprop` only moves the derived `ro.boot.*` props; the raw `androidboot.*`/`oplusboot.*` boot state in `/proc/cmdline` (and `/proc/bootconfig` on GKI) still contradicts them, which a detector can read directly. When the kernel exposes the `nomount` cmdline/bootconfig knobs, the module now serves a sanitized copy (verifiedbootstate=green, device_state=locked, flash.locked=1, warranty_bit=0, veritymode=enforcing, `verifiedbooterror` stripped, digest matched to the props). Prefix-agnostic, so it covers OnePlus `oplusboot.*` as well as generic `androidboot.*`. Requires `spoof_props=1` and only runs once the boot-state prop is actually normalized, so it can never flip the inconsistency the other way.
- **Detection-posture card** (WebUI › Status). Reports the residual tells a scanner can still read on a mountless engine — verified-boot state (worst of cmdline/bootconfig), build keys, SELinux — instead of a mount-only "clean" that was always green on a mountless build.

### Changed
- **Fingerprint harmonization.** `do_props` now rewrites `:userdebug`/`test-keys` tails in the composite fingerprint, description and flavor to `:user`/`release-keys` across all partitions, matching the `ro.build.type`/`tags` it already sets — closing a tags-vs-fingerprint inconsistency.

### Fixed
- Whiteout of a partition root is now refused in the plan builder and the doctor (a `product/.replace` marker could otherwise hide a whole partition and bootloop).
- A single malformed block-list entry no longer aborts the boot-time UID-apply (which would leave every app un-hidden); bad entries are skipped.
- `nm` path resolution is bounded to `PATH_MAX` and the list walk is signedness-safe, closing an out-of-bounds read on an over-long path or a negative reply.

## v1.0.6

### Changed
- **Cloak scanner is ~8× faster.** The Xposed-module probe now uses an `xargs -P` worker pool scaled to CPU count instead of fixed 8-at-a-time batches with a `wait` barrier, so one slow or wedged APK can no longer stall a whole batch. On a 303-app device the full scan dropped from ~30 s to ~3.7 s (identical results). The **Scan Xposed modules** button now also shows a "Scanning…" toast on press for immediate feedback.

## v1.0.5

### Added
- **Clear incident** — WebUI › Tools › Last incident now has a button to delete the saved `incident.log`, so the forensic card can be dismissed once the trip has been reviewed. The card note now states plainly that it is a saved record (survives reboots until overwritten or cleared), and that current disabled/armed state is the guard chip on Status.

### Changed
- **Re-arm & enable also clears the incident record.** Re-arming already dropped `disabled` + `bootcount`; it now also removes `incident.log`, so acknowledging a trip clears the lingering card in one action. The incident nav-alert dot is now cleared when the log is gone (previously it was only ever set).

## v1.0.4

### Changed
- **Cloak scanner is fast and no longer hangs.** The Xposed-module probe now runs in parallel (8 APKs at a time) with a per-APK `timeout`, and caches the result to `/data/adb/nomount/xposed_cache`. The WebUI reads the cache on open (~20 ms) instead of scanning ~all installed APKs; `service.sh` rebuilds the cache in the background at boot; the **Scan** button forces a refresh.

## v1.0.3

### Fixed
- **Cloak scanner found no Xposed modules.** The manifest probe grep'd the compiled `AndroidManifest.xml` for `xposedmodule`, but binary XML stores pool strings as UTF-16 (null bytes between chars) so the ASCII grep never matched. `scan.sh` now strips nulls (`tr -d '\000'`) before the grep.

## v1.0.2

### Added
- **Cloak (maps/fd)** — WebUI › Tools card to select Xposed/LSPosed packages and hide their APKs from every `/proc/<pid>/maps` and `/proc/<pid>/fd` via the kernel `pathhide` interface. Applied live and re-applied on boot from `/data/adb/nomount/pathhide.conf`. Collapsible list + module scanner.

### Fixed
- **metamount.sh module counter** — `grep -c … || echo 0` doubled the `0`, tripping a per-module arithmetic error in the card-refresh path (non-fatal but noisy).

## v1.0.1

### Fixed
- **False "per-UID inconsistency" on the manager card at boot.** The runtime
  self-consistency canary ran a single probe shortly after `boot_completed`, but
  app UIDs have not all launched and materialised their per-UID injection that
  early, so a transient disagreement stamped a scary "⚠️ per-UID inconsistency"
  on the card every boot even when the steady state was healthy. `service.sh`
  now retries the probe across a settle window (up to 6 × 15 s) and keeps the
  *settled* verdict; only a divergence that persists through the whole window —
  a real d_drop-style regression — reaches the card.

## v2.1.0

First release of the reworked hybrid metamodule.

### Mount
- **Mountless VFS redirection** — direct-path module files load at stock system
  paths via the `/dev/nomount` driver, with zero `/proc/mounts` entries.
- **Hybrid RRO overlay support** — module `**/overlay/*.apk` dirs are mounted as
  a real `overlayfs` (staged on tmpfs, because `/data` f2fs `casefold` is
  rejected by overlayfs as a lowerdir) so Android's `idmap2` / `OverlayManager`
  pipeline can enable them. Without this, RRO overlays stay `STATE_NO_IDMAP` and
  theming (e.g. OxygenCustomizer) breaks. Everything else stays mountless.
- **Self-mounting module blocklist** — skip modules that manage their own path
  redirection (built-in list + `/data/adb/nomount/blocklist`).

### Detection hiding (own footprint)
- Overlay mounts are registered with KernelSU's native umount
  (`kernel_umount` + `umount-config`) so they're `MNT_DETACH`ed inside DenyList
  apps' namespaces.
- `/dev/nomount` is hidden from non-root scanners via SUSFS `sus_path`.
- **Per-app UID isolation** — block specific UIDs so the VFS hook returns
  pristine stock for them.

### Manager & WebUI
- **Per-module manager tags** — each module's description is tagged with how
  it's served (`vfs` / `overlay` / `vfs + overlay`).
- **WebUI** — engine status/toggle, remount, bootloop-guard status + re-arm,
  modules list, active rules viewer, overlay-mounts list, and UID exclusions.

### Safety
- **Bootloop guard** — a boot counter self-disables NoMount after repeated
  failed boots and re-arms once the system boots healthy.
- **Install-time sha256 integrity check** — every bundled file is verified
  against a manifest at install; a corrupt or tampered zip aborts.

### Kernel
- Kernel patches for android12-5.10, android13-5.15, android14-6.1,
  android15-6.6, android16-6.12 (raw GKI + SUSFS-compatible variants). The
  recursion guard uses `current->journal_info` — never `android_oem_data1`,
  which OEMs like OnePlus use for their own per-task pointer (writing to it
  soft-locks the device at boot).
