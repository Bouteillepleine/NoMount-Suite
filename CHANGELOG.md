# Changelog

## Unreleased

- WebUI "Tools" tab.
- `pathhide`, end to end.
- Dead `nm` surface.
- The boot-identity knobs and the pathhide forwarder, in the kernel too.
- The status dot answers "is the engine up?", not "is anything wrong?".
- "Idle" is gone.
- "no rules - re-apply" on a device with nothing to apply.
- The last plan check that said "not measured" when it meant.

## v1.3.94

- An inert SUSFS module is reported as information, not a warning.

## v1.3.93

- An absent bootcount reads as zero, not as unknown.

## v1.3.92

- A process that vanished mid-probe is no longer counted as a failed measurement.

## v1.3.91

- `uninstall.sh` ships executable.
- Stray indentation stopped leaking into user-facing messages.
- Unmeasured stopped being reported as clean.
- The absorbed record and the PackageManager cache are kept honest across.
- The release path was fixed: `customize.sh`, `uninstall.sh` and `package.sh`.

## v1.3.88

- The build commit is stamped beside the version, so a phone reporting a version.
- False greens the audit found were closed.
- One findings list instead of seven cards.
- Acceptance, history and the reach pill were dropped - including.
- The mount table is read before the engine is cleared.
- `uninstall.sh` ships, and unknown stopped being reported as nothing.
- The release build stopped reporting itself dirty.
- Packaging builds on a Windows NDK host too.

## v1.3.81

- A mount the table says is not there is no longer asserted.
- A hand-written bindhosts override is not clobbered.
- The `timeout` fallback is bounded rather than dropped, so a device without.
- The drift check is reachable again, and `absorb` stopped losing a rule.
- The lints stopped reporting things that are not happening.

## v1.3.80

- One inode is not a bucket.
- An app's lib directory is treated as part of its codepath.

## v1.3.78

- Each target is applied once, and what cannot work on this device is named.
- `absorb` re-points when it serves a target that already has a rule.
- Directories that hold nothing but injections are named.
- A finding is stated once per module, not once per country directory.
- An image a module ships but never mentions is noticed.
- The question bindhosts asks about metamodules is answered.

## v1.3.76

- An absorb a `my_*` bind cannot accept is no longer offered.
- A deferred `my_*` bind points at a reboot, not at editing a module.
- The umount setting that could not be read is named.
- The engine version is read from the engine.
- The manager warning is written for the person reading.
- User-facing messages were shortened.
- The last check is remembered, and the report stays quiet when there is nothing.

## v1.3.69

- The detection audit reports differently.
- `SKIP` is now `N/A` or `UNMEASURED`.
- Every check carries a plain-language line.
- Findings name their owner.
- Findings carry a reachability tag.
- `--json` on `audit`, `doctor`, `selfcheck`.
- The boot pass caches the audit, so the WebUI opens on a verdict and an age.
- The posture shield contradicted the audit.

## v1.3.48 - v1.3.65

- Engine floor rose to v26.
- The existence cloak went live.
- The state directory's SELinux label was repaired.
- The early absorb pass moved to post-mount.

## v1.3.47

- The audit probe kept root's supplementary groups.
- The WebUI built two shell commands with a value interpolated outside `shq()`.

## v1.3.46

- Per-UID hiding leaked through the xattr path.
- The maps/fd cloak announced itself.
- `nm` dispatched on the first character of the command.
- `nm l j` emitted paths into JSON unescaped, so a filename containing.
- `--public` (exemption from per-UID hiding) was granted to any `.apk` under.
- `nm v` walked netlink attributes using the reply's own length field without.
- `spoof.log` and `pathhide.conf` were `0644` inside a `0700` directory whose.
- Blocking an appid in the isolated-process pools reported `-EEXIST` against.

## v1.3.17

- `doctor` told KernelSU Next users to delete a working module.

## v1.3.16

- Rules that hide nothing were counted as hidden apps.
- The isolated-process control wrapped 3 + 1 on a phone.

## v1.3.15

- `uidscan.sh` + a Scan button.
- `nomount uid preset --globs`.
- The scanner could silently check nothing.
- Globs could not be typed or removed in the WebUI.
- Whiteout paths reached the shell unquoted.
- A scan that found nothing, or a list emptied by applying, rendered an empty box.
- Candidates already in the hide list were offered again, pre-picked.

## v1.3.14

- Globs in the hide list.
- `nomount uid preset detectors`.
- The isolated-process control could lie about the kernel's state.
- A bad `packages.list` read could have un-hidden every hidden app.
- A glob can no longer reach a platform UID.
- `metamount.sh` claimed in its header that it hides RRO mounts via SUSFS.
- Per-UID hiding card rebuilt.
- The apply pass reads `packages.list` once instead of once per entry, and writes.

## v1.3.13

- A hidden app could still see the shape of what was hidden.
- A hidden app could read through its own SDK-runtime sandbox process.
- "Re-apply" silently unhid every app.
- The hide list and the module-skip list were the same file.
- Apps were unhidden for the first ~10-20 s of every boot.
- An entry for a not-yet-installed app stayed inert until the next reboot.
- `uid apply` could not fail.
- Blocking a platform uid was one keystroke away.

## v1.3.6

- A single Reload deleted every durable whiteout and every absorbed rule.
- Every module-mount counter was a constant zero.
- The posture shield said "fully mountless - zero mounts" while another module was mounting.
- `ro.boot.vbmeta.size` was never set.
- `/data/local/tmp` read as permanently dirty.
- Durable whiteouts did not apply until well after boot.
- `whiteout list` reported a path as hidden when nothing was hiding.
- Packaging silently shipped a stale `nm`.

## v1.3.0

- Injecting over a live mount stranded it in `mountinfo` permanently.

## v1.2.9

- A mount left standing on purpose is now info, not a warning.
- The rules breakdown bar now reads as the same material as the capsules.

## v1.2.8

- `/data/local/tmp` is restored to the owner, mode and SELinux context AOSP ships.

## v1.2.7

- Absorb now leaves every hook framework alone, by what it ships rather than by its name.

## v1.2.6

- Module whiteouts are held to the same rule as manual ones.

## v1.2.5

- `whiteout add` now refuses a target that is not on overlayfs.

## v1.2.4

- Absorb and `doctor` named a skip file that may not exist.

## v1.2.3

- The hook-path skip missed half of Vector's dex2oat paths.

## v1.2.2

- The absorb opt-out no longer depends on knowing a fork's module id.
- A missing skip file no longer fails open.

## v1.2.1

- `absorb-skip` is now `absorb-skip.txt`.

## v1.2.0

- `nomount absorb` - take over bind mounts other modules made.
- `nomount whiteout` - durable whiteouts.
- `/my_*` content is always served.
- `doctor` gained an informational level.
- Boot-time root code execution via the state directory.
- World-writable `/dev` lock that could wedge the mount pass.
- Bind-list locking silently degraded to no locking.
- Module files were permanently relabelled.

## v1.1.2

- Hookless `/my_*` serving (opt-in, `NM_MY_HOOKLESS`).
- Self-manage detection matches across the script and resolves simple vars.

## v1.1.1

- Self-manage detection no longer trips on comments.
- reload re-binds a my_* backing whose source changed.

## v1.1.0

- reload reconciles changed source/kind, not just presence.
- my_* bind hardening.
- Self-manage detection narrowed.
- Partition discovery follows symlinks again.
- reload safety + robustness.

## v1.0.13

- Dynamic resolver mistook `/system`-symlinks for partitions.

## v1.0.12

- Gap-free hot load / unload.

## v1.0.11

- my_* partition support via a scoped bind hybrid.
- `system/<X>` resolution is now dynamic.

## v1.0.10

- Procfs boot-state spoof now rides on the Boot-state toggle.

## v1.0.9

- `/proc/cmdline` + `/proc/bootconfig` boot-state sanitizer.
- Whiteout of a partition root is now refused in the plan builder and the doctor (a `product/.replace` marker.
- A single malformed block-list entry no longer aborts the boot-time UID-apply (which would leave every app.
- `nm` path resolution is bounded to `PATH_MAX` and the list walk is signedness-safe.

## v1.0.6

- Cloak scanner is ~8× faster.

## v1.0.5

- Re-arm & enable also clears the incident record.

## v1.0.4

- Cloak scanner is fast and no longer hangs.

## v1.0.3

- Cloak scanner found no Xposed modules.

## v1.0.2

- metamount.sh module counter.

## v1.0.1

- False "per-UID inconsistency" on the manager card at boot.

## v2.1.0 - superseded engine (historical)

- Mountless VFS redirection.
- Hybrid RRO overlay support.
- Self-mounting module blocklist.
- Detection hiding (own footprint).
- Overlay mounts are registered with KernelSU's native umount.
- `/dev/nomount` is hidden from non-root scanners via SUSFS `sus_path`.
- Per-app UID isolation.
- Manager & WebUI.
