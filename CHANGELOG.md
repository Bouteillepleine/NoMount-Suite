# Changelog

> **The Suite and the Prism engine update separately.**
>
> The engine is compiled into the kernel (`CONFIG_NOMOUNT=y`); the Suite is this
> module. Installing a Suite update does **not** move the engine - for that you
> flash a kernel built from the matching `hookless/` source.
>
> That is normal, not a fault: the Suite is built to run on an older engine.
> Anything that needs a newer one is **named** by `nomount check` and by the
> WebUI rather than silently doing nothing, so you can see exactly what a kernel
> update would buy you. The footer shows both numbers - `Suite vX · engine vY`.

## Unreleased

- Good to know is gone: notes no longer render in the WebUI. They stay in `nomount check --json` and in the copied report.
- Status leads with module coverage: served, absorbed, and how many ship files the Suite is not serving.
- Absorb moved from Hiding to Rules, next to Modules: it is about handling modules, not hiding them, and it is called Absorbable mounts now.
- The coverage metric opens the Modules list, so the count is a way in rather than a readout.
- Check is Diagnostics now, off the main path. The status line only appears when something needs it; the check itself still runs at boot and on reload.

## v1.3.176 - engine v32 (unchanged)

- Two layout fixes to the Hidden apps list, both introduced by v1.3.174.

## v1.3.174 - engine v32

- The hide list was still reaching shared storage, one file over.
- The status card said "clean" while the engine was down.
- An unexpected value blanked the whole app.
- Warnings you cannot act on are no longer warnings.

## v1.3.173 - engine v31 (unchanged)

- A hook framework's own mounts are information, not a warning.

## v1.3.172 - engine v31 (unchanged)

- A version bump could not be built.
- "will bite later" was the old ladder talking.
- The nav bar covered the last thing you were reading.

## v1.3.171 - engine v31

- The wrong-kernel card could never fire.
- One `:` could kill the boot script.
- `nomount export` shipped the hide list.
- A module could still forge a rule.
- A stacked mount was stranded forever.
- mount and reload disagreed a fourth time.
- The report says what it measured.
- `nomount` is not a command.

## v1.3.170 - engine v30 (unchanged)

- Absorbed rows survived their module's uninstall forever.

## v1.3.169 - engine v30 (unchanged)

- "Other modules' mounts: none", directly above "Already absorbed · 2".

## v1.3.168 - engine v30 (unchanged)

- The same fix, in the copy that mattered.

## v1.3.167 - engine v30 (unchanged)

- "Hidden paths: 0 - Nothing hidden", with two ROM directories hidden.
- The inode-collision check went UNMEASURED once a module was absorbed.
- What the modules exercised, for the record.
- Module content: nothing to inject, correctly.
- The runtime binds (issue #14).

## v1.3.166 - engine v30 (unchanged)

- `lseek(SEEK_DATA)` on a synthesized directory - fixed and boot-verified.

## v1.3.165 - engine v30 (unchanged)

- The engine fix is boot-verified.
- ...and this check now says what it measured.

## v1.3.164 - engine v30 (unchanged)

- New check: every synthesized directory shares an inode with a real.

## v1.3.163 - engine v30 (unchanged)

- "Real mounts: none" sat directly under "1 mount by design".

## v1.3.162 - engine v30 (unchanged)

- The Rules tab counted 260 while every other surface said 257.
- The panes the harness had not walked.

## v1.3.161 - engine v30 (unchanged)

- A device that had switched itself off said "Active", in green.
- ...and a stale paint could overwrite the fix.
- How both were found.

## v1.3.160 - engine v30 (unchanged)

- The two halves of the front page can no longer disagree about the engine.
- `scripts/webui-harness.py` - the WebUI can be run outside a phone.

## v1.3.159 - engine v30 (unchanged)

- Verified: the Magisk entry point.

## v1.3.158 - engine v30 (unchanged)

- A nested RRO was badged as a plain file redirect.
- Found by the category harness, which is the point.

## v1.3.157 - engine v30 (unchanged)

- The card now says when a module is installed but not served.
- `mounts ?` → `mounts unknown`.
- Measured, not changed.

## v1.3.156 - engine v30 (unchanged)

- An unreadable `apkstate.list` invalidated PM's parse of every injected APK.
- A re-absorbed target kept the source it was first absorbed.
- Measured, not changed.
- The `_ghost` cloak does cover the isolated pools.
- `MIN_PATTERN_LITERAL` counts bytes, not characters.
- `metamount`'s flock and `is_hook_framework`.

## v1.3.155 - engine v30 (unchanged)

- ksud is answered from every exit, not four of them.
- the uidwatch reaper tests death, not age.

## v1.3.154 - engine v30 (unchanged)

- `uid unblock` reported a removal it had not made.
- `nomount uid preset` with no name re-derived both kernel cloak tables.
- `boot.log` was unreachable from the app.

## v1.3.153 - engine v30 (unchanged)

- `File injections: mountless`.
- The unmeasured arm asserted the answer.
- Two packaging fallbacks.

## v1.3.152 - engine v30 (unchanged)

- One bootloop guard, not two.
- `NM_MY_HOOKLESS` is gone.

## v1.3.151 - engine v30 (unchanged)

- One content walk, not four.
- One probe harness, not three.
- A second definition of the erofs dirent formula.
- A second `statfs` decode and a second `0xE0F5E1E2`.
- Two of the three renderers of `ghost::Summary`.

## v1.3.150 - engine v30 (unchanged)

- The boot path deleted the one sentence that explains.
- A successful mount pass left no durable record.
- The WebUI's dead end.
- The readme never mentioned `CONFIG_NOMOUNT` on the first screen.

## v1.3.149 - engine v30 (unchanged)

- ### Fixed - Repairs a defect introduced in v1.3.148: the two hidden-app probes had their pipe sizes crossed.

## v1.3.148 - engine v30 (unchanged)

- The manager card said `healthy` while `check` reported FAILED.
- An unreadable mount table rendered as a clean mount posture.
- `check_xattr_agrees_when_hidden` passed when its own case could not arise.
- The verdict line ranked and named the wrong things.
- The "other modules' mounts" chip was dead.
- Two hide-list states rendered as green, counted, hidden apps.
- Two scans reported a green "nothing found" when they had not run.
- Re-arming the guard left "Nothing is being injected" on screen.

## v1.3.147 - engine v30 (unchanged)

- A corrupted download uninstalled the Suite you already had.
- One `mkdir` permanently disarmed the bootloop guard.
- A newline in a module filename forged a rule that `absorb` acted.
- One non-UTF-8 byte anywhere in the mount table stopped all injection.
- `absorb` injected over live mounts and stranded them forever.
- `run_mount` stole other modules' `my_*` binds.
- Three "only copy" records could be lost.

## v1.3.146 - engine v30 (unchanged)

- The notes, held to the same rule.

## v1.3.145 - engine v30 (unchanged)

- The rest of the plan section, audited against the same rule.

## v1.3.144 - engine v30 (unchanged)

- The Suite reports what a detector can see, and stops there.

## v1.3.143 - engine v30 (unchanged)

- "Delete the marker" told you the wrong thing about when it comes back.

## v1.3.142 - engine v30 (unchanged)

- The manager card counted whiteouts as rules; nothing else did.
- A whiteout-only module was reported as contributing nothing.
- A `my_*`-only module was reported as shipping no partition at all.
- `module content not served` double-counted convergence symlinks.
- The incompatibility lint stated a conditional branch as fact.
- `nomount export` reported "File exists" for a directory that does not exist.
- The Magisk boot path wrote a poorer incident record than the KSU.
- The manager card is one short line.

## v1.3.141 - engine v30 (unchanged)

- The incompatibility lint was blind to every `my_*` partition.
- `my_hookless` was read as intent whoever created.
- The bootloop guard bound the boot path and nothing else.
- The `_ghost` cloak went stale on every verb except `mount` and `reload`.
- The `_ghost` uid table was built from `uidhide.cache`, not from the engine.
- `nomount mount` applied every whiteout before every injection.
- An update threw away `absorbed-tmpfs.list` and `apkstate.list`.
- A module deleting ROM content was invisible if the line started with `rm`.

## v1.3.140 - engine v30 (unchanged)

- `updateJson`, so a manager can offer the update in-app.

## v1.3.139 - engine v30 (unchanged)

- A copy out of a ROM partition was reported as a write into.

## v1.3.138 - engine v30 (unchanged)

- ### Fixed - The incompatibility scanner never read the helper scripts its entry points source.

## v1.3.137 - engine v30 (unchanged)

- `bind-mounts its own content`, a fourth module-incompatibility finding.
- The record of what absorb already took over is now visible.
- Recorded rows from uninstalled modules were never retired.

## v1.3.136 - engine v30 (unchanged)

- ### Fixed - `nomount check --json` writes operational warnings to stdout ahead of the document.

## v1.3.135 - v1.3.126 - engine v30 (unchanged)

- The WebUI is organised by task instead of by data model.
- The hero verdict re-checks when the page opens.
- "What apps can see" folds to its verdict line.
- The mountless headline matches the row underneath.
- A card for the mounts other modules make.
- The six collapsible card headers were `<div onclick>`.

## v1.3.125 - engine v30 (unchanged)

- The `_ghost` tables were populated once per boot and never re-synced.
- The mount pass did one `fork`+`exec` of `nm` per rule.
- Four different idioms for `Path` → `CString`, two of them lossy.
- `nm block <uid>` parsed the uid with no overflow bound.
- Unaligned stores in `nm.c`'s batch encoder.
- The zip was not reproducible.
- `nomount check` reports the isolated-process pool setting.
- `nomount ghost sync` and `nomount ghost list`.

## v1.3.124 - engine v30 (unchanged)

- An image-backed module is a note now, not a warning.

## v1.3.123 - engine v30 (unchanged)

- ### Fixed - An incompatibility was reported against the wrong line - a probe instead of the use.

## v1.3.122 - engine v30 (unchanged)

- `check`: "xattr agrees with open for a hidden app".
- `verify` could not see a field that disappeared, and had no test at all.

## v1.3.121 - engine v30 (unchanged)

- The kernel's `_ghost` dump trusted another repository for a NUL.
- A redaction test stopped claiming coverage it could not have.

## v1.3.120 - engine v30 (unchanged)

- A shared `nomount export` published an appid off the hide list.
- Every state file except `binds.list` was a non-atomic `fs::write`.
- `service.sh` validated the boot epoch's two inputs concatenated.
- `package.sh` never enforced the versionCode field widths it reasons about.

## v1.3.119 - engine v30

- An app update permanently killed the absorbed-APK record.
- The Hidden paths card is back in the WebUI.
- `nm_dsnap_make()` cached its remaining failures as verdicts.
- `metamount.sh` could exit without `ksud kernel notify-module-mounted`.
- A genuine uninstall could leave `/data/adb/nomount.bak` behind forever.
- A guard that always passed, in both copies.
- doctor kept its own `is_partition_root`.
- Two hand-rolled `nm list` parsers survived in `whiteout.rs`.

## v1.3.118 - engine v29

- `nomount export` published a hidden app's appid to shared storage.
- An image mounted over the ROM passed every mount check.
- `uidwatch.sh` - the one entry point without the house guards.
- `nm_dsnap_make()` cached "could not ask" as a verdict.
- `nomount_hijack_superblock()` could not report failure.
- `absorb::refresh_app_apks()` re-implemented the one `nm list` parser.
- The last unquoted expansions in the module scripts.
- One `lib.sh`, sourced by all five entry points.

## v1.3.95 - v1.3.117

- WebUI "Tools" tab.
- `pathhide`, end to end.
- Dead `nm` surface.
- The boot-identity knobs and the pathhide forwarder, in the kernel too.
- The status dot answers "is the engine up?", not "is anything wrong?".
- "Idle" is gone.
- "no rules - re-apply" on a device with nothing to apply.
- "Nothing to test" was reported as "did not run".

## v1.3.94

- - An inert SUSFS module is reported as information, not a warning.

## v1.3.93

- - An absent bootcount reads as zero, not as unknown.

## v1.3.92

- - A process that vanished mid-probe is no longer counted as a failed measurement.

## v1.3.91

- Unmeasured stopped being reported as clean.

## v1.3.88

- One findings list instead of seven cards.

## v1.3.81

- - A mount the table says is not there is no longer asserted.

## v1.3.80

- - One inode is not a bucket.

## v1.3.78

- - Each target is applied once, and what cannot work on this device is named.

## v1.3.76

- - An absorb a `my_` bind cannot accept is no longer offered.

## v1.3.69

- The detection audit reports differently.
- `SKIP` is now `N/A` or `UNMEASURED`.
- Every check carries a plain-language line.
- Findings name their owner.
- Findings carry a reachability tag.
- `--json` on `audit`, `doctor`, `selfcheck`.
- The posture shield contradicted the audit.
- The ghost path populator split rule paths on spaces.

## v1.3.48 - v1.3.65

- Engine floor rose to v26.
- The existence cloak went live.
- The state directory's SELinux label was repaired.
- The early absorb pass moved to post-mount.

## v1.3.47

- The audit probe kept root's supplementary groups.

## v1.3.46

- Per-UID hiding leaked through the xattr path.
- The maps/fd cloak announced itself.
- `nm` dispatched on the first character of the command.

## v1.3.17

- `doctor` told KernelSU Next users to delete a working module.

## v1.3.16

- Rules that hide nothing were counted as hidden apps.

## v1.3.15

- `uidscan.sh` + a Scan button.
- `nomount uid preset --globs`.
- The scanner could silently check nothing.
- Globs could not be typed or removed in the WebUI.
- Whiteout paths reached the shell unquoted.

## v1.3.14

- Globs in the hide list.
- `nomount uid preset detectors`.
- The isolated-process control could lie about the kernel's state.
- A bad `packages.list` read could have un-hidden every hidden app.
- A glob can no longer reach a platform UID.
- Per-UID hiding card rebuilt.

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
- Per-app UID isolation.
- Manager & WebUI.
- Per-module manager tags.
- Install-time sha256 integrity check.
