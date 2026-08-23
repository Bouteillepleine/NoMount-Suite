# Audit — per-UID hiding ("hide UID")

Scope: the whole feature path, kernel to UI.

| Layer | Source audited |
|---|---|
| Kernel | `Bouteillepleine/kbuild@hookless` → `hookless/src/nomount.c` @ `40de86b` (what the builder actually applies) |
| Client | `userspace/src/nm.c` (`block` / `unblock` / `l u`) |
| CLI | `src/nm.rs`, `src/cli/{mod,handlers}.rs`, `src/blocklist.rs` |
| Boot | `module/metamount.sh`, `module/service.sh`, `src/mount.rs` |
| UI | `module/webroot/index.html` (Per-UID hiding card) |
| Health | `src/health.rs` |

Note: the local `kbuild/hookless` checkout was 10 commits behind `origin/hookless`; this audit
is against `origin/hookless`.

## How it works today

`nomount uid block <pkg|uid>` appends to `/data/adb/nomount/blocklist`, resolves the package
through `/data/system/packages.list`, and sends `NM_CMD_ADD_UID` over the private raw-netlink
protocol (29). The kernel stores `uid % 100000` (the **appid**) in `nomount_uid_idr` and flips
the `nomount_active_uids` static branch. `nomount_is_uid_blocked()` is then consulted in
`nomount_hijacked_lookup`, `nomount_hijacked_iterate_dir`, `nm_dir_lookup`, `nm_d_revalidate`
and `nm_reval_stale`; a blocked caller falls through to the real filesystem, and the stock
dentry it causes to be cached is tagged `DCACHE_DONTCACHE` so it cannot poison other UIDs.
Kernel state is runtime-only; `service.sh` re-applies the file after `sys.boot_completed`.

The design is sound and the dcache discipline is careful. The findings below are gaps around
it, ordered by severity.

---

## K7 — hiding a PackageManager-registered APK is worse than not hiding it  (High, fixed in engine v15 / Suite v1.3.42)

Found on OP15, 2026-08-23, from a user-visible crash rather than a probe: **La Banque Postale**
(`com.fullsix.android.labanquepostale.accountaccess`) died ~2 s after launch, every launch, with
`SIGSEGV` in a thread owned by its RASP, **IBM Trusteer** (`com.trusteer.mobile.*`, logcat tag
`TAZ`). The app was on the hide list.

The chain, all of it in `logcat -v threadtime`:

1. Trusteer walks the installed-package list at startup and calls
   `ApplicationPackageManager.getResourcesForApplication()` on every entry.
2. The PackageManager had already scanned `/product/overlay` **as `system_server`**, which is
   never on the hide list, so it parsed and registered the 139 `OxygenCustomizer*.apk` overlays
   NoMount injects there — and hands those paths to any app that asks.
3. For the hidden app every one of them is an ADDED name, so the engine serves the stock
   filesystem: `ENOENT`. 139 × `java.io.IOException: Failed to load asset path …`.
4. Trusteer's native side logs `Internal signal occured: 7`, ART reports
   `attempting to detach while still running code`, and the process dies.

The general shape matters more than the one app: per-UID hiding was **all-or-nothing per UID**,
so it also hid the one class of injection the system advertises to that UID by other means. An
app holding a path the PackageManager says exists and `open()` refuses is a *louder*
inconsistency than the injection it was hiding — and here it was fatal. Every other hidden app
on the device (GMS, Play, Wallet, FNB) was being served the same ghost paths; they only logged
the IOExceptions instead of crashing.

**Fix.** `NM_FLAG_PUBLIC` (engine v15): a rule may opt out of hiding. `Nm::add` sets it for
every ROM APK (`pmcache::is_rom_apk`), and the kernel strips it again from any rule that turns
out to shadow a stock file — where the hidden reader is already served the stock bytes, and
honouring the flag would leak the module's copy instead. The per-caller verdict moved from
`nomount_is_uid_blocked()` to `nm_uid_hidden(flags)` / `nm_child_visible(child)`, so lookup,
readdir, the real-dirent proxy and the parent's `nlink`/size deltas all agree about what a
hidden caller can see. The coarse per-directory bail-out survives, gated on a new
`dir_node->has_public`, so a device with no public rule behaves exactly as it did before.
Synthesized ancestor directories inherit the flag (`nm_mark_public_up`), or the rule they lead
to would be unreachable.

**Verification.** `nomount audit` gained *"PM-registered APKs open for a hidden app"*: it forks,
drops to a blocked appid and opens every ROM APK rule target. `nomount doctor` warns when the
running engine is older than v15, because there the flag is stripped with every other unknown
bit and the failure is otherwise silent.

---

## Status — all findings fixed in v1.3.13

Audited against `origin/suite` (`0f1c5da`) and `kbuild@hookless` (`40de86b`). Three
findings turned out to be **already fixed upstream** and were dropped from the port:
S5 (appid normalisation, done in `handlers.rs`), S7 (`nm l u` error propagation) and
the `nm k` knob verb, which `833080f` added for spoof.

| # | Finding | Fix |
|---|---|---|
| K1 | Directory metadata not UID-gated | `nomount_hijacked_getattr` skips the nlink/size correction for a hidden reader; the nlink delta counts only children that reader can see |
| K2 | Blanket isolated-pool hiding is an oracle | `NM_KNOB_HIDE_ISOLATED` + `nomount uid isolated <both\|appzygote\|platform\|off>`, default unchanged, trade documented in the UI |
| K3 | `nm clear` drops the hidden set | Header note; the real fix is S2 |
| K4 | netlink existence oracle | Documented at the registration site with the SELinux caveat; not reachable from an app domain |
| K5 | DONTCACHE timing asymmetry | Documented; narrower than the bug it replaces |
| K6 | `--uid` rules compared raw uids | `nm_rule_visible()` compares appids, like the block list |
| K7 | SDK-sandbox uid of a hidden app uncovered *(found while testing the fixes)* | Sandbox appid is followed back to its owner (`appid + 10000`) |
| S1 | `blocklist` file served two features | Hiding moved to `uidhide`; existing files split on first read |
| S2 | Re-apply / clear silently unhid everything | `run_mount()` and `vfs clear` re-assert the list |
| S3 | ~10–20 s boot exposure window | Resolved appids mirrored to `uidhide.cache`; mount pass re-hides at post-fs-data |
| S4 | No re-apply on install | `uidwatch.sh` via `inotifyd` on the package map |
| S5 | Clone UIDs mishandled | **already fixed upstream** (`handlers.rs` appid()) |
| S6 | `uid apply` could not fail | Counts and reports failures, non-zero exit, loud kmsg |
| S7 | `nm l u` returned success on error | **already fixed upstream**; the health fingerprint now reports `unknown` too |
| S8 | No guard on platform appids | Refused below 10000 without `--force`; canary reports `unchecked:probe-uid-hidden` |
| S9 | WebUI input/output handling | Allow-list validation, escaped rendering, data attributes, `esc()` covers quotes |
| S10 | Docs drift | README + WebUI note corrected |
| S11 | Legacy ioctl patches | `kernel_patches/` marked superseded |

The kernel changes are in the local `kbuild@hookless` checkout and are **not pushed** —
a kernel build picks them up only once that branch is pushed, and the compile matrix
(`.github/workflows/hookless-compile-matrix.yml`, 4.9 -> 6.18) only fires on a push to
`hookless`, so that run is the gate.

---

## K1 — `getattr` on a hijacked directory is not UID-gated  (High)

`nomount_hijacked_getattr()` (nomount.c:1001) corrects `nlink` (`nm_dir_nlink_delta`) and the
erofs directory size (`size_delta`) for **every** caller. There is no
`nomount_is_uid_blocked()` check on that path — the only major entry point without one.

So a blocked app gets:

* `readdir("/system/app")` → stock entry set (correct, that is the point)
* `stat("/system/app")` → `nlink` shifted by +1 per injected subdir, −1 per whiteout'd subdir,
  and on erofs `st_size` shifted by `size_delta` bytes

i.e. stat() and readdir() disagree **exactly for the app you are hiding from**. The comment
above `nm_dir_size_fix()` names this as the tell the correction exists to remove; for blocked
readers the correction reintroduces it, and the delta leaks how many entries are hidden.

Fix: after the real filesystem answers, `if (nomount_is_uid_blocked(current_uid().val)) goto
out;` before applying `nld`/`delta`. Same for rules carrying a `target_uid` — the deltas ignore
`target_uid` too, so a uid-scoped rule shifts the metadata for everyone.

## K2 — blanket isolated-process hiding is itself an oracle  (High, needs on-device confirmation)

nomount.c:73 hides from every appid in `[90000, 99999]` whenever *any* app is blocked. That
covers the app_zygote carrier Duck used, but it also covers ordinary
`android:isolatedProcess="true"` children and WebView/Chrome renderers — for **all** apps.

Consequence: with hiding armed, any unprivileged app can compare its own view against its own
isolated child's view of the same path. Main process sees the injected file, the isolated child
sees the stock one → injection proven, no root, no mounts, no SELinux probing. The oracle exists
only while at least one UID is blocked, so turning the feature on for one app arms a detector
for every other app.

Whether it is exploitable depends on `isolated_app` being able to `stat()` `/system` paths on
this device — `isolated_app` is an `appdomain`, so `r_file_perms` on `system_file` is likely,
but confirm with the probe below before deciding how to fix it.

If it is exploitable there is no clean kernel fix (an isolated uid does not encode its owner),
so the realistic options are: narrow the blanket to `[90000, 98999]` (app_zygote only, the
actual carrier) and accept regular isolated procs seeing injections; or make the range a knob
and document the trade-off. Either way the current default should be a deliberate choice.

## S1 — `/data/adb/nomount/blocklist` is two different lists  (High)

`src/mount.rs:37` reads that exact path as the **module-skip list** (module ids that must not be
injected — self-mounting modules, `kernelnosu`). `src/blocklist.rs:23` writes the same path as
the **per-UID hide list** (package names / uids). Same file, same parser, two schemas.

* Every package you hide is also inserted into the module-skip set. A module id that equals a
  package name silently stops being served.
* Every module-skip entry a user added by following `README.md:38` shows up in the WebUI as a
  hidden app ("not installed"), with a ✕ button. One click removes the line — and the next mount
  pass injects a self-mounting module that was deliberately excluded. That is the bootloop /
  broken-root class the skip list exists to prevent.

Fix: move per-UID entries to their own file (`/data/adb/nomount/uidhide`) with a one-time
migration, or namespace the lines. Do not leave a destructive UI control pointed at a
safety-critical file.

## S2 — "Re-apply" and "Clear rules" silently unhide every app  (High)

`nomount_nl_clear_rules()` → `__nomount_clear_all()` disables the static branch and
`idr_destroy()`s the uid idr — `nm clear` drops rules **and** UIDs ("Cleared all active rules
and UIDs"). `run_mount()` (src/mount.rs:282) calls `nm.clear()` on every pass, and the WebUI's
primary Status button is `remount()` → `nomount mount`. `clearRules()` → `vfs clear` does the
same.

At boot the order is harmless (mount, then `uid apply`). Post-boot it is not: pressing Re-apply
unhides every blocked app for the rest of the session, and nothing re-applies the list. The UI
does eventually reveal it (rows flip to "saved, not applied"), but only if the user looks.

Fix: re-apply the persistent list at the end of `run_mount()`, and after `vfs clear` in the UI.

## S3 — boot exposure window  (Medium)

`service.sh` applies the list only after waiting for `sys.boot_completed` (up to 240 s), then
`sleep 10`, then the pathhide/scan/ksud-delink steps. Injections are live from post-fs-data. So
every hidden app sees the full injected filesystem for the first ~10–20 s of user space —
including anything with a `BOOT_COMPLETED` receiver, which is exactly what a detector ships.

`/data/system/packages.list` lives in DE storage and is readable at post-fs-data, so the resolve
can happen much earlier. Better still: cache the resolved appid alongside each entry at block
time and have `metamount.sh` apply the cached appids immediately after the mount pass — zero
window, no `packages.list` dependency at that stage.

## S4 — nothing re-applies on install/update  (Medium)

An entry saved for a not-yet-installed package stays inert until the next reboot (`uid apply`
runs only from `service.sh`). Install the app you meant to hide from and it is unhidden until
you reboot. The UI does show "saved, not applied", which is honest, but the feature should close
itself: a package-event trigger, or a cheap poll while any entry is unresolved.

## S5 — clone / work-profile UIDs mis-handle in the CLI  (Medium)

The kernel normalises to appid; the Rust layer does not. With `10471` blocked and the user
entering the clone uid `1010471`:

* `uid unblock 1010471` → `uid_list_live()` (appids) does not contain it → the unblock call is
  skipped → prints "unhidden" while the kernel is **still hiding the app**. Silent false success.
* `uid block 1010471` → the "already" check misses → `EEXIST` from the kernel → spurious failure.

The field's own placeholder invites a raw UID. Fix: `% 100000` in `blocklist::resolve()` (or in
`Nm::uid_block/unblock`) so both layers agree.

## S6 — `uid apply` cannot fail  (Medium)

`handlers.rs`: `let _ = nm.uid_block(uid); applied += 1;`. Engine down, EPERM, missing `nm`
binary — all report "applied N, skipped 0", and `service.sh` logs "block list re-applied" to
kmsg. The one place that most needs to be trustworthy is the one that never reports failure.
Count `blocked` / `failed` separately and let a non-zero failure count reach the card.

## S7 — `nm l u` returns success on error  (Low)

`nm.c`: `unsigned int len = do_nm_cmd(...)` — an `NLMSG_ERROR` reply is caught by the
`nlmsg_type == 2` check at the top of the parse loop, so the client prints `[\n\n]` and exits 0.
"No blocked UIDs" and "EPERM / engine down" are indistinguishable. Downstream,
`uid_list_live()` yields an empty set → `health.txt` reports `blocked=0` and every row shows
"saved, not applied". Propagate the netlink error as a non-zero exit.

## S8 — no guard on system appids  (Low)

The picker is `pm list packages -3`, but the field takes free text and nothing validates the
range:

* `1000` hides injections from `system_server` — RRO/idmap and framework patches see stock.
* `2000` (shell) breaks the health canary permanently: `consistency_probe()` compares root
  against `su 2000`, so blocking shell stamps "⚠️ per-UID inconsistency" on the manager card
  forever.
* `0` hides injections from root itself.

Refuse appids < 10000 without an explicit `--force`, and have `health.rs` skip (or annotate) the
canary when appid 2000 is blocked.

## S9 — WebUI input/output handling  (Low)

* `uidOp()` rejects `[\s'"` + backtick + `;|&$<>()]` but allows `* ? [ ] \` — glob chars reach
  the shell unquoted. Not injection, but the wrong target can be blocked.
* `refreshBlocked()` interpolates `uid list` output straight into `innerHTML`, and into an
  `onclick="…('${t}')"` attribute with only `'` stripped. Entries are package names today, so it
  is not currently reachable, but the file is user-editable.

Fix: validate `^[A-Za-z0-9._]+$|^[0-9]+$`, escape on render, and move the buttons to `data-*` +
`addEventListener`.

## K3 / K4 / K5 / K6 — smaller kernel notes

* **K3** `nm clear` wiping the uid idr is the kernel half of S2. Defensible as a kernel
  primitive; the fix belongs in `run_mount()`, but it is worth a note in the header so the next
  caller of `clear` knows what it destroys.
* **K4** `netlink_kernel_create(&init_net, 29, …)` makes `socket(AF_NETLINK, SOCK_RAW, 29)`
  succeed on a patched kernel and fail `EPROTONOSUPPORT` on a stock one — an existence oracle
  for the engine. Every command is `netlink_capable(skb, CAP_NET_ADMIN)`-gated, so nothing can
  be read or changed, and for `untrusted_app` the SELinux `netlink_socket:create` check fires
  first (same `EACCES` on both kernels), which masks it. Confirm on device; if some
  app-reachable domain does hold `netlink_socket`, this is a free "kernel is patched" tell.
* **K5** `DCACHE_DONTCACHE` on the blocked reader's fallback means injected names are never
  dentry-cached *for that app* while its stock siblings are — a repeatable timing asymmetry a
  patient detector could measure per-name. Speculative, but it is a real asymmetry the
  non-blocked path deliberately avoids.
* **K6** `rule->target_uid` is compared against the raw `current_uid().val`, while blocking
  compares appids — a uid-scoped rule does not follow an app into a clone or work profile.
  `target_uid == 0` also means "everyone", so a root-only rule is not expressible. The Suite
  never emits `--uid` rules today.

## S10 / S11 — documentation and dead code  (Info)

* The WebUI note under the card claims it hides "injected files **and su**" — su is sucompat,
  entirely outside nomount, and is not affected. It also says it "doesn't cover …
  isolated-process probes", which is the opposite of what the kernel does (K2).
* `README.md` §Features still describes the pre-hookless engine: a "per-UID hash table",
  `/dev/nomount` hidden via SUSFS `sus_path`, overlayfs mounts. It also documents
  `/data/adb/nomount/blocklist` as the module-skip file — see S1.
* `kernel_patches/*.patch` (10 files) are the **legacy ioctl engine**: they patch `fs/namei.c`
  and implement per-UID hiding as `NOMOUNT_IOC_ADD_UID` over a hashtable and `/dev/nomount`.
  Nothing in the Suite can drive that — `nm`/`nm.rs` speak raw netlink only, and the builder
  applies `kbuild@hookless` instead. Anyone building from the in-repo patches gets a UID block
  the CLI cannot reach. Delete them or mark them legacy.

---

---

## Pre-push audit of the fixes themselves

A second pass over the two diffs before pushing, read adversarially. Nine issues;
all fixed in the same branches.

**P1 — `export` published the live hidden set (pre-existing, not from this work).**
`health.rs` treats the hide list as private and refuses to copy it to shared
storage, because it names the apps you are hiding from. It then wrote
`uid_live.txt` — the kernel's live hidden appid set, the same secret — to the
export directory unconditionally, and the WebUI's default destination is
`/sdcard/Download`. Every export handed a detector the list. Now gated on the same
`shared` check.

**P2 — that private-file guard pointed at the old filename.** S1 moved the hide
list from `blocklist` to `uidhide`, so `PRIVATE = ["blocklist", …]` was guarding a
file that now holds only module ids while the real secret (and `uidhide.cache`,
which spells out each resolved appid) was not in the export set at all. The guard
moved with the content.

**P3 — the mount pass re-hid after rebuilding the rules.** Correct at boot, wrong
after it: a post-boot Re-apply would clear, spend the length of a full mount pass
adding injections, and only then restore hiding — a window in which a hidden app
could see everything. Hiding is per-UID state that does not depend on any rule
existing, so it is asserted immediately after the `clear` now.

**P4 — `uid isolated` persisted a policy the engine had refused.** It wrote the
setting first and set the knob second, so on a kernel without the knob the file
claimed a policy that was not in force and every later apply re-tried and
re-reported the failure. Knob first, persist only on success.

**P5 — the migration rewrote the legacy file.** Splitting `blocklist` moved
entries out of it, which is the dangerous direction: this runs unattended at
post-fs-data, and if `is_dir()` ever misjudged (unreadable modules dir), a
module-skip entry would be dropped and that module injected on the next pass —
which for a self-mounting module or one shipping its own su is how a boot breaks.
It copies now and never removes. A leftover package name in `blocklist` is inert
(the file is only ever consulted as "is this the id of a module I am about to
inject?"), and copy-only also means a downgrade to 1.3.11 still finds its list.

**P6 — the package watcher was gated on a non-empty list.** Hide your first app
from the WebUI after boot and no watcher was running, so the install-time gap S4
exists to close stayed open until the next reboot. Started whenever the module is
active; `uidwatch.sh` exits immediately when there is nothing to apply.

**P7 — `inotifyd` mask letters are not portable.** busybox and toybox disagree on
them, and a letter this toybox does not know makes `inotifyd` exit at startup —
the watcher would be silently absent, which is precisely the failure mode it was
added to remove. Registered with no mask; the handler filters on the filename.

**P8 — the watcher's lock could leak.** A killed handler left the lockfile behind
and every later package change was ignored for the rest of the boot, with the
watcher still apparently alive. `trap … EXIT INT TERM`.

**P9 — apply could report EEXIST as a failure.** The pass takes one snapshot of
the live set and blocks what is missing from it; if that snapshot were stale, the
kernel's "already hidden" answer counted as a failure. On a failed block it now
re-asks once and counts the desired end state as success.

### Checked and clean

* `child->rule` is set when a child node is created and never nulled — only
  removed with the node — so gating the link-count delta on rule visibility cannot
  drop a live child. Where it could differ (a rule mid-insert) it errs in the same
  direction `readdir` already takes.
* The renamed pool macros (`NM_ISOLATED_START` 90000 → 99000) have no other users
  in the tree.
* `NOMOUNT_VERSION` is untouched — the knob is additive, so kernel and module stay
  compatible in both directions and do not have to be flashed as a set.
* The zip's sha256 manifest is generated by walking the staging dir, so
  `uidwatch.sh` is covered without touching the manifest step.
* Nothing parses `blocked=` numerically, so reporting `unknown` there breaks no
  reader; `verify` diffs the fingerprint textually.
* The WebUI script tag sits after the elements the new delegated handler binds.

## Device verification (not run — no adb device attached)

The expectations below are written for the **fixed** build (Suite v1.0.7 + a kernel built from
the patched `kbuild@hookless`). The kernel half is committed locally and unpushed, so until
that branch is pushed and a kernel is built, K1/K2/K7 will still show the old behaviour while
everything in the Suite half is already testable.

```sh
# 1. engine + live set
nm v; nm l u

# 2. K1: does a blocked app see corrected dir metadata?
#    pick a dir with an injected child from `nomount vfs list`
D=/system/app
nomount uid block <pkg>
stat -c '%h %s' $D                       # root view
su <uid> -c "stat -c '%h %s' $D"         # blocked view -> must match a stock device
su <uid> -c "ls -1 $D | wc -l"           # entry count  -> compare against %h - 2

# 3. K2: can an isolated process stat /system at all?
#    needs a tiny APK with android:isolatedProcess="true"; if stat() works there,
#    the main-vs-isolated comparison is a live oracle.

# 4. K4: netlink existence oracle, per domain
#    socket(AF_NETLINK, SOCK_RAW, 29) as shell and from an app context
#    expect EACCES from SELinux, not success

# 5. S2: re-apply must NOT wipe the set any more
nm l u; nomount mount; nm l u            # same set before and after

# 6. S5: clone-uid handling
nomount uid block <pkg>; nm l u          # note the appid N
nomount uid unblock $((1000000 + N))     # a clone uid for the same app
nm l u                                   # N must be GONE (before: silently still there)

# 7. S1: the two lists are separate now
cat /data/adb/nomount/uidhide            # apps only
cat /data/adb/nomount/blocklist          # module ids only, with a header

# 8. S3: hidden from first boot, not from boot_completed+10s
#    reboot, then:
dmesg | grep -i 'nomount.*hidden\|nomount.*hide list'
cat /data/adb/nomount/uidhide.cache      # pkg<TAB>appid mirror the early pass uses

# 9. S8: platform appids are refused
nomount uid block 1000                   # must fail with the explanation, not hide system_server

# 10. K7: the SDK sandbox of a hidden app
#     appid N hidden -> uid N+10000 must also get the stock view
```

## Suggested order of work

1. S1 (file collision — destructive UI control) and S2 (re-apply wipes blocks).
2. K1 (metadata leak to the blocked app) — small, self-contained kernel change.
3. S3 + S4 (coverage windows), S5/S6/S7 (honest state reporting).
4. K2 once the isolated-process probe answers whether the oracle is live.
5. S10/S11 doc + dead-code cleanup.
