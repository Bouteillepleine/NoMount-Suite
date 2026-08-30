# Changelog

## Unreleased

Three defects from a full read-through of the tree, and four things that had
outlived what they described.

### Fixed

- **The Magisk boot path could bootloop with the guard disarmed.** The
  pre-zygote `absorb --early` block sat ABOVE the bootloop counter in
  `post-fs-data.sh` — so a boot that died inside it never advanced `bootcount`,
  `GUARD_MAX` was unreachable, and the device looped with no self-recovery. That
  is not a hypothetical failure for that block: re-asserting a `my_*` rule has
  rebooted a device (OP11, four rules in a burst, clean `sys.boot.reason`, no
  tombstone), which is exactly why the pass exists there and only there.
  `metamount.sh` states the rule both files have to obey — "Anything placed
  above [the guard] is something `disabled` never suppresses and the counter
  cannot protect against" — and the KSU path always obeyed it: the counter is
  incremented in `metamount.sh` and the early absorb runs later, from
  `post-mount.sh`. The block now lives in the guard's `else` arm.

  Moving it also fixed an inverted ORDER that came with the old position. KSU
  runs the mount pass first and absorbs second; Magisk ran absorb first, so the
  `nm clear` that opens the mount pass dropped every rule absorb had just
  created — and `run_mount` re-serves only the absorbed record's APK entries
  (`is_app_apk`). A non-APK takeover was therefore recorded, wiped, and not
  re-served until `service.sh`'s pass, by which time its mount was gone and
  there was nothing left to absorb: that path served the stock file for the
  whole boot. Both paths now run in the same order.

- **`uidwatch.sh` ran a full `absorb` on every package change, on every
  device.** The gate was `[ -s absorbed.list ]`, but `set_absorbed_pairs` writes
  a three-line comment header before it writes any pairs, so the file is
  non-empty from the first mount pass whether or not anything has ever been
  absorbed. Measured on an OP11: 184 bytes, 0 non-comment lines, and `absorb`
  firing four times in the first 60 s after boot, each reporting "nothing to
  absorb" — a mountinfo survey, an `nm list`, a `/proc` walk over ~1000 pids and
  the engine-wide pass lock, once per install/update/uninstall, forever. Floor
  cost measured at 133 ms per run. Both gates in that file now ask whether the
  list holds an entry, using the same "first non-blank character is not `#`"
  predicate its readers use.

- **Per-UID hiding leaked module bytes under a shadowing dir-target rule**
  (engine, `nm_dir_child_lookup`). A passthrough child inherited
  `NM_FLAG_SHADOWS_STOCK` from its parent without inheriting anything for it to
  point at, so the two halves of the pair disagreed: `nm_hidden_from_caller()`
  saw the flag and declined `-ENOENT`, while `nm_stock_for_caller()` found no
  `s_path` and returned NULL — a blocked reader was served the MODULE's bytes
  for every name under that directory, while its `nm_open()` of the PARENT
  handed it the pinned stock directory. readdir listed stock names, lookup
  resolved module content. The child now resolves its own name under the
  parent's stock directory and pins the result; a name genuinely absent there
  loses the flag and is hidden like any other added name; a name that cannot be
  resolved leaves the flags alone, because "could not ask" is not "not there".

  Narrow, and stated as such: no shipped configuration builds that rule shape.
  `mount.rs::inject_would_mask_dir` refuses a target resolving to a live
  directory and `cli::handle_vfs` refuses a directory source, so only a
  hand-issued `nm add <existing-dir> <dir>` reaches it, and no measured device
  carried one. **Engine floor rises to v27**; userspace can neither set nor
  observe the difference, so the bump is there for `doctor` to tell a flashed
  engine from the one it replaced.

  The first build of this fix was inert, and only measuring it said so. It
  wrapped the stock lookup in `override_creds(nm_root_cred)` — whose SID is the
  KERNEL's, not root's — and `lookup_one_len_unlocked()` ends in
  `inode_permission()`, which runs the LSM. Asked directly through
  `/sys/fs/selinux/access` on an OP15: `kernel_t` may search `system_file` and
  `system_data_file` directories and may **not** search `shell_data_file` or
  `adb_data_file`. So the lookup returned `-EACCES` on any /data-labelled
  target, took the error arm, pinned nothing and left v26 behaviour in place —
  silently, because that denial is `dontaudit`'d and logs no AVC. Same rule
  shape, blocked reader, two labels:

  ```
  shell_data_file        both.txt=MODULE  modonly=MODULE    (inert)
  system_data_root_file  both.txt=STOCK   modonly=<ENOENT>  (works)
  ```

  The lookup uses the caller's creds now, matching the module-side lookup beside
  it, which removes the LSM dependency rather than trading one label for
  another. The first-toucher-wins case that motivated the override is covered by
  the parent already having passed `nm_inode_permission()`, whose mode, owner and
  context mirror the stock ancestor.

  **Engine floor is v28, not v27.** Two builds answered `nm v` with 27 and
  behaved differently — the one flashed from the first commit is inert on /data
  labels, the corrected one is not — and a capability counter exists precisely so
  `doctor` can tell a flashed engine from the one it replaced. 27 could no longer
  do that for itself. Nothing compares the number for equality (every gate in the
  Suite is `>=`, `<` or a range), so raising it is safe; release tags become
  `nm1.28.0`.

- `post-fs-data.sh`'s `disabled` arm was a bare `:`, so a Magisk user whose
  guard had tripped got nothing in `boot.log` at the stage that made the
  decision. It logs the same line `metamount.sh` does.

### Removed

- **The `CONFIG_BOOT_CONFIG` gate in the compile matrix**, and the per-version
  `bootcfg` column that drove it. It forced the symbol on and FATAL'd when it
  did not stick, for `#ifdef CONFIG_BOOT_CONFIG` blocks that retired with knob
  slots 0..3 — the driver names neither the symbol nor bootconfig anywhere. A
  gate over code that does not exist cannot fail usefully and can only fail
  spuriously.

### Changed

- `hookless/nm-verify-v14.sh` → `hookless/nm-verify.sh`. Both invariants it
  checks still hold; what was stale was demanding `engine == 14`, which printed
  "NOTE: expected 14" on every engine since. It now takes v14 as the floor those
  invariants arrived at and refuses outright if the engine answers no version at
  all.

## v1.3.95 – v1.3.117

The kernel engine now lives in this repository under `hookless/`, merged from
what was `kbuild@hookless`: it is versioned and flashed with the userspace that
drives it, and CI can finally assert that the two agree on the one list they
both carry (`pmcache::PM_SCAN_DIRS` and the engine's `nm_vpath_in_pm_scandir`).
Separately, the `kernel_patches/`
directory has been **removed** — it held the original `/dev/nomount` char-device
engine with `fs/namei.c` hooks and an ioctl control plane, which nothing in this
repo could drive any more: `nm` and `src/nm.rs` speak netlink only, so a kernel
built from those patches answered no CLI command. The README's Requirements
section still pointed users at it, 50 lines after the text saying it was dead.

### Removed

Older entries below still describe these. They are gone.

- **WebUI "Tools" tab** — Spoofing, Cloak, Hidden paths, Foreign mounts. Per-UID
  hiding moved to Status. Any "WebUI › Tools › …" pointer is stale.
- **`spoof.sh`** — vbmeta/uname spoofing, 761 lines and ~38 KB per zip, inert by
  default and carrying two unfixed digest defects. Its one live piece, the
  `/data/local/tmp` permission restore, moved into the boot scripts and still
  honours `fix_shell_tmp`. An existing `spoof.conf` is left alone.
- **`pathhide`, end to end.** No builder applies the patch, so `pathhide_ctl` is
  a NULL weak symbol and the kernel answers `-EINVAL` to `nm k p` — including
  the empty-value *presence probe*, because the NULL test runs before the probe
  short-circuit. Both Suite gates therefore always took the false branch: the
  boot pass in `service.sh` could never run, and `customize.sh` printed "kernel
  pathhide not present (needs a pathhide-enabled kernel)" on **every install of
  every kernel these builders produce**, naming a configuration gap that cannot
  be closed. Gone: the boot pass, the install-time probe and its two messages,
  the seeding and relabelling of `pathhide.conf`, and `nm`'s `l p` list option.
  An existing `pathhide.conf` is now simply inert; nothing reads it.
- **Dead `nm` surface** — the long-form aliases `whiteout`, `version` and `knob`
  (no caller, no documentation), the `--uid` option (per-UID *rules* need it and
  nothing has ever passed it; the wire field stays, always 0), and the `j` list
  option (`l u` turns JSON on by itself, and no consumer of the JSON rule shape
  exists).
- **`NOMOUNT_NL_VERSION`** — a generic-netlink leftover, referenced by neither
  the kernel nor the client.
- **The boot-identity knobs and the pathhide forwarder, in the KERNEL too**
  (`kbuild@hookless`). Retired: the uname release/version override, the
  `/proc/cmdline` + `/proc/bootconfig` takeover, and the `_pathhide` control
  forwarder and dump — 314 lines of driver, plus four includes nothing else
  needed. `nm` loses the letters `r`, `v`, `c`, `b` and `p`.

  Their enum SLOTS are reserved, not deleted. A knob is a raw `u32` at payload
  offset 0 and a command travels as `NLMSG_MIN_TYPE + cmd`, so renumbering would
  silently remap every knob and command below them for any `nm` already on a
  device — `nm k d 1` would arrive as something else entirely. Slots 0-3 and 6
  (knobs) and 10 (command) are reserved and will not be reused.

  The `16:` capability claim in `nomount.h` is retracted in place rather than
  removed, and `NOMOUNT_VERSION` stays 26: an engine reporting >= 16 no longer
  implies pathhide support, but 17 and above still make claims that hold.
  Validated by the ten-version compile matrix (4.9 through 6.18), zero warnings
  at `W=1`.
- **`spoof.log`** from `nomount export` — nothing has written it since `spoof.sh`
  was removed.
- **`scan.sh`** — scanned every installed APK on each boot to fill a cache whose
  only reader was the deleted Cloak picker.

### Fixed

- **The status dot answers "is the engine up?", not "is anything wrong?"** It is green whenever the Suite is running, including when a module ships files and no rule serves them — the substate still names the action there, and `check` is what reports faults. Two alarms for one condition taught people to read the dot as noise. It stays amber only when the probe could not tell either way.
- **"Idle" is gone.** While the engine answers, the card says ACTIVE — that is what the word is for. The substate line says what the Suite is doing and the dot says whether anything needs you. "Idle" read as "switched off" to people whose setup was fine, and it read badly even in the case that does need attention, where the engine is running too. Only "Engine offline" replaces it. The headline word answered "are there rules?" when the question a user asks is "is it working?" — so a device serving exactly what it should read as switched off. ACTIVE now means the Suite is doing its job, including correctly having nothing to do; IDLE is reserved for the one case that needs the user.
- **"no rules — re-apply" on a device with nothing to apply.** The status
  card had one message for both causes of zero rules, so a user whose modules are
  all script-only was told to press Reload — which can never work, and the card
  can never reach Active. It now says "nothing to inject — no module provides
  files", in green, and keeps "no rules — re-apply" for the case where a module
  does ship content. The extra check only runs when the count is zero.
- **The last plan check that said "not measured" when it meant "nothing to
  test".** `Level` had no N/A, so a plan finding with nothing to look at had to
  claim it could have run. On a script-only device nine device checks correctly
  said n/a while the ghost row alone kept the card amber. `Level::NotApplicable`
  now exists, ordered to match `Verdict`, and the ghost row uses it when nothing
  is being injected — while staying amber when rules are live and the cloak
  really is off.

- **"Nothing to test" was reported as "did not run".** On a device where no
  module provides files, the per-UID canary and the served-bytes check had no
  injected file to sample — and said UNMEASURED, with a remedy ("the boot pass
  runs before any app has opened an injected file — run them now") that could
  never work, because running again cannot conjure a rule. The card read "not
  fully measured" on a device that was working exactly as designed. Both are now
  N/A when there are zero rules, and stay UNMEASURED when rules exist but
  sampling failed — which is the distinction those two words are for.

- **A device with zero rules showed one rule, called "no rules".** `nomount vfs
  list` printed that phrase on an empty engine, and the WebUI counts every
  non-blank line of it as a rule — so the message counted itself. Status read
  `INJECTION RULES 1`, Rules read `Active rules 1 · (other) 1`, and the rule row
  was the word itself. Reported from an OP15 whose five modules are all script
  only, where 0 rules is the correct answer. The empty list now prints nothing,
  and the parser only counts lines that look like a path.

- **Removing the module threw away everything you had configured.**
  `uninstall.sh` did `rm -rf /data/adb/nomount`, taking the per-app hide list,
  the module blocklist and the `my_hookless` opt-in with it — so the classic
  recovery, remove then reinstall, silently reset your settings. (Flashing a
  newer zip straight over an older one does NOT run it: measured on OP15,
  v1.3.107 -> v1.3.108, all state intact.) Losing the marker alone moved
  85 `my_*` files from injection back to bind mounts on a live OP15: 260 rules
  became 175, and 85 mounts appeared over the ROM. `uninstall.sh` now stashes the
  user-owned files and `customize.sh` restores them, saying how many it put back.
  The operational flags are still cleared — `disabled` in particular, which is
  why that `rm` exists at all.
- **A Suite-made `my_*` bind is a NOTE, not a FAIL.** Serving `my_*` by bind is
  the DEFAULT — the `my_hookless` marker is what switches it to injection, not
  the reverse — so a stock install opened red on any device with a module that
  ships `my_*` content. The posture cost is real and the text still states it,
  but it is an accepted default, not a failure. A bind the Suite did NOT make
  stays a FAIL: someone else's mount over the ROM is what the check is for.
- **`foreign mount over the ROM` counted module mounts as foreign.** It flagged
  every subtree bind over a ROM path, including binds sourced from
  `/data/adb/modules` — while its own text read "come from outside the module
  system" and its owner read "a mount made outside /data/adb". Both were the
  opposite of the truth, and the same 85 binds were reported twice, in two
  different red rows. Module binds now belong to `zero-mount posture` alone.
- **`check` blamed other modules for the Suite's own mounts.** The owner was
  derived from the bind SOURCE, so a bind the Suite made to serve a module's
  `my_*` content was reported as that module's doing, with two remedies that
  could not work: reboot (we re-create them every boot from `binds.list`) and
  "delete the bind from its post-fs-data.sh" (there is none). It now reads
  `binds.list` to settle authorship, says plainly when the Suite made the mount,
  points at the `my_hookless` opt-in, and offers the reboot/edit advice only for
  mounts it did not create.

- **`service.sh` discarded `nm`'s exit status when building the ghost path
  table.** `nm` exits 4 on a truncated dump specifically so a caller can tell a
  prefix from the whole set, but the call was piped straight into `sed`, so `$?`
  was `sort`'s. A truncated dump half-populated the table — the state the same
  script calls worse than an empty one, because a hidden reader then sees some
  paths ghosted and the rest not. The dump is now captured on its own, the
  status checked, and a failure logged instead of silently half-applied. It was
  also the only `nm` call in the file without a timeout; it has one now.
- **`nomount check` said nothing when the ghost tables were empty.** The kernel
  answers an empty, *successful* dump both for "`_ghost` not compiled in" and
  for "compiled in, tables empty", and the check had no else arm — so neither
  case produced a finding of any level, and the silence was indistinguishable
  from a pass while `service.sh` logged the cloak as inert on the same boot. It
  now reports UNMEASURED with both table counts.

### Findings graded by what a detector can do

A tell nothing probes is no longer a failure. `erofs directory shape`,
`readdir cookie magic`, `overlay dir inode range` and `injected inode band` moved
FAIL → WARN; "directory holds only injected files" became a NOTE; a check that
could not run is now `UNMEASURED`, so "I did not look" stops counting against a
healthy device.

### Seven diagnostic verbs became one

`doctor`, `audit`, `posture` and `selfcheck` are **gone**, replaced by
`nomount check`. They were verbs over two verdict enums, three JSON shapes and a
fourth `key=value` one, and the WebUI existed to merge all of it back into one
list. `plan` was dropped with them and then brought back — see the table.

| was | now |
| :--- | :--- |
| `nomount doctor [--json]` | `nomount check --plan [--json]` |
| `nomount audit [--json] [--write]` | `nomount check --device [--json] [--write]` |
| `nomount selfcheck [--write] [--json]` | `nomount check --device [--json] [--write]` |
| `nomount posture` | removed — its three mount checks are rows in the one report |
| `nomount plan` | **restored.** Dropped here as having "no caller anywhere", which was true inside this repo and false outside it: the module test harness parses it to lint a staged module before it is ever applied, and nothing else can. |

`check` with neither flag runs both sections. It exits 1 when, and only when,
`summary.open_failures > 0` — the rule `audit` had, so the boot pass reads it the
same way.

One verdict enum, seven states: `FAIL`, `REBOOT`, `UNMEASURED`, `WARN`, `PASS`,
`N/A`, `NOTE`. `UNMEASURED` and `N/A` stay deliberately distinct — "nothing here
to test" is not a warning, "something stopped me testing" is, and neither is ever
a pass.

`snapshot`, `verify` and `export` are unchanged. `snapshot` was kept where
`posture` was dropped because it answers a question `check` structurally
cannot: not "is this device healthy now" but "has anything moved
since the boot I was happy with".

### The boot pass runs one measurement, not two

`service.sh` used to run `selfcheck --write` in a settle loop and then
`audit --json --write` separately. `check --device` does both halves in one pass,
so the loop runs the combined command once and only retries when the per-UID
consistency probe actually disagrees. The settle window and the "unchecked is not
a verdict" rule are unchanged.

The module card's health line parsed `summary: N errors, M warnings` out of
`doctor`'s prose. That line no longer exists, so the regex matched nothing on
every boot and the card silently sat in its "unknown" arm. It reads
`check --plan --json` now.

### A boot that never ran the mount pass says so

On a KernelSU build **without metamodule support**, `metamount.sh` is never
invoked and `post-fs-data.sh` hands over to it because `$KSU` is set — so the
module was a completely silent no-op: no kmsg line, no `boot.log` entry, no
`incident.log`, no card. Both entry points now stamp `mountpass.ts`, and
`service.sh` reports a boot with no stamp on the card and in `incident.log`.

The same for install-time: `customize.sh` now says so when the zip carries no
binaries for the device's ABI (it ships **arm64-v8a only**), and when the engine
probe could not run at all — a case that previously printed nothing.

### Packaging

- **The staleness guard could not catch the case that actually happens.** It
  compared mtimes with `find src/ -newer <binary>` and deliberately excluded
  `Cargo.toml` — but the version string is `env!("CARGO_PKG_VERSION")`, which
  comes *from* `Cargo.toml`, so a version-bump-only release could never trip it.
  It did not: the shipped v1.3.94 zip carries a binary reporting 1.3.92. The
  staged binary is now asked its version directly, and packaging aborts if it
  disagrees with the version being stamped.
- **The sha256 manifest was unverifiable on Android.** A Windows/Git-Bash host's
  `sha256sum` defaults to binary mode and writes `<hash> *./path`; Android's
  toybox reads the `*` as part of the filename and fails every entry, and
  `customize.sh` aborted the install with the reason hidden behind
  `>/dev/null 2>&1`. The manifest is forced to text mode, and a failed check now
  prints what `sha256sum -c` actually said.
- **The recovery `update-binary` never ran `customize.sh`.** It unzipped,
  chmod'd, printed a success line and exited 0 — skipping the integrity check,
  the "only one metamodule" refusal (a bootloop vector), the `$NMDIR` SELinux
  labelling and the bootcount reset. It also returned success when the `unzip`
  had failed, and unpacked `META-INF` into the module directory. It now provides
  the helpers `customize.sh` expects and sources it.
- The release path no longer hardcodes one maintainer's `~/.cargo`.

### Boot path

- The per-module card/tagging block in `metamount.sh` ran **outside** the
  bootloop guard and walked every enabled module's tree with an unbounded `find`.
  A device that had already written `disabled` to save itself still paid for that
  walk at post-fs-data. The loop is skipped once the guard has tripped, and each
  `find` is bounded.
- `bind` and opaque-directory reads no longer follow module symlinks.

### Docs

- The README documented roughly 40% of the CLI. Two documented commands did not
  exist (`vfs enable|disable|refresh`, `vfs query-status`) and eleven real ones
  were undocumented, `absorb` — which runs twice every boot — among them.
- The README described a **hybrid overlayfs** design, "real overlayfs for RRO"
  and per-app-umount hiding. The engine is 100% mountless: RRO overlay APKs are
  hookless-injected into `/product/overlay` and friends, and OverlayManagerService
  + idmap2 pick them up at the `system_server` scan. Those claims are gone.
- Issue links pointed at `Bouteillepleine/nomount2.0`; security disclosure
  pointed at `Enginex0/nomount`, a different owner entirely.

### Deferred

- **The spoof add-on (`module/spoof.sh`) is deferred and now ships off.** Every
  knob defaults to `off` rather than `auto`. Two defects in the vbmeta digest
  computation are known and unfixed, and both can produce a digest with the right
  shape and the wrong value — which is a sharper tell than setting none: the
  recursive chain-partition walk discards its status (a full-length digest over a
  partial chain), and a device asking for SHA-512 silently gets a SHA-256 when
  `sha512_of` fails. Both sites are marked in the source.

## v1.3.94

- An inert SUSFS module is reported as information, not a warning.

## v1.3.93

- An absent bootcount reads as zero, not as unknown.

## v1.3.92

- A process that vanished mid-probe is no longer counted as a failed measurement.

## v1.3.91

- `uninstall.sh` ships executable.
- Stray indentation stopped leaking into user-facing messages.
- **Unmeasured stopped being reported as clean.**
- The absorbed record and the PackageManager cache are kept honest across a
  re-absorb.
- The release path was fixed: `customize.sh`, `uninstall.sh` and `package.sh`.

## v1.3.88

- The build commit is stamped beside the version, so a phone reporting a version
  also says which commit it came from.
- False greens the audit found were closed.
- **One findings list instead of seven cards** in the WebUI.
- Acceptance, history and the reach pill were **dropped** — including the
  `nomount accept` command announced under v1.3.69 below, which no longer exists.
- The mount table is read before the engine is cleared.
- `uninstall.sh` ships, and unknown stopped being reported as nothing.
- The release build stopped reporting itself dirty.
- Packaging builds on a Windows NDK host too.

## v1.3.81

- A mount the table says is not there is no longer asserted.
- A hand-written bindhosts override is not clobbered.
- The `timeout` fallback is bounded rather than dropped, so a device without
  toybox `timeout` still runs the command under a bound.
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
- The manager warning is written for the person reading it.
- User-facing messages were shortened.
- The last check is remembered, and the report stays quiet when there is nothing
  to say.

## v1.3.69

Requires **Prism engine v26** for the existence cloak; the injection engine and
everything else here works from v16 as before. Pairs with a kernel built from
`kbuild@hookless` at `347ec5c` or later. (The second requirement named here,
`kernel_patches@main` at `8a41f77`, referred to the superseded ioctl engine; that
directory has since been removed.)

### The detection audit reports differently

Nothing about what is measured has changed, and no verdict has been softened.
What changed is that the report stopped describing two different situations with
the same word.

- **`SKIP` is now `N/A` or `UNMEASURED`.** A check with nothing to test here —
  no app on the hide list, no overlay mount, no single-block erofs parent — is
  **not applicable**, renders grey, and never colours the chip or the tab. A
  check that *could* have run and did not — mountinfo unreadable, the probe
  child said nothing, a directory that would not enumerate — is **unmeasured**
  and stays amber. Neither is ever counted as a pass.

  This is why a perfectly healthy device used to open on `4 unverified` in amber
  with an alert dot. It now reads `undetected`, with a grey `4 didn't apply`
  beside it.
- **Every check carries a plain-language line**, on every verdict, alongside the
  evidence it already printed. The evidence is unchanged and one disclosure away.
- **Findings name their owner.** `absorb` already resolved a leaked mount to the
  module that made it and the audit discarded that answer for the one case where
  the reader could act on it.
- **Findings carry a reachability tag** — `any app`, `needs effort` — and sort by
  it. One `getdents64` from any app and something needing a purpose-built erofs
  model are not the same problem and no longer look the same.
- **`nomount accept`** (REMOVED in v1.3.88 — see above) records that you have
  looked at a failing check and decided
  to live with it: a hook framework's bind, an installer's own tmpfs. It never
  marks anything clean. The verdict stays `FAIL`, it stays visible, it renders
  grey rather than green, it is counted separately, and it lapses the moment the
  evidence changes.
- **`--json` on `audit`, `doctor`, `selfcheck`**, plus a new `nomount posture`.
  The WebUI reads these instead of regexing prose.
- The boot pass caches the audit, so the WebUI opens on a verdict and an age
  instead of a dash.

### Fixed

- **The posture shield contradicted the audit.** It counted foreign mounts with
  `awk '$4 ~ "/adb/modules/"'`, which misses a bind from anywhere else under
  `/data/adb` (a ReVanced module binds out of `/data/adb/rvhc`; the audit has a
  regression test for it) and *counts* a hook framework's by-design bind, which
  the audit deliberately does not. Measured on an OP15 with LSPosed: the shield
  sat on a permanent amber "another module is mounting" over the one mount the
  audit reports as expected. Both now come from `nomount posture`, which runs the
  audit's own three mount checks.
- **The ghost path populator split rule paths on spaces.** A target containing
  one was torn in half: the fragment was submitted as a rule and accepted, the
  remainder dropped, and the boot log still reported the cloak fully populated
  while that path's existence oracles stayed open.
- **Every WebUI refresh ran a full `doctor` to read two booleans.** That resolves
  the whole mount plan, decodes the KSU allowlist and forks up to sixteen
  children to sample the ghost table — then threw the result away and left the
  Health card blank until the user pressed a button that ran it again. One run
  now paints both.
- The ghost rejection message named `GH_MAX_RULES=256`; the kernel has held 512
  since the table was resized. It no longer names a number the kernel owns.

### WebUI

- **Diagnostics is no longer a tab.** The bottom nav is four places you *do*
  something — Status, Modules, Rules, Tools. A fifth tab told every user there
  was a fifth job here, and the alert dot on it actively pulled people toward the
  one screen whose purpose is to enumerate what might be wrong.

  In its place, **one line on the Status card**, fed by the audit the boot pass
  already cached, so it costs nothing to show:

  - *Nothing detectable · checked 3h ago* — green, and that is the end of it
  - *2 things need attention ›* — the only state that asks for anything
  - *1 check couldn't run* — amber, honest, not alarming
  - *Nothing open · 1 accepted by you* — grey, because something IS still failing

  The `not_applicable` count never appears there. Tapping the line opens the
  findings list, with a way back; nothing else links to it.
- **Snapshot, Verify and Export moved behind a "Developer tools" disclosure.**
  Snapshot means nothing until you already suspect drift, Verify is meaningless
  without one, and Export produces a folder for someone else to read. Sitting
  them beside Self-check implied four equal choices. **Self-check** stays in the
  open, because "does a normal app see what root sees" is a real question with a
  yes/no answer.
- **The plan check leads with errors and warnings**; the eleven informational
  lines a healthy device produces sit behind *Full report*. Previously a real
  error rendered identically to a note about zygote FD allowlisting.
- **A tripped bootloop guard now raises a global banner** rather than a dot on a
  tab that no longer exists. A Suite that disabled itself is worth interrupting
  any screen for.
- **Check my setup** runs the audit, the plan check and the runtime check and
  gives one verdict. Every individual button is unchanged.
- **Red is reserved for a Suite that is not running.** A detection finding — even
  an open one — is amber: the setup is up and serving your modules either way.
  Red is spent only on engine-down and a tripped bootloop guard, which are
  categorically worse and must not read like everything else. The three amber
  findings (`detectable`, `reboot to finish`, `not verified`) are told apart by
  label and by group rather than by hue.
- **A dead engine is now a finding.** With the engine down `live_targets()` is
  empty, so every target-dependent check correctly reported n/a and the mount
  checks correctly passed — nothing *is* mounted — and the summary read
  `4 passed, 0 failed`. Every statement true, the conclusion false: the Status
  line rendered a green "Nothing detectable" beside the hero's own red "Engine
  offline". Liveness is a check now, ranked ahead of everything, and it carries
  its own reachability class (`not a detection`) because nobody detects you by it.
- **Checks no longer pass over a partial sample.** `readdir cookie magic` and
  `erofs directory shape` each skipped an unreadable input and then passed over
  whatever was left — a run where most parents failed to open still printed a
  clean verdict. Both now count what they could not read and report
  `unmeasured`. A *hit* still fails regardless of coverage; only a clean result
  needs full coverage. (`kernel surfaces` was fixed this way long ago; the fix
  was never carried to its siblings.)
- **A manual audit persists.** The button ran `audit --json` with no `--write`,
  so a verdict lived only in the page: close the WebUI, reopen it, and the
  Status line fell back to "Not checked yet" until the next boot.
- **Copy report** puts device, ROM, kernel, engine and Suite versions and every
  non-clean finding on the clipboard in one press.
- **Kernel features** says whether each cloak is active, idle or absent. These go
  inert rather than half-applying when the kernel cannot support them, which was
  previously announced only in `boot.log` and `/dev/kmsg`.
- **What this can and can't hide** states up front what a VFS engine is and is not
  responsible for, so verified-boot state and build keys stop reading as Suite
  failures — and links to the switch that does normalise them.

### Fixed (second pass)

- `nomount export` built `NM_REDACT_HIDE_LIST=1 '<self_exe>' doctor` and handed
  it to `sh -c`, with the path single-quoted but **not escaped** — while two
  other call sites in the same crate escape correctly. The shell was only ever
  there to set one environment variable; `Command::env` does that with no shell,
  so there is nothing left to quote.
- `nomount accept` validated its `--reason` *after* fingerprinting the finding,
  which means running the whole audit — forking a probe child and reading
  `/proc/<pid>/maps` for every process on the device — to then reject input it
  had at the start. The rules moved to `accept::validate` and are checked first.

### Build

- The shell lint gate moved from `-S error` to `-S warning -e SC3043`. The four
  suppressions this needed each carry their reason at the site.

## v1.3.48 – v1.3.65

These shipped without notes. Rather than reconstruct eighteen entries after the
fact, here is the part that actually affects whether a build works for you:

- **Engine floor rose to v26** over this range, for the existence cloak
  (`_ghost`) and the `nm k g` control plane it is driven through. The injection
  engine itself still works from v16 — on an older kernel the cloak goes inert
  and nothing else changes.
- **The existence cloak went live**, and is populated at boot from the live rule
  set. It closes seven "resolve a path, then act" oracles that could tell a
  hidden file from a missing one.
- **The state directory's SELinux label was repaired.** An earlier build
  relabelled `/data/adb/nomount` to a type every app domain can read, leaving
  `/data/adb` refusing traversal as the only thing between an app and the hide
  list. Reinstalling fixes it.
- **The early absorb pass moved to post-mount**, and `my_*` binds are absorbed
  before zygote.

Per-commit detail is in `git log v1.3.47..v1.3.65`.

## v1.3.47

Pairs with a kernel built from `kbuild@hookless` at 27f8d95 or later. Nothing here
requires a new engine version — v16 is still the floor, same as v1.3.46.

### Fixed
- **The audit probe kept root's supplementary groups.** `nomount audit` forks a
  child, drops to a hidden app's uid and asks whether it can still open the ROM
  APKs a `--public` rule serves. It called `setgid`/`setuid` but never
  `setgroups`, so the child carried root's group memberships into the test: on a
  target whose group bits grant more than its other bits, the probe reported the
  file readable where the real app is denied — a PASS on a check that should have
  failed. Groups are cleared first, while still privileged.
- The WebUI built two shell commands with a value interpolated outside `shq()`:
  the `nm` client path (derived from `ro.product.cpu.abi`) and the config key in
  `setConf`. Neither is reachable today — every caller passes a literal — but both
  were the only interpolations on those lines that could break out of their
  quoting.

## v1.3.46

Requires a kernel with **Prism engine v16**. On an older engine the maps/fd cloak
goes inert (the presence probe fails and no rules are applied) — the injection
engine itself is unaffected. Flash the kernel and the module as a set.

### Fixed
- **Per-UID hiding leaked through the xattr path.** An app on the hide list got
  `ENOENT` from `stat()`, `open()`, `access()` and `readdir()` for an injected
  file — and a valid answer from `listxattr()`/`getxattr()`, handing back the
  injected file's SELinux label at a path `stat()` said did not exist. Measured
  on OP15 as 10/10 reproducible once any unblocked process had warmed the shared
  dentry; now 0/10, with an unblocked reader unaffected.

  `fs/xattr.c::xattr_permission()` returns early for `security.*` without calling
  `inode_permission()`, so the engine's existing `-ENOENT` guard was never
  consulted on that path. The guard is now in the xattr ops themselves, and a
  hidden reader of a *shadowing* rule is served the stock file — the same answer
  `open()` already gave it. Reach was an added rule whose parent is a real
  directory; rules under a synthesized parent were never exposed.

- **The maps/fd cloak announced itself.** `pathhide` created `/proc/pathhide`
  unconditionally, and `proc:dir read` is granted to `untrusted_app`,
  `app_zygote` and `priv_app` — so any app could find the node with one readdir
  of `/proc`. A stock kernel has no such entry, which made it a louder tell than
  the package names it was concealing. The node is gone; configuration rides
  nomount's netlink channel (`nm k p`, `nm l p`), which is CAP_NET_ADMIN-gated
  and creates no dirent. Reading the live list back also works reliably now, so
  applying rules no longer risks clearing another module's.

- **`nm` dispatched on the first character of the command.** `nm check`,
  `nm count` and `nm config` all executed `clear`, which drops every rule *and*
  the blocked-UID set, exiting 0. Commands are matched as whole words.

- `nm l j` emitted paths into JSON unescaped, so a filename containing `"` or
  `\` produced a document the Suite's own reload reader could not parse.
- `--public` (exemption from per-UID hiding) was granted to any `.apk` under a
  ROM partition. It is justified only by the PackageManager already advertising
  the path, so it is now limited to the directories PM actually scans — an APK in
  e.g. `/product/etc` stays hidden.
- `nm v` walked netlink attributes using the reply's own length field without
  bounding it by the bytes actually read.
- `spoof.log` and `pathhide.conf` were `0644` inside a `0700` directory whose
  every other file is `0600`.
- Blocking an appid in the isolated-process pools reported `-EEXIST` against an
  empty table and silently did not add it.

### Changed
- `pathhide` no longer disables interrupts around its rule scan — nothing takes
  that lock from interrupt context, and the scan runs once per VMA on
  `/proc/<pid>/maps`.
- Removing a pathhide rule that does not exist now reports `-ENOENT` instead of
  success.

## v1.3.17

### Fixed
- **`doctor` told KernelSU Next users to delete a working module**
  ([KsuNext_NMS#13](https://github.com/Bouteillepleine/OnePlus-KsuNext_NMS/issues/13)).
  SUSFS presence was a boolean, and "the manager could not answer" collapsed into
  "the kernel has no SUSFS". KernelSU Next's ksud has no `susfs` subcommand at all,
  so on a kernel that *did* have SUSFS the check reported it missing and advised
  removing the module. It is three states now — Present, Absent, Unknown — and the
  removal advice needs a real answer. When nobody can tell us, the finding states
  the condition instead of asserting it.

  The Suite does not use SUSFS and deliberately knows nothing about its internals —
  no prctl magic, no command constants to keep in step with its releases. The one
  honest source is whether the manager's own CLI answers, so that is all we ask.

## v1.3.16

### Fixed
- **Rules that hide nothing were counted as hidden apps.** A glob with no installed
  match, and a package that is not installed, both sat in the "Hidden apps" list and
  in the card's count — so the count claimed more was in force than actually was.
  They now appear under **Waiting**, with a line explaining that a glob keeps
  watching, and only entries actually in force are counted.
- The isolated-process control wrapped 3 + 1 on a phone. It is a grid now: four
  across when they fit, an even 2x2 when they do not.

## v1.3.15

Candidate scan replaces the blunt preset. Adding a whole inventory put dozens of
entries for apps that are not installed in front of the handful that are — on the
test device, 41 of 48 entries were dead. The scan proposes only what is here, and
says why, in the same shape as the Cloak picker.

### Added
- **`uidscan.sh` + a Scan button.** Finds installed third-party apps worth hiding
  from and labels each: `detector` (matches the known-detector inventory, globs
  included), `queries-root` (the manifest names a root manager in `<queries>` — it is
  looking for us), `su-perm` (requests `ACCESS_SUPERUSER`). Nothing is hidden until
  picked. Detectors and root-lookers are pre-picked; `su-perm` is not, because those
  are usually your own root tools and hiding shows them the stock tree instead of
  your module content. `QUERY_ALL_PACKAGES` is an annotation only, never a reason on
  its own — ~50 of 64 apps request it, so a list led by it is noise, not a shortlist.
  The inventory comes from `nomount uid preset --dry-run`, so the package list still
  has exactly one home and the globs work verbatim as shell `case` patterns.
- **`nomount uid preset --globs`** and an "Add detector globs" button: the five glob
  rules on their own. They are the part a scan cannot give you — they keep matching
  a detector installed tomorrow, or repackaged under a new name.

### Fixed
- **The scanner could silently check nothing.** `$INV` must word-split, so it cannot
  be quoted — but its entries are globs, and without `set -f` the shell pathname-
  expands them against the caller's cwd first. A file named `x.duckdetector` in that
  directory replaced the rule `*.duckdetector` with that filename and the rule
  stopped matching, in a scan that otherwise looked like it ran fine. Verified on
  device by seeding a cwd with trap files.
- **Globs could not be typed or removed in the WebUI.** `UID_TARGET_RE` rejected
  `*`, so the Hide field refused a glob and the ✕ on a glob row reported "characters
  nomount won't take". Widened — and every target is now single-quoted where it is
  interpolated into a shell command, because an unquoted `*` would have been expanded
  by the shell before nomount ever saw it.
- **Whiteout paths reached the shell unquoted.** `whiteout add` rejected `;|&$` but
  not `*` or `?`, and `whiteout remove`/the suggestion buttons validated nothing at
  all before interpolating. All three now share one validator and are quoted.
- A scan that found nothing, or a list emptied by applying, rendered an empty box.
- Candidates already in the hide list were offered again, pre-picked.

## v1.3.14

Hide-list globs, a curated detector preset, and the per-UID card rebuilt so it is
readable on a phone.

### Added
- **Globs in the hide list.** `*.duckdetector`, `me.garfieldhan.*` and `*chunqiu*`
  are now valid entries, re-matched on every apply — so a detector that reinstalls
  under a new package name stays hidden, and one installed later is covered without
  being added by hand. Anchors are allowed at the ends only and a glob must carry at
  least four literal characters, so a typo cannot hide injections from the whole
  device. `uid list` prints each matched package with the glob that caught it, and
  removing the glob un-hides them.
- **`nomount uid preset detectors`** — 43 known detectors plus the five globs above,
  in one command, with `--dry-run` to see it first. Also a one-tap button in the
  WebUI. The inventory is adapted from Hide My Applist (HMA-OSS, AGPL-3.0); none of
  its code is used, only the package list.

### Fixed
- **The isolated-process control could lie about the kernel's state.** It only
  adopted the engine's answer when a regex matched, so if the engine did not answer
  at all — old kernel, no netlink — the control went on displaying "Hide from all
  (default)" whatever the kernel was actually doing. It now shows the state as
  unknown instead, and the failure path waits for the re-read before re-enabling.
- **A bad `packages.list` read could have un-hidden every hidden app.** The map
  answers "not installed" identically whether an app is gone or the file could not
  be read, and the new reconcile pass treats "not wanted" as "stop hiding". One
  unreadable pass would therefore have un-hidden everything and wiped the resolved
  mirror. Un-hiding is now gated on having actually read the map, and an empty parse
  counts as unread.
- **A glob can no longer reach a platform UID.** Unlike an exact entry it is
  evaluated on every pass, so it could start matching a package sharing
  `android.uid.system` (appid 1000) long after being added, with no chance for the
  `--force` prompt. Those matches are skipped and named on stderr.
- `metamount.sh` claimed in its header that it hides RRO mounts via SUSFS. It does
  not — the Suite makes no SUSFS call at all; RRO goes through the hookless engine
  and leaves no mount to hide. The only `ksu_susfs` reference is the guard against
  another module's action button clobbering ksud.

### Changed
- **Per-UID hiding card rebuilt.** The isolated-process `<select>` is now a
  segmented control: the native picker was drawn by the OS, ignored the theme
  entirely and covered the card behind it. One tap instead of two. The two long
  explanations fold away, which is most of the card's height back.
- The apply pass reads `packages.list` once instead of once per entry, and writes
  the hide list and the resolved mirror once instead of once per entry — a
  ~50-entry preset was doing ~50 rewrites of each in the boot path.

## v1.3.13

Audit pass over per-UID hiding, kernel to WebUI. Everything below is that audit's
findings, fixed. The kernel half lives in `kbuild@hookless`.

### Fixed
- **A hidden app could still see the shape of what was hidden.** `getattr` on an
  injected directory was the one major kernel entry point with no per-UID gate, so
  a hidden app got the *corrected* link count and erofs directory size while its
  own `readdir` and `lookup` returned the stock set. `stat()` and `readdir()`
  disagreed by exactly the number of hidden entries — for the one caller most
  likely to be measuring. The correction is skipped for a hidden reader now, and
  the link-count delta only counts children that reader can actually see.
- **A hidden app could read through its own SDK-runtime sandbox process.** Matching
  is on the appid, and a sandbox process runs at `appid + 10000` — outside the list.
  Unlike an isolated pool uid, that one names its owner exactly, so it is followed
  back to the app instead of being left uncovered.
- **"Re-apply" silently unhid every app.** `nm clear` drops the kernel's hidden-UID
  set along with the rules, and the mount pass clears before it rebuilds — so the
  WebUI's Re-apply button (and `vfs clear`) left every app on the list visible for
  the rest of the session, with nothing to put it back. Both paths re-assert the
  list now.
- **The hide list and the module-skip list were the same file.**
  `/data/adb/nomount/blocklist` was read as *module ids to skip injecting* and
  written as *apps to hide*. Hiding an app inserted it into the module-skip set, and
  every module-skip entry appeared in the WebUI as a hidden app with a ✕ that
  deleted it — one click from injecting a self-mounting module. Hiding moved to
  `/data/adb/nomount/uidhide`; an existing file is split on first read, with entries
  that name an installed module left where they were.
- **Apps were unhidden for the first ~10–20 s of every boot.** The list was applied
  only after `sys.boot_completed` plus a sleep, long after injections went live — a
  detector with a `BOOT_COMPLETED` receiver had a clean window. Each resolve is now
  mirrored to `uidhide.cache`, and the mount pass re-hides from it at post-fs-data,
  before any app starts. The later pass stays authoritative: it re-resolves against
  `packages.list`, refreshes the mirror, and retires an appid an entry no longer
  maps to (appids are reused after an uninstall).
- **An entry for a not-yet-installed app stayed inert until the next reboot.**
  `uidwatch.sh` re-applies the list on install/uninstall/update, via `inotifyd` on
  the package map.
- **`uid apply` could not fail.** Kernel errors were discarded and the pass reported
  "applied N" regardless, so an engine that hid nothing looked identical to a clean
  run — on the one path whose job is to be trustworthy. It counts and reports
  failures now, exits non-zero, and `service.sh` logs the failure loudly.
- **Blocking a platform uid was one keystroke away.** `1000` hides injections from
  system_server (RRO and framework patches revert to stock), `2000` breaks the
  health canary permanently (it probes as shell), `0` hides them from root. Appids
  below 10000 are refused without `--force`, and the canary reports
  `unchecked:probe-uid-hidden` instead of a standing inconsistency warning.
- **`blocked=0` when the engine could not be asked.** `nm l u` fails loudly on
  EPERM / engine-down, but the health fingerprint still reported zero hidden apps —
  a working feature with an empty list. It says `unknown` now, and `uid list` says
  "engine unreachable".
- **WebUI input and output handling.** The hide field's deny-list let glob
  characters through to an unquoted shell word; it is an allow-list now. List rows
  are escaped and their buttons carry data attributes instead of generated inline
  handlers.
- **A `--uid`-scoped rule missed the app's clones,** comparing a raw UID where the
  hide list compares appids.

- **`export` published the live hidden set.** The hide list is deliberately kept
  off shared storage — it names the apps you are hiding from — but `uid_live.txt`,
  the kernel's live hidden set, was written unconditionally, and the WebUI exports
  to `/sdcard/Download` by default. It obeys the same rule now, along with
  `uidhide` and its resolved-appid cache.

### Added
- **`nomount uid isolated <both|appzygote|platform|off>`** (WebUI: Per-UID hiding ›
  Isolated processes). An isolated process gets a pool UID that says nothing about
  which app spawned it, so hiding from a listed app can only mean hiding from every
  isolated process. That closes the hole where a hidden app farms its probing out to
  an isolated helper — but while it is on, an app that *is not* hidden can spot the
  injection by diffing its own view against its own isolated child's. The default is
  unchanged (both pools); the trade is now a deliberate, documented setting rather
  than a hardcoded range.
- **`nomount uid apply --early`** — resolve from the cached mirror, for the
  post-fs-data pass.
- **`nm k i <0..3>`** — the isolated-pool knob on the existing knob transport.

### Changed
- README's feature list, command table and kernel section still described the
  superseded hooked engine (`/dev/nomount`, SUSFS `sus_path`, a per-UID hash table);
  the WebUI note claimed hiding covered `su` (it is sucompat — untouched) and *not*
  isolated processes (the opposite of what the kernel does). Both corrected.
- `kernel_patches/` is marked superseded: those patches are the ioctl engine, which
  no current client can drive.
- Shipped scripts and assets are pinned to LF via `.gitattributes` — a Windows clone
  would otherwise check `module/*.sh` out with CRLF, and a local `package.sh` run
  would zip them that way.

## v1.3.6

### Fixed
- **A single Reload deleted every durable whiteout and every absorbed rule.** The reconcile drops any live rule the module plan does not name, and neither of those is nameable from a plan: a `nomount whiteout add` target is a *stock* path with no module and no backing file, and an absorbed rule comes from another module's bind whose source can sit anywhere inside that module, including paths the plan walk never visits. So tapping Reload in the WebUI silently stopped every manual hide and reverted every absorbed file to the stock one underneath, while `whiteout list` still reported them as applied and nothing came back until a reboot. Both lists are now protected from the prune, absorb records what it serves in `absorbed.list`, and a durable whiteout the engine is not serving is re-applied — so Reload converges on the saved state instead of merely not destroying it.
- **Every module-mount counter was a constant zero.** The card, the per-module badges, the WebUI module rows and the `mounts=` field of the health fingerprint all counted mounts by grepping `/proc/self/mountinfo` for `/data/adb/modules`, which never matches: field 4 is the mount's root *within its own filesystem*, so a bind out of a module reads `/adb/modules/<id>/…` because `/data` is its own filesystem. Every readout therefore claimed a clean posture on a device with real module mounts — verified live, one LSPosed `dex2oat` bind reported as zero everywhere. All four now match on the root field, and the Rust side resolves sources the way `absorb` already did.
- **The posture shield said "fully mountless — zero mounts" while another module was mounting.** It only ever counted `nomount_*` devices, which the mountless engine does not create, so the verdict could not be anything but clean. It now counts module-backed mounts and says which they are — that mount is as readable to an app as one of ours would be, and claiming zero over the top of it was the one false reassurance this card exists to prevent.
- **`ro.boot.vbmeta.size` was never set.** `compute_vbmeta_digest` recorded the chain length in a variable, but every caller runs it inside `$(...)`, so the value was gone before it could be read — which also meant the size cache it fell back to was never written, leaving the property permanently unset with `vbmeta_size=auto`. The length is written to the cache from inside the function now, and measured on demand when the digest itself was not recomputed. Verified on OP15: computes 19776, which is exactly what the bootloader reports.
- **`/data/local/tmp` read as permanently dirty.** `stat -c %C` answers correctly from a root shell but returns the bare letter `C` in the post-fs-data and ksud service contexts this actually runs in, so the label never compared equal: `chcon` was re-run on every boot, a change that had not happened was logged each time, and the status the UI reads never left "dirty". The reading is taken only when it looks like a context, with `ls -Zd` as a fallback, and "could not read" is no longer treated as "wrong".
- **Durable whiteouts did not apply until well after boot.** They were only re-applied from `service.sh`, which waits for `sys.boot_completed` and then a further 10s settle — so a path hidden precisely because it is a tell was plainly visible for the whole of boot. They now run in the mount pass, alongside the injections; `service.sh` still re-applies, which is idempotent.
- **`whiteout list` reported a path as hidden when nothing was hiding it.** State was inferred from whether the path exists, so an entry for a path this ROM does not ship read as `hidden` — indistinguishable from working. It now asks the engine which targets it is actually serving and distinguishes applied, saved-but-not-applied, and saved-with-no-such-path.
- **Packaging silently shipped a stale `nm`.** `nm` is freestanding C that only CI ever compiled; a local `package.sh --build` fell back to a gitignored prebuilt with nothing in the output saying so, so any change to `userspace/src/nm.c` was quietly left out of the zip. It is built from source when zig is present, and a prebuilt older than its source is now a hard error instead of a silent substitution.
- **`nm` reported success for work it had not done.** Arguments past the 64th were dropped silently, so a long batch `add` applied part of its list and still exited 0; `nm add` and `nm w` with no operands also exited 0. Both fail now.
- Live-rule parsing in `doctor` did not strip the ` [UID: N]` suffix, so every metadata check on a per-UID rule silently no-opped, and split on the first ` -> ` rather than the last. `measurable_hole` forked `nm v` once per whiteout and re-read `whiteouts.txt` each time; both are cached now, which matters most for a debloat module, which is entirely whiteouts.

### Added
- **Hidden paths card in the WebUI, with a real scan.** `nomount whiteout add/remove/list/suggest` had existed for a while with no way to reach it short of a root shell. The card lists each hidden path with its true state, adds and removes them, and **Scan** now walks the ROM (depth 2, so `/system/app/<Dir>/Superuser.apk` is reachable) for files only a root setup leaves behind, listing each hit with its reason and its own Hide button. `suggest` was previously three hardcoded path existence tests, none of which exist on a modern device. Matching is anchored rather than substring, because a substring sweep for `ksu`/`adbd` on OP15 returns `cksum` and `debuggerd` — proposing a hide for a stock coreutil is worse than proposing nothing. Candidates are filtered against what the engine is already serving (a walk of `/system/bin` meets module content, and hiding that hides the module), against paths no ordinary app can even see (`/system/bin/su` on a sucompat kernel is present for a granted uid and ENOENT for every app, so it is not a tell), and against paths that only stat and never open. Nothing is ever applied automatically.
- **Foreign mounts card in the WebUI.** Scan and absorb from the UI, with the survey's own wording about what was left mounted on purpose and why — previously visible only by reading `nomount doctor` output.
- **A spinner on every control that shells out.** A Cloak scan unzips every third-party manifest, absorb walks mountinfo and unmounts, `doctor` resolves the whole plan — with only a disabled button and a changed label there was no sign anything was still running. All 17 such controls now show the same spinning ring and restore their own label.

### Fixed (WebUI, found in the pre-release re-audit)
- `--dim` was referenced by seven CSS rules and defined by none, so each resolved to an invalid value: the app-picker's UID column, the section headings and the empty states all rendered at full `--txt` brightness instead of muted, and `.blk .dot` lost its background entirely — the status dot next to a hidden app was invisible in the `live` and `not installed` states, which is most of them. `--dim` is defined for both themes and those two states get their own colour.
- The Hidden-paths rows built their handlers as `onclick="woAddPath(${JSON.stringify(path)},this)"`. `JSON.stringify` emits double quotes, which closed the double-quoted attribute at the first character of the path, so **both the Hide and the Remove buttons were completely inert**. They take the path from a `data-` attribute now, like the Cloak rows already did, and `esc()` escapes quotes so every other `title="…"` is safe too.

### Changed
- **`nomount export` no longer writes the block list to shared storage.** The default destination is `/sdcard/Download`, readable by any app holding a storage permission, and the block list names the apps you are hiding *from*. It and `spoof.conf` are omitted there and the omission is stated; pass a private path to include them.
- The bind lock file is created 0600 rather than inheriting the boot umask, and `nm`'s doc comment no longer describes the generic-netlink control plane it stopped using.

## v1.3.0

### Fixed
- **Injecting over a live mount stranded it in `mountinfo` permanently.** Adding a rule `d_drop`s the cached dentry for that name, and a mount hangs off a specific `(vfsmount, dentry)` pair — so serving a path that already had a mount detached that mount from path resolution, after which `umount2` fails with EINVAL even with `MNT_DETACH` and the entry is stuck until reboot. `absorb` runs after boot and cannot undo it, so any module whose own script mounted earlier than the mount pass left a permanent entry behind — exactly the surface the zero-mount posture exists to remove. Reported in the field: a bootanimation module binding at post-fs-data, injected over by the mount pass, two unremovable mounts that `absorb` then correctly refused to touch. The mount pass and `reload` now read `mountinfo` and unmount a target before serving it; if the unmount fails they leave it alone rather than stranding it.

## v1.2.9

### Changed
- **A mount left standing on purpose is now info, not a warning.** LSPosed's `dex2oat` bind was reported as a warning on every health check, but absorb is never going to take it — the framework rule declines it by design — so there was nothing to act on and the card sat permanently at "1 warning". `doctor` now separates the two cases: a mount declined by the hook-framework rule or by the skip list is `[info] module mount left by design` and stays out of the warning count, while a mount that *nothing* declined is still a warning, because that one means absorb did not run or failed.
- **The rules breakdown bar now reads as the same material as the capsules.** It was a flat strip sitting next to domed pills. It gets the capsule's gloss and inset highlight/shade, applied as an overlay because the colour segments are children that fill the bar — an inset shadow on the bar itself is painted underneath them and never shows. One gloss spans the whole bar so it domes as a single capsule rather than looking like separate beads, and the light-theme gloss is softened from the capsule's value, which is tuned for a near-white chip and goes chalky over saturated colours.

## v1.2.8

### Added
- **`/data/local/tmp` is restored to the owner, mode and SELinux context AOSP ships.** Every device has it `0771 shell:shell u:object_r:shell_data_file:s0`; `ksud` stages files there and commonly leaves it `0777` and/or `root:root`, so the drift is caused by having a root manager rather than by anything the Suite hides — which makes it a zero-false-positive probe for a detector that can stat the path without root, and one no amount of mount-hiding can answer. Each field is corrected only when it already differs, so a clean device is a no-op, and the pass runs at post-fs-data and again after boot completes because `ksud` and `adbd` keep staging files there for the whole of boot. Config key `fix_shell_tmp` (default on); `spoof.sh shell-tmp-status` reports the current state and the real inode.

## v1.2.7

### Changed
- **Absorb now leaves every hook framework alone, by what it ships rather than by its name.** A module is treated as a framework if it carries `zygisk/<abi>.so` (any Zygisk module — LSPosed and all its forks, PlayIntegrityFix, HMA, zygisk-detach) or `bin/zygisk*` (the providers — Zygisk Next, ReZygisk, NeoZygisk), and then *nothing* it mounts is absorbed. This replaces guesswork with a structural fact: an id list misses renamed forks and a path list only covers the paths someone enumerated, while both markers are part of how these modules are built. `zygisksu` is also seeded into the skip file, and absorb and `doctor` now say which module the framework rule matched.

## v1.2.6

### Changed
- **Module whiteouts are held to the same rule as manual ones.** v1.2.5 guarded `whiteout add`, but the mount pass called the engine directly, so a module's `.replace` marker or Magisk char-device marker could still hide an entry on a non-overlay path and leave the directory reporting a size and link count that count it. Those are now declined with the reason printed, `doctor` reports them at plan time rather than after a reboot, and the override is the durable list: `nomount whiteout add <path> --force` marks the decision and the mount pass then honours it. Whiteouts under an overlayfs mount are unaffected.

## v1.2.5

### Changed
- **`whiteout add` now refuses a target that is not on overlayfs.** Hiding an entry is only unmeasurable where the directory's own metadata does not describe its contents. On the ROM's erofs partitions it does, exactly — `st_size == 12*entries + name bytes` and `st_nlink == 2 + subdirs`, which held with zero deviation across every stock directory checked on OP15. Removing an entry from the listing without changing either is something no real filesystem does, and one `stat` plus one `getdents64` finds it with no knowledge of the stock ROM. Overlayfs merged directories report neither relationship, so a whiteout there carries no evidence. `--force` overrides. `whiteout suggest` no longer proposes targets that would be refused, `whiteout apply` warns at boot for entries already on the list, and `doctor` reports them.

## v1.2.4

### Fixed
- **Absorb and `doctor` named a skip file that may not exist.** With no skip file present the built-in hook-path list is used, but both still reported "listed in /data/adb/nomount/absorb-skip.txt" and told you to remove an entry from it — sending you to edit a file that is not there. `skip_list()` now returns its source, absorb names it, and `doctor` says the built-in list is in use and how to override it.

## v1.2.3

### Fixed
- **The hook-path skip missed half of Vector's dex2oat paths.** ART lived in `/apex/com.android.runtime` before moving to `/apex/com.android.art`, and frameworks still hook whichever exists — JingMatrix's Vector targets eight paths spread across both. Keying only on `com.android.art` covered its four `art` variants by prefix and silently missed all four `com.android.runtime` ones, so those binds would have been absorbed. Both apex names are now covered, plus the pre-apex `/system/bin/dex2oat`. A test asserts the exact eight paths Vector hooks.

## v1.2.2

### Fixed
- **The absorb opt-out no longer depends on knowing a fork's module id.** The seeded skip list named specific ids (`zygisk_lsposed`, …), and matching is on `/modules/<id>/` — so a hook framework installed under any other id (`zygisk_lsposed_next`, a renamed fork, a new one) was not matched and its bind was absorbed. It now keys on the **path being hooked** (`/apex/com.android.art/bin/dex2oat`, `/system/bin/app_process`), which is identical across forks. Module ids still work for anything else.
- **A missing skip file no longer fails open.** `skip_list()` returned an empty list when the file could not be read, so deleting or losing it silently absorbed *everything*, hook frameworks included. It now falls back to the built-in hook paths, so the protection survives losing the file.

## v1.2.1

### Changed
- **`absorb-skip` is now `absorb-skip.txt`.** It is a hand-edited list — `doctor` tells you to edit it by name — and an extensionless file makes an Android file manager ask which app to open it with. Now matches its peer `whiteouts.txt`. An existing `absorb-skip` is *copied* to the new name on install — deliberately not moved, since the outgoing binary stays live until the next reboot and reads the old name, so a rename would silently drop its opt-outs in that window. The new binary prefers `.txt` and falls back to the old name, so both work.

## v1.2.0

Audit fix pass (14 findings) plus two new capabilities: absorbing other modules' mounts, and durable whiteouts.

### Added
- **`nomount absorb` — take over bind mounts other modules made.** A third-party module can still run its own `mount --bind` from a boot script, and every such mount is visible in `/proc/*/mountinfo` to any app, defeating the mountless posture no matter how mountless the Suite itself is. Absorb re-serves each module-backed mount as a hookless injection and drops the mount. Only possible *because* injection is mountless — no overlay- or bind-based metamodule can absorb a mount, since it would have to create one. Runs from `service.sh` after module scripts have settled. Verified on-device against LSPosed's `dex2oat` bind: the mount disappeared and `dex2oat64` picked up its stock apex `dev`/`ino` in place of `/data`'s.
  - Unmounts **before** injecting. Injecting first `d_drop`s the cached dentry, and a mount hangs off a specific `(vfsmount, dentry)` pair — dropping it detaches the mount from path resolution, so `umount2()` then returns `EINVAL` and the entry is stranded in mountinfo until reboot while content silently reverts to the file underneath.
  - Directory binds are **opt-in** (`--include-dirs`): injection snapshots the listing, so files the owning module adds later would never appear.
  - Opt-out list at `/data/adb/nomount/absorb-skip` (module id or target prefix). **Hook frameworks are skipped by default** — their bind comes from native daemon code that differs between forks, and the failure mode is silent and delayed (dex2oat runs during dexopt on app install, not at boot). `doctor` reports whatever stays mounted, so the trade is visible rather than silent.
- **`nomount whiteout` — durable whiteouts.** Whiteouts live in kernel memory and were lost on every reboot. A persisted list at `/data/adb/nomount/whiteouts.txt` is re-applied at boot. `add`/`remove`/`list`/`apply`/`suggest`; validation refuses partition roots (masking a whole partition is the same `forkSystemServer` abort an injection on a root causes), relative paths and `/data`. `suggest` inspects *this* device and only proposes genuinely openable files — a path that stats but cannot be opened is fabricated at the syscall layer (KSU sucompat's `su` does exactly this), and hiding it would be useless at best.

### Changed
- **`/my_*` content is always served.** The `self_binds_my` heuristic — which grepped a module's boot scripts and silently dropped its *entire* `/my_*` content if they "looked like" they mounted it — is gone. With hookless `/my_*` nothing bind-mounts, so the duplicate-mount hazard it guarded is gone; if a module does bind its own path, that real mount takes precedence over the injection anyway. Coverage no longer depends on a text match over shell source.
- **`doctor` gained an informational level.** The zygote FD-allowlist note fired once per injected file — 85 identical warnings on a configuration that boots fine, burying anything real. Now one counted line per partition, at `[info]`, excluded from the warning count. Overlay APKs on such a partition still error per-file, which is the case that actually aborts `forkSystemServer`.

### Fixed
- **Boot-time root code execution via the state directory.** `/data/adb/nomount` was created under the boot umask (`0777`) at all five `mkdir` sites, and `spoof.sh` **sourced** `spoof.conf` out of it as root at post-fs-data. Anything able to write there got arbitrary root code execution. The directory is now `0700` everywhere, and the config is *parsed* (known keys only, values never evaluated) instead of sourced.
- **World-writable `/dev` lock that could wedge the mount pass.** The single-run guard was a `noclobber` file in `/dev` — `0666`, named after the project, and "held" by mere existence, so anything able to create that path pre-empted the whole mount pass. Now a real `flock` in the `0700` state directory.
- **Bind-list locking silently degraded to no locking.** `Lock::acquire()` returned `Option` and every call site bound it to `_lock` and continued, so a failed open or `flock` meant no serialization at all — the exact concurrent mount/reload corruption of `binds.list` the lock exists to prevent. It now returns `Result` and propagates.
- **Module files were permanently relabelled.** A bind copied the target's SELinux label onto the module's source file and never restored it — not on teardown, not on umount, and not when the `mount` that followed failed. The original label is now recorded in `binds.list` and restored on all three paths.
- **The bootloop guard disarmed itself on a hanging boot.** The counter was cleared even when the `sys.boot_completed` wait *timed out*, so a boot that never finished re-armed the guard instead of counting toward `GUARD_MAX` — precisely the boots it exists to catch.
- **`chattr -i` on ksud is restored.** The susfs-action guard cleared the immutable flag to copy the binary and left it off permanently.
- **Per-UID rules are removable.** `parse_live_rules` stripped the ` [UID: N]` suffix, so a per-UID rule and a global one for the same target shared a key and `nm del` (always uid 0) could never remove the per-UID one — it re-counted as a failure on every reload, forever. Live rules are now keyed on `(target, uid)`.
- **Appid vs uid comparison.** The kernel stores and returns the appid (`uid % 100000`), so a raw-uid comparison missed for any work-profile or clone uid and reported "not blocked" for one that is.
- **`nm` client hardening.** `get_attr()` now bounds the attribute payload before returning a pointer (a truncated attribute yielded one running past the message, which `print_str` then walked to a NUL); numeric arguments are validated instead of silently computing garbage from non-digits; the version printer handles any width rather than exactly two digits.
- **Dump errors no longer read as success.** `nm list` conflated `NLMSG_ERROR` with `NLMSG_DONE` and exited 0, so a dump that aborted mid-stream handed `reload` a silently truncated list which it acted on as the whole live set.
- **`versionCode` no longer regresses on an auto-bump.** `package.sh` derived it by stripping dots (`1.2.0` → `120`), below the `10102` already shipped for v1.1.2 — a manager reads that as a downgrade. Now `major*10000 + minor*100 + patch`.
- **CI least privilege.** The build and package jobs inherited the repository default token scope; the workflow now pins `permissions: contents: read`.

### Note
This release pairs with the hookless kernel engine at `kbuild@hookless` ≥ `a12e0d0`, which moves the boot-identity knobs off `/sys/kernel/*` onto the netlink control plane. `spoof.sh` probes both layouts, so kernel and module can be flashed out of step.

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

## v2.1.0 — superseded engine (historical)

> **These notes describe the ORIGINAL `/dev/nomount` char-device engine and are
> kept as a record, not as current behaviour.** Nothing below is true of the
> Prism engine this Suite drives today: there is no `/dev/nomount` node, the
> control plane is netlink, RRO overlays are injected hooklessly with **no
> `overlayfs` and no tmpfs**, and SUSFS is optional and unused. The version
> number also predates the 1.3.x line it sits below.

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
