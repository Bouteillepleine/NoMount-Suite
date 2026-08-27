# 🫥 NoMount

> **WARNING:** NoMount operates directly at the kernel VFS layer and is intended for research and development. It's in beta — the full chain is tested end-to-end on a OnePlus 15 (Android 16, 6.12, SukiSU-Ultra), but edge cases are expected across other devices, ROMs, and kernels. Proceed with caution, and [open an issue](https://github.com/Bouteillepleine/nomount/issues) if something breaks.

**NoMount** is a kernel-based file injection and path-redirection framework for Android, packaged as a **KernelSU / SukiSU / APatch metamodule**, with a Magisk
`post-fs-data` path for managers that have no metamodule support. It loads your root modules **without touching the mount table** — every kind of module content, RRO theming overlays included. There is no `overlayfs`, no `tmpfs` and no bind: the mount table stays 100% stock.

Unlike traditional root solutions that rely on `mount --bind` (which pollutes `/proc/mounts`, changes mount namespaces, and is easily detected), NoMount's primary engine operates **purely at the VFS (Virtual File System) layer**. It manipulates path resolution and directory iteration directly inside the kernel, making injections effective yet virtually invisible to userspace detection.

## Why NoMount?

Traditional methods (such as Magic Mount) modify the mount table. Detectors and banking apps scan `/proc/self/mountinfo` to find these anomalies.

**NoMount changes the paradigm:**

1. **No mounts. At all.** No `mount()` syscall is made for any module content — the mount table stays 100% stock, and `su` comes from the kernel's `sucompat`, which is mountless too.
2. **Visual injection:** advanced `iterate_dir` hooking makes "new" files appear in read-only directories (like `/vendor`) without physically touching the partition.
3. **File redirection:** any path passing through `getname_hook` is intercepted, so any file can be redirected from anywhere.
4. **Native permission delegation:** it redirects the underlying inode without permission hooks, inherently bypassing restrictions while keeping **SELinux** perfectly intact.

## RRO overlays, without an overlay mount

Android's **RRO overlay** pipeline once looked like the one thing pure VFS
redirection could not serve: `OverlayManager` + `idmap2` were understood to need
the overlay APKs on a real filesystem mount, or they sit in `STATE_NO_IDMAP` and
never enable. Earlier builds of this project therefore mounted a real `overlayfs`
on `tmpfs` and hid it with the manager's per-app umount.

That is no longer how it works, and the mount is gone. A module's
`**/overlay/*.apk` files are **not** special-cased: they are hookless-injected
into `/product/overlay` (or wherever they belong) like any other file, and
OverlayManagerService picks them up during the `system_server` package scan —
which runs *after* the metamodule's post-fs-data pass. Theming modules idmap and
apply correctly with **zero mounts**, so there is nothing to hide and no reason
to enable a per-app umount for it. Leave the manager's "umount modules" switches
**off**; they hide nothing here.

## Metamodule

NoMount is a metamodule: at boot it scans `/data/adb/modules/`, classifies every
file, and serves all of it through hookless VFS injection — then enables the
engine, with no per-module setup. Only **one** metamodule can be active at a
time, so NoMount refuses to install alongside another.

## Key Features

* **Transparent path redirection** — intercepts a target VFS path (e.g. `/system/app/YouTube/YouTube.apk`) and redirects it to a modified file in another partition (e.g. `/data`). The userspace process is unaware.
* **VFS directory injection** — injects new file/directory entries into read-only system paths; via `iterate_dir` hooks they appear natively in `readdir`, `ls`, and Java `File.list()`.
* **Security-context correct** — `inode_permission` / `generic_permission` handling keeps injected files traversable and readable with correct system-partition attributes, SELinux intact.
* **Per-UID hiding** — named apps are shown the 100% stock filesystem: no injected files, no whiteouts, stock directory metadata. Matching is on the *appid*, so one entry covers the app in every user, work profile and clone, and follows it into its SDK-runtime sandbox. The list (`/data/adb/nomount/uidhide`) is applied by the mount pass at post-fs-data and re-resolved once boot completes. Isolated processes carry a pool UID that names no owner, so they are hidden as a group — `nomount uid isolated` sets which pools, and the note there explains the trade.

  One class of injection is deliberately **not** hidden: a ROM APK. The PackageManager scans `/system/app`, `/product/overlay` and friends as `system_server`, which is never on the hide list, so it registers an injected APK and then names that path to every app that asks about the package. Hiding the file would leave a hidden app holding a path the system says exists and `open()` answers `ENOENT` for — a louder inconsistency than the injection, and a real crash: IBM Trusteer (La Banque Postale) walks the package list at startup and `SIGSEGV`s on the resulting `IOException`. So those rules are served with `--public` and stay readable; the kernel strips the flag from any rule that turns out to *replace* a stock APK, where the hidden app is served the stock bytes instead. Needs engine **v15+** — `nomount check --plan` says so when the running one is older, and `nomount check --device` measures it by dropping to a hidden appid and opening every ROM APK rule.
* **RRO overlays, mountlessly** — overlay APKs are injected into the ROM's overlay directories and idmapped by `system_server` on its normal scan. No `overlayfs`, no staging `tmpfs`, no per-app umount.
* **Detection hiding (own footprint)** — the Prism engine has no `/dev/nomount` and no mounts of its own to hide: the control plane is a private netlink protocol behind `CAP_NET_ADMIN`, and injected inodes carry the stock `st_dev`, SELinux context and directory metadata.
* **Self-mounting module skip list** — modules that mount themselves are skipped (built-in list + `/data/adb/nomount/blocklist`, one module id per line). Distinct from the per-app hide list above, which lives in `uidhide`.
* **Bootloop guard** — a boot counter self-disables NoMount after repeated failed boots and re-arms once the system boots healthy.
* **Manager tags** — each module's description in the root manager is tagged with what it ships (`vfs` / `overlay` / `vfs + overlay`) and how many rules it actually got. `overlay` names the module's RRO APKs, not a mount.
* **Install integrity** — a bundled `sha256` manifest is verified at install; a corrupt or tampered zip aborts.

## Kernel Integration

The Suite drives the **Prism** engine — a per-inode ops hijack with a private
netlink control plane, built from
[`Bouteillepleine/kbuild@hookless`](https://github.com/Bouteillepleine/kbuild/tree/hookless).
That is what the kernel builders apply and what the bundled `nm` client speaks to.
Enable with `CONFIG_NOMOUNT=y`.

> The original `/dev/nomount` char device — `fs/namei.c` hooks and an ioctl
> control plane (`NOMOUNT_IOC_*`) — is gone. Nothing in this repo could drive it
> any more: `nm` and `src/nm.rs` speak netlink only, so a kernel built that way
> answered no CLI command, per-UID hiding included. Its patch set used to sit in
> `kernel_patches/`; that directory has been removed.

## Usage (Userspace)

The subsystem is controlled via the `nomount` binary, which drives the engine
through the bundled freestanding `nm` netlink client. This is the full command
set; `nomount help` and `nomount <command> --help` are the authority.

### Metamodule pass

| Command | Description |
| :--- | :--- |
| `nomount mount` | The boot pass: classify every enabled module and route it into Prism injections. Run by `metamount.sh`/`post-fs-data.sh`; you rarely run it by hand. |
| `nomount reload` | Gap-free hot load/unload — reconcile live rules to the current module set, applying only the delta (no clear). Run this after installing or removing a module instead of rebooting. |
| `nomount absorb [--dry-run] [--include-dirs] [--early]` | Take over bind mounts **other** modules made: re-serve each as a Prism injection, then unmount it. Restores the zero-mount posture even for a module that knows nothing about NoMount. Runs on its own every boot: an `--early` pre-zygote pass (post-mount on KSU/APatch, post-fs-data on Magisk) and a full pass once boot completes, plus again whenever a package changes. `--early` is the only mode allowed to take over a bind whose target is on a `my_*` partition — re-asserting a `my_*` rule on a live system has rebooted a device. `--include-dirs` is off by default because injection snapshots a directory listing, so files the owning module adds later would never appear. |

### Rules

| Command | Description |
| :--- | :--- |
| `nomount vfs add <virtual> <real>` | Inject `real` at `virtual`. |
| `nomount vfs del <virtual>` | Remove one rule. |
| `nomount vfs whiteout <path>` | Make `path` appear absent (this rule only, not the durable list). |
| `nomount vfs list` | Show the live rules. |
| `nomount vfs clear` | Flush every rule immediately. |

### Durable whiteouts

Hide a stock ROM file that is itself a tell. Unlike `vfs whiteout`, this list
survives reboots and is re-applied by the boot pass.

| Command | Description |
| :--- | :--- |
| `nomount whiteout add <path> [--force]` | Hide it now and on every boot. `--force` overrides the refusal on a filesystem where the resulting hole is measurable. |
| `nomount whiteout remove <path>` | Stop hiding it. |
| `nomount whiteout list` | The list, and whether each entry is currently applied. |
| `nomount whiteout apply` | Re-apply the whole list. |
| `nomount whiteout suggest` | Propose paths that exist on **this** device and are worth hiding. |

### Per-app hiding

| Command | Description |
| :--- | :--- |
| `nomount uid block <pkg\|uid\|glob> [--force]` | Show that app the stock filesystem. A package name is durable across reinstalls; a glob (`*.duckdetector`, `me.garfieldhan.*`) re-matches every apply, so it covers apps installed later too. `--force` is needed for a platform appid (< 10000) — hiding from those hides injections from Android itself. |
| `nomount uid unblock <pkg\|uid>` | Re-show injections, and drop the entry from the persistent list. |
| `nomount uid list` | The persistent list with each entry's resolved UID and state. |
| `nomount uid apply [--early]` | Re-assert the list to the kernel (the mount pass clears the kernel's set). `--early` resolves from the cached appid mirror, for post-fs-data before `packages.list` is meaningful. |
| `nomount uid preset [name] [--dry-run] [--globs]` | Add a curated preset. `detectors` covers the known root/environment detectors; no argument lists what is available. |
| `nomount uid isolated [mode]` | Which isolated-process pools hiding covers: `both` (default) \| `appzygote` \| `platform` \| `off`. No argument shows the current setting. |

### Diagnostics

| Command | Description |
| :--- | :--- |
| `nomount check [--plan] [--device] [--json] [--write]` | **The** diagnostic. One report, one shape, two sections: `--plan` is the static half (does the module set resolve into a bad rule?), cheap and safe at post-fs-data; `--device` is the measured half (is what we serve detectable, and is it being served?). Neither flag runs both. Exits 1 when a check has FAILED or needs a reboot. `--write` caches the report to `audit.json` and the fingerprint to `health.txt`, which is what the WebUI and the module card read. |
| `nomount plan` | Print what the mount pass would resolve to — target, kind, source, module — without applying anything. Read-only, and the only way to see a staged module's plan before it is ever served. |
| `nomount snapshot` | Freeze the current fingerprint as the baseline for `verify`. |
| `nomount verify` | Diff the live fingerprint against that baseline and name what drifted. |
| `nomount export [dir]` | Dump diagnostics to a timestamped folder (default `/sdcard/Download`). |
| `nomount version` | Print the version. |

Verdicts are `FAIL`, `REBOOT`, `UNMEASURED`, `WARN`, `PASS`, `N/A` and `NOTE`.
`UNMEASURED` and `N/A` are deliberately different: "nothing here to test" is not
a warning, "something stopped me testing" is, and neither is ever a pass.

`check` replaced `doctor`, `audit`, `posture` and `selfcheck`; those four verbs
are gone. `plan` was cut with them and then restored — it had no caller inside
this repo, which is not the same as no caller, and the module test harness parses
it to lint a staged module before it is ever applied. See the changelog for the
mapping.

### Examples

**Inject a custom library** (the system thinks `libfoo.so` is in `/vendor`, but it loads from `/data`):

```bash
nomount vfs add /vendor/lib64/soundfx/libfoo.so /data/local/tmp/my_lib.so
```

**Replace a config file** system-wide:

```bash
nomount vfs add /vendor/etc/audio_effects.conf /data/adb/modules/my_mod/audio_effects.conf
```

**Hide the injections from a banking app** (it sees the stock system; a package name is used so the entry survives a reinstall, and it covers the app in a clone or work profile too):

```bash
nomount uid block com.bank.app
```

**Pick up a module you just installed, without rebooting:**

```bash
nomount reload
```

**Check the setup and get machine-readable output:**

```bash
nomount check            # both sections, human-readable
nomount check --plan     # static half only: cheap, reads no running process
nomount check --json     # what the WebUI reads
```

## WebUI

A self-contained dashboard (root manager → NoMount → ⚙️): engine status (driver version, rule count) with an enable toggle, **Remount** / **Refresh**, bootloop-guard status + re-arm, the **Modules** list with per-module tags, an **Active rules** viewer, the cached **`nomount check`** report as one findings list, and the **per-app hide list**. There is no overlay-mounts pane, because there are no overlay mounts.

## Requirements

- Rooted device on **arm64** — the zip ships an `arm64-v8a` binary only.
  **KernelSU**, **SukiSU** or **APatch** with metamodule support is the primary
  path; on **Magisk**, or a manager without metamodule support, `post-fs-data.sh`
  runs the same pass instead. If neither path runs, the module says so loudly in
  `boot.log` and on its card rather than doing nothing silently.
- A kernel built with the **Prism** engine (`CONFIG_NOMOUNT=y`), from
  [`Bouteillepleine/kbuild@hookless`](https://github.com/Bouteillepleine/kbuild/tree/hookless).
  That branch is what the kernel builders apply and what the bundled `nm` client
  speaks to.
- SUSFS is **optional**. The Suite does not use it — RRO goes through the same
  hookless injection as everything else, so there is nothing here for SUSFS to
  hide — but the two coexist.

## Compatibility

| Kernel | Device | Status |
| :--- | :--- | :--- |
| 6.12 | OnePlus 15 | ✅ Boots, check clean, 258/258 rules verified |
| 6.1 | OnePlus 13R | ✅ Boots, 261/261 rules verified |
| 5.15 | OnePlus 11 | ✅ Boots, check clean, 118/118 rules verified |
| 4.9 – 6.18 (others) | — | 🧩 Compiles; never booted |

Root managers: **KernelSU**, **SukiSU** and **APatch** via the metamodule hook;
**Magisk** via `post-fs-data.sh`. The three tested devices above ran ReSukiSU.
Tested another combo? Open an issue — `nomount export` produces a bundle with the
hide list already redacted, which is the most useful thing to attach.

## License

GPL-3.0. See [LICENSE](LICENSE).

## Special thanks

- **[HymoFS](https://github.com/Anatdx/HymoFS)** — inspiration for the VFS approach.
- **[A7mdwassa](https://github.com/A7mdwassa)** — tester and contributor.
- **[ZQZCC](https://github.com/ZQZCC)** — WebUI MD3-style design.
- **[backslashxx](https://github.com/backslashxx)** — code optimization.
- **[KernelSU](https://github.com/tiann/KernelSU)** & **SukiSU-Ultra** — root solution and metamodule framework.
- **[SUSFS](https://gitlab.com/simonpunk/susfs4ksu)** — the stealth layer NoMount coexists with.
- **All testers** — thanks for making this project more stable!

## Disclaimer

**NoMount** is a powerful kernel modification tool intended for research and development. Modifying kernel behavior carries inherent risks, including system instability or data loss. The developers are not responsible for bricked devices or thermonuclear war.
