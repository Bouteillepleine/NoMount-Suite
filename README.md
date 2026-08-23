# 🫥 NoMount

> **WARNING:** NoMount operates directly at the kernel VFS layer and is intended for research and development. It's in beta — the full chain is tested end-to-end on a OnePlus 15 (Android 16, 6.12, SukiSU-Ultra), but edge cases are expected across other devices, ROMs, and kernels. Proceed with caution, and [open an issue](https://github.com/Bouteillepleine/nomount2.0/issues) if something breaks.

**NoMount** is a kernel-based file injection and path-redirection framework for Android, packaged as a **KernelSU / SukiSU metamodule**. It loads your root modules **without touching the mount table** — and, where a module genuinely needs a real mount (RRO theming overlays), it uses a hidden `overlayfs` so those work too.

Unlike traditional root solutions that rely on `mount --bind` (which pollutes `/proc/mounts`, changes mount namespaces, and is easily detected), NoMount's primary engine operates **purely at the VFS (Virtual File System) layer**. It manipulates path resolution and directory iteration directly inside the kernel, making injections effective yet virtually invisible to userspace detection.

## Why NoMount?

Traditional methods (such as Magic Mount) modify the mount table. Detectors and banking apps scan `/proc/self/mountinfo` to find these anomalies.

**NoMount changes the paradigm:**

1. **No mounts (for direct-path files):** no `mount()` syscalls for regular module files — the mount table stays 100% stock.
2. **Visual injection:** advanced `iterate_dir` hooking makes "new" files appear in read-only directories (like `/vendor`) without physically touching the partition.
3. **File redirection:** any path passing through `getname_hook` is intercepted, so any file can be redirected from anywhere.
4. **Native permission delegation:** it redirects the underlying inode without permission hooks, inherently bypassing restrictions while keeping **SELinux** perfectly intact.

## Hybrid: real overlays where the kernel demands them

Pure VFS redirection can't satisfy Android's **RRO overlay** pipeline — `OverlayManager` + `idmap2` need the overlay APKs on a **real filesystem mount**, or they sit in `STATE_NO_IDMAP` and never enable (theming silently breaks). So for module `*/overlay/*.apk` directories, NoMount mounts a real `overlayfs` — staged on `tmpfs`, because `/data` (f2fs with `casefold`) is rejected by overlayfs as a lowerdir — and then **hides that mount** with KernelSU's native per-app umount.

The result: a theming module (e.g. OxygenCustomizer) idmaps and applies correctly, while a plain APK/lib/priv-app module leaves no mount trace at all. Each module is served by whichever mechanism fits, automatically.

## Metamodule

NoMount is a metamodule: at boot it scans `/data/adb/modules/`, classifies every file, serves direct-path files via the VFS driver and RRO overlays via `overlayfs`, then enables the engine — no per-module setup. Only **one** metamodule can be active at a time, so NoMount refuses to install alongside another.

## Key Features

* **Transparent path redirection** — intercepts a target VFS path (e.g. `/system/app/YouTube/YouTube.apk`) and redirects it to a modified file in another partition (e.g. `/data`). The userspace process is unaware.
* **VFS directory injection** — injects new file/directory entries into read-only system paths; via `iterate_dir` hooks they appear natively in `readdir`, `ls`, and Java `File.list()`.
* **Security-context correct** — `inode_permission` / `generic_permission` handling keeps injected files traversable and readable with correct system-partition attributes, SELinux intact.
* **Per-UID hiding** — named apps are shown the 100% stock filesystem: no injected files, no whiteouts, stock directory metadata. Matching is on the *appid*, so one entry covers the app in every user, work profile and clone, and follows it into its SDK-runtime sandbox. The list (`/data/adb/nomount/uidhide`) is applied by the mount pass at post-fs-data and re-resolved once boot completes. Isolated processes carry a pool UID that names no owner, so they are hidden as a group — `nomount uid isolated` sets which pools, and the note there explains the trade.

  One class of injection is deliberately **not** hidden: a ROM APK. The PackageManager scans `/system/app`, `/product/overlay` and friends as `system_server`, which is never on the hide list, so it registers an injected APK and then names that path to every app that asks about the package. Hiding the file would leave a hidden app holding a path the system says exists and `open()` answers `ENOENT` for — a louder inconsistency than the injection, and a real crash: IBM Trusteer (La Banque Postale) walks the package list at startup and `SIGSEGV`s on the resulting `IOException`. So those rules are served with `--public` and stay readable; the kernel strips the flag from any rule that turns out to *replace* a stock APK, where the hidden app is served the stock bytes instead. Needs engine **v15+** — `nomount doctor` says so when the running one is older, and `nomount audit` measures it by dropping to a hidden appid and opening every ROM APK rule.
* **Real overlayfs for RRO** — hidden overlay mounts so `idmap2`/theming works.
* **Detection hiding (own footprint)** — the Prism engine has no `/dev/nomount` and no mounts of its own to hide: the control plane is a private netlink protocol behind `CAP_NET_ADMIN`, and injected inodes carry the stock `st_dev`, SELinux context and directory metadata.
* **Self-mounting module skip list** — modules that mount themselves are skipped (built-in list + `/data/adb/nomount/blocklist`, one module id per line). Distinct from the per-app hide list above, which lives in `uidhide`.
* **Bootloop guard** — a boot counter self-disables NoMount after repeated failed boots and re-arms once the system boots healthy.
* **Manager tags** — each module's description in the root manager is tagged with how it's served (`vfs` / `overlay` / `vfs + overlay`).
* **Install integrity** — a bundled `sha256` manifest is verified at install; a corrupt or tampered zip aborts.

## Kernel Integration

The Suite drives the **Prism** engine — a per-inode ops hijack with a private
netlink control plane, built from
[`Bouteillepleine/kbuild@hookless`](https://github.com/Bouteillepleine/kbuild/tree/hookless).
That is what the kernel builders apply and what the bundled `nm` client speaks to.
Enable with `CONFIG_NOMOUNT=y`.

> **`kernel_patches/` is the superseded engine.** Those patches implement the
> original `/dev/nomount` char device with `fs/namei.c` hooks and an ioctl control
> plane (`NOMOUNT_IOC_*`). Nothing in this repo can drive them any more: `nm` and
> `src/nm.rs` speak netlink only, so a kernel built from them answers no CLI
> command — per-UID hiding included. Kept for reference; see
> [`kernel_patches/README.md`](kernel_patches/README.md).

## Usage (Userspace)

The subsystem is controlled via the `nomount` binary, which drives the engine
through the bundled freestanding `nm` netlink client.

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **Metamodule pass** | `nomount mount` | Scan modules → inject direct-path files → overlay RRO dirs → enable. |
| **Add Rule** | `nomount vfs add <virtual> <real>` | Inject `real` file at `virtual` path. |
| **Delete Rule** | `nomount vfs del <virtual>` | Remove a specific injection rule. |
| **List Rules** | `nomount vfs list` | Show currently active rules. |
| **Clear All** | `nomount vfs clear` | Flush all rules immediately. |
| **Engine** | `nomount vfs enable\|disable\|refresh` | Toggle the engine / refresh the dcache. |
| **Status** | `nomount vfs query-status` | Driver version, engine state, rule count. |
| **Hide from app** | `nomount uid block <pkg\|uid>` | Show that app the stock filesystem. Persists; `--force` for platform uids. |
| **Hide list** | `nomount uid list` | Saved entries cross-referenced against the kernel's live set. |
| **Re-apply** | `nomount uid apply [--early]` | Re-assert the list (the mount pass clears the kernel's set). |
| **Isolated pools** | `nomount uid isolated <mode>` | `both` (default) \| `appzygote` \| `platform` \| `off`. |
| **Unblock UID** | `nomount uid unblock <uid>` | Restore injection visibility for a UID. |
| **Version** | `nomount version` | Show the subsystem version. |

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

## WebUI

A self-contained dashboard (root manager → NoMount → ⚙️): engine status (driver version, rule count) with an enable toggle, **Remount** / **Refresh**, bootloop-guard status + re-arm, the **Modules** list with per-module mechanism tags, an **Active rules** viewer, an **Overlay mounts** list, and **UID exclusions**.

## Requirements

- Rooted device with **KernelSU** or **SukiSU** (metamodule support required).
- A kernel built with the **NoMount patch** (`CONFIG_NOMOUNT=y`) — see [`kernel_patches/`](kernel_patches/).
- SUSFS is **optional**; if your kernel has it, use the `susfs/` patch variant so NoMount and SUSFS coexist.

## Compatibility

| Android | Kernel | Root | Status |
| :--- | :--- | :--- | :--- |
| 16 | 6.12 | SukiSU-Ultra | ✅ Tested end-to-end (VFS + overlay + hiding) on OnePlus 15 |
| 12–15 | 5.10 / 5.15 / 6.1 / 6.6 | KernelSU / SukiSU | 🧩 Patches provided, not device-tested |

APatch metamodule hooks exist but are unverified. Tested another combo? Open an issue.

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
