# 🫥 NoMount Suite

Loads root modules without adding a mount for them, RRO theming overlays
included. No `overlayfs`, no `tmpfs`. The kernel redirects VFS lookups instead,
so nothing the engine injects shows up in `/proc/mounts`.

One exception, on OnePlus/Oppo. The `my_*` partitions get a real bind mount,
because a hookless injection there trips zygote's FD allowlist and bootloops the
phone. Those rows are visible to any app. `nomount check` counts them, the WebUI
names them, and the `my_hookless` trial drops them if you'll take the risk.

A metamodule: at boot it scans `/data/adb/modules/`, classifies every file and
programs the kernel engine over netlink. No per-module setup. Only one
metamodule can be active, so it won't install next to another.

> **This needs a custom kernel.** NoMount is two halves: the **Prism** kernel
> driver and this module. On a stock kernel the module installs and injects
> nothing. The installer tells you so.

> **Beta.** What moves it to stable is reports from outside the tested set: a
> different phone, a different root manager, a module that behaves oddly.
> `nomount export` makes the bundle for that, hide list already redacted.

<table>
  <tr>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/status.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/status.jpg" width="155" alt="Status"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/hiding.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/hiding.jpg" width="155" alt="Hiding"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/rules.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/rules.jpg" width="155" alt="Rules"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/diagnostics.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/diagnostics.jpg" width="155" alt="Checks"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/duckdetector.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/duckdetector.jpg" width="155" alt="Duck Detector"></a></td>
  </tr>
  <tr>
    <td align="center"><sub><b>Status</b></sub></td>
    <td align="center"><sub><b>Hiding</b></sub></td>
    <td align="center"><sub><b>Rules</b></sub></td>
    <td align="center"><sub><b>Checks</b></sub></td>
    <td align="center"><sub><b>Duck Detector</b></sub></td>
  </tr>
</table>

## Install

**1. Get a kernel with the Prism engine.**

| | |
| :--- | :--- |
| **OnePlus** | Prebuilt kernels from [`OnePlus-BakaSu_NMS`](https://github.com/Bouteillepleine/OnePlus-BakaSu_NMS/releases), [`OnePlus-KsuNext_NMS`](https://github.com/Bouteillepleine/OnePlus-KsuNext_NMS/releases) or [`OnePlus-SukiSu_NMS`](https://github.com/Bouteillepleine/OnePlus-SukiSu_NMS/releases). Pick the one matching your root manager. |
| **Anything else** | Build with `CONFIG_NOMOUNT=y`. The driver and its integration patch are in [`hookless/`](hookless/), nothing in them vendor- or SoC-specific. |
| **Can't rebuild?** | See [Out-of-tree variants](#out-of-tree-variants) (untested on hardware). |

`zcat /proc/config.gz | grep NOMOUNT` should print `CONFIG_NOMOUNT=y`. If it
errors, your kernel just doesn't publish its config. Flash the zip and read the
install screen, which probes the engine.

**2. Install the module.** Flash
[the latest release](https://github.com/Bouteillepleine/NoMount-Suite/releases/latest)
from your manager (*Modules → Install from storage*), or:

```sh
ksud module install /sdcard/Download/00_NoMount-Module-vX.Y.Z.zip
```

It verifies the zip against a bundled `sha256` manifest, refuses to sit beside
another metamodule, and probes the engine. From recovery it can't probe, and says
so.

**3. Reboot.** Content is served from the first boot pass onwards.

**4. Check it worked.** The WebUI opens on Status. `nomount` isn't on `PATH`, so
for a root shell:

```sh
alias nomount=/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount

nomount check      # verdict, and what was measured
nomount vfs list   # every rule the engine is serving
```

A clean result is `verdict: clean`, zero failures **and zero unmeasured**. An
unmeasured check isn't a pass.

Updating is the same flash. Hide list, whiteouts, absorbed rules and settings
survive it, and come back if an install aborts.

## If it doesn't boot

The Suite counts boots. Three that never reach `boot_completed` and it parks
itself: writes `/data/adb/nomount/disabled`, stops injecting, logs the incident
to `/data/adb/nomount/incident.log`. So the usual answer is **let it boot twice
more** — the third failure disarms it, the fourth comes up stock.

To disarm it yourself, from recovery or `adb` in recovery:

```sh
mkdir -p /data/adb/nomount && touch /data/adb/nomount/disabled
```

Everything stays installed and configured. Clear the marker in the WebUI when you
want it back. To remove the module instead:

```sh
touch /data/adb/modules/meta-nomount/remove
```

Your manager uninstalls it on the next boot. Neither route touches your hide
list, whiteouts or settings. If the phone won't boot far enough for either, flash
the kernel you were on before: without the Prism engine the Suite injects
nothing.

## Requirements

- **arm64**. The zip ships an `arm64-v8a` binary only.
- A kernel with the **Prism** engine (`CONFIG_NOMOUNT=y`), source in
  [`hookless/`](hookless/). Flash the engine and the Suite as a set. The Suite
  runs on an older engine and `nomount check` names what is missing; a wire
  protocol change just reads as "engine not responding".
- **KernelSU** or a fork of it (SukiSU, ReSukiSU, BakaSU) through the
  metamodule hook, or **Magisk** (`post-fs-data`). Everything here was measured
  on ReSukiSU. The Magisk and APatch paths run, but nobody has reported back, so
  treat them as unverified.
- SUSFS isn't needed; nothing the engine serves is a mount. The `my_*` binds are
  the exception, and SUSFS or your manager's "umount modules" switch hides them.

## Layout

Both halves live here, because a mismatched pair is the one failure neither half
can explain.

| Path | What it is |
| :--- | :--- |
| `src/` | The Rust metamodule and CLI (`nomount`): boot pass, reconcile, diagnostics. |
| `hookless/` | The **Prism** kernel engine: `src/nomount.c` and the integration patch. |
| `userspace/` | `nm`, the freestanding netlink client. No libc, ~4 KB. |
| `module/` | What ships in the zip: boot scripts, installer, WebUI. |
| `scripts/` | `package.sh`, which builds and assembles the zip. |

## Building

CI builds the zip on every push to `main` or `prerelease` and publishes it on a
`v*` tag, so you rarely need to. Locally:

```sh
cargo test && cargo clippy --all-targets -- -D warnings
ANDROID_NDK_HOME=/path/to/ndk scripts/package.sh --build --version vX.Y.Z
```

The NDK does the Rust cross-compile. `nm` is built from source too, by `zig cc`
if zig is on `PATH`, otherwise by the NDK's clang. With neither, `package.sh`
falls back to a prebuilt newer than `userspace/src/nm.[ch]`, or errors.

Pushes touching `hookless/` run the ten-version engine compile matrix.

## Commands

Use the alias from **Install** step 4. The WebUI covers the same ground without a
shell.

| Command | Description |
| :--- | :--- |
| `nomount check` | The diagnostic. `--plan` is static (does the module set resolve into a bad rule?), `--device` is measured (is what we serve detectable?). Neither flag runs both. Exits 1 on a `FAIL` or a `REBOOT`. |
| `nomount reload` | Reconcile live rules to the current module set, delta only. Use it after installing a module instead of rebooting. |
| `nomount vfs list` | Every live rule. `vfs add`, `del`, `whiteout` and `clear` edit them for this boot. |
| `nomount whiteout add <path>` | Hide a path now and on every boot. With `remove`, `list`, `apply` and `suggest`. |
| `nomount uid block <pkg\|uid\|glob>` | Hide everything the Suite serves from an app. Matches on appid, so clones and work profiles count. With `unblock`, `list`, `apply` and `isolated`. |
| `nomount uid preset [name]` | Add a curated preset; no argument lists them. `uid ksu on` follows KernelSU's DenyList instead. |
| `nomount absorb [--dry-run]` | Take over bind mounts other modules made: re-serve each as an injection, then unmount it. Runs every boot. |
| `nomount export [dir]` | Dump diagnostics to a folder; the hide list is redacted on shared storage. |
| `nomount unbind` | Unmount the real `my_*` binds recorded in `binds.list`. |

`mount`, `ghost sync`, `plan`, `snapshot`, `verify` and `version` are run by the
boot scripts or there for debugging. `nomount --help` documents every flag.

Three files under `/data/adb/nomount/` are hand-edited, one entry per line.
`blocklist` parks a module without uninstalling it. `absorb-skip.txt` is mounts
`absorb` must leave alone. `public.txt` is ROM paths that stay visible to every
uid, hidden app or not.

The boot pass works most of `public.txt` out by itself: denying an app a path the
PackageManager already advertised is an inconsistency no stock device produces. A
library mapped into an app is the same case, but it lives under `lib64/`, where no
structural rule reaches it. List it and the rule is served `(public)`, which keeps
`ghost sync` off it.

## Compatibility

The engine builds on all ten kernel versions from 4.9 to 6.18. None of it is
OnePlus-specific: ordinary VFS code, no vendor hooks, no SoC assumptions. The
table names OnePlus devices because those are the kernels anyone has booted. I
only own a OnePlus 15, so every other row came from testers.

| Kernel | Tested on | Status |
| :--- | :--- | :--- |
| 6.12 | **OnePlus 15** | ✅ Booted |
| 6.1 | **OnePlus 13R** | ✅ Booted |
| 5.15 | **OnePlus 11** | ✅ Booted |
| 6.6 | **OnePlus 13 / 13T**, Ace 5 Pro, ... (18 models) | ✅ Booted |
| 5.10 | Ace 2, Ace 2V, Nord 3, ... (6 models) | ✅ Booted |
| 4.9 · 4.14 · 4.19 · 5.4 · 6.18 | no OnePlus ships these; other vendors do | Compiled, not tested |

"Compiled" means `fs/nomount.o` built against that version's canonical tree by the
[compile matrix](.github/workflows/hookless-compile-matrix.yml). It says nothing
about whether a phone boots, so a report either way is worth an issue, as is one
about another device or root manager. Attach what **Checks → Developer tools →
Export** writes; the hide list in it is already redacted.

## Out-of-tree variants

The supported build is in-tree. Two other ways to load the same engine live on
their own branches, for when you can't rebuild: [`KPM`](../../tree/KPM)
(KernelPatch/APatch, 5.10 to 6.6) and [`LKM`](../../tree/LKM) (4.9 to 6.18, and it
shows up in `/proc/modules`). Each pins its own revision of
`hookless/src/nomount.c` and they do fall behind, so check `NOMOUNT_VERSION`
first.

Neither has been loaded on a phone. They compile, and that is all CI proves. Read
the branch README, which leads with what it costs.

## License and credits

GPL-3.0, see [LICENSE](LICENSE). A modified derivative of
**[maxsteeel/nomount](https://github.com/maxsteeel/nomount)**, under the same
licence. The Suite and the Prism engine are a rewrite: the `/dev/nomount` char
device and its ioctl control plane are gone, replaced by a per-inode ops hijack
over netlink, and RRO overlays are injected hooklessly.

- **[maxsteeel/nomount](https://github.com/maxsteeel/nomount)** — the original this is built on.
- **[HymoFS](https://github.com/Anatdx/HymoFS)** — inspiration for the VFS approach.
- **[A7mdwassa](https://github.com/A7mdwassa)** — tester and contributor.
- **[ZQZCC](https://github.com/ZQZCC)** — WebUI MD3-style design.
- **[backslashxx](https://github.com/backslashxx)** — code optimization.
- **[KernelSU](https://github.com/tiann/KernelSU)** & **SukiSU-Ultra** — root solution and metamodule framework.
- **[SUSFS](https://gitlab.com/simonpunk/susfs4ksu)** — the stealth layer.
- All testers: thanks for making this thing more stable.

## Disclaimer

A kernel modification tool, for research and development. Modifying kernel
behaviour carries real risk, including instability and data loss. I'm not
responsible for bricked devices.
