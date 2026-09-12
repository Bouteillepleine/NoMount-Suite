# 🫥 NoMount Suite

Loads root modules **without touching the mount table** - RRO theming overlays
included. No `overlayfs`, no `tmpfs`: files are served by redirecting VFS lookups
in the kernel, so `/proc/mounts` shows the stock set and there is no mount gap
for a scanner to find.

It is a metamodule: at boot it scans `/data/adb/modules/`, classifies every file
and programs the kernel engine over netlink. No per-module setup. Only one
metamodule can be active, so it refuses to install alongside another.

> **This needs a custom kernel.** NoMount is two halves: the **Prism** kernel
> driver and this module. On a stock kernel the module installs, reports, and
> injects not one file - the installer says so rather than reporting success.

One exception to zero mounts: OnePlus/Oppo `my_*` partitions are served by a real
bind mount, because a hookless injection there trips zygote's FD allowlist and
bootloops the device. Those binds are visible to any app. `nomount check` counts
them and the WebUI names them; the `my_hookless` trial removes them at the risk
the bootloop guard exists to catch.

<table>
  <tr>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/status.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/status.jpg" width="155" alt="Status"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/modules.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/modules.jpg" width="155" alt="Modules"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/rules.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/rules.jpg" width="155" alt="Rules"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/check.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/check.jpg" width="155" alt="Check"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/duckdetector.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/duckdetector.jpg" width="155" alt="Duck Detector"></a></td>
  </tr>
  <tr>
    <td align="center"><sub><b>Status</b><br>zero mounts, live counts</sub></td>
    <td align="center"><sub><b>Modules</b><br>what is served, and how</sub></td>
    <td align="center"><sub><b>Rules</b><br>per-module rule breakdown</sub></td>
    <td align="center"><sub><b>Check</b><br>one diagnostic, plain verdicts</sub></td>
    <td align="center"><sub><b>Duck Detector</b><br>0 danger, 0 warning</sub></td>
  </tr>
</table>

## Install

**1. Get a kernel with the Prism engine.**

| | |
| :--- | :--- |
| **OnePlus** | Prebuilt kernels from [`OnePlus-ReSukiSu_NMS`](https://github.com/Bouteillepleine/OnePlus-ReSukiSu_NMS/releases), [`OnePlus-KsuNext_NMS`](https://github.com/Bouteillepleine/OnePlus-KsuNext_NMS/releases) or [`OnePlus-SukiSu_NMS`](https://github.com/Bouteillepleine/OnePlus-SukiSu_NMS/releases) - pick the one matching the root manager you want. |
| **Anything else** | Build your own with `CONFIG_NOMOUNT=y`. The driver and its integration patch are in [`hookless/`](hookless/); nothing in them is vendor- or SoC-specific. |
| **Cannot rebuild?** | See [Out-of-tree variants](#out-of-tree-variants) - untested on hardware. |

Already on a NoMount kernel? `zcat /proc/config.gz | grep NOMOUNT` should print
`CONFIG_NOMOUNT=y`. If it errors instead, your kernel simply does not publish its
config - not the same as "not set". Flash the zip and read the install screen,
which probes the engine directly.

**2. Install the module.** Download
[the latest release](https://github.com/Bouteillepleine/NoMount-Suite/releases/latest)
and flash the zip from your manager (*Modules → Install from storage*), or:

```sh
ksud module install /sdcard/Download/00_NoMount-Module-vX.Y.Z.zip
```

The installer verifies the zip against a bundled `sha256` manifest, refuses to
sit alongside another metamodule, and probes the engine so you find out at
install time whether the kernel has it. From recovery that probe cannot answer,
which it also says.

**3. Reboot.** Module content is served from the first boot pass onwards.

**4. Check it worked.** The WebUI opens on Status. Same answers from a root shell
- but `nomount` is **not on `PATH`**: it ships inside the module, so set this up
once per shell first.

```sh
alias nomount=/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount

nomount check      # one diagnostic - verdict, and what was measured
nomount vfs list   # every rule the engine is serving
```

A clean result is `verdict: clean` with zero failures **and zero unmeasured** -
an unmeasured check is not a pass, and the report says so rather than rounding up.

Updating is the same flash: your hide list, whiteouts, absorbed rules and
settings are preserved across an update, and restored if an install aborts.

## Requirements

- **arm64** device; the zip ships an `arm64-v8a` binary only.
- A kernel with the **Prism** engine (`CONFIG_NOMOUNT=y`), source in
  [`hookless/`](hookless/). The engine and this Suite are versioned together
  because they have to be flashed together: the control plane is a private
  protocol between them, and a mismatched pair reads as "engine not responding"
  with nothing to say why.
- **KernelSU**, **SukiSU** or **ReSukiSU** (metamodule hook), or **Magisk**
  (`post-fs-data`). Everything here was measured on ReSukiSU; the Magisk and
  APatch code paths exist and run, but nobody has reported back from either, so
  treat them as unverified rather than supported.
- SUSFS is not needed for the ordinary case - nothing the engine serves is a
  mount. The `my_*` binds above are the exception: they are ordinary mounts, on
  by default, and SUSFS or your manager's "umount modules" switch can hide them.
  The two coexist fine.

## Repository layout

Both halves live here, because they are flashed as a pair and a mismatched pair
is the one failure neither half can explain.

| Path | What it is |
| :--- | :--- |
| `src/` | The Rust metamodule and CLI (`nomount`) - the boot pass, the reconcile, the diagnostics. |
| `hookless/` | The **Prism** kernel engine: `src/nomount.c` and the integration patch. |
| `userspace/` | `nm`, the freestanding netlink client the Suite shells out to. No libc; ~4 KB. |
| `module/` | What ships in the zip: boot scripts, the installer, and the WebUI. |
| `scripts/` | `package.sh`, which builds and assembles the zip. |

## Building

CI builds the zip on every code push and publishes it on a `v*` tag, so you
rarely need to. Locally:

```
cargo test && cargo clippy --all-targets -- -D warnings
ANDROID_NDK_HOME=/path/to/ndk scripts/package.sh --build --version vX.Y.Z
```

The Android NDK is required for the Rust cross-compile. `nm` is built from
source too - by `zig cc` if zig is on `PATH` (what CI uses), otherwise by the
NDK's own clang. If neither is available, `package.sh` falls back to a prebuilt,
but only one newer than `userspace/src/nm.[ch]`; otherwise it errors rather than
packaging a stale binary.

## Out-of-tree variants

The supported build is in-tree: `CONFIG_NOMOUNT=y`, compiled into the kernel.
Two other ways to load the same engine live on their own branches, for cases
where you cannot rebuild the kernel. Both `#include` `hookless/src/nomount.c`
rather than copying it, so neither can drift from what the Suite ships, and both
carry the `/proc/<pid>/maps` spoof (through kprobes in the LKM, KernelPatch hooks
in the KPM).

| | branch | `/proc/modules` | maps spoof | kernels |
| :--- | :--- | :--- | :--- | :--- |
| **in-tree** | `main` | absent | yes | 4.9 - 6.18 |
| **KPM** (KernelPatch/APatch) | [`KPM`](../../tree/KPM) | absent | yes | 6 KMIs, 5.10 - 6.6 |
| **LKM** (loadable module) | [`LKM`](../../tree/LKM) | **listed** | yes | 4.9 - 6.18 |

Neither has been loaded on a device. They compile, and CI proves that much and no
more - read each branch's `README.md`, which says what it costs before it says
anything else. The `LKM` branch's **Build** workflow produces the module zip with
one `nomount-<kmi>.ko` per GKI KMI generation plus a loader; note that a module
is portable across a *KMI generation*, not a kernel version, and vermagic must
still match at load, so check `modinfo nomount.ko` against `cat /proc/version`.

## Commands

Every command below is the module's own binary at
`/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount` - use the alias from
**Install** step 4, or type the full path. The WebUI covers the same ground with
no shell at all: status, modules, rules, per-app hiding, and the durable
hidden-paths list.

| Command | Description |
| :--- | :--- |
| `nomount mount` | The boot pass: classify enabled modules and route them into Prism injections. Run by the boot scripts. |
| `nomount reload` | Reconcile live rules to the current module set, delta only. Use after installing or removing a module instead of rebooting. |
| `nomount absorb [--dry-run] [--include-dirs] [--early]` | Take over bind mounts other modules made: re-serve each as an injection, then unmount it. Runs itself every boot. |
| `nomount vfs add <virtual> <real>` | Inject `real` at `virtual`. |
| `nomount vfs del <virtual>` | Remove one rule. |
| `nomount vfs whiteout <path>` | Make a path appear absent (this rule only). |
| `nomount vfs list` | Show live rules. |
| `nomount vfs clear` | Flush every rule. |
| `nomount whiteout add <path> [--force]` | Hide a path now and on every boot. `--force` only silences the "leaves a measurable hole" note; nothing is refused on that ground. |
| `nomount whiteout remove <path>` | Stop hiding it. |
| `nomount whiteout list` | The durable list, and whether each entry is applied. |
| `nomount whiteout apply` | Re-apply the whole list. |
| `nomount whiteout suggest` | Propose paths on this device worth hiding. |
| `nomount uid block <pkg\|uid\|glob> [--force]` | Hide everything the Suite serves from an app. Matches on appid, so it covers clones and work profiles. |
| `nomount uid unblock <pkg\|uid>` | Stop hiding from it. |
| `nomount uid list` | Who is hidden. |
| `nomount uid apply [--early]` | Re-apply the hide list. |
| `nomount uid preset [name] [--dry-run] [--globs]` | Add a curated preset; no argument lists what is available. |
| `nomount uid isolated [mode]` | Which isolated-process pools are hidden. |
| `nomount check [--plan] [--device] [--json] [--write]` | **The** diagnostic. `--plan` static (does the module set resolve into a bad rule?), `--device` measured (is what we serve detectable, and is it being served?); neither flag runs both. Verdicts are `FAIL`, `REBOOT`, `UNMEASURED`, `WARN`, `PASS`, `N/A`, `NOTE` - "nothing to test" and "something stopped me testing" are deliberately different, and neither is a pass. Exits 1 on a FAIL. |
| `nomount plan` | Print what the mount pass would resolve to, without applying it. Read-only. |
| `nomount snapshot` | Freeze the current fingerprint as a baseline. |
| `nomount verify` | Diff live against that baseline and name what drifted. |
| `nomount export [dir]` | Dump diagnostics to a folder; the hide list is redacted on shared storage. |
| `nomount version` | Print the version. |

Two files under `/data/adb/nomount/` are hand-edited rather than driven by a
command, one entry per line: `blocklist` (module ids the boot pass must not
inject - the way to park one misbehaving module without uninstalling it) and
`absorb-skip.txt` (mounts `absorb` must leave alone; the installer seeds it with
an explanation in its own header).

## Compatibility

The engine builds on all ten kernel versions - 4.9, 4.14, 4.19, 5.4, 5.10, 5.15,
6.1, 6.6, 6.12 and 6.18 - and none of it is OnePlus-specific: it is ordinary VFS
code, no vendor hooks, no SoC assumptions. The table names OnePlus devices only
because those are the kernels anyone has *built and booted*. What differs between
the rows is not whether the engine builds, but whether anyone has booted it on a
phone.

| Kernel | Tested on | Status |
| :--- | :--- | :--- |
| 6.12 | **OnePlus 15** | ✅ Booted |
| 6.1 | **OnePlus 13R** | ✅ Booted |
| 5.15 | **OnePlus 11** | ✅ Booted |
| 6.6 | **OnePlus 13 / 13T**, Ace 5 Pro, ... (18 models) | ✅ Booted |
| 5.10 | Ace 2, Ace 2V, Nord 3, ... (6 models) | 🧩 Compiled, not tested |
| 4.9 · 4.14 · 4.19 · 5.4 · 6.18 | no OnePlus ships these - other vendors do | 🧩 Compiled, not tested |

"Compiled" means `fs/nomount.o` built against that version's canonical tree; the
`LKM` branch's out-of-tree gate still covers the whole set. It says nothing about
whether the device boots. A report either way is worth an issue.

Tested another device or root manager? Open an issue - the WebUI's **Check →
Developer tools → Export** button (or `nomount export` from a shell) produces a
bundle with the hide list already redacted, which is the most useful thing to
attach. A report that one of the untested managers works is as useful as a bug.

## License and origin

GPL-3.0. See [LICENSE](LICENSE).

This is a modified derivative of
**[maxsteeel/nomount](https://github.com/maxsteeel/nomount)**, and remains under
its GPL-3.0 licence. The Suite and the Prism engine it drives are a rewrite: the
original `/dev/nomount` char device and its ioctl control plane are gone,
replaced by a per-inode ops hijack with a netlink control plane, and RRO overlays
are injected hooklessly rather than mounted.

## Special thanks

- **[maxsteeel/nomount](https://github.com/maxsteeel/nomount)** - the original this is built on.
- **[HymoFS](https://github.com/Anatdx/HymoFS)** - inspiration for the VFS approach.
- **[A7mdwassa](https://github.com/A7mdwassa)** - tester and contributor.
- **[ZQZCC](https://github.com/ZQZCC)** - WebUI MD3-style design.
- **[backslashxx](https://github.com/backslashxx)** - code optimization.
- **[KernelSU](https://github.com/tiann/KernelSU)** & **SukiSU-Ultra** - root solution and metamodule framework.
- **[SUSFS](https://gitlab.com/simonpunk/susfs4ksu)** - the stealth layer.
- **All testers** - thanks for making this project more stable!

## Disclaimer

A kernel modification tool for research and development. Modifying kernel
behaviour carries real risk, including instability and data loss. The developers
are not responsible for bricked devices or thermonuclear war.

---

> **Beta.** It works at the kernel VFS layer, and the whole point of this stage
> is getting it to stable. What moves it there is reports from setups outside
> the tested set - a different device, a different root manager, a module that
> behaves oddly.
