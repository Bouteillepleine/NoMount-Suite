# 🫥 NoMount Suite

> **Beta.** It works at the kernel VFS layer, and the whole point of this stage
> is getting it to stable. What moves it there is reports from setups outside
> the tested set — a different device, a different root manager, a module that
> behaves oddly. `nomount export` produces the bundle for that, hide list
> already redacted.

Loads root modules **without touching the mount table** — RRO theming overlays
included. No `overlayfs`, no `tmpfs`, no bind mounts: `/proc/mounts` stays 100%
stock, so there is no mount gap for a scanner to find.

It is a metamodule: at boot it scans `/data/adb/modules/`, classifies every file
and programs the kernel engine over netlink. No per-module setup. Only one
metamodule can be active, so it refuses to install alongside another.

<table>
  <tr>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/status.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/status.jpg" width="185" alt="Status"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/modules.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/modules.jpg" width="185" alt="Modules"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/rules.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/rules.jpg" width="185" alt="Rules"></a></td>
    <td align="center"><a href="https://github.com/Bouteillepleine/NoMount-Suite/blob/main/docs/screenshots/check.jpg"><img src="https://raw.githubusercontent.com/Bouteillepleine/NoMount-Suite/main/docs/screenshots/check.jpg" width="185" alt="Check"></a></td>
  </tr>
  <tr>
    <td align="center"><sub><b>Status</b><br>zero mounts, live counts</sub></td>
    <td align="center"><sub><b>Modules</b><br>what is served, and how</sub></td>
    <td align="center"><sub><b>Rules</b><br>per-module rule breakdown</sub></td>
    <td align="center"><sub><b>Check</b><br>one diagnostic, plain verdicts</sub></td>
  </tr>
</table>

## Requirements

- **arm64** device; the zip ships an `arm64-v8a` binary only.
- A kernel with the **Prism** engine (`CONFIG_NOMOUNT=y`). Its source lives in
  this repository under [`hookless/`](hookless/) — the driver, the integration
  patch, and a matrix that compile-tests it against every supported kernel
  version. The engine and this Suite are versioned together because they have to
  be flashed together: the control plane is a private protocol between them, and
  a mismatched pair reads as "engine not responding" with nothing to say why.
- **KernelSU**, **SukiSU** or **ReSukiSU** (metamodule hook), or **Magisk**
  (`post-fs-data`). If neither path runs, the module says so loudly rather than
  doing nothing silently.
  **Magisk and APatch are untested.** Both code paths exist and are exercised by
  the boot scripts, but nobody has reported back from either, so treat them as
  unverified rather than supported — everything below was measured on ReSukiSU.
- **SUSFS is not needed** — the Suite already does that job. Nothing here is a
  mount, so there is no mount for it to conceal and no gap for it to close. The
  two *might* coexist, but nobody has run them together, so treat that as
  untested rather than supported.

## Repository layout

Both halves of the system live here, because they are flashed as a pair and a
mismatched pair is the one failure neither half can explain (see Requirements).

| Path | What it is |
| :--- | :--- |
| `src/` | The Rust metamodule and CLI (`nomount`) — the boot pass, the reconcile, the diagnostics. |
| `hookless/` | The **Prism** kernel engine: `src/nomount.c`, the integration patch, and a matrix that compile-tests it against ten kernel versions. |
| `userspace/` | `nm`, the freestanding netlink client the Suite shells out to. No libc; ~4 KB. |
| `module/` | What ships in the zip: boot scripts, the installer, and the WebUI. |
| `scripts/` | `package.sh`, which builds and assembles the zip. |

## Building

The zip is built by CI on every push and published on a `v*` tag, so you rarely
need to. Locally:

```
cargo test && cargo clippy --all-targets -- -D warnings
ANDROID_NDK_HOME=/path/to/ndk scripts/package.sh --build --version vX.Y.Z
```

You need the Android NDK for the Rust cross-compile. `nm` is built by `zig cc`
if zig is on `PATH`; without it, `package.sh` refuses to ship a prebuilt older
than its own source rather than quietly packaging a stale binary. The NDK's own
clang builds it too, if you would rather not install zig.

Every push runs the unit tests, clippy at `-D warnings`, shellcheck over the
module scripts and the build script, and the ten-version kernel compile matrix.

## Out-of-tree variants

The supported build is in-tree: `CONFIG_NOMOUNT=y`, compiled into the kernel.
Two other ways to load the same engine live on their own branches, for cases
where you cannot rebuild the kernel. Both include `hookless/src/nomount.c`
rather than copying it, so neither can drift from what the Suite ships.

| | branch | `/proc/modules` | maps spoof | kernels |
| :--- | :--- | :--- | :--- | :--- |
| **in-tree** | `main` | absent | yes | 4.9 – 6.18 |
| **KPM** (KernelPatch/APatch) | [`KPM`](../../tree/KPM) | absent | yes — two KernelPatch hooks | 6 KMIs, 5.10 – 6.6 |
| **LKM** (loadable module) | [`LKM`](../../tree/LKM) | **listed** | yes — two kprobes | 4.9 – 6.18 |

Both now carry the `/proc/<pid>/maps` spoof, reaching the same
`vfs_map_meta_override()` the in-tree call site does — through kprobes in the
LKM and KernelPatch hooks in the KPM, two each, because the inode and the
`dev`/`ino` pair live in different functions.

Neither has been loaded on a device. They compile, and CI proves that much and
no more — read each branch's `README.md`, which says what it costs before it
says anything else.

### Building them in CI

Both variants build from the Actions tab.

| workflow | branch | what it gives you |
| :--- | :--- | :--- |
| **Build** | `LKM` | the module zip, with one `nomount-<kmi>.ko` bundled per GKI KMI generation plus a loader. The `ko <kmi>` jobs take ~2 minutes each. |
| **NoMount LKM — out-of-tree build** | `LKM` | compile gate over all ten kernel versions. It proves the engine still builds as a module and nothing more — it runs modpost under `KBUILD_MODPOST_WARN=1`, which suppresses undefined symbols and missing namespace imports alike, so it cannot tell you a module would link. |
| **NoMount KPM — build a KernelPatch module** | `KPM` | one `nomount-<kmi>.kpm` per KMI up to 6.6, built in the DDK containers, failing if any symbol would be unresolvable at load. Note the CFI caveat in `kpm/README.md`. |

The per-KMI modules are built inside `ghcr.io/ylarod/ddk:<kmi>`, whose `$KDIR`
already holds a released GKI kernel's real `Module.symvers` — so they link
against the same export table a phone has, without compiling a kernel.

A module is portable across a **KMI generation**, not a kernel version:
`android12-5.10` and `android13-5.10` are the same version and different KMIs.
Vermagic must still match at load — it is `UTS_RELEASE` plus flags, and GKI keeps
the git SHA out of it, which is what lets one `.ko` serve a generation. A custom
kernel that sets its own `LOCALVERSION` breaks that, so check `modinfo
nomount.ko` against `cat /proc/version` before assuming.

## Commands

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
| `nomount whiteout add <path> [--force]` | Hide a path now and on every boot. |
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
| `nomount check [--plan] [--device] [--json] [--write]` | **The** diagnostic. `--plan` static, `--device` measured, neither flag runs both. Exits 1 on a FAIL. `--write` caches for the WebUI and card. |
| `nomount plan` | Print what the mount pass would resolve to, without applying it. Read-only. |
| `nomount snapshot` | Freeze the current fingerprint as a baseline. |
| `nomount verify` | Diff live against that baseline and name what drifted. |
| `nomount export [dir]` | Dump diagnostics to a folder; the hide list is redacted on shared storage. |
| `nomount version` | Print the version. |

`check` is the one diagnostic: `--plan` is static (does the module set resolve
into a bad rule?), `--device` is measured (is what we serve detectable, and is it
being served?). Verdicts are `FAIL`, `REBOOT`, `UNMEASURED`, `WARN`, `PASS`,
`N/A`, `NOTE` — "nothing to test" and "something stopped me testing" are
deliberately different, and neither is a pass.

A WebUI covers the same ground on the phone: status, modules, rules, per-app
hiding.

## Compatibility

The engine compile-tests against ten kernel versions on every push. Five of
those are versions OnePlus actually ships; three have been booted and measured on
a real phone. The rest compile and nothing more — which is a weaker claim, so it
is written as one.

| Kernel | OnePlus | Status |
| :--- | :--- | :--- |
| 6.12 | **OnePlus 15** | ✅ Booted, `check` clean, 258/258 rules verified |
| 6.1 | **OnePlus 13R** | ✅ Booted, 261/261 rules verified |
| 5.15 | **OnePlus 11** | ✅ Booted, `check` clean, 118/118 rules verified |
| 6.6 | **OnePlus 13 / 13T**, Ace 5 Pro, … (18 models) | ✅ Booted, 261/261 rules verified |
| 5.10 | Ace 2, Ace 2V, Nord 3, … (6 models) | 🧩 Compiled, not tested |
| 4.9 · 4.14 · 4.19 · 5.4 · 6.18 | — not used by any OnePlus | 🧩 Compiled, not tested |

"Compiled" means `fs/nomount.o` builds against that version's canonical tree in
CI — it says nothing about whether the device boots. A report either way is
worth an issue.

Root managers: **KernelSU**, **SukiSU** and **ReSukiSU** via the metamodule
hook; **Magisk** via `post-fs-data.sh`, and **APatch** via the same metamodule
hook. Every device in the table above ran ReSukiSU — Magisk and APatch have not
been tested by anyone yet.

Tested another combo? Open an issue — `nomount export` produces a bundle with the
hide list already redacted, which is the most useful thing to attach. A report
that one of the untested managers works is as useful as a bug.

## License and origin

GPL-3.0. See [LICENSE](LICENSE).

This is a modified derivative of
**[maxsteeel/nomount](https://github.com/maxsteeel/nomount)**, and remains under
its GPL-3.0 licence. The Suite and the Prism engine it drives are a rewrite: the
original `/dev/nomount` char device and its ioctl control plane are gone,
replaced by a per-inode ops hijack with a netlink control plane, and RRO overlays
are injected hooklessly rather than mounted.

## Special thanks

- **[maxsteeel/nomount](https://github.com/maxsteeel/nomount)** — the original this is built on.
- **[HymoFS](https://github.com/Anatdx/HymoFS)** — inspiration for the VFS approach.
- **[A7mdwassa](https://github.com/A7mdwassa)** — tester and contributor.
- **[ZQZCC](https://github.com/ZQZCC)** — WebUI MD3-style design.
- **[backslashxx](https://github.com/backslashxx)** — code optimization.
- **[KernelSU](https://github.com/tiann/KernelSU)** & **SukiSU-Ultra** — root solution and metamodule framework.
- **[SUSFS](https://gitlab.com/simonpunk/susfs4ksu)** — the stealth layer.
- **All testers** — thanks for making this project more stable!

## Disclaimer

A kernel modification tool for research and development. Modifying kernel
behaviour carries real risk, including instability and data loss. The developers
are not responsible for bricked devices or thermonuclear war.
