# 🫥 NoMount Suite

> **Beta.** It works at the kernel VFS layer. Verified end to end on three
> devices (below); expect edges elsewhere.

Loads root modules **without touching the mount table** — RRO theming overlays
included. No `overlayfs`, no `tmpfs`, no bind mounts: `/proc/mounts` stays 100%
stock, so there is no mount gap for a scanner to find.

It is a metamodule: at boot it scans `/data/adb/modules/`, classifies every file
and programs the kernel engine over netlink. No per-module setup. Only one
metamodule can be active, so it refuses to install alongside another.

## Requirements

- **arm64** device; the zip ships an `arm64-v8a` binary only.
- A kernel with the **Prism** engine (`CONFIG_NOMOUNT=y`). Its source lives in
  this repository under [`hookless/`](hookless/) — the driver, the integration
  patch, and a matrix that compile-tests it against every supported kernel
  version. The engine and this Suite are versioned together because they have to
  be flashed together: the control plane is a private protocol between them, and
  a mismatched pair reads as "engine not responding" with nothing to say why.
- **KernelSU**, **SukiSU** or **APatch** (metamodule hook), or **Magisk**
  (`post-fs-data`). If neither path runs, the module says so loudly rather than
  doing nothing silently.
- SUSFS optional and unused; the two coexist.

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

## License and origin

GPL-3.0. See [LICENSE](LICENSE).

This is a modified derivative of
**[maxsteeel/nomount](https://github.com/maxsteeel/nomount)**, and remains under
its GPL-3.0 licence. The Suite and the Prism engine it drives are a rewrite: the
original `/dev/nomount` char device and its ioctl control plane are gone,
replaced by a per-inode ops hijack with a netlink control plane, and RRO overlays
are injected hooklessly rather than mounted. Changes were made through 2026 by
XxxY.

## Special thanks

- **[HymoFS](https://github.com/Anatdx/HymoFS)** — inspiration for the VFS approach.
- **[A7mdwassa](https://github.com/A7mdwassa)** — tester and contributor.
- **[ZQZCC](https://github.com/ZQZCC)** — WebUI MD3-style design.
- **[backslashxx](https://github.com/backslashxx)** — code optimization.
- **[KernelSU](https://github.com/tiann/KernelSU)** & **SukiSU-Ultra** — root solution and metamodule framework.
- **[SUSFS](https://gitlab.com/simonpunk/susfs4ksu)** — the stealth layer NoMount coexists with.
- **All testers** — thanks for making this project more stable!

## Disclaimer

A kernel modification tool for research and development. Modifying kernel
behaviour carries real risk, including instability and data loss. The developers
are not responsible for bricked devices or thermonuclear war.
