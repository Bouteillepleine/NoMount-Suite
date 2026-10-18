# 🫥 NoMount Suite

Loads root modules without mounting anything, RRO overlays included. No
`overlayfs`, no `tmpfs`: the **Prism** kernel engine redirects VFS lookups, so
nothing shows up in `/proc/mounts`. It is a metamodule.

> **Beta.** Reports from other phones, managers and odd modules move it to
> stable. `nomount export` builds the bundle, hide list redacted.

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

Each [release](https://github.com/Bouteillepleine/NoMount-Suite/releases/latest) has two zips:

| Zip | For |
| :--- | :--- |
| `00_NoMount-Module` | A kernel with the engine built in: the [`BakaSu`](https://github.com/Bouteillepleine/OnePlus-BakaSu_NMS/releases), [`KsuNext`](https://github.com/Bouteillepleine/OnePlus-KsuNext_NMS/releases) or [`SukiSu`](https://github.com/Bouteillepleine/OnePlus-SukiSu_NMS/releases) OnePlus kernels, or your own build with `CONFIG_NOMOUNT=y` from [`hookless/`](hookless/) |
| `01_NoMount-Module-LKM` | A stock GKI kernel. It loads the engine as a module at boot (android12-5.10 to android17-6.18) |

Flash it from your manager, reboot, then check from a root shell:

```sh
alias nomount=/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount
nomount check      # want: verdict: clean, 0 failed, 0 unmeasured
```

Needs arm64 and KernelSU (or a fork) or Magisk. SUSFS is not needed. Updates
are the same flash and keep your settings.

## If it doesn't boot

Let it boot twice more: after three failed boots the Suite parks itself. To
park it by hand from recovery:

```sh
mkdir -p /data/adb/nomount && touch /data/adb/nomount/disabled
```

## Commands

The WebUI does all of this. From a shell: `nomount check`, `reload`,
`uid block <pkg>`, `whiteout add <path>`, `export`. `nomount --help` has the
rest. To report a problem, attach what **Checks → Developer tools → Export**
writes.

## Building

```sh
cargo test && ANDROID_NDK_HOME=/path/to/ndk scripts/package.sh --build --version vX.Y.Z
```

## License and credits

GPL-3.0, see [LICENSE](LICENSE). A rewrite of
**[maxsteeel/nomount](https://github.com/maxsteeel/nomount)**. Thanks to
[HymoFS](https://github.com/Anatdx/HymoFS), [A7mdwassa](https://github.com/A7mdwassa),
[ZQZCC](https://github.com/ZQZCC), [backslashxx](https://github.com/backslashxx),
[KernelSU](https://github.com/tiann/KernelSU), SukiSU-Ultra,
[SUSFS](https://gitlab.com/simonpunk/susfs4ksu) and every tester.

Modifying a kernel can brick a phone or lose data. Use at your own risk.
