# 🫥 NoMount Suite

**[English](README.md)** | 简体中文

> 本页仅为简要说明。命令、规则作用范围与自行构建等完整内容，以 [英文 README](README.md) 为准。

无需任何挂载即可加载 root 模块（包括 RRO 覆盖层）。不使用 `overlayfs`，也不使用 `tmpfs`：由内核引擎 **Prism** 重定向 VFS 查找，`/proc/mounts` 中不会出现任何挂载。本模块是一个元模块（metamodule）。

> [!NOTE]
> **测试版。** 欢迎反馈其他机型、管理器与特殊模块的使用情况。`nomount export` 可生成诊断包，隐藏列表会被脱敏。

## 安装

每个 [Release](https://github.com/Bouteillepleine/NoMount-Suite/releases/latest) 提供两个 ZIP，按内核选择**其一**：

| ZIP | 适用于 |
| :--- | :--- |
| `00_NoMount-Module` | 已内置引擎的内核：一加 [`BakaSu`](https://github.com/Bouteillepleine/OnePlus-BakaSu_NMS/releases)、[`KsuNext`](https://github.com/Bouteillepleine/OnePlus-KsuNext_NMS/releases)、[`SukiSu`](https://github.com/Bouteillepleine/OnePlus-SukiSu_NMS/releases) 内核，或使用 [`hookless/`](hookless/) 自行编译且 `CONFIG_NOMOUNT=y` 的内核 |
| `01_NoMount-Module-LKM` | 原厂 GKI 内核：开机时以内核模块加载引擎（android12-5.10 至 android17-6.18） |

1. 在管理器中刷入 ZIP。如已安装其他元模块，请先删除并重启：同一时间只能启用一个。
2. 重启后在 root shell 中检查：

```sh
alias nomount=/data/adb/modules/meta-nomount/bin/arm64-v8a/nomount
nomount check      # 期望：verdict: clean, 0 failed, 0 unmeasured
```

需要 arm64，以及 KernelSU（或其分支）或 Magisk。无需 SUSFS。更新方式相同，设置会保留。Magisk 没有 WebUI，请在 root shell 中使用命令。

## 防卡开机

连续两次启动未完成时，第三次启动会自动停用 NoMount，不注入任何内容。同一次启动内 system_server 崩溃循环（启动完成前重启四次）也会立即停用。在 Recovery 中手动停用：

```sh
mkdir -p /data/adb/nomount && touch /data/adb/nomount/disabled
```

停用原因记录在 `/data/adb/nomount/incident.log`（WebUI：**Checks → Copy incident**），请先复制保存。然后在 **Checks → Bootloop guard** 重新启用，或执行以下命令后重启：

```sh
rm /data/adb/nomount/disabled /data/adb/nomount/bootcount
```

## 常用命令

WebUI 可完成全部操作。Shell 中：`nomount check`、`reload`、`uid block <包名>`、`whiteout add <路径>`、`export`，其余见 `nomount --help`。反馈问题时，请粘贴 **Checks → Copy report** 复制的内容。

## 许可与致谢

GPL-3.0，见 [LICENSE](LICENSE)。基于 **[maxsteeel/nomount](https://github.com/maxsteeel/nomount)** 重写。感谢 [HymoFS](https://github.com/Anatdx/HymoFS)、[A7mdwassa](https://github.com/A7mdwassa)、[ZQZCC](https://github.com/ZQZCC)、[backslashxx](https://github.com/backslashxx)、[KernelSU](https://github.com/tiann/KernelSU)、SukiSU-Ultra、[SUSFS](https://gitlab.com/simonpunk/susfs4ksu) 以及每一位测试者。

> [!WARNING]
> 修改内核可能导致设备变砖或数据丢失，风险自负。
