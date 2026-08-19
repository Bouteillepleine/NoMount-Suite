//! Static pre-flight: what a module's own scripts will do to the mount table.
//!
//! The mount pass classifies a module by the FILES it ships, so a module that
//! also runs `mount` from post-fs-data.sh looks fully handled in `plan` while it
//! still goes on to mount at boot. absorb then has to take that over afterwards
//! -- and for the nsenter family it cannot, because those replicate the mount
//! into another process's namespace where absorb has no standing.
//!
//! Surveyed against the 1000 most-starred modules (836 real ones): 103 (12.3%)
//! mount something themselves -- bind 93, tmpfs 12, loop 9, nsenter 11,
//! overlayfs 2 -- and 57 of those ALSO ship overlay content, which is exactly
//! the set that looks clean in `plan` today. The scripts are already on disk, so
//! saying this before boot costs a read.
//!
//! Deliberately conservative: this reports what a script CAN do, not what it
//! will do on this device. A guarded `mount` behind an `if` still counts, since
//! the point is to warn before installing rather than to predict a boot.

use std::fs;
use std::path::Path;

/// Scripts a root manager executes, in the order they run.
const SCRIPTS: &[&str] = &[
    "post-fs-data.sh",
    "post-mount.sh",
    "service.sh",
    "boot-completed.sh",
    "customize.sh",
    "action.sh",
    "uninstall.sh",
    "common.sh",
];

/// A module rewriting the ROOT MANAGER's global settings from its own scripts.
///
/// A different class from touching the mount table, and in one respect worse:
/// it re-applies at every boot, so a user who fixes the setting by hand finds it
/// back on next reboot with nothing to explain why.
///
/// BRENE (rrr333nnn333/BRENE, 325*) is the case this was written from. It makes
/// no direct `mount` call at all -- it drives a susfs binary -- so the mount scan
/// below sees nothing, while its boot-completed.sh runs
/// `ksud feature set kernel_umount 1` with `config_kernel_umount=1` by DEFAULT.
/// That is the switch that broke root on this hardware, and it also silently
/// turns on "Umount modules by default".
pub struct ManagerWrite {
    pub module: String,
    /// The setting being written, e.g. "kernel_umount".
    pub key: String,
    /// The value written, when the script writes a literal.
    pub value: Option<String>,
    /// Why this particular write is harmful, or None when it is merely notable.
    pub harm: Option<&'static str>,
}

/// The VALUE decides the harm, not the key. `feature set su_compat 1` is what a
/// healthy system already has; `feature set su_compat 0` removes root entirely.
/// Grading on the key alone would warn about the first and miss the second.
///
/// Read off the live feature set (ksud 4.2.0-rc1): su_compat, kernel_umount,
/// sulog, adb_root, selinux_hide.
fn harm_of(key: &str, value: Option<&str>) -> Option<&'static str> {
    match (key, value) {
        ("su_compat", Some("0")) => Some(
            "su on this configuration comes from sucompat, so disabling it removes root \
             outright -- a harder failure than any mount switch",
        ),
        ("kernel_umount", Some("1")) => Some(
            "it can hide nothing the Suite serves (injections are not mounts), it turns on \
             \"Umount modules by default\" with it, and it has broken root on this hardware",
        ),
        ("selinux_hide", Some("0")) => Some(
            "it sanitizes /sys/fs/selinux for app UIDs; turning it off re-opens the SELinux \
             oracles detectors already use",
        ),
        ("sulog", Some("1")) => Some(
            "it persists su events to disk, which is both a forensic trail and a file a \
             detector can look for",
        ),
        // A write with no literal value still deserves naming: the module is
        // taking the setting over, whatever it decides at runtime.
        (k, None) if matches!(k, "su_compat" | "kernel_umount" | "selinux_hide" | "sulog") => {
            Some("the value is computed at runtime, so what it ends up as is the module's call")
        }
        _ => None,
    }
}

/// `ksud feature set <key> <value>`, however the binary is spelled -- a literal
/// path, `$KSU_BIN`, `ksud`. Matches on the verb, not the binary.
fn manager_writes(code: &str) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::new();
    for line in code.lines() {
        // Drop quoted text first, exactly as the mount scan does: `echo "we
        // never feature set anything"` is prose, not a setting being written.
        let bare = unquote(line);
        let w: Vec<&str> = bare.split_whitespace().collect();
        for i in 0..w.len() {
            if w[i] == "feature" && w.get(i + 1) == Some(&"set") {
                if let Some(k) = w.get(i + 2) {
                    let k = k.trim_matches(|c| c == '"' || c == '\'');
                    // A literal 0/1 is the value; a variable or substitution is
                    // unknown rather than assumed.
                    let v = w
                        .get(i + 3)
                        .map(|v| v.trim_matches(|c| c == '"' || c == '\''))
                        .filter(|v| *v == "0" || *v == "1")
                        .map(|v| v.to_string());
                    if !k.is_empty() && !out.iter().any(|(e, _)| e == k) {
                        out.push((k.to_string(), v));
                    }
                }
            }
        }
    }
    out
}

/// Does this module's own scripts drive SUSFS?
///
/// Matters because a SUSFS module on a kernel without SUSFS is all cost and no
/// benefit: every hiding call it makes is a no-op, while its side effects --
/// flipping manager settings, writing props, mounting -- still happen. BRENE and
/// susfs4ksu-module are both in this shape on a hookless build.
fn uses_susfs(code: &str) -> bool {
    const MARKERS: &[&str] = &[
        "ksu_susfs",
        "susfs_bin",
        "add_sus_path",
        "add_sus_mount",
        "add_sus_kstat",
        "add_try_umount",
        "add_open_redirect",
        "hide_sus_mnts_for_non_su_procs",
        "sus_su",
    ];
    MARKERS.iter().any(|m| code.contains(m))
}

/// Does this module ship files to inject? A module with a partition tree is a
/// CONTENT module; SUSFS calls in it are an assist, not its purpose.
///
/// This is the line between "remove it" and "ignore it". OnePlus_Dialer_Universal
/// makes two best-effort `ksu_susfs` calls (`|| true`) inside the fallback branch
/// that only runs when NoMount is absent -- its actual job is shipping dialer
/// content. Advising its removal would delete something the user wants, on the
/// strength of two lines that never execute here.
fn ships_content(dir: &Path) -> bool {
    const PARTS: &[&str] = &[
        "system", "product", "vendor", "system_ext", "odm", "my_product", "my_stock",
        "my_region", "my_heytap", "my_preload", "my_company", "my_engineering", "my_carrier",
    ];
    PARTS.iter().any(|p| dir.join(p).is_dir())
}

pub struct SusfsUser {
    pub module: String,
    /// True when SUSFS is the module's whole purpose -- it ships no content of
    /// its own, so with SUSFS absent it does nothing at all.
    pub susfs_is_its_purpose: bool,
}

/// Enabled modules whose scripts drive SUSFS.
pub fn scan_susfs_users(modules_dir: &str, self_id: &str) -> Vec<SusfsUser> {
    let mut out = Vec::new();
    let Ok(dirs) = fs::read_dir(modules_dir) else { return out };
    for e in dirs.flatten() {
        let dir = e.path();
        if !dir.is_dir() || dir.join("disable").exists() || dir.join("remove").exists() {
            continue;
        }
        let Some(id) = dir.file_name().and_then(|n| n.to_str()) else { continue };
        if id == self_id {
            continue;
        }
        let hit = SCRIPTS.iter().any(|n| {
            fs::read_to_string(dir.join(n)).map(|r| uses_susfs(&code_only(&r))).unwrap_or(false)
        });
        if hit {
            out.push(SusfsUser {
                module: id.to_string(),
                susfs_is_its_purpose: !ships_content(&dir),
            });
        }
    }
    out.sort_by(|a, b| b.susfs_is_its_purpose.cmp(&a.susfs_is_its_purpose).then(a.module.cmp(&b.module)));
    out
}

/// Every enabled module whose scripts rewrite root-manager settings.
pub fn scan_manager_writes(modules_dir: &str, self_id: &str) -> Vec<ManagerWrite> {
    let mut out = Vec::new();
    let Ok(dirs) = fs::read_dir(modules_dir) else { return out };
    for e in dirs.flatten() {
        let dir = e.path();
        if !dir.is_dir() || dir.join("disable").exists() || dir.join("remove").exists() {
            continue;
        }
        let Some(id) = dir.file_name().and_then(|n| n.to_str()) else { continue };
        if id == self_id {
            continue;
        }
        let mut keys: Vec<(String, Option<String>)> = Vec::new();
        for name in SCRIPTS {
            let Ok(raw) = fs::read_to_string(dir.join(name)) else { continue };
            for kv in manager_writes(&code_only(&raw)) {
                if !keys.iter().any(|(k, _)| *k == kv.0) {
                    keys.push(kv);
                }
            }
        }
        for (key, value) in keys {
            let harm = harm_of(&key, value.as_deref());
            out.push(ManagerWrite { module: id.to_string(), key, value, harm });
        }
    }
    out.sort_by(|a, b| b.harm.is_some().cmp(&a.harm.is_some()).then(a.module.cmp(&b.module)));
    out
}

/// What a module will do to the mount table, worst case first.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub enum MountHabit {
    /// Replicates a mount into another process's namespace. absorb can see it
    /// but cannot unmount it: the mount lives in a namespace we do not own.
    Namespace,
    /// Mounts a filesystem of its own (overlayfs, loop image). absorb cannot
    /// re-serve this as an injection -- there is no backing file to point at.
    ForeignFs,
    /// bind/tmpfs/whiteout-node work that absorb can take over and unmount,
    /// restoring the zero-mount posture.
    Absorbable,
    /// A kernel pseudo-filesystem (debugfs, tracefs, configfs...). It carries no
    /// module content, so absorb has nothing to re-serve and correctly leaves it
    /// alone. Reported only so the mount is accounted for: tcp_optimiser mounts
    /// debugfs to write sysctls, and calling that "absorb takes it over" would
    /// be a plainly wrong explanation of a mount the user can see.
    Pseudo,
}

pub struct Habit {
    pub module: String,
    pub habit: MountHabit,
    /// The token that triggered it, so the finding can be checked by hand.
    pub evidence: &'static str,
}

/// Strip comments and here-doc noise so a mention in a banner or a commented-out
/// line does not read as behaviour. Cheap and good enough: full shell parsing
/// would be a lie about precision we do not have.
fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| match l.find(" #") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
}

/// Drop quoted text, so a banner like `echo "does not mount"` is not read as
/// behaviour. Unbalanced quotes just drop the tail, which errs toward silence.
fn unquote(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None => out.push(c),
        }
    }
    out
}

/// `mount` in COMMAND position -- not inside `umount`/`remount`/`mountpoint`,
/// and not as a word in a message. Splits on the shell separators that start a
/// new command and allows the usual prefixes (`busybox mount`, `$MAGISK mount`).
fn calls_mount(code: &str) -> bool {
    // No "-c": it would let `X=$(grep -c mount /proc/mounts)` reach the `mount`
    // token. A genuine `su -c "mount ..."` carries its command quoted, and
    // unquote() drops that -- a miss we accept, because a doctor that cries wolf
    // gets ignored and this check only earns its place by being quiet.
    const PREFIXES: &[&str] = &["busybox", "toybox", "sudo", "su", "exec", "then", "do", "else"];
    for line in code.lines() {
        for seg in unquote(line).split(|c| c == ';' || c == '|' || c == '&') {
            let mut words = seg.split_whitespace().skip_while(|w| {
                PREFIXES.contains(w) || w.starts_with('$') || w.contains('=')
            });
            if words.next() == Some("mount") {
                return true;
            }
        }
    }
    false
}

fn classify(code: &str) -> Option<(MountHabit, &'static str)> {
    // Order matters: report the worst habit a module has.
    if code.contains("nsenter") {
        return Some((MountHabit::Namespace, "nsenter"));
    }
    for (tok, ev) in [
        ("lowerdir=", "overlayfs"),
        ("-t overlay", "overlayfs"),
        ("losetup", "loop device"),
        ("-o loop", "loop device"),
    ] {
        if code.contains(tok) {
            return Some((MountHabit::ForeignFs, ev));
        }
    }
    for (tok, ev) in [
        ("-t debugfs", "debugfs"),
        ("-t tracefs", "tracefs"),
        ("-t configfs", "configfs"),
        ("-t securityfs", "securityfs"),
        ("-t sysfs", "sysfs"),
        ("-t proc", "procfs"),
        ("-t cgroup", "cgroup"),
    ] {
        if code.contains(tok) {
            return Some((MountHabit::Pseudo, ev));
        }
    }
    for (tok, ev) in [
        ("-o bind", "bind mount"),
        ("--bind", "bind mount"),
        ("-o rbind", "bind mount"),
        ("--rbind", "bind mount"),
        ("-t tmpfs", "tmpfs"),
        ("mknod", "device node"),
    ] {
        if code.contains(tok) {
            return Some((MountHabit::Absorbable, ev));
        }
    }
    // A bare `mount` with no recognisable flag still moves the mount table.
    if calls_mount(code) {
        return Some((MountHabit::Absorbable, "mount"));
    }
    None
}

/// Scan one module directory. `None` when its scripts touch no mounts.
pub fn scan_module(dir: &Path) -> Option<(MountHabit, &'static str)> {
    let mut worst: Option<(MountHabit, &'static str)> = None;
    for name in SCRIPTS {
        let p = dir.join(name);
        let Ok(raw) = fs::read_to_string(&p) else { continue };
        if let Some(hit) = classify(&code_only(&raw)) {
            worst = match worst {
                Some(w) if w.0 <= hit.0 => Some(w),
                _ => Some(hit),
            };
        }
    }
    worst
}

/// Every enabled module whose scripts will touch the mount table.
/// `self_id` is skipped: the metamodule's own scripts drive absorb.
pub fn scan_all(modules_dir: &str, self_id: &str) -> Vec<Habit> {
    let mut out = Vec::new();
    let Ok(dirs) = fs::read_dir(modules_dir) else { return out };
    for e in dirs.flatten() {
        let dir = e.path();
        if !dir.is_dir() || dir.join("disable").exists() || dir.join("remove").exists() {
            continue;
        }
        let Some(id) = dir.file_name().and_then(|n| n.to_str()) else { continue };
        if id == self_id {
            continue;
        }
        if let Some((habit, evidence)) = scan_module(&dir) {
            out.push(Habit { module: id.to_string(), habit, evidence });
        }
    }
    out.sort_by(|a, b| a.habit.cmp(&b.habit).then(a.module.cmp(&b.module)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_banners_are_not_behaviour() {
        assert_eq!(classify(&code_only("# mount -o bind /a /b\necho hi")), None);
        assert_eq!(classify(&code_only("echo 'this module does not mount'")), None);
    }

    #[test]
    fn umount_alone_is_not_a_mount() {
        assert_eq!(classify(&code_only("umount /system/etc")), None);
        assert_eq!(classify(&code_only("mountpoint -q /data && echo y")), None);
        assert_eq!(classify(&code_only("remount_ro /system")), None);
    }

    /// The bare-`mount` fallback fires only in command position. Everything here
    /// mentions the word without running it.
    #[test]
    fn the_word_mount_is_not_a_mount() {
        for s in [
            "echo 'this module does not mount'",
            "echo \"remount done\"",
            "ui_print \"- mounting skipped\"",
            "MOUNTED=$(grep -c mount /proc/mounts)",
        ] {
            assert_eq!(classify(&code_only(s)), None, "false positive on: {s}");
        }
    }

    /// ...but a real invocation still counts, with or without a prefix.
    #[test]
    fn command_position_mount_counts() {
        for s in ["mount /a /b", "busybox mount /a /b", "true && mount /a /b"] {
            assert_eq!(
                classify(&code_only(s)).map(|h| h.0),
                Some(MountHabit::Absorbable),
                "missed: {s}"
            );
        }
    }

    #[test]
    fn the_three_habits() {
        assert_eq!(
            classify(&code_only("mount -o bind $MODDIR/system /system")).unwrap().0,
            MountHabit::Absorbable
        );
        assert_eq!(
            classify(&code_only("mount -t overlay overlay -o lowerdir=/system /system")).unwrap().0,
            MountHabit::ForeignFs
        );
        assert_eq!(
            classify(&code_only("nsenter -t $p -m -- mount -o bind /a /b")).unwrap().0,
            MountHabit::Namespace
        );
    }

    #[test]
    fn pseudo_filesystems_are_not_content() {
        assert_eq!(
            classify(&code_only("mount -t debugfs debugfs /sys/kernel/debug")).unwrap().0,
            MountHabit::Pseudo
        );
        // ...but tmpfs often IS content staging, so it stays absorbable.
        assert_eq!(
            classify(&code_only("mount -t tmpfs tmpfs /dev/x")).unwrap().0,
            MountHabit::Absorbable
        );
    }

    /// Verbatim from BRENE's boot-completed.sh, which the mount scan cannot see.
    #[test]
    fn catches_a_module_flipping_manager_settings() {
        let code = code_only(
            "if [[ \"${config_kernel_umount}\" == \"1\" ]]; then\n\
             \t${KSU_BIN} feature set kernel_umount 1\nfi\n\
             ${KSU_BIN} feature set selinux_hide 1\n",
        );
        let keys = manager_writes(&code);
        assert!(keys.iter().any(|(k, _)| k == "kernel_umount"), "must catch the dangerous key");
        assert!(keys.iter().any(|(k, _)| k == "selinux_hide"));
        // and it must not fire on prose or on reading a feature
        assert!(manager_writes(&code_only("ksud feature get kernel_umount")).is_empty());
        assert!(manager_writes(&code_only("echo 'we never feature set anything'")).is_empty());
    }

    #[test]
    fn susfs_users_are_recognised() {
        assert!(uses_susfs(&code_only("${SUSFS_BIN} add_sus_path /system/addon.d")));
        assert!(uses_susfs(&code_only("ksu_susfs add_try_umount /data/adb/modules 1")));
        assert!(!uses_susfs(&code_only("echo hello; mount -o bind /a /b")));
    }

    /// The VALUE decides harm. Turning su_compat OFF is worse than anything a
    /// mount switch can do; turning it ON is what a healthy system already has.
    #[test]
    fn harm_is_judged_on_the_value_not_the_key() {
        assert!(harm_of("su_compat", Some("0")).is_some(), "disabling su must warn");
        assert!(harm_of("su_compat", Some("1")).is_none(), "enabling su is not harm");
        assert!(harm_of("kernel_umount", Some("1")).is_some());
        assert!(harm_of("kernel_umount", Some("0")).is_none(), "turning it OFF is a fix");
        assert!(harm_of("selinux_hide", Some("0")).is_some());
        assert!(harm_of("sulog", Some("1")).is_some());
        assert!(harm_of("adb_root", Some("1")).is_none());
        // an unresolved value on a sensitive key is still worth naming
        assert!(harm_of("kernel_umount", None).is_some());
        assert!(harm_of("adb_root", None).is_none());
    }

    /// The worst habit wins even when a milder one appears first.
    #[test]
    fn worst_habit_wins() {
        let code = code_only("mount -o bind /a /b\nnsenter -t 1 -m -- mount -o bind /c /d");
        assert_eq!(classify(&code).unwrap().0, MountHabit::Namespace);
    }
}
