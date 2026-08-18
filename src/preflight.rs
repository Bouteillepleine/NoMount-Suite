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

    /// The worst habit wins even when a milder one appears first.
    #[test]
    fn worst_habit_wins() {
        let code = code_only("mount -o bind /a /b\nnsenter -t 1 -m -- mount -o bind /c /d");
        assert_eq!(classify(&code).unwrap().0, MountHabit::Namespace);
    }
}
