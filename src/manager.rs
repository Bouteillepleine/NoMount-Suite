//! What the ROOT MANAGER is configured to do about module mounts.
//!
//! Three switches in the manager promise to "hide modules", and none of them can
//! hide anything this Suite serves: injections are VFS redirects, not mounts, so
//! there is no mount to remove. They are at best no-ops here, and on this device
//! one of them cost ~8 reboots in July, back when su itself arrived as a module
//! overlay and anything stripping module content stripped su with it.
//!
//! Only ONE of the three is read, and only through the manager's own CLI:
//!
//!   kernel_umount           `ksud feature get kernel_umount` -> exact.
//!
//! The other two used to be decoded out of `/data/adb/ksu/.allowlist`, a private
//! binary format belonging to ksud: a 784-byte record layout, a "$"/9999 sentinel
//! record, and a flag byte located by differential against apps whose setting was
//! known. ~455 lines of it. That is gone, on the strength of its own opening
//! paragraph -- none of what it reported can hide anything the Suite serves, so
//! the whole decode bought three informational notes about settings that do
//! nothing here, at the price of a parser that would rot to "unknown" on any ksud
//! layout change and be believed until someone noticed. A reader who wants to know
//! what their manager's per-app profiles say has the manager's own UI, which is
//! where they can change them anyway.
//!
//! `ksud feature get` is a documented command with stable output, so what remains
//! is a measurement rather than a reverse-engineering.
//!
//! susfs's `hide_sus_mnts_for_non_su_procs` is deliberately NOT checked: this
//! kernel reports `# CONFIG_KSU_SUSFS is not set`, so ksud's persisted susfs
//! config is inert and warning about it would send the reader to a setting that
//! does nothing on their build.

/// Is there a KernelSU-family manager here at all?
///
/// Gates the "could not read your manager's setting" finding: a manager that
/// keeps no state directory has none to fail at reading, and warning about a
/// missing file that was never meant to exist is noise, not a finding.
pub fn ksu_manager_present() -> bool {
    std::path::Path::new("/data/adb/ksu").is_dir()
}

/// `ksud feature get kernel_umount` -> Some(true) when enabled.
///
/// `None` means ksud could not be asked, or answered in a shape this does not
/// recognise -- NOT that the switch is off. Folding those together is what made
/// "the switch is off" and "ksud is missing" render identically in `doctor`.
pub fn kernel_umount_enabled() -> Option<bool> {
    let out = std::process::Command::new("/data/adb/ksu/bin/ksud")
        .args(["feature", "get", "kernel_umount"])
        .output()
        .ok()?;
    parse_feature_value(&String::from_utf8_lossy(&out.stdout)).map(|v| v != 0)
}

pub fn parse_feature_value(s: &str) -> Option<u32> {
    s.lines()
        .find_map(|l| l.trim().strip_prefix("Value:"))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::parse_feature_value;

    #[test]
    fn feature_value_parsing() {
        assert_eq!(
            parse_feature_value("Feature: kernel_umount (1)\nValue: 0\nStatus: disabled"),
            Some(0)
        );
        assert_eq!(parse_feature_value("Value: 1"), Some(1));
        // "nothing to parse" must stay distinct from "the value is 0": the whole
        // point of the Option is that an unreadable setting is not an off one.
        assert_eq!(parse_feature_value("nothing"), None);
        assert_eq!(parse_feature_value(""), None);
        assert_eq!(parse_feature_value("Value: yes"), None);
    }
}
