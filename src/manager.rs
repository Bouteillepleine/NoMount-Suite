//! What the root manager is configured to do about module mounts

/// Is there a KernelSU-family manager here at all?
pub fn ksu_manager_present() -> bool {
    std::path::Path::new("/data/adb/ksu").is_dir()
}

/// `ksud feature get kernel_umount` -> Some(true) when enabled
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
        assert_eq!(parse_feature_value("nothing"), None);
        assert_eq!(parse_feature_value(""), None);
        assert_eq!(parse_feature_value("Value: yes"), None);
    }
}
