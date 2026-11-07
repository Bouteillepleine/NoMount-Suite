
pub fn ksu_manager_present() -> bool {
    std::path::Path::new("/data/adb/ksu").is_dir()
}

pub fn kernel_umount_enabled() -> Option<bool> {
    let mut cmd = std::process::Command::new("/data/adb/ksu/bin/ksud");
    cmd.args(["feature", "get", "kernel_umount"]);
    // Bounded: ksud is the daemon this module is loaded by, and a wedged one would
    // otherwise hold a `nomount check` open with no deadline anywhere in the chain.
    let out = crate::nm::Nm::run_within(cmd, std::time::Duration::from_secs(10), "ksud feature get")
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
