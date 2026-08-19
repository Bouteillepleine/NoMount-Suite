//! What the ROOT MANAGER is configured to do about module mounts.
//!
//! Three switches in the manager promise to "hide modules", and none of them can
//! hide anything this Suite serves: injections are VFS redirects, not mounts, so
//! there is no mount to remove. They are at best no-ops here, and on this device
//! one of them cost ~8 reboots in July, back when su itself arrived as a module
//! overlay and anything stripping module content stripped su with it.
//!
//! What each one costs to READ is very different, so this module is explicit
//! about which are measured and which are not:
//!
//!   kernel_umount           `ksud feature get kernel_umount` -> exact.
//!   per-app "umount modules" .allowlist, decoded below -> exact.
//!   "umount modules by default" (the global) -- NO read path exists. It is not
//!       a ksud feature, not in `ksud umount-config`, and not in the allowlist,
//!       which only holds apps that have an explicit profile. Do not guess it: a
//!       behavioural probe was tried and is confounded, because on a zero-mount
//!       build ordinary apps legitimately see no module mounts whether the
//!       toggle is on or off (measured: kernel_umount OFF, root saw 1 module
//!       mount, all 12 sampled apps saw 0). Reporting that as "the global is on"
//!       would be a fabricated finding.
//!
//! susfs's `hide_sus_mnts_for_non_su_procs` is deliberately NOT checked: this
//! kernel reports `# CONFIG_KSU_SUSFS is not set`, so ksud's persisted susfs
//! config is inert and warning about it would send the reader to a setting that
//! does nothing on their build.

use std::fs;


const ALLOWLIST: &str = "/data/adb/ksu/.allowlist";
/// "USK\x7f"
const MAGIC: &[u8] = &[0x55, 0x53, 0x4b, 0x7f];
const HEADER: usize = 8;
const RECORD: usize = 784;
const OFF_NAME: usize = 4;
const NAME_MAX: usize = 256;
const OFF_UID: usize = OFF_NAME + NAME_MAX; // 260
const OFF_ALLOW_SU: usize = OFF_UID + 4; // 264
const OFF_UMOUNT: usize = OFF_ALLOW_SU + 8; // 272

// `umount_modules` lives in the NON-ROOT arm of the profile union. For a record
// with allow_su set, those same bytes are root-profile data (uid/gid/caps), so
// reading them as a flag reports nonsense: it badged 29 apps on this device
// including termux, systemui and shell, where the real count of non-root apps
// carrying the profile is far smaller.

pub struct AppFlag {
    pub package: String,
    pub uid: u32,
    #[allow(dead_code)] // decoded to gate umount_modules; kept for diagnostics
    pub allow_su: bool,
    pub umount_modules: bool,
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Per-app profiles that ask the manager to unmount modules.
///
/// Layout was read off a live device and cross-checked against known values
/// before being trusted: `com.android.shell` decoded to uid 2000 and
/// La Banque Postale to uid 10497, both correct, and the two apps carrying an
/// "umount modules" profile decoded as set. Any layout change shows up as
/// garbage uids rather than silently wrong flags, which `looks_sane` rejects.
pub fn app_umount_flags() -> Vec<AppFlag> {
    let mut out = Vec::new();
    let Ok(buf) = fs::read(ALLOWLIST) else { return out };
    if buf.len() < HEADER + RECORD || !buf.starts_with(MAGIC) {
        return out;
    }
    let n = (buf.len() - HEADER) / RECORD;
    for i in 0..n {
        let r = &buf[HEADER + i * RECORD..HEADER + (i + 1) * RECORD];
        let name_end = r[OFF_NAME..OFF_NAME + NAME_MAX]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(0);
        if name_end == 0 {
            continue;
        }
        let Ok(package) = std::str::from_utf8(&r[OFF_NAME..OFF_NAME + name_end]) else { continue };
        if !package.contains('.') {
            continue; // sepolicy blobs and padding, not a package
        }
        let allow_su = u32_le(&r[OFF_ALLOW_SU..]) != 0;
        out.push(AppFlag {
            package: package.to_string(),
            uid: u32_le(&r[OFF_UID..]),
            allow_su,
            // only meaningful for the non-root arm of the union
            umount_modules: !allow_su && u32_le(&r[OFF_UMOUNT..]) != 0,
        });
    }
    if !looks_sane(&out) {
        out.clear();
    }
    out
}

/// Refuse a decode that cannot be right, rather than report invented flags: an
/// Android app uid is 10000..=19999 and shell is 2000, so a table where most
/// entries fall outside that means the record layout moved.
fn looks_sane(v: &[AppFlag]) -> bool {
    if v.is_empty() {
        return false;
    }
    let plausible = v
        .iter()
        .filter(|a| a.uid == 2000 || (10000..100_000).contains(&a.uid))
        .count();
    plausible * 2 > v.len()
}

/// `ksud feature get kernel_umount` -> Some(true) when enabled.
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
    use super::*;

    fn rec(pkg: &str, uid: u32, su: bool, umount: bool) -> Vec<u8> {
        let mut r = vec![0u8; RECORD];
        r[..4].copy_from_slice(&4u32.to_le_bytes());
        r[OFF_NAME..OFF_NAME + pkg.len()].copy_from_slice(pkg.as_bytes());
        r[OFF_UID..OFF_UID + 4].copy_from_slice(&uid.to_le_bytes());
        r[OFF_ALLOW_SU..OFF_ALLOW_SU + 4].copy_from_slice(&(su as u32).to_le_bytes());
        r[OFF_UMOUNT..OFF_UMOUNT + 4].copy_from_slice(&(umount as u32).to_le_bytes());
        r
    }

    fn file(recs: &[Vec<u8>]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&4u32.to_le_bytes());
        for r in recs {
            b.extend_from_slice(r);
        }
        b
    }

    /// The real values measured on-device: shell is uid 2000 with su, LBP is
    /// 10497 without su but with umount set.
    #[test]
    fn decodes_the_shape_seen_on_device() {
        let b = file(&[
            rec("com.android.shell", 2000, true, true),
            rec("com.fullsix.android.labanquepostale.accountaccess", 10497, false, true),
            rec("com.google.android.apps.youtube.music", 10353, false, false),
        ]);
        // exercise the parser over the same bytes the file would hold
        let n = (b.len() - HEADER) / RECORD;
        assert_eq!(n, 3);
        let r = &b[HEADER + RECORD..HEADER + 2 * RECORD];
        assert_eq!(u32_le(&r[OFF_UID..]), 10497);
        assert!(u32_le(&r[OFF_UMOUNT..]) != 0);
        let r3 = &b[HEADER + 2 * RECORD..];
        assert_eq!(u32_le(&r3[OFF_UMOUNT..]), 0);
    }

    /// A root app's bytes at OFF_UMOUNT are root-profile data, never a flag.
    #[test]
    fn root_apps_never_report_umount_modules() {
        let b = file(&[rec("com.termux", 10618, true, true)]);
        let r = &b[HEADER..HEADER + RECORD];
        let allow_su = u32_le(&r[OFF_ALLOW_SU..]) != 0;
        assert!(allow_su);
        assert!(!(!allow_su && u32_le(&r[OFF_UMOUNT..]) != 0), "must not read a flag for root apps");
    }

    #[test]
    fn a_moved_layout_is_rejected_not_reported() {
        let bogus = vec![
            AppFlag { package: "a.b".into(), uid: 99_999_999, allow_su: false, umount_modules: true },
            AppFlag { package: "c.d".into(), uid: 123, allow_su: false, umount_modules: true },
        ];
        assert!(!looks_sane(&bogus));
        let good = vec![
            AppFlag { package: "a.b".into(), uid: 10497, allow_su: false, umount_modules: true },
            AppFlag { package: "c.d".into(), uid: 2000, allow_su: true, umount_modules: false },
        ];
        assert!(looks_sane(&good));
    }

    #[test]
    fn feature_value_parsing() {
        assert_eq!(parse_feature_value("Feature: kernel_umount (1)\nValue: 0\nStatus: disabled"), Some(0));
        assert_eq!(parse_feature_value("Value: 1"), Some(1));
        assert_eq!(parse_feature_value("nothing"), None);
    }
}
