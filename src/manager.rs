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
//!   "Umount modules by default" (the global, exact manager label; note the
//!       manager spells it "Umount") -- the allowlist SENTINEL record, below. It is not
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
/// The real file is ~25 KB (32 records). Cap the read so a corrupt or hostile
/// file cannot pull an arbitrary amount into memory: this parses bytes another
/// component owns, on a path we do not control.
const MAX_ALLOWLIST: u64 = 4 * 1024 * 1024;
/// "USK\x7f"
const MAGIC: &[u8] = &[0x55, 0x53, 0x4b, 0x7f];
const HEADER: usize = 8;
const RECORD: usize = 784;
const OFF_NAME: usize = 4;
const NAME_MAX: usize = 256;
const OFF_UID: usize = OFF_NAME + NAME_MAX; // 260
const OFF_ALLOW_SU: usize = OFF_UID + 4; // 264
// +272 and +273 are adjacent single BYTES, not one u32, and the one that means
// "umount modules" is +273 -- established by differential against apps whose
// setting is known: La Banque Postale and FNB both carry the per-app profile and
// both read +272=00, +273=01, while another app reads +272=01 with no umount
// profile at all. An earlier read of +272 badged the wrong apps.
//
// The SENTINEL uses the SAME offset: its +273 is the default value of that field
// for apps with no profile, which is precisely what the manager calls "Umount
// modules by default".
const OFF_OTHER_FLAG: usize = OFF_ALLOW_SU + 8; // 272, not umount; unidentified
const OFF_UMOUNT: usize = OFF_OTHER_FLAG + 1; // 273

/// The allowlist carries a sentinel record that is not an app: name "$",
/// uid 9999 (nobody). Its byte at +273 is the manager's GLOBAL "Umount modules
/// by default".
///
/// Found by differential, not by reading source: with the switch OFF a full
/// snapshot was taken, the user flipped it in the manager, and exactly one bit
/// moved in the whole system -- `.allowlist` byte 4202, which is record #5
/// offset +273. Every ksud read surface (`feature list`, `kernel umount list`,
/// `umount-config list`, `profile list-templates`) was byte-identical before and
/// after, which is why no CLI path for it exists.
const SENTINEL_NAME: &str = "$";
const SENTINEL_UID: u32 = 9999;

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
    match read_allowlist() {
        Some(buf) => parse_apps(&buf),
        None => Vec::new(),
    }
}

/// Read the allowlist, bounded. `None` when absent, unreadable, or implausibly
/// large.
fn read_allowlist() -> Option<Vec<u8>> {
    let meta = fs::metadata(ALLOWLIST).ok()?;
    if meta.len() > MAX_ALLOWLIST {
        return None;
    }
    fs::read(ALLOWLIST).ok()
}

/// Split out from the file read so it can be tested against hostile input.
fn parse_apps(buf: &[u8]) -> Vec<AppFlag> {
    let mut out = Vec::new();
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
        // The sentinel is not an app; it carries the global default.
        if package == SENTINEL_NAME && u32_le(&r[OFF_UID..]) == SENTINEL_UID {
            continue;
        }
        if !package.contains('.') {
            continue; // sepolicy blobs and padding, not a package
        }
        let allow_su = u32_le(&r[OFF_ALLOW_SU..]) != 0;
        out.push(AppFlag {
            package: package.to_string(),
            uid: u32_le(&r[OFF_UID..]),
            allow_su,
            // single byte, and only meaningful for the non-root arm of the union
            umount_modules: !allow_su && r[OFF_UMOUNT] != 0,
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

/// The manager's GLOBAL "Umount modules by default".
///
/// `None` when the sentinel is absent or the file does not look like an
/// allowlist -- never guessed. This is the switch that removes module content
/// from every app WITHOUT a profile, and the one that broke root on this device
/// in July, so a wrong answer here is worse than no answer.
pub fn global_umount_default() -> Option<bool> {
    global_from(&read_allowlist()?)
}

fn global_from(buf: &[u8]) -> Option<bool> {
    if buf.len() < HEADER + RECORD || !buf.starts_with(MAGIC) {
        return None;
    }
    for i in 0..(buf.len() - HEADER) / RECORD {
        let r = &buf[HEADER + i * RECORD..HEADER + (i + 1) * RECORD];
        // One unterminated name must not abandon the search: `?` here made a
        // single malformed record read as "no sentinel", i.e. the dangerous
        // switch silently reported unknown.
        let Some(end) = r[OFF_NAME..OFF_NAME + NAME_MAX].iter().position(|&c| c == 0) else {
            continue;
        };
        if &r[OFF_NAME..OFF_NAME + end] == SENTINEL_NAME.as_bytes()
            && u32_le(&r[OFF_UID..]) == SENTINEL_UID
        {
            return Some(r[OFF_UMOUNT] != 0);
        }
    }
    None
}

/// Does this kernel actually have SUSFS?
///
/// Probed through ksud rather than guessed: on a kernel without it,
/// `ksud susfs show version` answers `Error: Unsupported SuSFS command`, because
/// the prctl the tool issues is not implemented. Falls back to the build config
/// when ksud cannot be run at all. Measured here: `# CONFIG_KSU_SUSFS is not
/// set`, no /sys/fs/susfs, and the error above.
pub fn susfs_present() -> bool {
    if let Ok(out) = std::process::Command::new("/data/adb/ksu/bin/ksud")
        .args(["susfs", "show", "version"])
        .output()
    {
        let txt = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if txt.contains("Unsupported SuSFS command") {
            return false;
        }
        if txt.chars().any(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    std::path::Path::new("/sys/fs/susfs").exists()
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
        r[OFF_UMOUNT] = umount as u8;
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

    /// The sentinel is not reported as an app, and its +273 byte is the global.
    #[test]
    fn sentinel_carries_the_global_not_an_app() {
        let mut sent = rec("$", SENTINEL_UID, false, false);
        sent[OFF_UMOUNT] = 1;
        let b = file(&[sent, rec("com.example.app", 10001, false, true)]);
        let r0 = &b[HEADER..HEADER + RECORD];
        let end = r0[OFF_NAME..].iter().position(|&c| c == 0).unwrap();
        assert_eq!(&r0[OFF_NAME..OFF_NAME + end], b"$");
        assert_eq!(u32_le(&r0[OFF_UID..]), SENTINEL_UID);
        assert_eq!(r0[OFF_UMOUNT], 1, "global lives at +273, same field as per-app");
        // the per-app flag is the same single byte, and +272 is a different flag
        let r1 = &b[HEADER + RECORD..];
        assert_eq!(r1[OFF_UMOUNT], 1);
        assert_eq!(r1[OFF_OTHER_FLAG], 0, "the adjacent byte is not umount_modules");
    }

    /// Nothing in here may panic on bytes another component owns.
    #[test]
    fn hostile_input_never_panics() {
        assert!(parse_apps(&[]).is_empty());
        assert!(parse_apps(b"USK\x7f").is_empty());
        assert!(parse_apps(&vec![0u8; HEADER + RECORD]).is_empty()); // bad magic
        assert!(global_from(&[]).is_none());
        assert!(global_from(&vec![0xffu8; HEADER + RECORD]).is_none());
        // truncated final record: loop must not slice past the end
        let mut t = file(&[rec("a.b", 10001, false, true)]);
        t.truncate(t.len() - 13);
        let _ = parse_apps(&t);
        let _ = global_from(&t);
        // a record whose name field has no NUL at all
        let mut nz = file(&[rec("a.b", 10001, false, true)]);
        for b in nz[HEADER + OFF_NAME..HEADER + OFF_NAME + NAME_MAX].iter_mut() {
            *b = b'x';
        }
        let _ = parse_apps(&nz);
        assert!(global_from(&nz).is_none()); // no sentinel, but must not abort early
        // ...and one bad record must not hide a sentinel that follows it
        let mut sent = rec("$", SENTINEL_UID, false, false);
        sent[OFF_UMOUNT] = 1;
        let mut bad = rec("a.b", 10001, false, false);
        for b in bad[OFF_NAME..OFF_NAME + NAME_MAX].iter_mut() {
            *b = b'x';
        }
        assert_eq!(global_from(&file(&[bad, sent])), Some(true), "bad record must not mask the sentinel");
    }

    #[test]
    fn feature_value_parsing() {
        assert_eq!(parse_feature_value("Feature: kernel_umount (1)\nValue: 0\nStatus: disabled"), Some(0));
        assert_eq!(parse_feature_value("Value: 1"), Some(1));
        assert_eq!(parse_feature_value("nothing"), None);
    }
}
