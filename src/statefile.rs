//! Crash-safe replacement of the state files under `/data/adb/nomount`

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Replace `path` with `body`, atomically, mode 0600
pub(crate) fn write_atomic(path: impl AsRef<Path>, body: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    fs::create_dir_all(dir)?;

    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.new", std::process::id()));
    let tmp = dir.join(name);

    let write = || -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body.as_ref())?;
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replaces_content_and_forces_0600() {
        let d = tempdir();
        let p = d.join("uidhide");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();

        write_atomic(&p, b"com.example.detector\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "com.example.detector\n");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn creates_the_state_directory_and_the_file() {
        let d = tempdir();
        let p = d.join("nested").join("whiteouts.txt");
        write_atomic(&p, b"/system/etc/x\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "/system/etc/x\n");
    }

    /// The temp must not survive a successful write: a leftover beside the hide list is
    #[test]
    fn leaves_no_temp_behind() {
        let d = tempdir();
        let p = d.join("absorbed.list");
        write_atomic(&p, b"a\n").unwrap();
        write_atomic(&p, b"b\n").unwrap();
        let left: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".new"))
            .collect();
        assert!(left.is_empty(), "temp files left behind: {left:?}");
        assert_eq!(fs::read_to_string(&p).unwrap(), "b\n");
    }

    /// An empty body is a legitimate state ("nothing is hidden"), and must land as an empty
    #[test]
    fn an_empty_body_is_a_write_not_a_no_op() {
        let d = tempdir();
        let p = d.join("uidhide");
        write_atomic(&p, b"com.a\n").unwrap();
        write_atomic(&p, b"").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "");
    }

    /// The update stash: `uninstall.sh` saves, `customize.sh` restores, and the two lists must
    #[test]
    fn the_stash_and_restore_lists_name_the_same_files() {
        let saved = stash_list(include_str!("../module/uninstall.sh"));
        let restored = stash_list(include_str!("../module/customize.sh"));
        let swept = stash_list(include_str!("../module/lib.sh"));
        assert!(!saved.is_empty(), "could not find uninstall.sh's stash list");
        assert_eq!(saved, restored, "uninstall.sh stashes a different set than customize.sh restores");
        assert_eq!(
            saved, swept,
            "lib.sh's boot-time stash consumer names a different set than uninstall.sh saves"
        );

        // EVERY file the three lists carry. The equality assertion above catches a list
        // that drifts from its siblings; this catches all three being trimmed together,
        // which is just as good a way to lose a user's hide list across an update.
        for must in [
            "uidhide",
            "uidhide.conf",
            "uidhide.cache",
            "blocklist",
            "my_hookless",
            "absorb-skip.txt",
            "whiteouts.txt",
            "snapshot.txt",
            "spoof.conf",
            "absorbed.list",
            "absorbed-tmpfs.list",
            "binds.list",
            "apkstate.list",
        ] {
            assert!(saved.iter().any(|f| f == must), "{must} is not carried across an update");
        }
    }

    /// Pull the `for _f in
    fn stash_list(script: &str) -> Vec<String> {
        let mut acc = String::new();
        let mut collecting = false;
        for line in script.lines() {
            let t = line.trim();
            if !collecting {
                let Some(rest) = t.strip_prefix("for _f in ") else { continue };
                collecting = true;
                acc.push_str(rest);
            } else {
                acc.push_str(t);
            }
            acc.push(' ');
            if t.ends_with("; do") {
                break;
            }
        }
        acc.split_whitespace()
            .map(|w| w.trim_end_matches([';', '\\']))
            .filter(|w| !w.is_empty() && *w != "do")
            .map(str::to_string)
            .collect()
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("nm-statefile-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }
}
