//! The backing identity of every injected rule, as last applied.
//!
//! A rule names a source PATH, but the engine pins the file behind it. ksud's
//! hot install (`MODULE_HOT_INSTALL_REQUEST`, upstream 200818ca) renames the
//! whole module dir into `/data/adb/ksu/hot_install_trash` and drops the new one
//! in its place, so every source path still reads the same while the files are
//! new. A reload comparing paths therefore finds nothing to do, and the engine
//! keeps serving the replaced version -- with `nm list` naming the live path --
//! until the next boot. Measured on OP15: a hot-updated module kept serving its
//! previous version's bytes through `+0 ~0 -0 rules`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const STATE: &str = "/data/adb/nomount/rulestate.list";

/// dev:ino of what a source resolves to. A missing source is None, which never
/// matches a record, so the rule re-applies once the file is back.
fn identity(source: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(source).ok()?;
    Some(format!("{}:{}", m.dev(), m.ino()))
}

/// What each target was last served from.
pub fn read() -> HashMap<PathBuf, String> {
    let Ok(txt) = fs::read_to_string(STATE) else { return HashMap::new() };
    txt.lines()
        .filter_map(|l| {
            let (t, id) = l.split_once('\t')?;
            Some((PathBuf::from(t), id.to_string()))
        })
        .collect()
}

/// Is the engine serving a file other than the one `source` names now?
///
/// An unrecorded target is never stale: the first pass after an upgrade adopts
/// what is live instead of re-adding every rule.
pub fn is_stale(previous: &HashMap<PathBuf, String>, target: &Path, source: &Path) -> bool {
    let Some(prev) = previous.get(target) else { return false };
    identity(source).is_some_and(|now| now != *prev)
}

/// Record what the engine is serving now. Replaces the file: a target no longer
/// served has no identity worth keeping.
pub fn write(served: &[(PathBuf, PathBuf)]) {
    let body: Vec<String> = served
        .iter()
        .filter_map(|(t, s)| Some(format!("{}\t{}", t.display(), identity(s)?)))
        .collect();
    if let Err(e) = crate::statefile::write_atomic(STATE, body.join("\n")) {
        eprintln!("nomount: could not write {STATE}: {e} - a hot-swapped module may serve stale bytes until the next boot");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("nm-rulestate-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// The hot-install shape: same path, different file behind it.
    #[test]
    fn a_replaced_source_is_stale_though_its_path_is_unchanged() {
        let d = tempdir();
        let src = d.join("file");
        fs::write(&src, b"v1").unwrap();
        let target = PathBuf::from("/system/etc/x");
        let recorded: HashMap<PathBuf, String> =
            [(target.clone(), identity(&src).unwrap())].into_iter().collect();
        assert!(!is_stale(&recorded, &target, &src));

        // Rename-in-place, as ksud's hot install does to the whole module dir.
        let other = d.join("file.new");
        fs::write(&other, b"v2").unwrap();
        fs::rename(&other, &src).unwrap();
        assert!(is_stale(&recorded, &target, &src));
    }

    #[test]
    fn an_unrecorded_target_is_never_stale() {
        let d = tempdir();
        let src = d.join("file");
        fs::write(&src, b"v1").unwrap();
        assert!(!is_stale(&HashMap::new(), Path::new("/system/etc/x"), &src));
    }
}
