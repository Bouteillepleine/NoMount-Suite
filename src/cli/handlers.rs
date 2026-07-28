use std::path::Path;

use anyhow::Result;

use super::{UidAction, VfsAction};
use crate::nm::Nm;

pub fn handle_vfs(action: VfsAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        VfsAction::Add { virtual_path, real_path } => {
            nm.add(Path::new(&virtual_path), Path::new(&real_path))?;
            println!("ok");
        }
        VfsAction::Del { virtual_path } => {
            nm.del(Path::new(&virtual_path))?;
            println!("ok");
        }
        VfsAction::Whiteout { path } => {
            nm.whiteout(Path::new(&path))?;
            println!("ok");
        }
        VfsAction::Clear => {
            nm.clear()?;
            println!("ok");
        }
        VfsAction::List => {
            let list = nm.list()?;
            if list.trim().is_empty() {
                println!("no rules");
            } else {
                print!("{list}");
            }
        }
    }
    Ok(())
}

pub fn handle_uid(action: UidAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        UidAction::Block { uid } => {
            nm.uid_block(uid)?;
            println!("ok");
        }
        UidAction::Unblock { uid } => {
            nm.uid_unblock(uid)?;
            // While a UID is blocked, its lookup of an injected path installs a shared
            // negative dentry that also hides that path from unblocked readers (root and
            // other apps) until the dcache is evicted — verified on-device: the injected
            // file stays ENOENT after unblock until `drop_caches`. Drop dentries+inodes
            // here (mode 2, slab only — not page cache) so unhiding actually restores the
            // injected view. This is a stopgap for a kernel-side d_revalidate limitation;
            // it does not stop re-poisoning while the block is still active.
            let _ = std::fs::write("/proc/sys/vm/drop_caches", "2\n");
            println!("ok");
        }
    }
    Ok(())
}
