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
            println!("ok");
        }
    }
    Ok(())
}
