//! KernelSU driver client: the DenyList verdict and the try-umount list.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

const DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver]";
const SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]";

const INSTALL_MAGIC1: libc::c_long = 0xDEAD_BEEF;
const INSTALL_MAGIC2: libc::c_long = 0xCAFE_BABE;

const DIR_WRITE: u32 = 1;
const DIR_READ: u32 = 2;

const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((b'K' as u32) << 8) | nr
}

const GET_INFO: u32 = ioc(DIR_READ, 2, 16);
const GET_INFO_LEGACY: u32 = ioc(DIR_READ, 2, 0);
const UID_SHOULD_UMOUNT: u32 = ioc(DIR_READ | DIR_WRITE, 9, 0);
const ADD_TRY_UMOUNT: u32 = ioc(DIR_WRITE, 18, 0);

const UMOUNT_ADD: u8 = 1;

/// No app profile can be keyed on an isolated-pool uid, so the verdict for it is
/// the global "umount modules by default" setting.
const UNPROFILED_UID: u32 = 99_999;
const _: () = assert!(UNPROFILED_UID > 19_999, "the probe uid must be outside the app appid range");

pub const MAX_UMOUNT_PATH: usize = 255;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Info {
    pub version: u32,
    pub flags: u32,
    pub features: u32,
    pub uapi_version: u32,
}

#[repr(C)]
struct ShouldUmountCmd {
    uid: u32,
    should_umount: u8,
}

#[repr(C, align(8))]
struct TryUmountCmd {
    arg: u64,
    flags: u32,
    mode: u8,
}

static DRIVER_FD: OnceLock<RawFd> = OnceLock::new();
static INFO: OnceLock<Option<Info>> = OnceLock::new();

fn scan_driver_fd() -> Option<RawFd> {
    let mut fallback = None;
    for e in fs::read_dir("/proc/self/fd").ok()?.flatten() {
        let Ok(fd) = e.file_name().to_string_lossy().parse::<RawFd>() else { continue };
        let Ok(target) = fs::read_link(e.path()) else { continue };
        if target == Path::new(SU_DRIVER_FD_NAME) {
            return Some(fd);
        }
        if target == Path::new(DRIVER_FD_NAME) {
            fallback = Some(fd);
        }
    }
    fallback
}

/// The hook installs the fd and still reports failure, so only the out-parameter counts.
/// A kernel without the hook rejects the magic without side effects.
fn install_driver_fd() -> Option<RawFd> {
    let mut fd: libc::c_int = -1;
    unsafe {
        libc::syscall(libc::SYS_reboot, INSTALL_MAGIC1, INSTALL_MAGIC2, 0, &mut fd);
    }
    (fd >= 0).then_some(fd)
}

fn driver_fd() -> RawFd {
    *DRIVER_FD.get_or_init(|| scan_driver_fd().or_else(install_driver_fd).unwrap_or(-1))
}

fn ksuctl<T>(request: u32, cmd: &mut T) -> io::Result<()> {
    let fd = driver_fd();
    if fd < 0 {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    let r = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            fd as libc::c_long,
            request as libc::c_long,
            cmd as *mut T,
        )
    };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

pub fn info() -> Option<Info> {
    *INFO.get_or_init(|| {
        let mut cmd = Info::default();
        if ksuctl(GET_INFO, &mut cmd).is_ok() {
            return Some(cmd);
        }
        let mut cmd = Info::default();
        ksuctl(GET_INFO_LEGACY, &mut cmd).ok().map(|()| cmd)
    })
}

pub fn available() -> bool {
    info().is_some()
}

/// `None` means the question could not be put to the kernel - never "no".
pub fn uid_should_umount(uid: u32) -> Option<bool> {
    if !available() {
        return None;
    }
    let mut cmd = ShouldUmountCmd { uid, should_umount: 0 };
    ksuctl(UID_SHOULD_UMOUNT, &mut cmd).ok()?;
    Some(cmd.should_umount != 0)
}

pub fn global_umount_default() -> Option<bool> {
    uid_should_umount(UNPROFILED_UID)
}

pub fn umount_list_add(target: &Path, flags: u32) -> Result<()> {
    let bytes = target.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_UMOUNT_PATH {
        bail!("a try-umount path must be 1-{MAX_UMOUNT_PATH} bytes");
    }
    let path = CString::new(bytes).context("try-umount path carries a NUL")?;
    let mut cmd =
        TryUmountCmd { arg: path.as_ptr() as u64, flags, mode: UMOUNT_ADD };
    match ksuctl(ADD_TRY_UMOUNT, &mut cmd) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| {
            format!("register {} with KernelSU's try-umount list", target.display())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_the_ksu_uapi() {
        assert_eq!(GET_INFO, 0x8010_4B02);
        assert_eq!(GET_INFO_LEGACY, 0x8000_4B02);
        assert_eq!(UID_SHOULD_UMOUNT, 0xC000_4B09);
        assert_eq!(ADD_TRY_UMOUNT, 0x4000_4B12);
    }
}
