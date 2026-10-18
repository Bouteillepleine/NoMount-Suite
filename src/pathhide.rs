//! The maps cloak: keep the root stack's own libraries out of an app's
//! /proc/<pid>/maps.
//!
//! This is not about NoMount's injections. The Suite serves those mountlessly
//! (RRO via hookless), so they never appear in a mapping list to begin with.
//! What does appear is anything a Zygisk implementation dlopen()s into a target
//! process: on a stock OxygenOS 16 device with ReZygisk + LSPosed, ordinary
//! apps carry lines like
//!
//!     /data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
//!     /data/adb/modules/waenh_zygisk/lib/arm64-v8a/libwaenh.so
//!
//! in their OWN address space, readable with no privilege at all. The path
//! names /data/adb and the module directory outright.
//!
//! One rule covers every case seen, because every one of them is under the
//! root data directory and nothing in a stock ROM is:
//!
//!     /data/adb/
//!
//! The trailing slash matters. `pathhide` matches by substring, so a short
//! fragment is dangerous in a way that is easy to miss: "ksu" matches
//! /system/lib64/libvndksupport.so, and hiding a stock system library from
//! every app is a far louder artifact than the one being hidden.

use anyhow::Result;

use crate::nm::Nm;

/// Every mapping the root stack has been observed to leak sits under this, and
/// no stock path does. Kept as a slice so adding a second rule is a one-liner.
pub const RULES: &[&str] = &["/data/adb/"];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub programmed: usize,
    pub rejected: Vec<String>,
    /// The engine answered, and answered that it has no pathhide knob. That is
    /// every kernel built before the cloak existed, which is most of them: the
    /// engine ships in the kernel, so a module update alone never adds it. It
    /// is a statement about the kernel, not a fault, and nothing a detector can
    /// use against the user -- so it reads as plain information.
    pub cloak_absent: bool,
    /// The engine did not answer at all. Unlike the above this is a real
    /// problem, because it means nm could not reach an engine that should be
    /// there.
    pub cloak_unknown: bool,
}

impl Summary {
    /// Whether this pass left the cloak actually covering something. Mirrors
    /// `ghost::Summary::effective` so a health line can treat the two alike.
    #[allow(dead_code)]
    pub fn effective(&self) -> bool {
        self.programmed > 0 && self.rejected.is_empty()
    }

    pub fn line(&self) -> String {
        if self.cloak_absent {
            return "maps cloak: this kernel has no pathhide knob, so there is nothing to \
                    program - the engine ships in the kernel, not in this module"
                .into();
        }
        if self.cloak_unknown {
            return "\u{26a0} maps cloak: nm would not answer, so whether this kernel carries \
                    pathhide at all is unknown - nothing was programmed this pass"
                .into();
        }
        if !self.rejected.is_empty() {
            return format!(
                "\u{26a0} maps cloak: {} rule(s) programmed, {} refused by the engine ({})",
                self.programmed,
                self.rejected.len(),
                self.rejected.join(", ")
            );
        }
        format!("maps cloak: {} rule(s) programmed", self.programmed)
    }
}

/// Replace the live rule set with [`RULES`].
///
/// The engine takes one rule per write, so this clears first and then adds. A
/// failure partway leaves fewer rules than intended rather than a stale set,
/// which is the safer direction: a missing rule leaks, a stale one could hide
/// something the operator no longer wants hidden.
pub fn sync(nm: &Nm) -> Summary {
    let mut s = Summary::default();

    match nm.pathhide_present() {
        Some(false) => {
            s.cloak_absent = true;
            return s;
        }
        None => {
            s.cloak_unknown = true;
            return s;
        }
        Some(true) => {}
    }

    if nm.pathhide_ctl("-").is_err() {
        s.rejected.push("clear".into());
        return s;
    }

    for r in RULES {
        match nm.pathhide_ctl(r) {
            Ok(()) => s.programmed += 1,
            Err(_) => s.rejected.push((*r).to_string()),
        }
    }
    s
}

pub fn run_sync(print: bool) -> Result<()> {
    let nm = Nm::new();
    let s = sync(&nm);
    if print {
        println!("{}", s.line());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_is_specific_enough_to_be_safe() {
        for r in RULES {
            assert!(r.starts_with('/'), "{r}: a bare fragment matches far too much");
            assert!(r.len() >= 6, "{r}: too short to be unambiguous");
            assert!(!r.contains("//"), "{r}: doubled separator");
            // The libvndksupport lesson: no rule may match a stock system path.
            for stock in [
                "/system/lib64/libvndksupport.so",
                "/system/lib64/libc.so",
                "/vendor/lib64/hw/gralloc.default.so",
                "/apex/com.android.runtime/lib64/bionic/libc.so",
                "/product/etc/permissions/UimService.xml",
            ] {
                assert!(!stock.contains(*r), "{r} would hide the stock path {stock}");
            }
        }
    }

    #[test]
    fn summary_reports_unknown_distinctly_from_failure() {
        let s = Summary { cloak_unknown: true, ..Default::default() };
        assert!(!s.effective());
        assert!(s.line().contains("unknown"));

        let s = Summary { programmed: 1, ..Default::default() };
        assert!(s.effective());
    }

    /// A kernel predating the cloak is the common case, not a fault: the engine
    /// ships in the kernel, so anyone who updates only the module lands here.
    /// Warning them about a capability their kernel never had, that no detector
    /// can use against them, is noise they cannot act on.
    #[test]
    fn a_kernel_without_pathhide_is_stated_plainly_not_warned_about() {
        let s = Summary { cloak_absent: true, ..Default::default() };
        assert!(!s.effective());
        let line = s.line();
        assert!(!line.contains('\u{26a0}'), "absence must not render as a warning: {line}");
        assert!(!line.contains("unknown"), "the engine answered, so nothing is unknown: {line}");

        // The genuinely unreachable case keeps its warning.
        let s = Summary { cloak_unknown: true, ..Default::default() };
        assert!(s.line().contains('\u{26a0}'));
    }
}
