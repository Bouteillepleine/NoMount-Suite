//! Persistent whiteouts — hide stock ROM files that are themselves the tell.
//!
//! The engine supports whiteouts (`nm w`), but nothing kept a list, so any hide
//! was lost on reboot and had to be re-applied by hand. Mountify solves the same
//! problem with a curated `whiteouts.txt` plus a generator; this is the mountless
//! equivalent — a durable list re-applied at boot, with no module to install and
//! no mount to hide.
//!
//! Deliberately NOT seeded from someone else's list: the paths worth hiding are
//! ROM- and device-specific, and blindly whiting out a path this device does not
//! have is at best a no-op and at worst a boot hazard. `suggest` inspects THIS
//! device instead and only ever proposes paths that actually exist.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

pub const WHITEOUT_PATH: &str = "/data/adb/nomount/whiteouts.txt";


/// Statfs magic of the directory holding `target`.
fn parent_fs_magic(target: &Path) -> Option<i64> {
    crate::dirshape::fs_magic(target.parent().unwrap_or(Path::new("/")))
}

/// Does hiding `target` leave evidence in its PARENT's metadata?
///
/// Only erofs describes a directory's contents in the directory itself, and only
/// while it fits in one block:
///   * **erofs, size < 4096** — `st_size == 12*(entries incl . and ..) + name
///     bytes` exactly, so a hidden entry is one stat plus one getdents64 away…
///     UNLESS the engine corrects it, which it does from v13 (it recomputes both
///     size and nlink from the served listing). Hence the version gate: a new
///     Suite on an OLD kernel still leaves the hole and must still say so.
///   * **erofs, size >= 4096** — erofs pads each block by an amount that depends
///     on where the names fall (measured +18…+208 on stock dirs), so there is no
///     closed form for the engine to correct, and the hole stays.
///   * **overlayfs** — reports `nlink=1` and a size unrelated to the entry set.
///   * **f2fs / ext4** — block-granular (`/data/adb` is 3452 for 22 entries).
///     These were previously reported as holes by a plain "not overlayfs" test,
///     which was wrong: there is no invariant to contradict.
pub(crate) fn measurable_hole(target: &Path) -> bool {
    if parent_fs_magic(target) != Some(crate::dirshape::EROFS_MAGIC) {
        return false;
    }
    let dir = target.parent().unwrap_or(Path::new("/"));
    let size = fs::metadata(dir).map(|m| m.len()).unwrap_or(0);
    if size >= 4096 || size == 0 {
        return true; // multi-block: no closed form, engine cannot correct it
    }
    // Single block: only a hole on an engine that does not recompute.
    engine_predates_v13()
}

/// Cached: `measurable_hole` runs once per whiteout, and every call used to fork
/// `nm v`. A debloat module is ENTIRELY whiteouts, so `doctor` on one spawned a
/// process per hide for an answer that cannot change within a run.
fn engine_predates_v13() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| crate::nm::Nm::new().version().map(|v| v < 13).unwrap_or(true))
}

/// How a filename is matched. Anchored on purpose: a plain substring test for
/// "ksu" matches `/system/bin/cksum`, and a scanner that proposes hiding a stock
/// coreutil is worse than no scanner. Measured on OP15, where `cksum` and
/// `debuggerd` were the ONLY hits a substring sweep produced.
enum Match {
    Exact(&'static str),
    Prefix(&'static str),
    Suffix(&'static str),
}

impl Match {
    fn hits(&self, name: &str) -> bool {
        match self {
            Match::Exact(x) => name == *x,
            Match::Prefix(x) => name.starts_with(x),
            Match::Suffix(x) => name.ends_with(x),
        }
    }
}

/// What the scan looks for, and why each one is a tell. Every entry is a file a
/// ROOT SETUP leaves on a read-only ROM partition — none of it ships on a stock
/// device, so a hit is meaningful rather than a heuristic.
const PATTERNS: &[(Match, &str)] = &[
    (Match::Prefix("install-recovery"), "recovery-restore script; a classic root-check target"),
    (Match::Exact("daemonsu"), "SuperSU daemon binary"),
    (Match::Exact("supolicy"), "SuperSU sepolicy tool"),
    (Match::Exact(".installed_su_daemon"), "SuperSU install marker"),
    (Match::Prefix("magisk"), "Magisk binary or applet left on the ROM"),
    (Match::Exact("Superuser.apk"), "SuperSU manager APK on the ROM"),
    (Match::Prefix("SuperSU"), "SuperSU payload on the ROM"),
    (Match::Exact("XposedBridge.jar"), "Xposed framework jar; probed directly by RASP"),
    (Match::Prefix("app_process_xposed"), "Xposed's replacement zygote entry point"),
    (Match::Prefix("libriru"), "Riru injection library"),
    (Match::Prefix("libzygisk"), "Zygisk injection library"),
    (Match::Prefix("libxposed"), "Xposed injection library"),
    (Match::Suffix("SuperSUDaemon"), "SuperSU init.d hook"),
];

/// Directories the scan reads. One level each -- bounded on purpose, and these
/// are where a root setup actually writes. `/system/xbin`, `/system/sbin` and
/// `/system/etc/init.d` do not exist on a modern device; that is the point, and
/// a hit there is worth more than one anywhere else.
const SCAN_DIRS: &[&str] = &[
    "/system/bin", "/system/xbin", "/system/sbin", "/system/etc", "/system/etc/init",
    "/system/etc/init.d", "/system/addon.d", "/system/framework", "/system/lib",
    "/system/lib64", "/system/app", "/vendor/bin", "/vendor/etc/init",
    "/product/etc/init", "/system_ext/bin", "/system_ext/etc/init",
];

/// A path that stats but cannot be OPENED is not a real file — it is fabricated
/// at the syscall layer. KSU's sucompat does exactly this for `/system/bin/su`:
/// `ls` and `stat` answer, `open` returns ENOENT, and it is how root is invoked.
/// Proposing a whiteout for such a path is useless at best and, for su,
/// recommends hiding the root mechanism itself. Only ever suggest real files.
fn is_real_file(p: &Path) -> bool {
    p.is_file() && fs::File::open(p).is_ok()
}

/// Read the persisted list: trimmed, comment- and blank-stripped, deduplicated.
pub fn read() -> Result<Vec<String>> {
    let raw = match fs::read_to_string(WHITEOUT_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read whiteouts.txt"),
    };
    Ok(parse(&raw))
}

/// Mirror the engine's `nm_norm_vpath`: collapse runs of `/`, drop a trailing
/// one. `nm_alloc_rule` does `while (v_len > 1 && v_path[v_len-1] == '/') v_len--;`
/// and then normalises, and `nm list` prints the NORMALISED spelling — so a rule
/// filed from `/product/app/AIMemory/` comes back as `/product/app/AIMemory`.
///
/// We persisted the raw string and compared it against that, which broke both
/// readers at once: `whiteout list` reported "not applied (and no such path on
/// this ROM)" forever for a path that was hidden right then, and
/// `run_reload`'s `prunable()` — `!durable_whiteouts.contains(target)` against
/// the kernel's spelling — DELETED the whiteout on every reload while the
/// convergence loop re-added it and inflated the `+N rules` count. A shell tab
/// completing a directory name is all it takes to produce the entry.
///
/// This is the one normalisation `validate` refuses to do to `..` and to
/// symlinks, and deliberately so: those change WHICH FILE is named, so the
/// string a human reads back must stay the string they typed. A trailing or
/// doubled `/` names the same file either way, so normalising it costs the
/// reader nothing and is the only thing that makes our record and the engine's
/// agree. Collapse-then-trim is equivalent to the engine's trim-then-collapse.
fn norm(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for c in p.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Pure: trimmed, normalised, comment/blank-stripped, order-preserving,
/// deduplicated. Normalising HERE also heals a file already on disk, and the
/// dedup below then collapses the two spellings of one entry into one.
fn parse(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let e = line.trim();
        if e.is_empty() || e.starts_with('#') {
            continue;
        }
        let e = norm(e);
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

fn write(entries: &[String]) -> Result<()> {
    let mut body = String::from("# NoMount whiteouts — one absolute path per line, re-applied at boot.\n");
    for e in entries {
        body.push_str(e);
        body.push('\n');
    }
    // Atomic. The engine's copy of a whiteout is runtime-only, so THIS FILE is
    // the durable state: losing it to a half-write un-hides every path at the
    // next boot. See crate::statefile.
    crate::statefile::write_atomic(WHITEOUT_PATH, body).context("write whiteouts.txt")
}

/// A path is only worth whiting out if it is absolute, currently exists, and is
/// not a partition root. Hiding a whole partition masks every stock entry under
/// it, which is the same forkSystemServer abort an injection on a root causes.
pub(crate) fn validate(p: &str) -> Result<()> {
    let path = Path::new(p);
    if !path.is_absolute() {
        anyhow::bail!("not an absolute path: {p}");
    }
    // Refuse `..` outright, BEFORE counting depth. Path::components() does not
    // resolve it -- ParentDir comes back as its own component -- so
    // "/system/../product" counted four, cleared the depth test below, and then
    // resolved to "/product" in the engine, which resolves the vpath with
    // kern_path(LOOKUP_FOLLOW). That is a partition-root whiteout reached
    // through the check that exists to prevent one, and a partition-root rule is
    // what bootlooped zygote by masking every stock entry underneath.
    // Normalising instead of refusing would be worse: the path a caller typed
    // and the path we act on should be the same string, and a whiteout list is
    // read back by humans.
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        anyhow::bail!("refusing {p}: '..' is not allowed in a whiteout path (pass the resolved path)");
    }
    // A whiteout target is the SECOND door into the rule table, and it did not
    // ask the question the first one asks. `mount::path_is_representable` (see
    // its doc for the escalation) is not a cosmetic check: `nm::parse_list` is
    // line-oriented, so a target carrying a newline comes back out of `nm list`
    // as an extra rule that `absorb::refresh_app_apks` and `add_repointing` will
    // act on — injecting a module's file over an installed app's base.apk, as
    // root. Reachable with no user action at all: `absorb::rom_tmpfs_target`
    // takes field 4 of a mountinfo line and OCTAL-UNESCAPES it, so a module that
    // mounts a tmpfs on a path containing `\012` hands us a real newline here,
    // and this function is the only gate between it and `nm.whiteout()`.
    // The CLI reaches the same hole more cheaply: a persisted entry with a
    // newline in it splits into two on the next `parse()`, and `apply()` then
    // fails — non-zero, from a boot script — on every boot thereafter.
    crate::mount::path_is_representable(path)
        .map_err(|why| anyhow::anyhow!("refusing {p}: {why}"))?;
    // DELEGATE the rest to the predicate the module plan uses, rather than
    // re-deriving a weaker subset of it.
    //
    // This used to be a bare depth test plus a `/data` prefix test, and it was
    // strictly weaker than `mount::can_whiteout` in a way nothing surfaced:
    // `/apex/com.android.art/bin/dex2oat`, `/proc/self/maps`, `/sys/...`,
    // `/dev/...`, `/mnt/...` and `/storage/...` all passed here while the plan
    // refuses every one of them as "not a ROM partition". That mattered because
    // this function IS the gate on four paths that believe it is the same
    // predicate and say so in their comments -- `whiteout add` (CLI and WebUI),
    // `whiteout::apply` (both boot entry points, every boot),
    // `mount::run_reload`'s durable-convergence loop, and
    // `absorb::reapply_tmpfs_whiteouts`. A durable entry naming an /apex binary
    // was therefore accepted, persisted, and re-asserted on every boot, with
    // nothing in the product able to notice.
    //
    // The two tests above stay HERE and stay FIRST, because `can_whiteout`
    // cannot make them: it does not resolve `..` either (so `/system/../product`
    // clears its partition-root test and then resolves to one), and on a
    // relative path its `components().nth(1)` reads the second component as the
    // partition, which accepts `system/bin/x`.
    crate::mount::can_whiteout(path).map_err(|why| anyhow::anyhow!("refusing {p}: {why}"))?;
    // ...and again on the RESOLVED path.
    //
    // CORRECTED (round 8). The round-7 rationale here claimed that
    // `whiteout add /system/vendor` "lands a whiteout on /vendor, the
    // bare-partition-root shape that masks every stock entry and aborts
    // forkSystemServer". Re-read against `hookless/src/nomount.c`, that is not
    // what the engine does, and the difference matters to anyone reasoning from
    // this comment later:
    //
    //   * `nomount_generate_virtual_topology()` walks the vpath STRING back to
    //     its last `/`, resolves only the PARENT prefix with `kern_path`, and
    //     files the rule as a child node named by the last component.
    //     Enforcement is that child: `nomount_hijacked_lookup()` matches the
    //     name inside the parent's `dir_node` and, for NM_FLAG_WHITEOUT,
    //     `d_add(dentry, NULL)`.
    //   * `nm_alloc_rule()`'s `kern_path` on the FULL vpath only samples stock
    //     metadata for NM_FLAG_SHADOWS_STOCK / NM_FLAG_IS_DIR. It never
    //     relocates the rule.
    //   * A bare partition root is refused by the engine independently:
    //     `nm_target_too_shallow()` returns -EINVAL below two components.
    //
    // So `/system/vendor` hides the NAME `vendor` INSIDE `/system` — every
    // legacy `/system/vendor/...` lookup breaks — and no rule on `/vendor` is
    // ever created. Smaller blast radius than the old comment claimed, still a
    // bad idea, and the gate is kept because it is one `canonicalize` and
    // refusing it costs nothing. `/system/vendor`, `/system/product` and
    // `/system/system_ext` really are symlinks to the partition roots on every
    // modern Android (verified on an OP15/CPH2747, 2026-09-07), each is three
    // components so `is_partition_root` says no, and `system` is not a non-ROM
    // root — which is why the literal string sails through `can_whiteout` and
    // only the resolved form catches it.
    //
    // The RESOLVED path is only the gate. What gets persisted is still the string
    // the user typed — the argument for that stands, and a whiteout list is read
    // back by humans. (`norm` above is not an exception to it: collapsing a
    // trailing `/` does not change which file is named.)
    //
    // A path that does not exist cannot be resolved and is left to the string
    // test alone: `add` deliberately accepts an absent target ("recorded anyway"),
    // and a name that is not there yet cannot be a symlink to anything.
    if let Ok(real) = fs::canonicalize(path) {
        resolved_is_allowed(path, &real).map_err(|why| anyhow::anyhow!("refusing {p}: {why}"))?;
    }
    Ok(())
}

/// The gate applied to the RESOLVED path, kept pure so it can be tested without a
/// ROM to point at.
///
/// `Ok` when the link goes nowhere interesting or resolves to something
/// `can_whiteout` still permits; `Err` naming both paths when resolution turns an
/// acceptable-looking string into one the plan refuses.
fn resolved_is_allowed(literal: &Path, resolved: &Path) -> std::result::Result<(), String> {
    if resolved == literal {
        return Ok(());
    }
    crate::mount::can_whiteout(resolved)
        .map_err(|why| format!("it resolves to {} — {why}", resolved.display()))
}

pub fn add(target: &str, force: bool) -> Result<()> {
    // Serialise the read-modify-write against the OTHER writer of this file.
    //
    // `read()` -> mutate -> `write()` is not atomic just because `write()` is:
    // `absorb`'s M-S8 migration calls `whiteout::remove` while holding this same
    // lock, from a pass service.sh fires 45s after boot and uidwatch fires on
    // every package change. Interleaved, either the user's new hide is lost with
    // a green toast, or the migration's removal is undone and the target ends up
    // in BOTH `whiteouts.txt` and `absorbed-tmpfs.list` — "uninstall the module
    // and the ROM directory stays hidden forever", the exact failure M-S8 exists
    // to end, curable only by a manual `whiteout remove` on a path the user never
    // added.
    //
    // `pass_lock` is the right lock rather than a new one: it already serialises
    // the only other writer, it is bounded, and its "proceed unserialised rather
    // than stall" fallback is the correct trade for a user-initiated verb.
    let _pass = crate::mount::pass_lock();
    // Normalised to the spelling the engine will file the rule under -- see
    // `norm`. Without it the entry we persist and the target `nm list` reports
    // are different strings, and every reader that compares them is wrong.
    let t = norm(target.trim());
    validate(&t)?;
    let p = Path::new(&t);
    // Warn, do not refuse. Module whiteouts are applied off overlayfs (see
    // mount::whiteout_leaves_hole), and a CLI that still refused the same
    // operation would be the odd one out. `--force` is kept as a no-op so
    // existing scripts and the message this used to print stay valid; passing it
    // just silences the note.
    if measurable_hole(p) && !force {
        eprintln!(
            "nomount: note - hiding {t} leaves a measurable hole: its parent is a multi-block \
             erofs directory (or the engine predates v13), so the size and link count still \
             count this entry and the engine cannot recompute them. Applying anyway; \
             `nomount check --plan` lists every such path."
        );
    }
    if !p.exists() {
        eprintln!("nomount: note - {t} does not exist right now; recorded anyway");
    } else if !is_real_file(p) && p.is_file() {
        eprintln!(
            "nomount: warning - {t} stats but cannot be opened, so it is fabricated at the \
             syscall layer (e.g. KSU sucompat's su), not a real file. A whiteout will not \
             hide it and may interfere with whatever provides it."
        );
    }
    let mut list = read()?;
    if list.contains(&t) {
        println!("already listed: {t}");
        return Ok(());
    }
    list.push(t.clone());
    write(&list)?;
    // Apply immediately so the effect does not wait for a reboot.
    // The message was right and the EXIT CODE was not: both arms returned Ok(()),
    // so `nomount whiteout add` exited 0 whether or not the engine took it. The
    // WebUI's Hidden paths card reads errno first (index.html `woApply`, and the
    // delegated row handler that calls it) — so a failed apply toasted "Hidden"
    // and removed the row from the suggestion list, for a file every app can still
    // read. The list entry IS saved, which is why this is a warning in the text
    // and a failure in the status; the card prints the text on a non-zero exit for
    // exactly that reason.
    match Nm::new().whiteout(Path::new(&t)) {
        Ok(()) => {
            println!("ok: {t} hidden (persists across reboots)");
            Ok(())
        }
        Err(e) => Err(e.context(format!(
            "saved {t} to the durable list, but applying it now FAILED — the path is still \
             visible until the next reboot"
        ))),
    }
}

/// Take the pass lock and remove. For a caller that already holds it, use
/// [`remove_locked`] — see the note there.
pub fn remove(target: &str) -> Result<()> {
    // Same lock, same reason as `add`.
    let _pass = crate::mount::pass_lock();
    remove_locked(target)
}

/// `remove`, for a caller that ALREADY HOLDS `mount::pass_lock()`.
///
/// CONTRACT: only call this from inside a pass that took the lock. It does not
/// take it, so calling it from anywhere else re-opens the unserialised
/// read-modify-write `add`'s comment describes.
///
/// It exists because `pass_lock` is a plain flock on one path, and flock locks
/// attach to the open file description: a second `pass_lock()` in the SAME
/// process conflicts with the first. `absorb::run_absorb` holds the lock and the
/// tmpfs takeover called `whiteout::remove` per entry, so each of those paid the
/// full PASS_LOCK_WAIT spin (25s) and then proceeded unserialised anyway, with a
/// "another pass still holds ..." line on stderr for a pass that was holding it
/// itself. A migration touching a handful of entries stalled the boot for
/// minutes for nothing.
pub(crate) fn remove_locked(target: &str) -> Result<()> {
    // Normalised for the same reason `add` normalises: the durable list holds the
    // engine's spelling, so `whiteout remove /product/app/Foo/` must match the
    // `/product/app/Foo` we wrote.
    let normalised = norm(target.trim());
    let t = normalised.as_str();
    let mut list = read()?;
    let before = list.len();
    list.retain(|x| x != t);
    if list.len() == before {
        println!("not listed: {t}");
        return Ok(());
    }
    write(&list)?;
    // Two outcomes, like `add`. Dropping the row is only half of it: if the engine
    // refuses the `del` the path stays whited out for the rest of the session, and
    // "no longer hidden" -- printed by the CLI and echoed by the WebUI -- asserts
    // the opposite of what the user will see.
    // ...and the exit code has to say so too. `Ok(())` on both arms made the
    // WebUI, which reads only errno, toast "No longer hidden" for a path that
    // stays whited out for the rest of the session — the exact assertion the
    // comment above says must not be made.
    match Nm::new().del(Path::new(t)) {
        Ok(()) => {
            println!("ok: {t} no longer hidden");
            Ok(())
        }
        Err(e) => Err(e.context(format!(
            "removed {t} from the durable list, but un-hiding it now FAILED — it stays \
             hidden until the next reboot"
        ))),
    }
}

/// The engine's live rule set, or an error saying we could not read it.
///
/// `unwrap_or_default()` used to stand here and in [`injected_targets`], and it
/// turned "cannot ask the engine" into "the engine holds nothing". `Nm::list`
/// fails on a dead engine, a missing or relocated `nm`, a netlink timeout, and
/// -- BY CONTRACT -- on a TRUNCATED dump (`userspace/src/nm.c` exits 4 there
/// precisely so "a prefix" and "the whole set" stay distinguishable). Every one
/// of those became an empty set, and the two callers then asserted something
/// they had not measured: `list()` printed "not applied (and no such path on this
/// ROM)" -- the exact hidden-vs-absent conflation it exists to end -- for every
/// saved entry, and `scan()` lost the `injected` guard entirely and started
/// proposing whiteouts over a module's OWN content.
///
/// [`crate::nm::parse_list`], not a local split, for the reason that parser
/// documents: it is the ONE reader of the client's output. The hand-rolled
/// version here peeled ` (whiteout)` as a suffix and nothing else, so a rule
/// carrying ` (public)` after it would not have matched.
fn live_rules() -> Result<Vec<crate::nm::LiveRule>> {
    Ok(crate::nm::parse_list(&Nm::new().list().context(
        "cannot read the engine's rule set, so nothing can be said about which entries are applied",
    )?))
}

/// Targets the engine is currently whiting out, from `nm list`.
fn live_whiteouts() -> Result<std::collections::HashSet<String>> {
    Ok(live_rules()?
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::Whiteout)
        .map(|r| r.target.to_string_lossy().into_owned())
        .collect())
}

pub fn list() -> Result<()> {
    let entries = read()?;
    if entries.is_empty() {
        println!("no whiteouts configured");
        return Ok(());
    }
    // Path-absence alone cannot tell "hidden" from "was never there": an entry for a
    // path this ROM does not ship reported `hidden`, which reads as working. Ask the
    // engine which targets it is actually serving, and use absence only to confirm.
    let live = live_whiteouts()?;
    for e in &entries {
        let applied = live.contains(e);
        let present = Path::new(e).exists();
        let state = match (applied, present) {
            (true, false) => "hidden",
            (true, true) => "applied, but still visible - the engine is not serving it",
            (false, false) => "not applied (and no such path on this ROM)",
            (false, true) => "not applied - run `nomount whiteout apply`",
        };
        println!("{e}\t{state}");
    }
    Ok(())
}

/// Re-apply the whole list. Called at boot, after the mount pass.
pub fn apply() -> Result<()> {
    let nm = Nm::new();
    let (mut ok, mut failed) = (0u32, 0u32);
    for e in read()? {
        if validate(&e).is_err() {
            eprintln!("nomount: skipping invalid whiteout entry {e:?}");
            failed += 1;
            continue;
        }
        if measurable_hole(Path::new(&e)) {
            eprintln!(
                "nomount: warning - {e} leaves a measurable hole; the whiteout is detectable \
                 from its directory's size and link count"
            );
        }
        match nm.whiteout(Path::new(&e)) {
            Ok(()) => ok += 1,
            Err(_) => failed += 1,
        }
    }
    println!("nomount whiteout: applied {ok}, failed {failed}");
    if failed > 0 {
        // Exit non-zero. This runs unattended from metamount.sh and service.sh,
        // which only see the process's status: returning Ok made a boot where
        // every whiteout failed indistinguishable from one where all applied, and
        // a whiteout that did not apply means a path the user believes is hidden
        // is plainly visible. The message carries both counts so the single line
        // service.sh puts in kmsg is self-contained.
        anyhow::bail!("{failed} of {} whiteout(s) could not be applied (applied {ok})", ok + failed);
    }
    Ok(())
}

/// Targets NoMount is currently serving.
///
/// A scanner that walks `/system/bin` will happily meet a file a MODULE put
/// there, and proposing a whiteout for it would hide that module's own content.
/// The old three-entry list never needed this check; a directory walk does.
///
/// Through [`live_rules`], which is also why the failure PROPAGATES: with the
/// dump unreadable this set is empty, and an empty set here means the guard is
/// gone and the scan proposes hiding module content.
fn injected_targets() -> Result<std::collections::HashSet<String>> {
    Ok(live_rules()?
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::Inject)
        .map(|r| r.target.to_string_lossy().into_owned())
        .collect())
}

/// Can an ordinary, non-root-granted app see this path at all?
///
/// The decisive question, and the one a path list cannot answer. `/system/bin/su`
/// is the case that proves it: on a sucompat kernel it is present for a granted
/// uid and ENOENT for every app, so it is not a tell and hiding it would only
/// interfere with how root is invoked. uid 9999 (`nobody`) is never on the allow
/// list, and was verified on OP15 to see stock AND injected files while getting
/// ENOENT for `su`.
fn app_can_see_raw(path: &str) -> bool {
    // Single-quoted: `path` is a FILENAME READ OFF THE FILESYSTEM, and this string
    // is handed to a shell. A ROM (or a module writing into one) carrying a name
    // like `x; id` would otherwise run it. uid 9999 is unprivileged, but a shell
    // built by concatenation is not something to leave standing.
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    std::process::Command::new("su")
        .args(["9999", "-c", &format!("ls -d {quoted}")])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(true) // cannot ask -> do not silently drop the candidate
}

/// Does the visibility probe work AT ALL on this device?
///
/// `unwrap_or(true)` above honours "cannot ask -> do not drop the candidate" for
/// exactly one of the two ways of not being able to ask: `su` failing to SPAWN.
/// If `su` exists but refuses the `su <uid> -c` form, is denied by the manager
/// for this context, or is one of the cloaked/renamed shapes this project ships
/// against, `.output()` returns `Ok` with a non-zero status -- so every candidate
/// read as invisible, every one was dropped, and `suggest` then printed "no
/// ordinary app can see them, so hiding them would be a no-op", an assertion the
/// code had not measured. On the only devices where `suggest` has anything to say
/// (a real `install-recovery.sh` or `magiskinit` on the ROM) the answer was
/// "nothing to suggest" plus a confident explanation.
///
/// `/system/bin/sh` is on every device and visible to every app, so a `false`
/// here means the probe itself does not work. Cached: `scan` would otherwise
/// re-run it per candidate for an answer that cannot change within a run.
fn probe_works() -> bool {
    static P: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *P.get_or_init(|| app_can_see_raw("/system/bin/sh"))
}

/// One thing the scan found worth hiding.
pub struct Candidate {
    pub path: String,
    pub why: &'static str,
    /// Hiding it still leaves the parent's size and link count counting it.
    /// Reported, NOT filtered -- see `scan`.
    pub hole: bool,
}

/// Walk the ROM for files that only a root setup leaves behind.
///
/// Returns (candidates, skipped_invisible, skipped_injected) so the caller can
/// say what was filtered rather than just showing a short list.
///
/// `Err` when the engine's rule set could not be read: without it the
/// "NoMount is already serving this" guard below is silently absent, and the
/// scan would propose whiteouts over a module's own content.
pub fn scan() -> Result<(Vec<Candidate>, usize, usize)> {
    let have = read().unwrap_or_default();
    let injected = injected_targets()?;
    // One control probe for the whole sweep, not one answer per candidate.
    let can_probe = probe_works();
    let (mut out, mut invisible, mut ours) = (Vec::new(), 0usize, 0usize);

    // Depth 2, not 1. `/system/app` and `/system/priv-app` hold one DIRECTORY per
    // app, so a stale `Superuser.apk` lives at `/system/app/Superuser/Superuser.apk`
    // and a depth-1 walk could never match it -- the pattern was unreachable.
    let mut queue: Vec<(PathBuf, u8)> =
        SCAN_DIRS.iter().map(|d| (PathBuf::from(d), 0u8)).collect();
    let mut seen = 0usize;
    while let Some((dir, depth)) = queue.pop() {
        // Bounded: a symlinked ROM root could otherwise turn this into a full walk.
        seen += 1;
        if seen > 4096 {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let path = e.path();
            if depth < 1 && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                queue.push((path.clone(), depth + 1));
            }
            let Some((_, why)) = PATTERNS.iter().find(|(m, _)| m.hits(&name)) else { continue };
            let ps = path.to_string_lossy().into_owned();

            // Fabricated-at-the-syscall-layer paths stat but never open; a
            // whiteout cannot hide one and may break whatever provides it.
            if !is_real_file(&path) {
                continue;
            }
            if have.contains(&ps) || validate(&ps).is_err() {
                continue;
            }
            if injected.contains(&ps) {
                ours += 1;
                continue;
            }
            if can_probe && !app_can_see_raw(&ps) {
                invisible += 1;
                continue;
            }
            // NOT a filter. `/system/bin` is a multi-block erofs directory (8541
            // bytes on OP15), so every candidate in the one place these files
            // actually live leaves a measurable hole -- dropping them here made the
            // scan silently report "nothing found" on exactly the device that has
            // something to find. `whiteout add` applies such a hide anyway and says
            // so, so the scan proposes it and carries the same warning.
            out.push(Candidate { path: ps, why, hole: measurable_hole(&path) });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((out, invisible, ours))
}

/// `nomount whiteout suggest` — scan THIS device and propose what it finds.
pub fn suggest() -> Result<()> {
    let (found, invisible, ours) = scan()?;
    for c in &found {
        let note = if c.hole { " (hiding it leaves a measurable hole in the parent)" } else { "" };
        println!("{}\t{}{note}", c.path, c.why);
    }
    if found.is_empty() {
        println!(
            "nothing to suggest: no root-setup leftovers on any ROM partition here. On a \
             mountless setup that is the expected result -- nothing is written to /system, so \
             there is nothing on it to hide."
        );
    } else {
        println!("\n{} candidate(s); add with: nomount whiteout add <path>", found.len());
    }
    if !probe_works() {
        // Say what was NOT measured, instead of the claim this used to make on
        // the same evidence. See `probe_works`.
        println!(
            "(visibility filter unavailable: `su 9999` did not answer for /system/bin/sh, so \
             nothing was skipped on the ground that no ordinary app can see it)"
        );
    } else if invisible > 0 {
        println!(
            "({invisible} match(es) skipped: no ordinary app can see them, so hiding them \
             would be a no-op)"
        );
    }
    if ours > 0 {
        println!("({ours} match(es) skipped: NoMount is serving them -- they are module content)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_strips_comments_blanks_and_dedups() {
        let raw = "# hdr\n\n/system/bin/x\n  /system/bin/y  \n/system/bin/x\n";
        assert_eq!(parse(raw), vec!["/system/bin/x".to_string(), "/system/bin/y".to_string()]);
    }

    /// The false positive that made a substring sweep useless: "ksu" is inside
    /// `cksum`, and `debuggerd` contains "adbd". Both are stock binaries, and
    /// proposing a hide for either is worse than proposing nothing.
    #[test]
    fn patterns_are_anchored_and_miss_stock_binaries() {
        for stock in ["cksum", "debuggerd", "sh", "linker64", "app_process64", "toybox"] {
            assert!(
                !PATTERNS.iter().any(|(m, _)| m.hits(stock)),
                "{stock} is a stock binary and must never be proposed"
            );
        }
        for tell in [
            "install-recovery.sh", "install-recovery_oplus.sh", "daemonsu", "magiskinit",
            "XposedBridge.jar", "libriru.so", "99SuperSUDaemon",
        ] {
            assert!(PATTERNS.iter().any(|(m, _)| m.hits(tell)), "{tell} must be found");
        }
    }

    #[test]
    fn rejects_partition_roots_and_relative_and_data() {
        assert!(validate("/product").is_err(), "partition root must be refused");
        assert!(validate("/").is_err());
        assert!(validate("system/bin/x").is_err(), "relative must be refused");
        assert!(validate("/data/adb/x").is_err(), "/data is not a ROM path");
        assert!(validate("/system/bin/install-recovery.sh").is_ok());
    }

    /// The durable list may not name a path the module plan would refuse.
    ///
    /// `validate` is the gate on four separate paths that each believe it is the
    /// same predicate `mount::can_whiteout` applies, and it was strictly weaker:
    /// a depth test plus a `/data` prefix, with no idea that `/apex`, `/proc`,
    /// `/sys`, `/dev`, `/mnt` and `/storage` are not ROM partitions. An entry
    /// naming an /apex binary was accepted, written to whiteouts.txt, and
    /// re-asserted on every boot by `whiteout::apply`.
    #[test]
    fn refuses_every_root_the_module_plan_refuses() {
        for p in [
            "/apex/com.android.art/bin/dex2oat",
            "/apex/com.android.runtime/bin/dex2oat",
            "/proc/self/maps",
            "/sys/kernel/notes",
            "/dev/binder",
            "/mnt/vendor/persist/x",
            "/storage/emulated/0/x",
            "/data/adb/modules/x/y",
            "/d/tracing/x",
        ] {
            assert!(validate(p).is_err(), "{p} must be refused");
            assert!(
                crate::mount::can_whiteout(Path::new(p)).is_err(),
                "{p}: the two predicates must agree"
            );
        }
        // ...and the ROM paths a whiteout is FOR still pass, on both.
        for p in [
            "/system/bin/install-recovery.sh",
            "/product/app/AIMemory",
            "/my_stock/app/OplusOperationManual",
            "/vendor/etc/foo.conf",
        ] {
            assert!(validate(p).is_ok(), "{p} must be allowed");
            assert!(crate::mount::can_whiteout(Path::new(p)).is_ok(), "{p}");
        }
    }

    /// `..` must not be a way around the partition-root refusal.
    ///
    /// The depth test counts Path::components(), which does NOT resolve `..` --
    /// it yields ParentDir as its own component. So "/system/../product" counted
    /// four and passed while resolving to "/product", and the engine resolves the
    /// vpath with kern_path(LOOKUP_FOLLOW), which does resolve it. That is the
    /// exact rule shape recorded as bootlooping zygote by masking a partition
    /// root, arrived at through the check meant to prevent it.
    /// A SYMLINK to a partition root is the other half of the same hazard, and it
    /// needs no `..` at all.
    ///
    /// `/system/vendor -> /vendor`, `/system/product -> /product` and
    /// `/system/system_ext -> /system_ext` exist on every modern Android —
    /// verified on an OP15 (CPH2747), 2026-09-07. Each is three components, so
    /// `is_partition_root` says no and `system` is not a non-ROM root, which is
    /// how the literal string clears `can_whiteout`. What the engine then does
    /// with it is NOT "a whiteout on /vendor" — see the corrected note in
    /// `validate`: the rule is filed under the vpath string's parent, so it hides
    /// the name `vendor` inside `/system` and breaks every legacy
    /// `/system/vendor/...` lookup, while `/vendor` itself is untouched and the
    /// bare root is refused by `nm_target_too_shallow` anyway. Still worth
    /// refusing, and one `canonicalize` to do it.
    ///
    /// Tested on the PURE half: the resolution itself is one `canonicalize` and
    /// needs a real ROM, but the decision it feeds does not.
    #[test]
    fn a_symlink_that_resolves_to_a_partition_root_is_refused() {
        // The three real ones.
        for (lit, real) in [
            ("/system/vendor", "/vendor"),
            ("/system/product", "/product"),
            ("/system/system_ext", "/system_ext"),
        ] {
            let e = resolved_is_allowed(Path::new(lit), Path::new(real))
                .expect_err("a link onto a partition root must be refused");
            assert!(e.contains(real), "the message must name where it lands: {e}");
        }
        // A link that lands somewhere still legal is fine -- most of /system's
        // links do, and refusing them all would be the over-correction.
        assert!(resolved_is_allowed(
            Path::new("/system/etc/hosts"),
            Path::new("/product/etc/hosts")
        )
        .is_ok());
        // Not a link at all: canonicalize returns the same path and there is
        // nothing to re-check.
        assert!(
            resolved_is_allowed(Path::new("/product/app/Foo"), Path::new("/product/app/Foo"))
                .is_ok()
        );
        // ...and the trap this closes: the literal string passes the plan's own
        // predicate, which is why the resolved check has to exist at all.
        assert!(crate::mount::can_whiteout(Path::new("/system/vendor")).is_ok());
        assert!(crate::mount::can_whiteout(Path::new("/vendor")).is_err());
    }

    #[test]
    fn rejects_dotdot_escapes_to_a_partition_root() {
        for p in [
            "/system/../product",
            "/product/app/../..",
            "/system/bin/../../vendor",
            "/product/./..",
        ] {
            assert!(validate(p).is_err(), "{p} resolves to a partition root and must be refused");
        }
        // A `..` that stays deep is still refused: normalising is not this
        // function's job, and a caller that wants a real path can pass one.
        assert!(validate("/system/bin/../lib/x.so").is_err(), "any .. must be refused");
        // ...while the ordinary paths keep working.
        assert!(validate("/product/overlay/Foo.apk").is_ok());
        assert!(validate("/system/bin/install-recovery.sh").is_ok());
    }

    /// A whiteout target is the SECOND door into the rule table, and it did not
    /// ask the question the first one asks. A newline in a target is a forged
    /// rule in `nm list` that `absorb` acts on as root, and it arrives with no
    /// user action: `absorb::rom_tmpfs_target` octal-unescapes a mountinfo field
    /// and hands the result straight to `validate`.
    #[test]
    fn a_whiteout_target_the_wire_format_cannot_carry_is_refused() {
        for bad in [
            "/system/etc/A\n/data/app/~~a==/com.bank-1==/base.apk",
            "/system/etc/A\r/x",
            "/system/etc/A\tB",
            "/system/etc/A -> /data/adb/modules/evil/p",
            "/system/etc/A [UID: 10123]",
            "/system/etc/A (whiteout)",
            "/system/etc/A (public)",
            "/system/etc/A (virtual dir)",
        ] {
            assert!(validate(bad).is_err(), "{bad:?} must be refused");
            assert!(
                crate::mount::path_is_representable(Path::new(bad)).is_err(),
                "{bad:?}: the two gates must agree"
            );
        }
        // ...and the spellings that are only a hazard as a SUFFIX stay legal
        // mid-path, exactly as the plan's gate has it.
        assert!(validate("/system/etc/A (whiteout) B/c.conf").is_ok());
        assert!(validate("/system/etc/A [UID] B").is_ok());
    }

    /// The engine normalises the vpath and `nm list` prints the normalised
    /// spelling, so the string we persist has to be that one. It was not: a
    /// trailing `/` — which shell tab-completion appends to any directory —
    /// made `whiteout list` say "not applied (and no such path on this ROM)"
    /// forever, and made `run_reload`'s prune DELETE the whiteout on every run.
    #[test]
    fn norm_mirrors_the_engines_vpath_normalisation() {
        assert_eq!(norm("/product/app/AIMemory/"), "/product/app/AIMemory");
        assert_eq!(norm("/product/app/AIMemory//"), "/product/app/AIMemory");
        assert_eq!(norm("/product//app///AIMemory/"), "/product/app/AIMemory");
        assert_eq!(norm("//"), "/", "the root survives as itself");
        assert_eq!(norm("/"), "/");
        assert_eq!(norm(""), "");
        // A name with a space or a bracket is untouched -- only separators move.
        assert_eq!(norm("/product/app/Foo (2)/x.apk"), "/product/app/Foo (2)/x.apk");
    }

    /// ...and the durable file is healed on read, so an entry an older Suite
    /// already wrote with a trailing slash starts matching. The dedup then
    /// collapses the two spellings into one row.
    #[test]
    fn parse_normalises_and_collapses_the_two_spellings() {
        let raw = "/product/app/Foo/\n/product/app/Foo\n/system//bin//x\n";
        assert_eq!(
            parse(raw),
            vec!["/product/app/Foo".to_string(), "/system/bin/x".to_string()]
        );
    }
}
