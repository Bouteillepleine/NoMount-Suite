  "use strict";

  function vpath(l) {
    let s = String(l).trim();
    s = s.replace(/\s\[UID:\s*\d+\]$/, "");
    if (s.endsWith(" (public)")) s = s.slice(0, -9);
    const i = s.lastIndexOf(" -> ");
    if (i >= 0) return s.slice(0, i).trim();
    if (s.endsWith(" (whiteout)")) s = s.slice(0, -11);
    else if (s.endsWith(" (virtual dir)")) s = s.slice(0, -14);
    return s.trim();
  }
  function ruleDump() {
    if (RULES) return RULES;
    RULES = nm("vfs list").then(function (r) {
      const lines = r.errno === 0
        ? r.stdout.split("\n").map(x => x.trim())
            .filter(x => x && x.startsWith("/")) : [];
      const d = {
        ok: r.errno === 0,
        raw: (r.stdout || "").trim(),
        err: (r.stderr || "").trim(),
        lines: lines,
        rules: lines.filter(l => !l.includes("(virtual dir)")).length,
        injects: lines.filter(l => !l.includes("(virtual dir)") && !l.includes("(whiteout)"))
                      .map(vpath),
      };
      d.rro = d.injects.filter(t => /\/overlay\/[^\s]*\.apk$/.test(t));
      return d;
    });
    return RULES;
  }

  async function refreshStatus() {
    const gen = ++STATUS_GEN;
    const d = await ruleDump();
    if (gen !== STATUS_GEN) return d.rules;
    const dot = $("dot");
    const wasLive = ENGINE_LIVE;
    ENGINE_LIVE = d.ok;
    const e0 = d.err || "";
    ENGINE_STATE = d.ok ? "live"
      : /socket was denied/.test(e0) ? "denied"
      : /no NoMount engine/.test(e0) ? "absent"
      : /cannot open the NoMount netlink socket/.test(e0) ? "unreachable"
      : "error";
    paintHealthLine(CHECK);
    if (wasLive !== d.ok) {
      if (!CHECK_RUNNING) renderCheck(CHECK);
      refreshStealth();
    }
    if (!d.ok) {
      // nm already tells the three cases apart on stderr. Reading only errno asserted the
      // worst one -- "no kernel driver" -- over an SELinux denial on the netlink socket,
      // where the engine is usually live and injecting.
      const e = d.err || "";
      if (/socket was denied/.test(e)) {
        $("state").textContent = "Engine unreachable";
        $("substate").textContent =
          "SELinux denied this page the netlink socket, so the engine could not answer. " +
          "Injections may well be live - run `nomount check` from a terminal to be sure.";
      } else if (/no NoMount engine/.test(e) && (await zipVariant()) === "lkm") {
        if (gen !== STATUS_GEN) return 0;
        // The LKM zip carries the engine as a module, so the kernel is not the thing to
        // replace: the module did not load on it.
        $("state").textContent = "Engine module not loaded";
        $("substate").textContent =
          "the NoMount module did not load on this kernel, so nothing is being injected. " +
          "Get the LKM release that matches this kernel, or put a nomount.ko built for it " +
          "at /data/adb/nomount/nomount.ko, then reboot. boot.log says which KMI was tried.";
      } else if (/no NoMount engine/.test(e)) {
        $("state").textContent = "No kernel driver";
        $("substate").textContent =
          "this kernel was not built with NoMount. Flash one that was, or the " +
          "01_NoMount-Module-LKM zip, then reboot. " +
          "Nothing is being injected. Prebuilt OnePlus kernels: " +
          "github.com/Bouteillepleine/OnePlus-BakaSu_NMS/releases · " +
          "source: github.com/Bouteillepleine/NoMount-Suite";
      } else if (/ended early|list is incomplete/.test(e)) {
        $("state").textContent = "Rule list incomplete";
        $("substate").textContent =
          "the engine's rule list was cut off mid-read (rules were changing), so its state is " +
          "unknown, not missing. Press refresh to ask again.";
      } else if (/did not answer/.test(e)) {
        $("state").textContent = "Engine slow to answer";
        $("substate").textContent =
          "the rule list timed out, so its state is unknown. Press refresh to ask again.";
      } else if (/no webui env/.test(e)) {
        $("state").textContent = "No root manager";
        $("substate").textContent =
          "this page only works inside a root manager's WebUI, which runs its commands.";
      } else if (/cannot open the NoMount netlink socket/.test(e)) {
        $("state").textContent = "Engine unreachable";
        $("substate").textContent =
          "the engine did not answer. Check dmesg for a nomount line at boot.";
      } else {
        $("state").textContent = "Suite not running";
        $("substate").textContent =
          "the nomount binary could not be run" + (e ? ": " + e.split("\n")[0] : "") +
          ". Re-flash the Suite zip.";
      }
      dot.className = "dot info";
      $("mRules").textContent = " - ";
      $("mOv").textContent = " - ";
      return 0;
    }
    $("mRules").textContent = d.injects.length;
    $("mOv").textContent = d.rro.length;
    if (GUARD_TRIPPED === true) {
      $("state").textContent = "Disabled";
      $("substate").textContent =
        "the bootloop guard tripped. " + GUARD_HINT;
      dot.className = "dot info";
      return d.rules;
    }
    $("state").textContent = "Active";
    if (d.rules > 0) {
      let pending = 0;
      try {
        // As sets: absorbed rules and durable whiteouts are live but not planned, and a
        // count comparison let them hide the same number of unserved planned files.
        const p = await planByModule();
        if (p) {
          const live = new Set(d.lines.map(vpath));
          pending = [...p.planned].filter(function (t) { return !live.has(t); }).length;
        }
      } catch (e) {  }
      if (gen !== STATUS_GEN) return d.rules;
      // The hero used to paint green from the rule count alone, so it read "Active · modules
      // injected" with a green dot while the findings list directly below said three things
      // needed attention. Injection working and nothing being wrong are different questions.
      const attn = checkAttention();
      const bits = [];
      if (pending > 0) {
        bits.push(`${pending} planned file${pending > 1 ? "s" : ""} not served yet. Press Reload`);
      }
      if (attn > 0) {
        bits.push(`${attn} finding${attn > 1 ? "s" : ""} · see Checks`);
      }
      $("substate").textContent = bits.length ? "modules injected · " + bits.join(" · ")
                                              : "modules injected";
      // Green means measured and nothing to look at; a finding is attention, not clean.
      dot.className = pending > 0 || attn > 0 ? "dot info" : "dot ok";
      return d.rules;
    }
    let ships = -1, planned = -1;
    try {
      const p = await planByModule();
      if (p) { ships = p.expectLive; planned = p.total; }
    } catch (e) {  }
    if (gen !== STATUS_GEN) return d.rules;
    if (ships === 0) {
      $("substate").textContent = planned > 0
        ? "nothing to inject: this device's module content is served by real binds"
        : "nothing to inject: no module provides files";
      dot.className = "dot ok";
    } else if (ships > 0) {
      // The plan ships files and the engine holds nothing: measured, and NOT healthy. This
      // painted green while the `ships === -1` case below - where the plan could not even be
      // read - correctly painted amber, i.e. a known-bad device looked better than an
      // unknown one. Reachable from this page's own Clear rules button.
      $("substate").textContent = "no rules: " + ships + " planned file(s) unserved, re-apply";
      dot.className = "dot info";
    } else {
      $("substate").textContent = "no rules";
      dot.className = "dot info";
    }
    return d.rules;
  }

  async function refreshDevice() {
    const r = await exec('echo "$(getprop ro.product.marketname)|$(getprop ro.product.manufacturer)|$(getprop ro.product.model)|$(getprop ro.build.version.release)|$(getprop ro.build.version.sdk)|$(uname -r)"');
    const p = (r.stdout || "").trim().split("|");
    const name = (p[0] && p[0].trim()) ? p[0] : (((p[1] ? p[1] + " " : "")) + (p[2] || " - "));
    $("dModel").textContent = name || " - ";
    $("dAndroid").textContent = p[3] || " - ";
    $("dApi").textContent = p[4] || " - ";
    $("dKernel").textContent = p[5] || " - ";
  }
  let STEALTH_PROBE = null;
  // The probe counts real mounts, so anything that REMOVES one has to drop the memo
  // or the posture card keeps reporting the mounts absorb just took away.
  function forgetStealthProbe() {
    STEALTH_PROBE = null;
  }
  function stealthProbe() {
    if (STEALTH_PROBE) return STEALTH_PROBE;
    STEALTH_PROBE = (async function () {
      // Every substitution here used to run a BARE command, and the exec this page gets
      // can arrive with no PATH at all (the same gap that made `su 2000 -c stat` exit 127
      // and is why 30-checks.js uses absolute paths). Each one then produced nothing,
      // `root_nm` parsed as 0 = "no mounts", and the card said "Fully mountless" having
      // measured none of it. Set PATH once, mark anything unmeasured with '?' rather than
      // letting it fall through as a clean value, and finish with a trailer -- the exit
      // status of a run of `echo`s is the last echo's, so r.errno could never report this.
      const r = await exec(
        'export PATH=/system/bin:/system/xbin:/vendor/bin; ' +
        'q() { v=$(eval "$2" 2>/dev/null); case "$v" in "") v="?";; esac; echo "$1=$v"; }; ' +
        'echo "sucompat=$(/data/adb/ksud feature list 2>/dev/null | grep su_compat | grep -q ENABLED && echo 1 || echo 0)"; ' +
        'echo "ksud=$([ -x /data/adb/ksud ] && echo 1 || echo 0)"; ' +
        'n=$(grep -c \'^nomount_\' /proc/self/mounts 2>/dev/null); ' +
        'case "$n" in ""|*[!0-9]*) n="?";; esac; echo "root_nm=$n"; ' +
        'q fp "getprop ro.build.fingerprint"; ' +
        'q se "getenforce"; ' +
        'q bootid "cat /proc/sys/kernel/random/boot_id"; ' +
        'echo "done=1";'
      );
      const kv = {};
      r.stdout.split("\n").forEach((l) => { const i = l.indexOf("="); if (i > 0) kv[l.slice(0, i)] = l.slice(i + 1).trim(); });
      // -1 is "not measured" and is NEVER treated as zero mounts anywhere below.
      const rootNm = /^\d+$/.test(kv.root_nm || "") ? parseInt(kv.root_nm, 10) : -1;
      let appNm = 0;
      if (rootNm > 0) {
        const appOut = ((await exec(
          'export PATH=/system/bin:/system/xbin:/vendor/bin; ' +
          'su 2000 -c "grep -c \'^nomount_\' /proc/self/mounts"'
        )).stdout || "").trim();
        appNm = /^\d+$/.test(appOut) ? parseInt(appOut, 10) : -1;
      }
      return { ok: r.errno === 0 && kv.done === "1" && rootNm >= 0, kv: kv, rootNm: rootNm, appNm: appNm };
    })();
    return STEALTH_PROBE;
  }
  async function refreshStealth() {
    const probe = await stealthProbe();
    const kv = probe.kv;
    const sucompat = kv.sucompat === "1";
    const noKsud = kv.ksud !== "1";
    const rootNm = probe.rootNm, appNm = probe.appNm;

    const mrows = ["zero-mount-posture", "tmpfs-over-the-rom", "foreign-mount-over-the-rom"].map(checkById);

    const byDesign = (function () {
      const c = mrows[0];
      if (!c || !c.evidence) return 0;
      const d = c.evidence.match(/(\d+)\s+left by design/);
      return d ? parseInt(d[1], 10) : 0;
    })();
    const ourBinds = (function () {
      const c = mrows[0];
      if (!c || !c.evidence) return 0;
      if (c.verdict !== "note" && c.verdict !== "warn") return 0;
      const v = c.evidence.match(/(\d+)\s+module mount\(s\) visible/);
      return v ? parseInt(v[1], 10) : 0;
    })();
    // This arm has now been permanently false twice. First it keyed on verdict === "warn",
    // which `zero-mount posture` never emits (audit.rs pins pass/note/fail/unmeasured).
    // The replacement keyed on `appNm > 0`, which cannot happen either: appNm stays 0
    // unless rootNm > 0, and both counts are `grep -c '^nomount_' /proc/self/mounts` - the
    // mount SOURCE field - which nothing produces, since the engine makes no mounts and a
    // module bind's source is /data/adb/modules/...
    //
    // `ourBinds` already answers the question the arm is about: it is parsed from the
    // zero-mount check's own "N module mount(s) visible" evidence, and that check measured
    // the app-visible mount table. So the branch below tags on `ourBinds` alone.
    // A report from a previous boot describes mounts that may be gone or new, and a report
    // with no plan section never looked at other namespaces or unabsorbed module mounts:
    // neither can say "clean".
    const stale = !!(CHECK && CHECK.boot && kv.bootid && kv.bootid !== "?" && CHECK.boot !== kv.bootid);
    const planRan = !!(CHECK && (CHECK.sections || []).indexOf("plan") >= 0);
    const measured = !stale && planRan &&
      mrows.every(function (c) { return c && c.verdict !== "unmeasured"; });
    // A module mount replicated into zygote's namespace is inherited by every app, even
    // though this namespace's three mount rows pass; an unabsorbed module mount is visible.
    const nsRows = ((CHECK && CHECK.checks) || []).filter(function (c) {
      return (c.name === "foreign mount in another namespace" || c.name === "module mount not absorbed") &&
        (c.verdict === "warn" || c.verdict === "fail");
    });
    const bad = mrows.filter(function (c) { return c && (c.verdict === "fail" || c.verdict === "reboot"); })
      .concat(nsRows);
    const fmnt = measured ? bad.length : -1;

    // '?' is the probe saying it could not read this, which the "" path already treats as
    // not-measured. Folding them keeps one meaning for one empty string.
    const fp = kv.fp === "?" ? "" : (kv.fp || "");
    const se = kv.se === "?" ? "" : (kv.se || "").trim();
    const keyMatch = fp === "" ? null : fp.match(/test-keys|dev-keys|userdebug|:eng\//);
    const seTell = se !== "" && se !== "Enforcing";
    const tells = [];
    if (keyMatch) tells.push("build keys");
    if (seTell) tells.push("SELinux " + se);

    $("mSu").innerHTML = kv.done !== "1" ? 'not measured <small>probe did not run</small>'
      : noKsud ? 'not measured <small>no KernelSU-family manager here</small>'
      : sucompat ? 'sucompat <small>kernel · mountless</small>'
      : 'external <small>unmanaged</small>';

    const rows = [
      sucompat ? { k: "Root · su", v: "sucompat · mountless", t: "vfs" }
        : noKsud ? { k: "Root · su", v: "not measured", t: "off" }
        : { k: "Root · su", v: "external", t: "off" },
    ];
    if (rootNm < 0) {
      rows.push({ k: "Real mounts", v: "not measured", t: "off" });
    } else if (rootNm > 0) {
      rows.push(appNm === 0 ? { k: "Real mounts", v: "root " + rootNm + " · apps 0, hidden", t: "vfs" }
              : appNm > 0 ? { k: "Real mounts", v: "apps see " + appNm + " · VISIBLE", t: "info" }
              : { k: "Real mounts", v: "root " + rootNm + " · app-view n/a", t: "off" });
    } else {
      rows.push(fmnt > 0 ? { k: "Real mounts", v: fmnt + " finding" + (fmnt > 1 ? "s" : "") + " · open Check", t: "info" }
              : fmnt < 0 ? { k: "Real mounts", v: "not measured", t: "off" }
              : ourBinds > 0
                ? { k: "Real mounts", v: ourBinds + " of ours · my_* bind" + (ourBinds > 1 ? "s" : ""),
                    t: "info" }
              : byDesign > 0
                ? { k: "Real mounts", v: "none of ours · " + byDesign + " left by design", t: "vfs" }
                : { k: "Real mounts", v: "none, pure Prism", t: "vfs" });
    }
    rows.push({ k: "Build keys",
                v: fp === "" ? "n/a" : keyMatch ? keyMatch[0].replace(/^:|\/$/g, "") + " · tell" : "release-keys",
                t: fp === "" ? "off" : keyMatch ? "info" : "vfs" });
    rows.push({ k: "SELinux", v: se || "n/a", t: seTell ? "info" : (se ? "vfs" : "off") });
    $("posture").innerHTML = rows.map((x) =>
      `<div class="row"><span class="name">${x.k}</span><span class="tag ${x.t}">${esc(x.v)}</span></div>`
    ).join("");

    let told = false;
    const say = function (kind, title, desc, note) {
      if (tells.length && !told) {
        kind = "info";
        note += " Also readable by a scanner, whatever the mount table says: " +
                tells.map(esc).join(", ") + ".";
      }
      $("shield").className = "shield " + kind;
      $("stealthT").textContent = title;
      $("stealthD").textContent = desc;
      $("stealthNote").innerHTML = note;
      if (kind !== "clean") {
        let pref = null;
        try { pref = localStorage.getItem("nmcol:cardPosture"); } catch (e) {}
        const card = $("cardPosture");
        if (pref === null && card && card.classList.contains("collapsed")) {
          card.classList.remove("collapsed");
          const ch = card.querySelector(".card-h");
          if (ch) { ch.classList.add("open"); setExp(ch); }
        }
      }
    };
    if (engineDown(CHECK)) {
      say("info", "The engine isn’t running", "nothing is being injected",
        "There are no mounts because there is nothing being served. This card cannot say " +
        "anything about how you look to an app until the engine answers. Open " +
        "<b>Checks</b>.");
    } else if (guardTripped(CHECK)) {
      say("info", "Paused by the bootloop guard", "nothing is being injected",
        "The guard parked the Suite, so there is nothing being served to look at. " +
        esc(GUARD_HINT));
    } else if (!probe.ok) {
      // Ahead of every "clean" arm on purpose: without this, a probe that read nothing
      // fell through to "Fully mountless · zero mounts, nothing to hide".
      say("info", "Posture not measured",
        kv.done !== "1" ? "the probe could not read this device" : "the mount count could not be read",
        (kv.done !== "1"
          ? "None of the readings on this card ran here, so this says nothing either way - "
          : "The rows that read a value are shown; without the mount count this says nothing " +
            "either way about mounts - ") +
        "it is not a clean result. This is usually a shell with no <code>PATH</code>. Run " +
        "<code>nomount check</code> from a terminal.");
    } else if (appNm > 0) {
      say("info", "Mount visible to apps", "uid 2000 sees " + appNm + " nomount_* mount(s)",
        "A live non-root check sees <code>nomount_*</code> mounts. This build is <b>fully " +
        "mountless</b> (Prism RRO). If you see this, an older overlay build is still active; reboot.");
    } else if (fmnt > 0) {
      const owner = bad.map(function (c) { return c.owner; }).filter(Boolean).join(", ");
      say("info", "Something is mounting over the ROM",
        owner ? "from " + owner : fmnt + " finding(s) in the mount table",
        esc(redactUids(bad.map(function (c) { return c.meaning || c.name; }).join(" "))) +
        " Open <b>Checks</b>: it names each one, who caused it, and what " +
        "you can do about it.");
    } else if (ourBinds > 0) {
      say("info", "Our own my_* binds are visible",
        ourBinds + " real bind" + (ourBinds > 1 ? "s" : "") + " any app can read",
        esc(redactUids((mrows[0] && (mrows[0].meaning || mrows[0].evidence)) || "")) +
        " Open <b>Checks</b>.");
    } else if (fmnt < 0) {
      say("info", "Mount posture not measured", "no check has read the mount table yet",
        "Nothing has read the mount table here yet, so this says nothing either " +
        "way. Open <b>Checks</b>.");
    } else if (appNm < 0 && rootNm > 0) {
      say("info", "App view unavailable", "could not measure what a non-root reader sees",
        "Couldn’t drop to a non-root uid to verify here, and root sees " + rootNm +
        " <code>nomount_*</code> mount(s).");
    } else if (rootNm > 0) {
      say("clean", "Clean · nothing visible to apps",
        rootNm + " mount" + (rootNm > 1 ? "s" : "") + " hidden from non-root",
        "Injections are mountless" + (sucompat ? " and su is sucompat" : "") +
        ". Any remaining <code>nomount_*</code> mount " +
        "is kernel-hidden from non-root readers of <code>/proc/*/mountinfo</code>; root still " +
        "sees everything.");
    } else if (tells.length) {
      told = true;
      say("info", "Residual tells present", tells.join(" · "),
        "Mount surface is clean, but a scanner can still read: " + tells.map(esc).join(", ") +
        ". These are properties and boot state, not mounts; nothing on this page changes them.");
    } else {
      const how =
        "Injections and RRO overlays are both Prism (<b>no overlayfs</b>, no tmpfs)" +
        (sucompat ? " and su is sucompat" : "") +
        ". Root and apps see the <b>same</b> mount table, so there is no gap to flag." +
        (CHECK && CHECK.ts ? " Mount readings from the check " + esc(auAge(CHECK.ts)) + "." : "");
      if (ourBinds > 0) {
        const them = ourBinds > 1 ? "them" : "it";
        say("clean", "Mountless · " + ourBinds + " my_* bind" + (ourBinds > 1 ? "s" : ""),
          (ourBinds > 1 ? "these are" : "this is") + " served by a real bind, by design",
          how + " The exception is <code>my_*</code>: served by a real bind unless the " +
          "<code>my_hookless</code> trial is on, so apps reading <code>mountinfo</code> see " +
          them + ". Default here, nothing broken.");
      } else if (byDesign > 0) {
        say("clean", "Mountless · " + byDesign + " mount" + (byDesign > 1 ? "s" : "") + " by design",
          "the Suite adds none it can avoid; " + byDesign + " left in place on purpose",
          how + " What is left is a hook framework's own bind, which <code>absorb</code> never " +
          "takes over: a broken hook fails at the next app install, not at boot. Apps can see " +
          (byDesign > 1 ? "them" : "it") + ".");
      } else {
        say("clean", "Fully mountless", "zero mounts, nothing to hide", how);
      }
    }
  }

  async function refreshGuard() {
    const cr = await exec(
      "if [ -e /data/adb/nomount/bootcount ]; then cat /data/adb/nomount/bootcount; else echo 0; fi"
    );
    const dr = await exec("[ -e /data/adb/nomount/disabled ] && echo 1 || echo 0");
    if (dr.errno !== 0) {
      $("gchip").textContent = "?";
      $("gstate").textContent = "Unknown · could not read the guard";
      $("gdot").className = "dot";
      $("rearm").classList.remove("u-hide");
      return;
    }
    const c = cr.errno === 0 ? cr.stdout.trim() : "";
    const disabled = dr.stdout.trim() === "1";
    const wasTripped = GUARD_TRIPPED;
    GUARD_TRIPPED = disabled;
    if (wasTripped !== disabled) {
      refreshStatus();
      if (!CHECK_RUNNING) renderCheck(CHECK); else paintHealthLine(CHECK);
      refreshStealth();
    }
    $("gchip").textContent = "boot " + (cr.errno !== 0 ? "?" : c === "" ? "0" : c) + "/3";
    if (disabled) {
      $("gstate").textContent = "Tripped · disabled"; $("gdot").className = "dot info"; $("rearm").classList.remove("u-hide");
      expandCard("cardGuard");
      expandCard("incidentcard");
    } else {
      $("gstate").textContent = "Armed"; $("gdot").className = "dot ok"; $("rearm").classList.add("u-hide");
    }
  }
