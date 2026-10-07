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
    paintHealthLine(CHECK);
    if (wasLive !== d.ok) {
      if (!CHECK_RUNNING) renderCheck(CHECK);
      refreshStealth();
    }
    if (!d.ok) {
      $("state").textContent = "No kernel driver";
      $("substate").textContent =
        "this kernel was not built with NoMount. Flash one that was, then reboot. " +
        "Nothing is being injected. Prebuilt OnePlus kernels: " +
        "github.com/Bouteillepleine/OnePlus-ReSukiSu_NMS/releases · " +
        "source: github.com/Bouteillepleine/NoMount-Suite";
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
        "the bootloop guard tripped. Re-arm it in Bootloop guard below, then reboot";
      dot.className = "dot info";
      return d.rules;
    }
    $("state").textContent = "Active";
    if (d.rules > 0) {
      let pending = 0;
      try {
        const p = await planByModule();
        if (p) pending = Math.max(0, p.expectLive - d.rules);
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
      dot.className = pending > 0 ? "dot info" : "dot ok";
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
      const r = await exec(
        'echo "sucompat=$(/data/adb/ksud feature list 2>/dev/null | grep su_compat | grep -q ENABLED && echo 1 || echo 0)"; ' +
        'echo "ksud=$([ -x /data/adb/ksud ] && echo 1 || echo 0)"; ' +
        'echo "root_nm=$(grep -c \'^nomount_\' /proc/self/mounts 2>/dev/null)"; ' +
        'echo "fp=$(getprop ro.build.fingerprint 2>/dev/null)"; ' +
        'echo "se=$(getenforce 2>/dev/null)";'
      );
      const kv = {};
      r.stdout.split("\n").forEach((l) => { const i = l.indexOf("="); if (i > 0) kv[l.slice(0, i)] = l.slice(i + 1).trim(); });
      const rootNm = parseInt(kv.root_nm || "0", 10);
      let appNm = 0;
      if (rootNm > 0) {
        const appOut = ((await exec('su 2000 -c "grep -c \'^nomount_\' /proc/self/mounts"')).stdout || "").trim();
        appNm = /^\d+$/.test(appOut) ? parseInt(appOut, 10) : -1;
      }
      return { ok: r.errno === 0, kv: kv, rootNm: rootNm, appNm: appNm };
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
    // `zero-mount posture` is emitted as pass/note/fail/unmeasured and NEVER as "warn" -
    // pinned by audit.rs's own test - so keying on "warn" made this permanently false and
    // the "Our own my_* binds are visible" arm below unreachable. Ask the question the arm
    // is actually about: is the Suite's own bind visible to an app?
    const ourBindsWarn = ourBinds > 0 && appNm > 0;
    const measured = mrows.every(function (c) { return c && c.verdict !== "unmeasured"; });
    const bad = mrows.filter(function (c) { return c && (c.verdict === "fail" || c.verdict === "reboot"); });
    const fmnt = measured ? bad.length : -1;

    const fp = kv.fp || "";
    const se = (kv.se || "").trim();
    const keyMatch = fp === "" ? null : fp.match(/test-keys|dev-keys|userdebug|:eng\//);
    const seTell = se !== "" && se !== "Enforcing";
    const tells = [];
    if (keyMatch) tells.push("build keys");
    if (seTell) tells.push("SELinux " + se);

    $("mSu").innerHTML = !probe.ok ? 'not measured <small>probe did not run</small>'
      : noKsud ? 'not measured <small>no KernelSU-family manager here</small>'
      : sucompat ? 'sucompat <small>kernel · mountless</small>'
      : 'external <small>unmanaged</small>';

    const rows = [
      sucompat ? { k: "Root · su", v: "sucompat · mountless", t: "vfs" }
        : noKsud ? { k: "Root · su", v: "not measured", t: "off" }
        : { k: "Root · su", v: "external", t: "off" },
    ];
    if (rootNm > 0) {
      rows.push(appNm === 0 ? { k: "Real mounts", v: "root " + rootNm + " · apps 0, hidden", t: "vfs" }
              : appNm > 0 ? { k: "Real mounts", v: "apps see " + appNm + " · VISIBLE", t: "info" }
              : { k: "Real mounts", v: "root " + rootNm + " · app-view n/a", t: "off" });
    } else {
      rows.push(fmnt > 0 ? { k: "Real mounts", v: fmnt + " finding" + (fmnt > 1 ? "s" : "") + " · open Check", t: "info" }
              : fmnt < 0 ? { k: "Real mounts", v: "not measured", t: "off" }
              : ourBinds > 0
                ? { k: "Real mounts", v: ourBinds + " of ours · my_* bind" + (ourBinds > 1 ? "s" : ""),
                    t: ourBindsWarn ? "info" : "vfs" }
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
    } else if (ourBindsWarn) {
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
        "Injections are mountless and su is sucompat. Any remaining <code>nomount_*</code> mount " +
        "is kernel-hidden from non-root readers of <code>/proc/*/mountinfo</code>; root still " +
        "sees everything.");
    } else if (tells.length) {
      told = true;
      say("info", "Residual tells present", tells.join(" · "),
        "Mount surface is clean, but a scanner can still read: " + tells.map(esc).join(", ") +
        ". These are properties and boot state, not mounts; nothing on this page changes them.");
    } else {
      const how =
        "Injections and RRO overlays are both Prism (<b>no overlayfs</b>, no tmpfs) and su is " +
        "sucompat. Root and apps see the <b>same</b> mount table, so there is no gap to flag.";
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
    } else {
      $("gstate").textContent = "Armed"; $("gdot").className = "dot ok"; $("rearm").classList.add("u-hide");
    }
  }
