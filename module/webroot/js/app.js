  "use strict";
  const SUITE_VERSION = "dev";
  const SUITE_COMMIT = "dev";
  const SUITE_PROFILE = "dev";
  let execId = 0;
  const KSU = window.ksu;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  document.getElementById("banner").hidden = !!(KSU && KSU.exec);

  const EXEC_TIMEOUT_MS = 120000;
  function exec(cmd, opts = {}) {
    return new Promise((resolve) => {
      if (!KSU || !KSU.exec) { resolve({ errno: -1, stdout: "", stderr: "no webui env" }); return; }
      const name = "__nmcb" + (execId++);
      let settled = false;
      const finish = (r) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        delete window[name];
        resolve(r);
      };
      const timer = setTimeout(() => finish({
        errno: -1, stdout: "",
        stderr: "timed out after " + (EXEC_TIMEOUT_MS / 1000) +
                "s - it may still be running; reopen this pane to see the result",
      }), EXEC_TIMEOUT_MS);
      window[name] = (errno, stdout, stderr) =>
        finish({ errno: Number(errno), stdout: stdout || "", stderr: stderr || "" });
      try { KSU.exec(cmd, JSON.stringify(opts), name); }
      catch (e) { finish({ errno: -1, stdout: "", stderr: String(e) }); }
    });
  }

  let NMBIN = null;
  async function bin() {
    if (NMBIN) return NMBIN;
    const abi = (await exec("getprop ro.product.cpu.abi")).stdout.trim() || "arm64-v8a";
    NMBIN = `/data/adb/modules/meta-nomount/bin/${abi}/nomount`;
    return NMBIN;
  }
  async function nmc() { return (await bin()).replace(/nomount$/, "nm"); }
  async function engineVersion() {
    const r = await exec(shq(await nmc()) + " v 2>/dev/null");
    const v = (r.stdout || "").trim();
    return /^\d+$/.test(v) ? v : "";
  }

  let PLAN_BY_MODULE = null;
  function planByModule(force) {
    if (PLAN_BY_MODULE && !force) return PLAN_BY_MODULE;
    PLAN_BY_MODULE = (async function () {
      const r = await exec(shq(await bin()) + " plan 2>/dev/null");
      if (r.errno !== 0) { PLAN_BY_MODULE = null; return null; }
      const modules = {};
      let total = 0;
      let expectLive = 0;
      (r.stdout || "").split("\n").forEach((l) => {
        const m = /^(inject|whiteout|bind)\s+(.*) <- (.*) \[([^\]]*)\]/.exec(l);
        if (!m) return;
        const kind = m[1], target = m[2], id = m[4];
        if (kind !== "bind" && l.indexOf("<< UNSERVABLE") < 0) expectLive++;
        const e = modules[id] || (modules[id] = { files: 0, overlay: false, vfs: false, bind: false });
        e.files++;
        total++;
        if (kind === "bind") e.bind = true;
        else if (/\/overlay\/[^\s]*\.apk$/.test(target)) e.overlay = true;
        else e.vfs = true;
      });
      return { total, expectLive, modules };
    })();
    return PLAN_BY_MODULE;
  }

  async function nm(args) {
    const b = await bin();
    const nmClient = b.replace(/nomount$/, "nm");
    return exec(`NM_BIN=${shq(nmClient)} ${shq(b)} ${args}`);
  }

  function failText(r, fallback) {
    const e = ((r && r.stderr) || "").trim();
    if (/bootloop guard has parked the Suite/.test(e)) {
      return "Blocked - the bootloop guard disabled the Suite, so nothing is injected. " +
             "Open Status to find out why, then clear it and reboot.";
    }
    return "Failed: " + ((fallback || "").trim() || e || "error");
  }

  const _SPIN = '<svg class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2.4" stroke-linecap="round"><circle cx="12" cy="12" r="9" opacity=".25"/>' +
    '<path d="M21 12a9 9 0 0 0-9-9"/></svg>';
  function busy(btn, label) {
    if (!btn) return function () {};
    const html = btn.innerHTML, wasDisabled = btn.disabled;
    btn.disabled = true;
    btn.innerHTML = _SPIN + (label ? "<span>" + label + "</span>" : "");
    let restored = false;
    return function () {
      if (restored) return;
      restored = true;
      btn.innerHTML = html;
      btn.disabled = wasDisabled;
    };
  }

  function toast(msg, kind = "") {
    const t = $("toast");
    t.textContent = msg; t.className = "show " + kind;
    clearTimeout(t._t); t._t = setTimeout(() => { t.className = ""; }, 2400);
  }

  let _cfClose = null;
  function confirmAction(title, body, verb) {
    return new Promise(function (resolve) {
      const wrap = $("confirm"), yes = $("cfYes"), no = $("cfNo");
      if (!wrap) { resolve(false); return; }
      if (_cfClose) _cfClose(false);
      $("cfTitle").textContent = title;
      $("cfBody").textContent = body;
      yes.textContent = verb;
      wrap.hidden = false;
      const returnTo = document.activeElement;
      const onKey = function (e) {
        if (e.key === "Escape") { done(false); return; }
        if (e.key !== "Tab") return;
        e.preventDefault();
        const first = no, last = yes;
        const fwd = !e.shiftKey;
        const next = document.activeElement === last ? (fwd ? first : no)
                   : document.activeElement === first ? (fwd ? last : last)
                   : first;
        try { next.focus(); } catch (err) {}
      };
      const onWrap = function (e) { if (e.target === wrap) done(false); };
      function done(v) {
        if (_cfClose !== done) return;
        _cfClose = null;
        wrap.hidden = true;
        yes.onclick = null; no.onclick = null; wrap.onclick = null;
        document.removeEventListener("keydown", onKey);
        try { if (returnTo && returnTo.focus) returnTo.focus(); } catch (err) {}
        resolve(v);
      }
      _cfClose = done;
      yes.onclick = function () { done(true); };
      no.onclick = function () { done(false); };
      wrap.onclick = onWrap;
      document.addEventListener("keydown", onKey);
      try { no.focus(); } catch (e) {}
    });
  }

  let RULES = null;
  let ENGINE_LIVE = null;
  let GUARD_TRIPPED = null;
  let STATUS_GEN = 0;
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
        "this kernel was not built with NoMount - flash one that was, then reboot. " +
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
        "the bootloop guard tripped - re-arm it in Bootloop guard below, then reboot";
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
        bits.push(`${pending} planned file${pending > 1 ? "s" : ""} not served yet - press Reload`);
      }
      if (attn > 0) {
        bits.push(`${attn} finding${attn > 1 ? "s" : ""} - see Checks`);
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
        ? "nothing to inject - this device's module content is served by real binds"
        : "nothing to inject - no module provides files";
      dot.className = "dot ok";
    } else if (ships > 0) {
      // The plan ships files and the engine holds nothing: measured, and NOT healthy. This
      // painted green while the `ships === -1` case below - where the plan could not even be
      // read - correctly painted amber, i.e. a known-bad device looked better than an
      // unknown one. Reachable from this page's own Clear rules button.
      $("substate").textContent = "no rules - " + ships + " planned file(s) unserved, re-apply";
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
      rows.push(appNm === 0 ? { k: "Real mounts", v: "root " + rootNm + " · apps 0 - hidden", t: "vfs" }
              : appNm > 0 ? { k: "Real mounts", v: "apps see " + appNm + " - VISIBLE", t: "info" }
              : { k: "Real mounts", v: "root " + rootNm + " · app-view n/a", t: "off" });
    } else {
      rows.push(fmnt > 0 ? { k: "Real mounts", v: fmnt + " finding" + (fmnt > 1 ? "s" : "") + " - open Check", t: "info" }
              : fmnt < 0 ? { k: "Real mounts", v: "not measured", t: "off" }
              : ourBinds > 0
                ? { k: "Real mounts", v: ourBinds + " of ours · my_* bind" + (ourBinds > 1 ? "s" : ""),
                    t: ourBindsWarn ? "info" : "vfs" }
              : byDesign > 0
                ? { k: "Real mounts", v: "none of ours · " + byDesign + " left by design", t: "vfs" }
                : { k: "Real mounts", v: "none - pure Prism", t: "vfs" });
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
        "anything about how you look to an app until the engine answers - open " +
        "<b>Checks</b>.");
    } else if (appNm > 0) {
      say("info", "Mount visible to apps", "uid 2000 sees " + appNm + " nomount_* mount(s)",
        "A live non-root check sees <code>nomount_*</code> mounts. This build is <b>fully " +
        "mountless</b> (Prism RRO) - if you see this, an older overlay build is still active; reboot.");
    } else if (fmnt > 0) {
      const owner = bad.map(function (c) { return c.owner; }).filter(Boolean).join(", ");
      say("info", "Something is mounting over the ROM",
        owner ? "from " + owner : fmnt + " finding(s) in the mount table",
        esc(redactUids(bad.map(function (c) { return c.meaning || c.name; }).join(" "))) +
        " Open <b>Checks</b> - it names each one, who caused it, and what " +
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
      say("clean", "Clean - nothing visible to apps",
        rootNm + " mount" + (rootNm > 1 ? "s" : "") + " hidden from non-root",
        "Injections are mountless and su is sucompat. Any remaining <code>nomount_*</code> mount " +
        "is kernel-hidden from non-root readers of <code>/proc/*/mountinfo</code>; root still " +
        "sees everything.");
    } else if (tells.length) {
      told = true;
      say("info", "Residual tells present", tells.join(" · "),
        "Mount surface is clean, but a scanner can still read: " + tells.map(esc).join(", ") +
        ". These are properties and boot state, not mounts - nothing on this page changes them.");
    } else {
      const how =
        "Injections and RRO overlays are both Prism - <b>no overlayfs</b>, no tmpfs - and su is " +
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
          "the Suite adds none it can avoid - " + byDesign + " left in place on purpose",
          how + " What is left is a hook framework's own bind, which <code>absorb</code> never " +
          "takes over: a broken hook fails at the next app install, not at boot. Apps can see " +
          (byDesign > 1 ? "them" : "it") + ".");
      } else {
        say("clean", "Fully mountless", "zero mounts - nothing to hide", how);
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
      $("gstate").textContent = "Unknown - could not read the guard";
      $("gdot").className = "dot";
      $("rearm").style.display = "";
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
      $("gstate").textContent = "Tripped - disabled"; $("gdot").className = "dot info"; $("rearm").style.display = "";
    } else {
      $("gstate").textContent = "Armed"; $("gdot").className = "dot ok"; $("rearm").style.display = "none";
    }
  }

  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("nm_theme", t); } catch (e) {}
  }
  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    applyTheme(cur === "light" ? "dark" : "light");
  }
  (function initTheme() {
    let t = null;
    try { t = localStorage.getItem("nm_theme"); } catch (e) {}
    if (t !== "light" && t !== "dark") {
      t = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    }
    document.documentElement.setAttribute("data-theme", t);
  })();

  function movePill(animate) {
    const pill = document.getElementById("navpill");
    const btn = document.querySelector(".navb.on");
    if (!pill || !btn) return;
    if (animate === false) pill.classList.add("noanim");
    pill.style.width = btn.offsetWidth + "px";
    pill.style.height = btn.offsetHeight + "px";
    pill.style.transform = "translateX(" + btn.offsetLeft + "px)";
    pill.style.opacity = "1";
    if (animate === false) {
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { pill.classList.remove("noanim"); });
      });
    }
  }
  window.addEventListener("resize", function () { movePill(false); });

  function showTab(name, btn) {
    document.querySelectorAll(".tab").forEach(function (t) { t.classList.remove("on"); });
    var pane = document.getElementById("tab-" + name);
    if (pane) pane.classList.add("on");
    document.querySelectorAll(".navb").forEach(function (b) {
      b.classList.remove("on"); b.setAttribute("aria-selected", "false");
    });
    if (btn) { btn.classList.add("on"); btn.setAttribute("aria-selected", "true"); }
    var pill = document.getElementById("navpill");
    if (!btn) {
      if (pill) pill.style.opacity = "0";
    } else {
      movePill(true);
    }
    // Only panes that have a nav button are worth restoring. Diagnostics is a detail view opened
    // from the health line, so remembering it left the next visit on a pane with nothing lit in
    // the nav and no obvious way back.
    try {
      if (document.getElementById("nb-" + name)) sessionStorage.setItem("nm_tab", name);
    } catch (e) {}
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function openDetail() {
    showTab("diag", document.getElementById("nb-diag"));
    if (!CHECK) runCheck(null);
  }

  let _rulesRaw = "";
  var _ruleGroup = false;
  function _ruleModule(line) {
    const m = line.match(/\/data\/adb\/modules(?:_update)?\/([^/ ]+)/);
    return m ? m[1] : "(other)";
  }
  function toggleRuleGroup(btn) {
    _ruleGroup = !_ruleGroup;
    btn.textContent = _ruleGroup ? "Flat list" : "Group by module";
    btn.classList.toggle("primary", _ruleGroup);
    filterRules();
  }
  function filterRules() {
    const q = ($("rulefilter").value || "").trim().toLowerCase();
    const lines = _rulesRaw.split("\n").filter(Boolean);
    const keep = q ? lines.filter(function (l) { return l.toLowerCase().indexOf(q) !== -1; }) : lines;
    if (!keep.length) {
      $("ruleslist").textContent = "(no match)";
    } else if (_ruleGroup) {
      const groups = {};
      keep.forEach(function (l) { (groups[_ruleModule(l)] = groups[_ruleModule(l)] || []).push(l); });
      const names = Object.keys(groups).sort();
      $("ruleslist").textContent = names.map(function (n) {
        return "── " + n + " (" + groups[n].length + ") ──\n" + groups[n].join("\n");
      }).join("\n\n");
    } else {
      $("ruleslist").textContent = keep.join("\n");
    }
    $("rulecount").style.display = "";
    const vd = lines.filter(function (l) { return l.includes("(virtual dir)"); }).length;
    const wo = lines.filter(function (l) { return l.includes("(whiteout)"); }).length;
    $("rulecount").textContent = q
      ? keep.length + " of " + lines.length + " lines match"
      : (lines.length - vd - wo) + " rules" +
        (wo ? " · " + wo + " hidden path" + (wo === 1 ? "" : "s") : "") +
        (vd ? " · " + vd + " engine-made director" + (vd === 1 ? "y" : "ies") : "");
  }

  let CHECK = null;

  // Every spelling of a hidden appid that any producer emits. Keep in step with
  // `hidden_uid_label` in src/audit.rs AND src/doctor.rs.
  function redactUids(s) {
    return String(s == null ? "" : s)
      .replace(/uid \d+ \(hidden\)/g, "uid <redacted> (hidden)")
      .replace(/hidden uid \d+/g, "hidden uid <redacted>");
  }

  function parseJson(r) {
    const raw = (r.stdout || "").trim();
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) {}
    const a = raw.indexOf("{"), b = raw.lastIndexOf("}");
    if (a < 0 || b <= a) return null;
    try { return JSON.parse(raw.slice(a, b + 1)); } catch (e) { return null; }
  }

  function ranSection(r, s) {
    if (!r) return false;
    if (r.sections && r.sections.length) return r.sections.indexOf(s) >= 0;
    return !!(r.checks || []).some(function (c) { return c.section === s; });
  }

  function findCheck(r, id) {
    const cs = (r && r.checks) || [];
    for (var i = 0; i < cs.length; i++) if (cs[i].id === id) return cs[i];
    return null;
  }
  function checkById(id) { return findCheck(CHECK, id); }

  function engineDown(r) {
    if (ENGINE_LIVE === false) return true;
    return !!r && ranSection(r, "device") && r.engine === null;
  }
  function guardTripped(r) {
    if (GUARD_TRIPPED !== null) return GUARD_TRIPPED;
    const g = findCheck(r, "boot-guard-armed");
    return !!g && g.verdict === "fail";
  }

  const VERDICT_LABEL = {
    fail: "worth knowing",
    reboot: "reboot to finish",
    warn: "worth a look",
    unmeasured: "not measured",
    note: "for information",
  };

  // Only a finding that carries an oracle - a named way an app would actually observe it - may
  // claim a detector can see it. Half the warn findings are not visibility problems at all
  // ("module content not served", "planned rule not live", "target claimed twice"), and
  // stamping them all with the detector line told the user they were exposed by something no
  // app can look at, directly above evidence saying the files are served by nothing.
  function verdictLabel(c) {
    if ((c.verdict === "warn" || c.verdict === "fail") && c.oracle) return "a detector can see this";
    return VERDICT_LABEL[c.verdict] || c.verdict;
  }
  function isAttention(v) { return v === "fail" || v === "reboot" || v === "warn"; }

  // How many findings the last check left open. Returns 0 when nothing has been checked, so a
  // device with no report reads as "no news", never as "N things wrong".
  function checkAttention() {
    const s = CHECK && CHECK.summary;
    if (!s) return 0;
    return (s.open_failures || 0) + (s.warn || 0);
  }
  function isShown(v) { return isAttention(v) || v === "unmeasured"; }

  function auAge(ts) {
    if (!ts) return "";
    const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (secs < 90) return "just now";
    const mins = Math.round(secs / 60);
    if (mins < 90) return mins + " min ago";
    const hrs = Math.round(mins / 60);
    if (hrs < 36) return hrs + "h ago";
    return Math.round(hrs / 24) + "d ago";
  }

  function paintHealthLine(r) {
    const el = $("healthline"), dot = $("hlDot"), txt = $("hlTxt");
    if (!el) return;
    el.classList.remove("attn", "down");
    // engineDown() and guardTripped() answer from ENGINE_LIVE/GUARD_TRIPPED without needing a
    // report, so they are asked first. Testing !r first told the one user who most needs an
    // answer - the kernel has no engine, so no check can ever produce a report - that they had
    // simply not run a check yet, and sent them to press a button that does not exist.
    if (engineDown(r) || guardTripped(r)) {
      el.classList.add("attn", "down");
      dot.className = "hl-dot info";
      txt.innerHTML = engineDown(r)
        ? "<b>The engine isn’t running</b> <span class=\"age\">· nothing is being injected</span>"
        : "<b>The bootloop guard tripped</b> <span class=\"age\">· the Suite disabled itself</span>";
      return;
    }
    if (!r || !r.summary) {
      dot.className = "hl-dot";
      txt.innerHTML = "<b>Not checked yet</b> <span class=\"age\"> - tap to run a check</span>";
      return;
    }
    const s = r.summary;
    const attn = (s.open_failures || 0) + (s.warn || 0);
    const unm = s.unmeasured || 0;
    const age = r.ts ? ' <span class="age">· checked ' + esc(auAge(r.ts)) + "</span>" : "";
    if (attn > 0) {
      dot.className = "hl-dot ok";
      txt.innerHTML = "<b>" + attn + (attn > 1 ? " findings" : " finding") +
                      " worth reading</b>" + age;
    } else if (!ranSection(r, "device")) {
      dot.className = "hl-dot info";
      txt.innerHTML = "<b>Only your plan was checked</b> " +
                      "<span class=\"age\"> - tap to check the device too</span>";
    } else if (unm > 0 || s.complete === false) {
      dot.className = "hl-dot info";
      txt.innerHTML = "<b>Not fully checked yet</b> <span class=\"age\"> - " +
                      (unm || 1) + (unm === 1 ? " check" : " checks") +
                      " had nothing to look at</span>";
    } else {
      dot.className = "hl-dot ok";
      txt.innerHTML = "<b>Nothing found</b>" + age;
    }
    el.style.display = "";
  }

  let CHECK_RUNNING = false;
  async function runCheck(btn) {
    if (CHECK_RUNNING) { toast("A check is already running", "info"); return; }
    const done = busy(btn, "Checking...");
    $("findlist").innerHTML = '<div class="empty">Checking...</div>';
    CHECK_RUNNING = true;
    try {
      const r0 = await nm("check --json --write");
      const rep = parseJson(r0);
      if (rep) CHECK = rep;
      else toast("Check did not run - " +
                 (((r0.stderr || "").trim().split("\n")[0]) || "no output"), "bad");
      renderCheck(CHECK);
      refreshStealth(); refreshStatus(); paintModuleMetric();
    } finally { CHECK_RUNNING = false; done(); }
  }

  const CHECK_FRESH_SECS = 60;
  async function autoCheck() {
    if (CHECK_RUNNING) return;
    const ts = CHECK && typeof CHECK.ts === "number" ? CHECK.ts : 0;
    const fresh = ts && (Math.floor(Date.now() / 1000) - ts) < CHECK_FRESH_SECS;
    if (fresh && ranSection(CHECK, "device")) return;
    CHECK_RUNNING = true;
    try {
      const r = parseJson(await nm("check --json --write"));
      if (r) { CHECK = r; renderCheck(CHECK); refreshStealth(); refreshStatus(); paintModuleMetric(); }
    } catch (e) {
    } finally { CHECK_RUNNING = false; }
  }

  async function loadCheckCache() {
    CHECK = parseJson(await exec("cat /data/adb/nomount/audit.json 2>/dev/null"));
    renderCheck(CHECK);
  }

  function renderCheck(r) {
    const list = $("findlist"), chip = $("fchip"), sub = $("fsub"), age = $("auage");
    paintHealthLine(r);
    paintAbsorbChip();
    // Keep Copy report reachable when the engine is down. That is the state a bug report is
    // most needed in, and it is exactly the state that produces no report to gate the button on.
    $("auCopy").style.display = (r || engineDown(r)) ? "" : "none";

    if (!r || !r.checks) {
      list.innerHTML = engineDown(r)
        ? '<div class="empty">No kernel driver, so there is nothing to check yet. Use <b>Copy report</b> to get the details for a bug report.</div>'
        : '<div class="empty">Not checked yet - press <b>Re-run</b>.</div>';
      chip.textContent = engineDown(r) ? "engine down" : "not checked";
      chip.className = "chip info";
      age.style.display = "none";
      return;
    }

    // runCheck does not set NM_REDACT_HIDE_LIST, so the raw report carries real appids. This
    // pane is the one users screenshot and paste into a bug report, and copyReport already
    // redacts on the way out - the same rule has to hold here.
    $("auditout").textContent = redactUids(JSON.stringify(r, null, 1));
    age.style.display = "";
    age.textContent = "Checked " + (auAge(r.ts) || "now") + " · " +
      (r.sections && r.sections.length ? r.sections.join(" + ") : "unknown") + " · " +
      (r.verdict || "");

    const rows = r.checks.filter(function (c) { return isShown(c.verdict); });
    const attention = rows.filter(function (c) { return isAttention(c.verdict); });
    const unmeasured = rows.filter(function (c) { return c.verdict === "unmeasured"; });
    const down = engineDown(r);

    if (down) { chip.textContent = "engine down"; chip.className = "chip info"; }
    else if (guardTripped(r)) { chip.textContent = "guard tripped"; chip.className = "chip info"; }
    else if (attention.length) {
      chip.textContent = attention.length + (attention.length > 1 ? " findings" : " finding");
      chip.className = "chip ok";
    }
    else if (!ranSection(r, "device")) { chip.textContent = "plan only"; chip.className = "chip info"; }
    else if (unmeasured.length) { chip.textContent = unmeasured.length + " not measured"; chip.className = "chip info"; }
    else { chip.textContent = "all clear"; chip.className = "chip ok"; }

    const s = r.summary || {};
    const clean = (s.pass || 0) + (s.not_applicable || 0) + (s.note || 0);

    const group = function (title, gr) {
      return gr.length
        ? '<div class="fgroup">' + title + ' <span class="cnt">' + gr.length + "</span></div>" +
          gr.map(checkRow).join("")
        : "";
    };

    if (down || guardTripped(r)) {
      sub.textContent = down
        ? "The engine is not answering, so nothing here describes what is being served."
        : "The Suite disabled itself, so nothing is being injected.";
      list.innerHTML =
        '<div class="frow"><div class="fname">' +
        (down ? "The engine isn’t running" : "The bootloop guard tripped") + "</div>" +
        '<div class="fmean">' +
        (down
          ? "Nothing is being injected, so a clean result below says nothing about how you " +
            "look to an app."
          : "Re-arm it in Bootloop guard on Status, then reboot.") +
        '</div><div class="fmeta"><span class="tag info">' +
        (down ? "engine down" : "guard tripped") + "</span></div></div>" +
        group("Worth knowing", attention);
      return;
    }
    if (!rows.length && ranSection(r, "device")) {
      sub.textContent = clean + " check" + (clean === 1 ? "" : "s") +
        " ran across " + (r.sections || []).join(" and ") + ". Nothing to report.";
      list.innerHTML = "";
      return;
    }

    sub.textContent = "Everything that passed is left out. What is left is information about this device - the Suite is working, and nothing here has to be fixed for it to keep working.";
    let head = "";
    if (!ranSection(r, "device")) {
      head = '<div class="frow"><div class="fname">Only your plan was checked</div>' +
        '<div class="fmean">This report covers what your module set will do at the next boot. ' +
        "Nothing on the device itself was measured, so nothing here says whether what you " +
        "serve is detectable.</div>" +
        '<div class="fmeta"><span class="tag info">plan only</span>' +
        '<button class="act" style="flex:none;min-width:0;padding:12px 16px;font-size:12.5px;margin-left:auto" ' +
        'onclick="runCheck(this)">Check the device</button></div></div>';
    }
    let unmHead = "";
    if (unmeasured.length || s.complete === false) {
      unmHead = '<div class="frow"><div class="fname">' +
        (attention.length ? "Not a complete answer" : "Not everything could be measured") + "</div>" +
        '<div class="fmean">' + unmeasured.length + " check" +
        (unmeasured.length === 1 ? "" : "s") + " had nothing to look at when this ran, so " +
        (unmeasured.length === 1 ? "it is" : "they are") + " not " +
        (unmeasured.length === 1 ? "a pass" : "passes") + ". " +
        (attention.length
          ? "Read what is above first - several of these depend on it."
          : "The usual reason is timing: the boot pass runs before any app has opened an " +
            "injected file, so the checks that need a running app cannot answer then. " +
            "Run them now that the device is up.") + "</div>" +
        '<div class="fmeta"><span class="tag info">not measured</span>' +
        '<button class="act" style="flex:none;min-width:0;padding:12px 16px;font-size:12.5px;margin-left:auto" ' +
        'onclick="runCheck(this)">Run them now</button></div></div>';
    }
    list.innerHTML = head +
      group("Worth knowing", attention) +
      (unmeasured.length ? '<div class="fgroup">Not measured <span class="cnt">' +
        unmeasured.length + "</span></div>" + unmHead + unmeasured.map(checkRow).join("")
        : unmHead);
  }

  function checkRow(c) {
    const b = [];
    b.push('<div class="frow" id="chk-' + esc(c.id) + '">');
    // Lead with the plain-English meaning the backend already writes for 65 of these, and keep
    // the check's own name as the secondary technical label. Leading with "readdir ino vs stat
    // ino" told the reader nothing they could act on.
    if (c.meaning) {
      b.push('<div class="fname">' + esc(redactUids(c.meaning)) + "</div>");
      b.push('<div class="fmean">' + esc(c.name) + "</div>");
    } else {
      b.push('<div class="fname">' + esc(c.name) + "</div>");
    }
    if (c.verdict === "reboot") {
      b.push('<div class="fmean"><b>Next:</b> reboot to finish this one.</div>');
    }
    if (c.owner) b.push('<div class="fowner">From: <b>' + esc(c.owner) + "</b></div>");
    b.push('<div class="fmeta"><span class="tag ' + (c.verdict === "note" ? "off" : "info") + '">' +
           esc(verdictLabel(c)) + "</span>" +
           '<span class="tag off">' + esc(c.section || "") + "</span></div>");
    b.push('<details><summary>What was measured</summary><div class="ev">' +
           esc(redactUids(c.evidence || "(nothing recorded)")) +
           (c.oracle ? "\n\nhow an app would use it: " + esc(c.oracle) : "") +
           "</div></details>");
    b.push("</div>");
    return b.join("");
  }

  async function copyReport(btn) {
    if (!CHECK && !engineDown(CHECK)) { toast("Run the check first."); return; }
    if (!CHECK) {
      // No engine means no report will ever exist, so hand over what can be gathered without
      // one rather than refusing - this is the install that most needs to be reportable.
      const d = busy(btn, "Copying...");
      const e = await exec(
        'echo "$(getprop ro.product.marketname)|$(getprop ro.build.version.release)|' +
        '$(getprop ro.build.id)|$(uname -r)|$(uname -v)|$(getprop ro.product.model)|' +
        '$(lsmod 2>/dev/null | grep -c -i kernelsu)"'
      );
      const q = (e.stdout || "").trim().split("|");
      const t = [
        "NoMount Suite " + SUITE_VERSION +
          (SUITE_COMMIT && SUITE_COMMIT !== "dev" ? " (" + SUITE_COMMIT + ")" : "") + " - check",
        "device: " + (q[0] || q[5] || "?") + " · Android " + (q[1] || "?") + " · " + (q[2] || "?"),
        "kernel: " + (q[3] || "?") + (q[4] ? " · " + q[4] : ""),
        "root: " + (q[6] && q[6] !== "0" ? "LKM - kernelsu.ko is loaded, so the running kernel is not a NoMount build" : "built into the kernel, or unknown"),
        "engine: not responding - no CONFIG_NOMOUNT kernel, so no check could run",
      ].join("\n");
      let copied = false;
      try {
        await navigator.clipboard.writeText(t);
        copied = true;
      } catch (err) { copied = false; }
      d();
      if (copied) toast("Report copied.");
      else {
        $("auditout").textContent = t;
        const dd = $("auditout").closest("details");
        if (dd) dd.open = true;
        $("devtools").open = true;
        toast("Clipboard unavailable - the report is in Raw report, ready to select.");
      }
      return;
    }
    const done = busy(btn, "Copying...");
    const env = await exec(
      'echo "$(getprop ro.product.marketname)|$(getprop ro.build.version.release)|' +
      '$(getprop ro.build.id)|$(uname -r)|$(uname -v)|$(getprop ro.product.model)|' +
      '$(lsmod 2>/dev/null | grep -c -i kernelsu)"'
    );
    const p = (env.stdout || "").trim().split("|");
    const s = CHECK.summary || {};
    const lines = [
      "NoMount Suite " + (CHECK.suite || SUITE_VERSION) +
        (SUITE_COMMIT && SUITE_COMMIT !== "dev" ? " (" + SUITE_COMMIT + ")" : "") + " - check",
      "device: " + (p[0] || p[5] || "?") + " · Android " + (p[1] || "?") + " · " + (p[2] || "?"),
      "kernel: " + (p[3] || "?") + (p[4] ? " · " + p[4] : ""),
      "root: " + (p[6] && p[6] !== "0" ? "LKM - kernelsu.ko is loaded, so the running kernel is not a NoMount build" : "built into the kernel, or unknown"),
      "engine: " + (CHECK.engine === null || CHECK.engine === undefined ? "not responding" : "v" + CHECK.engine),
      "sections: " + ((CHECK.sections || []).join(", ") || "?"),
      "rules: " + (CHECK.rules === null || CHECK.rules === undefined
        ? "could not enumerate"
        : CHECK.rules + " across " + (CHECK.directories === null || CHECK.directories === undefined
            ? "?" : CHECK.directories) + " directories"),
      "summary: " + (s.fail || 0) + " failed, " + (s.reboot || 0) + " pending reboot, " +
        (s.unmeasured || 0) + " unmeasured, " + (s.warn || 0) + " warnings, " +
        (s.pass || 0) + " passed, " + (s.not_applicable || 0) + " n/a, " + (s.note || 0) + " notes",
      "verdict: " + (CHECK.verdict || "?"),
      ""
    ];
    (CHECK.checks || []).forEach(function (c) {
      if (!isShown(c.verdict)) return;
      lines.push("[" + String(c.verdict).toUpperCase() + "] " + c.name + " (" + c.section + ")");
      if (c.owner) lines.push("  from: " + c.owner);
      // BOTH label formats: audit.rs writes "uid N (hidden)", doctor.rs writes
      // "hidden uid N". `runCheck` does not set NM_REDACT_HIDE_LIST, so the real appid is in
      // the JSON and this is the only thing standing between it and a pasted bug report.
      lines.push("  measured: " + redactUids(c.evidence));
      if (c.meaning) lines.push("  means: " + redactUids(c.meaning));
      lines.push("");
    });
    const text = lines.join("\n");
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) { ok = false; }
    done();
    if (ok) toast("Report copied.");
    else {
      $("auditout").textContent = text;
      const d = $("auditout").closest("details");
      if (d) d.open = true;
      $("devtools").open = true;
      toast("Clipboard unavailable - the report is in Raw report, ready to select.");
    }
  }

  function _healthShow(txt) { const o = $("healthout"); o.style.display = ""; o.textContent = txt.trim() || "(no output)"; }

  async function runSnapshot(btn) {
    const had = (await exec("[ -f /data/adb/nomount/snapshot.txt ] && echo 1 || echo 0")).stdout.trim() === "1";
    if (had && !(await confirmAction(
      "Replace the saved baseline?",
      "Verify compares this device against the snapshot you took when you were happy with it. " +
      "A new one overwrites that reference with today's state - including anything that has " +
      "drifted since - and the old baseline cannot be recovered.",
      "Replace"))) return;
    const done = busy(btn, "Saving...");
    const r = await nm("snapshot");
    _healthShow((r.stdout || "") + (r.stderr || ""));
    toast(r.errno === 0 ? "Snapshot saved as baseline" : "Snapshot failed", r.errno === 0 ? "ok" : "bad");
    done();
  }
  async function runVerify(btn) {
    const done = busy(btn, "Verifying...");
    const r = await nm("verify");
    const txt = (r.stdout || "") + (r.stderr || "");
    _healthShow(txt);
    if (r.errno !== 0 || !txt.trim()) toast("Verify did not run", "bad");
    else if (/DRIFT/.test(txt)) toast("Drift from snapshot - see output", "bad");
    else if (/no snapshot yet/.test(txt)) toast("No baseline yet - take a snapshot first", "");
    else if (/no drift/.test(txt)) toast("Matches snapshot", "ok");
    else toast("Verify gave no verdict - see output", "");
    done();
  }
  async function runExport(btn) {
    if (!(await confirmAction(
      "Write diagnostics to /sdcard/Download?",
      "Any app with storage permission can read that folder. The check report, the fingerprint, " +
      "your rule list and your mount table go there. The apps you hide from, and what is being " +
      "spoofed, are deliberately left out of a shared destination.",
      "Export"))) return;
    const done = busy(btn, "Exporting...");
    const r = await nm("export");
    const txt = (r.stdout || "") + (r.stderr || "");
    _healthShow(txt);
    const path = (txt.match(/exported to (\S+)/) || [])[1];
    toast(path ? "Exported to " + path : "Export failed", path ? "ok" : "bad");
    done();
  }

  async function refreshIncident() {
    const r = await exec("cat /data/adb/nomount/incident.log 2>/dev/null");
    const txt = (r.stdout || "").trim();
    const card = $("incidentcard");
    if (!txt) {
      card.style.display = "none";
      const w = $("incwarn");
      if (w) w.hidden = true;
      return;
    }
    card.style.display = "";
    $("incidentout").textContent = txt;
    const el = $("incwarn");
    if (el) {
      const dr = await exec("[ -e /data/adb/nomount/disabled ] && echo 1 || echo 0");
      const off = ((dr && dr.stdout) || "").trim() === "1";
      const btn = '<button class="act" style="flex:none;min-width:0;padding:11px 15px;' +
        'font-size:12px;margin-left:8px" onclick="openDetail()">See what happened</button>';
      el.hidden = false;
      el.innerHTML = off
        ? "\u26a0\ufe0f The bootloop guard tripped and disabled the Suite. " +
          "<b>Nothing is being injected</b> until you re-arm it. " + btn
        : "\u26a0\ufe0f An earlier boot recorded an incident. The Suite is running now \u2014 " +
          "this is a saved record, not current state. " + btn;
    }
  }
  async function clearIncident(btn) {
    if (!(await confirmAction(
      "Delete the incident record?",
      "The saved crash from the boot that disabled the Suite is removed for good. It is the only " +
      "copy, and it usually names the file that caused the failure.",
      "Delete"))) return;
    { const el = $("incwarn"); if (el) el.hidden = true; }
    btn.disabled = true;
    await exec("rm -f /data/adb/nomount/incident.log");
    toast("Incident record cleared", "ok");
    btn.disabled = false; refreshIncident();
  }

  async function refreshModules() {
    const box = $("modules");
    const r = (await exec(
      'for d in /data/adb/modules/*/; do [ -d "$d" ] || continue; ' +
      'id=$(basename "$d"); ' +
      'mnt=$(NM_P="/adb/modules/$id" awk \'$4==ENVIRON["NM_P"] || index($4, ENVIRON["NM_P"] "/")==1 {n++} END{print n+0}\' /proc/self/mountinfo 2>/dev/null); ' +
      '[ "$id" = meta-nomount ] && { echo "$id|suite|$mnt"; continue; }; ' +
      '[ "$id" = kernelnosu ] && { echo "$id|su|$mnt"; continue; }; ' +
      'st=on; { [ -f "$d/disable" ] || [ -f "$d/remove" ] || [ -f "$d/skip_mount" ]; } && st=off; ' +
      'echo "$id|$st|$mnt"; done'
    ));
    if (r.errno !== 0) {
      box.innerHTML = '<div class="empty">Unknown - the module list could not be read.</div>';
      $("modcount").textContent = "?"; $("mMod").textContent = "?";
      return;
    }
    const out = r.stdout.trim();
    if (!out) { box.innerHTML = '<div class="empty">No modules installed.</div>'; $("modcount").textContent = "0"; $("mMod").textContent = "0"; return; }
    const byModule = await planByModule();
    // The check already works out which modules ship files nobody serves
    // and names the owner. Say it on the row, not only in the count.
    const unservedBy = {};
    ((CHECK && CHECK.checks) || []).forEach(function (c) {
      if (c.name === "module content not served" && c.owner) unservedBy[c.owner] = c;
    });
    const rows = out.split("\n").filter(Boolean);
    $("modcount").textContent = rows.length;
    let served = 0;
    box.innerHTML = rows.map((l) => {
      const p = l.split("|");
      const id = p[0];
      const plan = byModule ? (byModule.modules[id] || { files: 0, overlay: false, vfs: false }) : null;
      const cnt = plan ? plan.files : 0;
      const mntRaw = (p[2] || "").trim();
      const mnt = /^\d+$/.test(mntRaw) ? parseInt(mntRaw, 10) : -1;
      let label, cls, showCnt = false, tip = "";
      if (p[1] === "suite") { label = "suite"; cls = "suite"; tip = "The NoMount Suite metamodule itself."; }
      else if (p[1] === "su") { label = "su backend"; cls = "su"; served++; tip = "Provides su; not injected by the Suite."; }
      else if (p[1] === "off") { label = "skipped"; cls = "off"; tip = "Has a disable / remove / skip_mount marker, so the Suite leaves it alone."; }
      else if (!plan) { label = "?"; cls = "off"; tip = "The plan could not be read, so what this module contributes is unknown."; }
      else if (plan.overlay && plan.vfs) { label = "vfs + overlay"; cls = "ov"; served++; showCnt = true; }
      else if (plan.overlay) { label = "overlay"; cls = "ov"; served++; showCnt = true; }
      else if (plan.vfs) { label = "vfs"; cls = "vfs"; served++; showCnt = true; }
      else if (plan.bind) { label = "bind"; cls = "off"; served++; showCnt = true;
                            tip = "Served by a real bind mount, not an injection - a my_* target is bound unless the my_hookless trial is on."; }
      else { label = "nothing to inject"; cls = "off"; tip = "This module ships no files the Suite can serve - scripts, zygisk, binaries, or an empty partition directory."; }
      const files = (showCnt && cnt > 0) ? `<span class="files">${cnt} file${cnt > 1 ? "s" : ""}</span>` : `<span class="files"></span>`;
      const vis = mnt < 0
        ? `<span class="tag off" title="The mount table could not be read, so this module's visibility is unknown - it is not a claim that it owns no mount">mounts unknown</span>`
        : mnt > 0
        ? `<span class="tag info" title="This module has ${mnt} mount(s) of its own in the mount table - visible to a scanner">${mnt} mount${mnt > 1 ? "s" : ""}</span>`
        : `<span class="tag ok" title="Nothing this module owns appears in the mount table">mountless</span>`;
      const uns = unservedBy[id];
      if (uns) {
        label = "not served"; cls = "info"; tip = "";
      }
      const why = uns
        ? `<div class="mwhy">${esc(redactUids(uns.evidence || uns.meaning || ""))}</div>`
        : "";
      return `<div class="mrow${uns ? " unserved" : ""}"><div class="mname">${esc(id)}</div>${why}` +
             `<div class="mmeta">${files}${vis}<span class="tag ${cls}"${tip ? ` title="${esc(tip)}"` : ""}>${label}</span></div></div>`;
    }).join("");
    MOD_SERVED = served;
    paintModuleMetric();
  }

  async function refreshRuleSummary() {
    const d = await ruleDump();
    if (!d.ok) {
      $("rulechip").textContent = "?";
      $("rulebreak").textContent = "Unknown \u2014 the engine did not answer.";
      return;
    }
    const rro = d.rro.length, vfs = d.injects.length - rro;
    $("rulechip").textContent = d.injects.length;
    $("rulebreak").textContent = d.injects.length
      ? `${vfs} file redirect${vfs === 1 ? "" : "s"} · ${rro} RRO overlay APK${rro === 1 ? "" : "s"} - all Prism, no mounts`
      : "No rules active.";
    _paintRuleModuleBar(d.lines.filter((l) => !l.includes("(virtual dir)")));
  }

  const _RM_PALETTE = ["#57e6c3", "#7c9cff", "#c792ea", "#4fd1e0", "#9ccc65", "#a5b4fc", "#5eead4"];
  function _paintRuleModuleBar(lines) {
    const box = $("ruleModuleBar"); if (!box) return;
    if (!lines.length) { box.style.display = "none"; box.innerHTML = ""; return; }
    const counts = {};
    lines.forEach((l) => { const m = _ruleModule(l); counts[m] = (counts[m] || 0) + 1; });
    const entries = Object.keys(counts).map((k) => [k, counts[k]]).sort((a, b) => b[1] - a[1]);
    const total = lines.length;
    const MAX = 5;
    const shown = entries.slice(0, MAX);
    const rest = entries.slice(MAX);
    if (rest.length) shown.push(["other", rest.reduce((a, e) => a + e[1], 0), true]);
    const col = (e, i) => e[2] ? "var(--faint)" : _RM_PALETTE[i % _RM_PALETTE.length];
    const seg = shown.map((e, i) =>
      `<span style="width:${(e[1] / total * 100).toFixed(2)}%;background:${col(e, i)}" title="${esc(e[0])}: ${e[1]}"></span>`
    ).join("");
    const legend = shown.map((e, i) => {
      const nm = e[2] ? `other (${rest.length} module${rest.length > 1 ? "s" : ""})` : e[0];
      return `<span class="rmleg"><span class="rmsw" style="background:${col(e, i)}"></span>` +
             `<span class="rmname" title="${esc(nm)}">${esc(nm)}</span> <b>${e[1]}</b></span>`;
    }).join("");
    box.style.display = "";
    box.innerHTML = `<div class="rmbar">${seg}</div><div class="rmlegend">${legend}</div>`;
  }

  var _files = [];
  async function refreshFiles() {
    const box = $("vfsdirs");
    const d = await ruleDump();
    if (!d.ok) {
      $("vfscount").textContent = "?";
      box.innerHTML = '<div class="empty">Unknown \u2014 the engine did not answer.</div>';
      _files = [];
      return;
    }
    const isOv = (p) => /\/overlay\/[^\s]*\.apk$/.test(p);
    const dirs = {};
    _files = d.injects.filter(Boolean).sort();
    for (const vp of _files) {
      const dir = vp.replace(/\/[^/]*$/, "") || "/";
      const e = dirs[dir] || (dirs[dir] = { n: 0, ov: 0 });
      e.n++; if (isOv(vp)) e.ov++;
    }
    const keys = Object.keys(dirs).sort((a, b) => dirs[b].n - dirs[a].n || a.localeCompare(b));
    $("vfscount").textContent = _files.length;
    if (!keys.length) box.innerHTML = '<div class="empty">No rules active.</div>';
    else box.innerHTML = keys.map((k) => {
      const e = dirs[k], ov = e.ov === e.n;
      return `<div class="row"><span class="name mono">${esc(k)}</span>` +
        `<span class="sub" style="font-size:11px;color:var(--muted);margin-right:8px">${e.n} ` +
        `${ov ? "apk" : "file"}${e.n > 1 ? "s" : ""}</span>` +
        `<span class="tag ${ov ? "ov" : "vfs"}">${ov ? "RRO" : "Prism"}</span></div>`;
    }).join("");
    if ($("vfsfull").style.display !== "none") renderFilesFull();
  }
  const WO_PATH_RE = /^\/[^\x00-\x1f\x7f]+$/;
  function toggleWhiteouts(h) {
    const on = h.classList.toggle("open");
    setExp(h);
    $("wobody").style.display = on ? "" : "none";
    if (on) refreshWhiteouts();
  }
  async function whiteoutSets() {
    const r = await nm("whiteout list");
    if (r.errno !== 0) return { ok: false, durable: [], auto: [] };
    const durable = (r.stdout || "").split("\n").map(x => x.trim())
      .filter(Boolean).filter(l => !/^no whiteouts/.test(l));
    const live = await ruleDump();
    const auto = live.ok
      ? live.lines.filter(l => l.includes("(whiteout)"))
          .map(l => (l.split(" (whiteout)")[0] || "").trim())
          .filter(p => p && !durable.some(x => x.split("	")[0] === p))
      : [];
    return { ok: true, durable, auto };
  }

  async function woChipOnly() {
    const w = await whiteoutSets();
    $("wochip").textContent = w.ok ? String(w.durable.length + w.auto.length) : "?";
  }
  async function refreshWhiteouts() {
    const box = $("woList");
    const w = await whiteoutSets();
    if (!w.ok) {
      $("wochip").textContent = "?";
      box.innerHTML = '<div class="empty">Unknown - the list could not be read.</div>';
      return;
    }
    const lines = w.durable;
    const auto = w.auto;
    const autoHtml = auto.map((p) =>
      `<div class="row abrow"><span class="ab-main">` +
      `<div class="ab-path">${esc(p)}</div>` +
      `<div class="ab-why">managed automatically - it goes when the module that asked for it goes</div>` +
      `</span><span class="tag vfs">from a module</span></div>`).join("");

    if (!lines.length) {
      $("wochip").textContent = String(auto.length);
      box.innerHTML = auto.length
        ? '<div class="empty">Nothing saved by you. The Suite hid ' + auto.length +
          ' ROM path' + (auto.length > 1 ? 's' : '') +
          " in place of a module's tmpfs:</div>" + autoHtml
        : '<div class="empty">Nothing hidden.</div>';
      return;
    }
    $("wochip").textContent = String(lines.length + auto.length);
    box.innerHTML = lines.map(l => {
      const path = l.split("\t")[0];
      const st = (l.split("\t")[1] || "").trim();
      const cls = /^hidden/.test(st) ? "vfs"
        : /^not applied \(and no such path/.test(st) ? "off" : "info";
      const hint = /^not applied - run/.test(st) ? "saved, not live yet - tap Reload on Status"
                 : /^applied, but still visible/.test(st) ? "the engine is not serving it - tap Reload on Status"
                 : /^not applied \(and no such path/.test(st) ? "this ROM has no such path - nothing to hide"
                 : "";
      const tag = /^not applied \(/.test(st) ? "not applied" : st.split(" - ")[0];
      return `<div class="row abrow"><span class="ab-main">` +
             `<div class="ab-path">${esc(path)}</div>` +
             (hint ? `<div class="ab-why">${esc(hint)}</div>` : "") + `</span>` +
             `<span class="tag ${cls}">${esc(tag)}</span>` +
             `<button class="bx" title="Stop hiding" data-act="wodel" data-nmp="${esc(path)}">✕</button></div>`;
    }).join("") + autoHtml;
  }
  async function woAdd(btn) {
    const v = ($("woPath").value || "").trim();
    if (!v) { toast("Enter an absolute path", "bad"); return; }
    if (!WO_PATH_RE.test(v)) { toast("An absolute path, on one line", "bad"); return; }
    const done = busy(btn, "Hiding...");
    const r = await woApply(v);
    if (r.errno === 0) $("woPath").value = "";
    RULES = null;
    PLAN_BY_MODULE = null;
    done(); refreshWhiteouts(); refreshStatus();
  }
  async function woApply(path) {
    const r = await nm(`whiteout add ${shq(path)}`);
    const txt = ((r.stdout || "") + (r.stderr || "")).trim();
    toast(r.errno === 0 ? (txt.split("\n").pop() || "Hidden") : failText(r, txt),
          r.errno === 0 ? "ok" : "bad");
    return r;
  }
  async function woRemove(path, btn) {
    if (!(await confirmAction(
      "Stop hiding " + path + "?",
      "That path becomes visible again to every app the moment it next looks, and the entry " +
      "is removed from your list. A module that hid it will hide it again on the next boot; " +
      "one you added by hand will not come back.",
      "Stop hiding"))) return;
    const done = busy(btn);
    const r = await nm(`whiteout remove ${shq(path)}`);
    const txt = ((r.stdout || "") + (r.stderr || "")).trim();
    toast(r.errno === 0 ? "No longer hidden" : "Failed: " + (txt || "error"),
          r.errno === 0 ? "ok" : "bad");
    RULES = null;
    PLAN_BY_MODULE = null;
    done(); refreshWhiteouts(); refreshStatus();
  }
  function absorbable(r) {
    const c = findCheck(r, "zero-mount-posture");
    if (!c) return -1;
    if (c.verdict === "pass") return 0;
    if (c.verdict === "unmeasured") return -1;
    if (c.verdict === "note" || c.verdict === "warn") return 0;
    const m = c.evidence && c.evidence.match(/(\d+)\s+module mount\(s\) visible/);
    return m ? parseInt(m[1], 10) : -1;
  }
  async function refreshAbsorbed() {
    const box = $("abDone");
    if (!box) return;
    const r = await exec(
      "while IFS= read -r l; do case \"$l\" in ''|'#'*) continue;; esac; " +
      "t=${l%%\t*}; s=${l#*\t}; " +
      "[ \"$t\" = \"$s\" ] && continue; " +
      "printf '%s\\t%s\\t%s\\n' \"$t\" \"$s\" \"$([ -e \"$s\" ] && echo live || echo gone)\"; " +
      "done < /data/adb/nomount/absorbed.list 2>/dev/null"
    );
    const rows = (r.stdout || "").split("\n").map(x => x.trim()).filter(Boolean);
    ABSORBED_N = rows.length;
    paintModuleMetric();
    if (!rows.length) { box.innerHTML = ""; return; }
    const owner = (s) => {
      const m = s.match(/\/data\/adb\/modules(?:_update)?\/([^/]+)/);
      return m ? m[1] : s;
    };
    box.innerHTML = `<div class="blk-head">Already absorbed · ${rows.length}</div>` +
      rows.map(function (l) {
        const p = l.split("\t"), tgt = p[0] || "", src = p[1] || "", live = p[2] === "live";
        return `<div class="row abrow"><span class="ab-main">` +
               `<div class="ab-path">${esc(tgt)}</div>` +
               `<div class="ab-why">from ${esc(owner(src))}` +
               (live ? "" : " - module no longer installed") + `</div>` +
               `</span><span class="tag ${live ? "vfs" : "off"}">` +
               (live ? "absorbed" : "stale entry") + `</span></div>`;
      }).join("");
  }

  let ABSORBED_N = -1;
  let MOD_SERVED = -1;
  // Coverage is the thing the Suite exists to get right, so it goes on Status
  // rather than in a check nobody opens. Painted by whichever of refreshModules
  // and refreshAbsorbed finishes last: they run in parallel.
  function paintModuleMetric() {
    if (MOD_SERVED < 0) return;
    // "0 unserved" is the strongest claim this page makes: the module set is
    // fully covered. With no cached report -- absent audit.json, or service.sh
    // deleting it after a check that timed out or did not finish -- filtering an
    // empty list also yields 0, and the card asserted full coverage having
    // measured nothing. Unmeasured is not clean.
    //
    // The question is "is there a report", NOT `ranSection(CHECK,"plan")`: the
    // plan half emits a finding only when it HAS one, so a device whose module
    // set is perfectly clean produces zero plan checks and `sections` omits
    // "plan" entirely. Keying on that rendered "coverage unchecked" on exactly
    // the fully-covered device the metric exists to praise -- the inverse of
    // this bug. See check.rs's `ran()`, which cannot tell clean from absent.
    const measured = !!(CHECK && Array.isArray(CHECK.checks));
    const unserved = measured
      ? CHECK.checks.filter(function (c) { return c.name === "module content not served"; }).length
      : -1;
    // the bare number needs its word, or "4 0 unserved" reads as two figures
    const rest = [];
    if (ABSORBED_N > 0) rest.push(ABSORBED_N + " absorbed");
    rest.push(unserved < 0 ? "coverage unchecked" : unserved + " unserved");
    $("mMod").innerHTML = MOD_SERVED +
      "<small>served · " + rest.join(" · ") + "</small>";
  }

  async function refreshAbsorb() {
    await refreshAbsorbed();
    paintAbsorbChip();
  }
  function paintAbsorbChip() {
    const chip = $("abchip");
    if (!chip) return;
    const n = absorbable(CHECK);
    if (n < 0) { chip.textContent = " - "; chip.className = "chip"; return; }
    chip.textContent = n === 0 ? (ABSORBED_N > 0 ? "none left" : "none") : String(n);
    chip.className = n === 0 ? "chip ok" : "chip info";
  }

  async function abScan(btn) {
    const done = busy(btn, "Scanning...");
    const r = await nm("absorb --dry-run");
    const out = ((r.stdout || "") + (r.stderr || "")).trim();
    const box = $("abFound");
    box.style.display = "";
    const lines = out.split("\n").map(x => x.trim()).filter(Boolean);
    if (!lines.length) {
      box.innerHTML = '<div class="empty">No answer from absorb.</div>';
    } else {
      const KINDS = [
        [/^skipping the tmpfs over /, "off",  "left alone"],
        [/^skipping /,                "off",  "left alone"],
        [/^would skip directory bind /, "off", "needs --include-dirs"],
        [/^would drop redundant mount /, "vfs", "already served"],
        [/^redundant /,               "vfs",  "already served"],
        [/^would absorb /,            "info", "would absorb"],
        [/^would empty /,             "info", "would empty"],
        [/^nomount: LEAK /,           "info", "absorb cannot fix"],
        [/^nomount absorb: \d+ my_\* mount\(s\) deferred/, "info", "deferred to next boot"],
      ];
      const owner = (s) => {
        const m = s.match(/\/data\/adb\/modules(?:_update)?\/([^/]+)/);
        return m ? m[1] : s;
      };
      box.innerHTML = lines.map(function (l) {
        let kind = null;
        for (var i = 0; i < KINDS.length && !kind; i++) if (KINDS[i][0].test(l)) kind = KINDS[i];
        if (!kind) {
          if (/^nomount absorb:/.test(l))
            return `<div class="empty">${esc(l.replace(/^nomount absorb:\s*/, ""))}</div>`;
          return `<div class="empty">${esc(l)}</div>`;
        }
        if (kind[2] === "absorb cannot fix" || kind[2] === "deferred to next boot")
          return `<div class="row abrow"><span class="ab-main">` +
                 `<div class="ab-why">` +
                 esc(l.replace(/^nomount: LEAK /, "").replace(/^nomount absorb: /, "")) +
                 `</div></span><span class="tag ${kind[1]}">${kind[2]}</span></div>`;

        let rest = l.replace(kind[0], "");
        let why = "";
        const paren = rest.match(/\s*\(([^)]*)\)\s*$/);
        if (paren) { why = paren[1]; rest = rest.slice(0, paren.index); }
        const arrow = rest.split(" <- ");
        const path = arrow[0].trim();
        if (why === kind[2]) why = "";
        if (arrow[1]) why = (why ? why + " · " : "") + "from " + owner(arrow[1].trim());
        return `<div class="row abrow"><span class="ab-main">` +
               `<div class="ab-path">${esc(path)}</div>` +
               (why ? `<div class="ab-why">${esc(why)}</div>` : "") +
               `</span><span class="tag ${kind[1]}">${kind[2]}</span></div>`;
      }).join("");
    }
    done();
  }

  async function abAbsorb(btn) {
    const n = absorbable(CHECK);
    if (n === 0) { toast("Nothing to absorb", "ok"); return; }
    if (!(await confirmAction(
      "Absorb other modules' mounts?",
      "Each bind another module made is re-served as a Prism injection and then unmounted. " +
      "The files still reach apps; the mounts stop existing. Hook-framework binds are left alone. " +
      "If something depended on the mount itself rather than its contents, reboot to restore it.",
      "Absorb"))) return;
    const done = busy(btn, "Absorbing...");
    const r = await nm("absorb");
    const out = ((r.stdout || "") + (r.stderr || "")).trim();
    $("abFound").style.display = "";
    $("abFound").innerHTML = `<div class="empty">${esc(out || "(no output)")}</div>`;
    // The deferred line is printed before absorb decides whether anything else was taken, so it
    // can sit alongside a summary that absorbed plenty. Only say nothing was absorbed when the
    // summary itself says so. The deferral is also conditional on the my_hookless trial, which
    // the old wording dropped - without the marker those mounts are not taken at the next boot
    // either, so promising "the next boot" was wrong on a default install.
    const deferred = /deferred to the pre-zygote pass/.test(out);
    const absorbedNone = /nothing to absorb/.test(out) || /: 0 mount\(s\) absorbed/.test(out);
    toast(r.errno !== 0 ? failText(r)
          : deferred
            ? (absorbedNone
                ? "Deferred - my_* mounts cannot be absorbed while Android is running"
                : "Absorbed, with my_* mounts deferred")
            : "Absorb complete",
          r.errno === 0 ? "ok" : "bad");
    await runCheck(null);
    RULES = null;
    PLAN_BY_MODULE = null;
    refreshStatus();
    refreshAbsorb();
    done();
  }

  async function woScan(btn) {
    const done = busy(btn, "Scanning...");
    const r = await nm("whiteout suggest");
    if (r.errno !== 0) {
      $("woFound").style.display = "";
      $("woFound").innerHTML = '<div class="empty">Scan did not run - ' +
        esc((r.stderr || "").trim() || "the command failed") + "</div>";
      toast("Scan did not run", "bad");
      done();
      return;
    }
    const out = (r.stdout || "") + (r.stderr || "");
    const box = $("woFound");
    const cands = out.split("\n").map(x => x.trim()).filter(l => l.indexOf("\t") > 0);
    const notes = out.split("\n").map(x => x.trim())
      .filter(l => /^\(|^nothing to suggest/.test(l)).join(" ");
    box.style.display = "";
    if (!cands.length) {
      box.innerHTML = `<div class="empty">${esc(notes || "Nothing found.")}</div>`;
      toast("Nothing to hide on this device", "ok");
    } else {
      box.innerHTML =
        `<div class="blk-head">Found · ${cands.length}</div>` +
        cands.map(l => {
          const p = l.split("\t")[0], why = l.split("\t")[1] || "";
          return `<div class="row"><span class="name mono" title="${esc(p)}">${esc(p)}</span>` +
                 `<span class="tag info" title="${esc(why)}">${esc(why.split(";")[0])}</span>` +
                 `<button class="bx" title="Hide this path" data-act="woadd" data-nmp="${esc(p)}">+</button></div>`;
        }).join("") +
        (notes ? `<div class="empty">${esc(notes)}</div>` : "");
      toast(cands.length + " candidate(s) found", "ok");
    }
    done();
  }
  document.getElementById("wobody").addEventListener("click", async ev => {
    const b = ev.target.closest("button[data-act]");
    if (!b) return;
    const p = b.getAttribute("data-nmp") || "";
    if (!WO_PATH_RE.test(p)) { toast("That path has characters nomount won't take", "bad"); return; }
    if (b.getAttribute("data-act") === "wodel") { woRemove(p, b); return; }
    const done = busy(b);
    const r = await woApply(p);
    if (r.errno === 0) { RULES = null; PLAN_BY_MODULE = null; }
    done(); refreshWhiteouts();
    if (r.errno === 0) {
      const row = b.closest(".row");
      if (row) row.remove();
      refreshStatus();
    }
  });

  function renderFilesFull() {
    const q = ($("vfsfilter").value || "").trim().toLowerCase();
    const f = q ? _files.filter(p => p.toLowerCase().indexOf(q) !== -1) : _files;
    $("vfsfull").innerHTML = !f.length ? '<div class="empty">(no match)</div>'
      : f.map(p => {
          const ov = /\/overlay\/[^\s]*\.apk$/.test(p);
          return `<div class="row"><span class="name mono" title="${esc(p)}">` +
                 `${esc(p.replace(/^.*\//, ""))}</span>` +
                 `<span class="tag ${ov ? "ov" : "vfs"}">${ov ? "RRO" : "Prism"}</span></div>`;
        }).join("");
  }
  function toggleModules(h) {
    const on = h.classList.toggle("open");
    setExp(h);
    $("modules").style.display = on ? "" : "none";
  }
  let rulesShown = false;
  let _fileView = false;
  function toggleFileView(btn) {
    _fileView = !_fileView;
    if (btn) btn.textContent = _fileView ? "By module" : "By file";
    // Same six panes toggleRules drives; both must respect the collapse or switching
    // view while the card is shut reveals the list under a closed header.
    $("vfsdirs").style.display = rulesShown && _fileView ? "" : "none";
    $("vfsfull").style.display = rulesShown && _fileView ? "" : "none";
    $("vfsfilterbar").style.display = rulesShown && _fileView ? "" : "none";
    $("ruleslist").style.display = rulesShown && !_fileView ? "" : "none";
    $("rulefilterbar").querySelector("#rulefilter").style.display = _fileView ? "none" : "";
    const gb = $("rulegroupBtn");
    if (gb) gb.style.display = _fileView ? "none" : "";
    if (_fileView) renderFilesFull();
  }

  async function loadRules() {
    const d = await ruleDump();
    if (!d.ok) {
      _rulesRaw = "";
      $("ruleslist").textContent = "unknown - the engine did not answer";
      $("rulecount").style.display = "none";
      return;
    }
    _rulesRaw = d.raw;
    if (!_rulesRaw) {
      $("ruleslist").textContent = "no rules";
      $("rulecount").style.display = "none";
      return;
    }
    filterRules();
  }
  async function toggleRules(h) {
    rulesShown = h.classList.toggle("open");
    setExp(h);
    $("rulefilterbar").style.display = rulesShown ? "" : "none";
    $("rulecount").style.display = rulesShown ? "" : "none";
    // The card has no id, so applyCardState's `.card.collapsed > :not(.card-h)` rule
    // never reaches these; visibility is only ever these explicit writes. Driving
    // three of the six left the By-file panes under a closed header.
    $("ruleslist").style.display = rulesShown && !_fileView ? "" : "none";
    $("vfsdirs").style.display = rulesShown && _fileView ? "" : "none";
    $("vfsfull").style.display = rulesShown && _fileView ? "" : "none";
    $("vfsfilterbar").style.display = rulesShown && _fileView ? "" : "none";
    if (rulesShown) { $("ruleslist").textContent = "Loading..."; loadRules(); }
  }

  async function reloadRules(btn) {
    const svg = btn.querySelector("svg");
    btn.disabled = true; if (svg) svg.classList.add("spin");
    const r = await nm("reload");
    const out = (r.stdout || "").trim();
    if (r.errno === 0) {
      toast((out.split("\n")[0] || "").replace(/^nomount reload:\s*/, "") || "Reloaded", "ok");
    }
    else toast(failText(r), "bad");
    if (svg) svg.classList.remove("spin"); btn.disabled = false;
    await refreshAll().catch(refreshFailed);
    const w = $("incwarn");
    if (w && r.errno === 0 && /REBOOT REQUIRED/.test(out)) {
      w.hidden = false;
      w.innerHTML = "⚠️ A system APK changed - <b>reboot to finish</b>. " +
        "Until then, apps over those APKs can force-close.";
    }
  }
  async function clearRules(btn) {
    if (!(await confirmAction(
      "Clear every injection rule?",
      "Every file your modules add disappears straight away - apps go back to seeing the stock " +
      "ROM, and anything relying on an injected file may misbehave until you put them back. " +
      "Nothing is uninstalled: Reload, or a reboot, restores all of it.",
      "Clear rules"))) return;
    const done = busy(btn, "Clearing...");
    const r = await nm("vfs clear");
    if (r.errno === 0) toast((r.stdout || "").replace(/^ok\b\s*/, "Rules cleared ").trim() || "Rules cleared", "ok");
    else toast(/could not be re-applied/.test(r.stderr || "")
                 ? "Rules cleared - but the hide list could not be re-applied: those apps are not hidden"
                 : failText(r), "bad");
    RULES = null;
    PLAN_BY_MODULE = null;
    done();
    refreshAll().catch(refreshFailed);
  }
  async function rearm(btn) {
    if (!(await confirmAction(
      "Re-arm the bootloop guard?",
      "This deletes the record of the boot that failed, including the crash log - which is the " +
      "only copy and usually names the file that caused it. Read or copy it first. The Suite " +
      "stays off until you reboot.",
      "Delete and re-arm"))) return;
    btn.disabled = true;
    await exec("rm -rf /data/adb/nomount/disabled /data/adb/nomount/bootcount /data/adb/nomount/incident.log");
    toast("Guard re-armed - reboot to re-enable", "ok");
    btn.disabled = false; refreshGuard(); refreshIncident();
  }
  const UID_TARGET_RE = /^[A-Za-z0-9._*]+$/;
  async function uidOp(op, btn) {
    const v = $("uid").value.trim();
    if (!v) { toast("Enter a package name or UID", "bad"); return; }
    if (!UID_TARGET_RE.test(v)) { toast("Letters, digits, dots, underscores, and * for a glob", "bad"); return; }
    if (op === "unblock" && !(await confirmAction(
      "Stop hiding " + v + "?",
      v.indexOf("*") >= 0
        ? "That entry is a pattern. Every app it matches stops being hidden - now, and any that " +
          "install later - and the pattern itself is deleted from your list."
        : "This app sees your injected files again the moment it next looks, and the entry is " +
          "removed from your list.",
      "Stop hiding"))) return;
    const done = busy(btn, op === "block" ? "Hiding..." : "Unhiding...");
    const r = await nm(`uid ${op} ${shq(v)}`);
    if (r.errno === 0) {
      toast((r.stdout || "").replace(/^ok:\s*/, "").trim() || `${v} ${op === "block" ? "hidden" : "unhidden"}`, "ok");
      if (op === "block") $("uid").value = "";
      refreshBlocked();
    } else {
      toast("Failed: " + (r.stderr || "error"), "bad");
    }
    done();
  }
  async function refreshBlocked() {
    const box = $("blocked");
    const r = await nm("uid list");
    if (r.errno !== 0) {
      const uc0 = $("uidchip");
      if (uc0) uc0.textContent = "?";
      box.innerHTML = `<div class="blk-none">Unknown \u2014 the hide list could not be read.</div>`;
      return;
    }
    const lines = (r.stdout || "").split("\n").map(s => s.trim()).filter(Boolean);
    const none = !lines.length || lines[0] === "no blocked apps";
    const uc = $("uidchip");
    if (none && uc) uc.textContent = "0";
    if (none) {
      box.innerHTML = `<div class="blk-none">No per-UID hiding active - no apps hidden.</div>`;
      return;
    }
    const rows = lines.map(l => {
      const [name, stateRaw] = l.split("\t");
      const s = (stateRaw || "").trim();
      let cls = "live";
      // Every string here is one `nomount uid list` really emits. `/unreachable/`
      // used to be in the "gone" set and nothing has ever produced it.
      if (/unread/.test(s)) cls = "unknown";
      else if (/not installed/.test(s) ||
          /no match/.test(s) || /invalid glob/.test(s)) cls = "gone";
      else if (/not applied/.test(s)) cls = "pending";
      else if (/not saved/.test(s)) cls = "drift";
      const uidM = s.match(/uid (\d+)/);
      const viaM = s.match(/^via (\S+)/);
      const target = viaM ? viaM[1]
        : (/^uid \d+$/.test(name) ? (uidM ? uidM[1] : name) : name);
      const xTitle = viaM ? `Remove ${viaM[1]} - the rule hiding this app` : "Unhide";
      const actionable = UID_TARGET_RE.test(target);
      const covIdx = s.indexOf(" \u00b7 also covered by ");
      const sHead = covIdx === -1 ? s : s.slice(0, covIdx);
      const sCov  = covIdx === -1 ? "" : s.slice(covIdx + 3);
      const save = cls === "drift" && actionable
        ? `<button class="bx save" title="Save so it survives reboot" data-act="save" data-nmt="${esc(target)}">💾</button>` : "";
      return { active: cls === "live" || cls === "pending" || cls === "drift",
               hiding: cls === "live" || cls === "drift",
               unknown: cls === "unknown",
               key: uidM ? uidM[1] : name,
               html: `<div class="blk ${cls}">
        <span class="dot"></span>
        <span class="bmid">
          <span class="btop"><span class="bn">${esc(name)}</span><span class="bs">${esc(sHead)}</span></span>
          ${sCov ? `<span class="bcov">${esc(sCov)}</span>` : ""}
        </span>
        ${save}
        ${actionable ? `<button class="bx" title="${esc(xTitle)}" data-act="unblock" data-nmt="${esc(target)}">✕</button>` : ""}
      </div>` };
    });
    const active = rows.filter(function (x) { return x.active; });
    const unknown = rows.filter(function (x) { return x.unknown; });
    const waiting = rows.filter(function (x) { return !x.active && !x.unknown; });
    const hiding = new Set(rows.filter(function (x) { return x.hiding; })
                               .map(function (x) { return x.key; })).size;
    const htmlOf = function (a) { return a.map(function (x) { return x.html; }).join(""); };
    if (uc) uc.textContent = unknown.length ? "?" : String(hiding);
    box.innerHTML =
      (active.length ? `<div class="blk-head">Hidden apps · ${hiding}</div>` + htmlOf(active) : "") +
      (unknown.length ? `<div class="blk-head">Could not be checked · ${unknown.length}</div>` +
        `<div class="blk-sub">These are saved, but the engine did not answer, so whether they are
          in force right now is unknown.</div>` + htmlOf(unknown) : "") +
      (waiting.length ? `<div class="blk-head">Waiting · ${waiting.length}</div>` +
        `<div class="blk-sub">Nothing installed matches these yet. A glob keeps watching, so a
          detector installed later is hidden the moment it appears.</div>` + htmlOf(waiting) : "");
  }

  document.getElementById("blocked").addEventListener("click", ev => {
    const b = ev.target.closest("button[data-act]");
    if (!b) return;
    const t = b.getAttribute("data-nmt") || "";
    if (!UID_TARGET_RE.test(t)) { toast("That entry has characters nomount won't take", "bad"); return; }
    if (b.getAttribute("data-act") === "save") saveOne(t, b); else unblockOne(t, b);
  });
  function usPickFrom(row) {
    if (!row) return;
    const t = row.getAttribute("data-nmt") || "";
    if (!UID_TARGET_RE.test(t)) { toast("That entry has characters nomount won't take", "bad"); return; }
    usPick(t);
  }
  document.getElementById("usList").addEventListener("click", ev => {
    usPickFrom(ev.target.closest("[data-act='uspick']"));
  });
  document.getElementById("usList").addEventListener("keydown", ev => {
    if (ev.key !== "Enter" && ev.key !== " ") return;
    const row = ev.target.closest("[data-act='uspick']");
    if (!row) return;
    ev.preventDefault();
    usPickFrom(row);
  });
  var _pkgsLoaded = false, _pkgs = [], _pkgSel = -1;
  async function loadPkgList() {
    if (_pkgsLoaded) return;
    const r = await exec("pm list packages -3 -U 2>/dev/null | sort");
    _pkgs = (r.stdout || "").split("\n").map(function (l) {
      const m = l.match(/^package:(\S+)\s+uid:(\d+)/);
      return m ? { name: m[1], uid: m[2] } : null;
    }).filter(Boolean);
    if (_pkgs.length) _pkgsLoaded = true;
  }
  function pkgHide() { const d = $("pkgdd"); d.classList.remove("show"); d.innerHTML = ""; _pkgSel = -1; }
  function pkgBlur() { setTimeout(pkgHide, 130); }
  function pkgFilter() {
    const q = ($("uid").value || "").trim().toLowerCase();
    const d = $("pkgdd"); _pkgSel = -1;
    if (!_pkgs.length) { pkgHide(); return; }
    const matches = q
      ? _pkgs.filter(function (p) { return p.name.toLowerCase().indexOf(q) !== -1 || p.uid.indexOf(q) !== -1; })
      : _pkgs;
    if (!matches.length) { d.innerHTML = '<div class="none">No matching installed app</div>'; d.classList.add("show"); return; }
    const head = '<div class="pkghead">' + matches.length + ' app' + (matches.length > 1 ? 's' : '') +
                 (q ? ' match' : '') + ' · type to filter</div>';
    d.innerHTML = head + matches.map(function (p) {
      return '<div class="opt" data-nm="' + esc(p.name) + '" onmousedown="pkgPick(this)">' +
             '<span class="pn">' + esc(p.name) + '</span>' +
             '<span class="pu">uid ' + esc(p.uid) + '</span></div>';
    }).join("");
    d.classList.add("show");
  }
  function pkgPick(el) { $("uid").value = el.getAttribute("data-nm"); pkgHide(); }
  function pkgKey(e) {
    const d = $("pkgdd"); if (!d.classList.contains("show")) return;
    const opts = d.querySelectorAll(".opt");
    if (e.key === "Escape") { pkgHide(); return; }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!opts.length) return;
      _pkgSel = (_pkgSel + (e.key === "ArrowDown" ? 1 : -1) + opts.length) % opts.length;
      opts.forEach(function (o, i) { o.classList.toggle("sel", i === _pkgSel); });
      opts[_pkgSel].scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter" && _pkgSel >= 0 && opts[_pkgSel]) {
      e.preventDefault(); pkgPick(opts[_pkgSel]);
    }
  }
  const ISO_MODES = {
    both:      "Hiding covers every isolated process.",
    appzygote: "Hiding covers the app-zygote pool only.",
    platform:  "Hiding covers the platform pool (99000-99999) only.",
    off:       "Isolated processes are not hidden from.",
  };
  function isoPaint(mode, note, bad) {
    const seg = $("isoSeg"), st = $("isoState");
    const known = Object.prototype.hasOwnProperty.call(ISO_MODES, mode);
    seg.classList.toggle("unknown", !known);
    seg.querySelectorAll(".seg-b").forEach(function (b) {
      const on = known && b.dataset.v === mode;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    st.textContent = note || (known ? ISO_MODES[mode] : "");
    st.classList.toggle("bad", !!bad);
  }
  async function refreshIsolated() {
    if (!(await ruleDump()).ok) {
      isoPaint(null, "Engine not responding - this is the saved policy, not what the kernel is doing.", true);
      return;
    }
    const r = await nm("uid isolated");
    const m = (r.stdout || "").trim().match(/^(both|appzygote|platform|off)/);
    if (r.errno === 0 && m) isoPaint(m[1]);
    else isoPaint(null, "Could not read the saved policy.", true);
  }
  async function setIsolated(mode) {
    const seg = $("isoSeg");
    const btns = Array.prototype.slice.call(seg.querySelectorAll(".seg-b"));
    btns.forEach(function (b) { b.disabled = true; });
    try {
      const r = await nm(`uid isolated ${mode}`);
      if (r.errno === 0) {
        toast((r.stdout || "").replace(/^ok:/, "").trim() || "Updated", "ok");
        isoPaint(mode);
      } else {
        toast("Failed: " + (r.stderr || "error"), "bad");
        await refreshIsolated();
      }
    } finally {
      btns.forEach(function (b) { b.disabled = false; });
    }
  }

  const US = new Map();
  let usShown = false;
  const US_REASONS = {
    detector:       { label: "known detector",   cls: "r-det",  pick: true },
    "queries-root": { label: "looks for root",   cls: "r-qr",   pick: true },
    "su-perm":      { label: "wants superuser",  cls: "r-su",   pick: false },
    "queries-all":  { label: "enumerates apps",  cls: "r-qa",   pick: false },
  };
  function usParse(out) {
    (out || "").split("\n").forEach(function (l) {
      const [pkg, raw] = l.replace(/\r/g, "").split("\t");
      if (!pkg || !raw) return;
      const reasons = raw.trim().split(",").filter(Boolean);
      const prev = US.get(pkg);
      const pick = reasons.some(function (r) { return US_REASONS[r] && US_REASONS[r].pick; });
      US.set(pkg, { reasons: reasons, pick: prev ? prev.pick : pick });
    });
  }
  async function uidScan(btn) {
    const done = busy(btn, "Scanning...");
    const r = await exec("sh /data/adb/modules/meta-nomount/uidscan.sh");
    if (r.errno !== 0) {
      done();
      toast("Scan did not run - " +
            (((r.stderr || "").trim().split("\n")[0]) || "the script failed"), "bad");
      return;
    }
    const degraded = /no detector inventory/i.test(r.stderr || "");
    usParse(r.stdout);
    const cur = await nm("uid list");
    (cur.stdout || "").split("\n").forEach(function (l) {
      const name = l.split("\t")[0].trim();
      if (name && US.has(name)) US.delete(name);
    });
    done();
    if (!usShown) usToggle($("usShow"));
    usRender();
    const note = degraded ? " (by manifest only - the detector name list was unavailable)" : "";
    toast(
      US.size ? `${US.size} candidate(s)${note}` : `Nothing worth hiding found${note}`,
      US.size ? "ok" : ""
    );
  }
  function usToggle(btn) {
    usShown = !usShown;
    $("usList").style.display = usShown ? "" : "none";
    btn.style.display = "";
    btn.textContent = usShown ? "Hide list" : "Show list";
  }
  function usPick(pkg) {
    const e = US.get(pkg); if (!e) return;
    e.pick = !e.pick; usRender();
  }
  function usRender() {
    const box = $("usList");
    $("usShow").style.display = US.size ? "" : "none";
    if (!US.size) {
      box.innerHTML = '<div class="blk-none">Nothing left to pick - scan again after installing apps.</div>';
      return;
    }
    const order = ["detector", "queries-root", "su-perm", "queries-all"];
    const rank = (e) => Math.min.apply(null, e.reasons.map(function (r) {
      const i = order.indexOf(r); return i < 0 ? 9 : i;
    }));
    const rows = [...US.entries()].sort(function (a, b) {
      return rank(a[1]) - rank(b[1]) || a[0].localeCompare(b[0]);
    }).map(function ([pkg, e]) {
      const chips = e.reasons.map(function (r) {
        const d = US_REASONS[r] || { label: r, cls: "" };
        return `<span class="rch ${d.cls}">${esc(d.label)}</span>`;
      }).join("");
      return `<div class="usrow${e.pick ? " on" : ""}" data-act="uspick" data-nmt="${esc(pkg)}"
        role="checkbox" tabindex="0" aria-checked="${e.pick ? "true" : "false"}"
        aria-label="${esc(pkg)}">
        <span class="uscb">${e.pick ? "✓" : ""}</span>
        <span class="usn">${esc(pkg)}</span>
        <span class="usr">${chips}</span>
      </div>`;
    }).join("");
    const n = [...US.values()].filter(function (e) { return e.pick; }).length;
    box.innerHTML = `<div class="blk-head">Candidates · ${US.size}</div>${rows}
      <div class="usfoot">
        <button class="act primary" onclick="usApply(this)"${n ? "" : " disabled"}>Hide ${n} selected</button>
        <span class="presethint">Picked by default: known detectors and apps that look for a root
          manager. Apps that merely request superuser are left unpicked - those are usually your own
          root tools, and hiding shows them the stock tree instead of your module content.</span>
      </div>`;
  }
  async function usApply(btn) {
    const picks = [...US.entries()].filter(function ([, e]) { return e.pick; }).map(function ([p]) { return p; });
    if (!picks.length) return;
    const done = busy(btn, "Hiding...");
    const b = await bin();
    const nmClient = b.replace(/nomount$/, "nm");
    await exec(`NM_BIN=${shq(nmClient)} ` +
               picks.map(function (p) { return `${shq(b)} uid block ${shq(p)}`; }).join("; "));
    const after = await nm("uid list");
    const listed = {};
    (after.stdout || "").split("\n").forEach(function (l) {
      const n = (l.split("\t")[0] || "").trim();
      if (n) listed[n] = 1;
    });
    let ok = 0, bad = 0;
    picks.forEach(function (p) {
      if (listed[p]) { ok++; US.delete(p); } else bad++;
    });
    done();
    usRender();
    refreshBlocked();
    toast(bad ? `${ok} hidden, ${bad} failed` : `${ok} app(s) hidden`, bad ? "bad" : "ok");
  }
  async function addGlobs(btn) {
    const done = busy(btn, "Adding...");
    const r = await nm("uid preset detectors --globs");
    if (r.errno === 0) toast((r.stdout || "").replace(/^preset /, "").trim() || "Added", "ok");
    else toast("Failed: " + (r.stderr || "error"), "bad");
    done();
    refreshBlocked();
  }

  async function unblockOne(target, btn) {
    if (!(await confirmAction(
      "Stop hiding " + target + "?",
      target.indexOf("*") >= 0
        ? "That entry is a pattern. Every app it matches stops being hidden - now, and any that " +
          "install later - and the pattern itself is deleted from your list."
        : "This app sees your injected files again the moment it next looks, and the entry is " +
          "removed from your list.",
      "Stop hiding"))) return;
    btn.disabled = true;
    const r = await nm(`uid unblock ${shq(target)}`);
    if (r.errno === 0) toast(`${target} unhidden`, "ok");
    else toast("Failed: " + (r.stderr || "error"), "bad");
    refreshBlocked();
  }
  async function saveOne(target, btn) {
    btn.disabled = true;
    const r = await nm(`uid block ${shq(target)}`);
    if (r.errno === 0) toast(`${target} saved`, "ok");
    else toast("Failed: " + (r.stderr || "error"), "bad");
    refreshBlocked();
  }

  function setExp(h) {
    if (h) h.setAttribute("aria-expanded", h.classList.contains("open") ? "true" : "false");
  }
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" && e.key !== " " && e.key !== "Spacebar") return;
    const h = e.target && e.target.closest && e.target.closest(".card-h.clp");
    if (!h) return;
    e.preventDefault();
    h.click();
  });

  function toggleCard(h) {
    const card = h.closest(".card");
    const on = card.classList.toggle("collapsed");
    h.classList.toggle("open", !on);
    setExp(h);
    if (card.id) { try { localStorage.setItem("nmcol:" + card.id, on ? "1" : "0"); } catch (e) {} }
  }
  function applyCardState() {
    document.querySelectorAll(".card[id]").forEach(card => {
      let v = null;
      try { v = localStorage.getItem("nmcol:" + card.id); } catch (e) {}
      const collapsed = v === null ? card.classList.contains("collapsed") : v === "1";
      card.classList.toggle("collapsed", collapsed);
      const h = card.querySelector(".card-h");
      if (h) { h.classList.toggle("open", !collapsed); setExp(h); }
    });
  }

  function refreshFailed(e) {
    const ic = document.querySelector("#refreshBtn svg");
    if (ic) ic.classList.remove("spin");
    toast("Something went wrong reading the device - press refresh to try again. " +
          ((e && e.message) || e), "bad");
  }
  let REFRESH_RUNNING = false;
  async function refreshAll(btn) {
    if (REFRESH_RUNNING) return;
    REFRESH_RUNNING = true;
    const ic = btn && btn.querySelector("svg");
    if (ic) ic.classList.add("spin");
    try {
      RULES = null;
      PLAN_BY_MODULE = null;
      STEALTH_PROBE = null;
      await loadCheckCache();
      const ev = await engineVersion();
      const eng = ev ? ("engine v" + ev) : "engine offline";
      // A pending update lives in modules_update and swaps in on the next reboot; its presence IS
      // the signal, including a same-version reinstall carrying new code. This used to read the
      // LIVE module.prop, whose version package.sh stamps from the same value as SUITE_VERSION,
      // so the two could never differ and the indicator was permanently off.
      const pv = (await exec(
        "sed -n 's/^version=//p' /data/adb/modules_update/meta-nomount/module.prop 2>/dev/null"
      )).stdout.trim();
      const staged = !!pv;
      $("ver").textContent = SUITE_VERSION;
      $("hdreng").textContent = eng;
      $("vstage").hidden = !staged;
      $("ver").title = staged
        ? pv + " is installed but not live yet - its files are in modules_update and swap in on the next reboot. This page, and everything it reports, is still " + SUITE_VERSION + "."
        : "Suite " + SUITE_VERSION + " - " + eng + ". Two independent numbers: the engine is in the kernel, the Suite is this module.";
      const suiteId = SUITE_VERSION + (SUITE_COMMIT && SUITE_COMMIT !== "dev" ? " (" + SUITE_COMMIT + ")" : "");
      const prof = (SUITE_PROFILE && SUITE_PROFILE !== "release") ? " · " + SUITE_PROFILE + " build" : "";
      $("footver").textContent = "Suite " + suiteId + prof + " · " + eng +
        (staged ? " · " + pv + " staged - reboot to activate" : "");
      await Promise.all([refreshStatus(), refreshDevice(), refreshStealth(), refreshGuard(),
                         refreshAbsorb(),
                         refreshModules(), refreshFiles(), refreshRuleSummary(),
                         refreshIncident(), refreshBlocked(), refreshIsolated(),
                         $("wobody").style.display === "none" ? woChipOnly() : refreshWhiteouts()]);
      if (rulesShown) loadRules();
      loadPkgList();
    } finally {
      if (ic) ic.classList.remove("spin");
      REFRESH_RUNNING = false;
    }
  }

  (function restoreTab() {
    let t = null;
    try { t = sessionStorage.getItem("nm_tab"); } catch (e) {}
    if (t && document.getElementById("tab-" + t)) showTab(t, document.getElementById("nb-" + t));
  })();
  movePill(false);
  window.addEventListener("load", function () { movePill(false); });

  applyCardState();
  refreshAll().then(autoCheck).catch(refreshFailed);
