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
  // The one place the recovery step is named: the guard card lives on the Checks tab.
  const GUARD_HINT = "Re-arm it in Checks \u2192 Bootloop guard, then reboot.";
  function expandCard(id) {
    const card = $(id);
    if (!card || !card.classList.contains("collapsed")) return;
    card.classList.remove("collapsed");
    const h = card.querySelector(".card-h");
    if (h) { h.classList.add("open"); h.setAttribute("aria-expanded", "true"); }
  }
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
      let timer = setTimeout(() => finish({
        errno: -1, stdout: "",
        stderr: "timed out after " + (EXEC_TIMEOUT_MS / 1000) +
                "s. It may still be running; reopen this pane to see the result",
      }), EXEC_TIMEOUT_MS);
      window[name] = (errno, stdout, stderr) =>
        finish({ errno: Number(errno), stdout: stdout || "", stderr: stderr || "" });
      const start = Date.now();
      try { KSU.exec(cmd, JSON.stringify(opts), name); }
      catch (e) { finish({ errno: -1, stdout: "", stderr: String(e) }); }
      // A synchronous bridge (ReSukiSU, KernelSU Next) returns only once the command has
      // finished, and its callback still has to hop the UI thread, so an overdue timer fired
      // first and dropped the real result. The command is done: give the callback a grace.
      if (!settled && Date.now() - start >= 1000) {
        clearTimeout(timer);
        timer = setTimeout(() => finish({
          errno: -1, stdout: "",
          stderr: "the root manager ran the command but did not return its result",
        }), 10000);
      }
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
    const t = (r.stdout || "").trim().split(/\s+/);
    return /^\d+$/.test(t[0]) ? { proto: t[0], build: t[1] || "" } : null;
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
      const planned = new Set();
      (r.stdout || "").split("\n").forEach((l) => {
        const m = /^(inject|whiteout|bind)\s+(.*) <- (.*) \[([^\]]*)\]/.exec(l);
        if (!m) return;
        const kind = m[1], target = m[2], id = m[4];
        if (kind !== "bind" && l.indexOf("<< UNSERVABLE") < 0) { expectLive++; planned.add(target); }
        const e = modules[id] || (modules[id] = { files: 0, overlay: false, vfs: false, bind: false });
        e.files++;
        total++;
        if (kind === "bind") e.bind = true;
        else if (/\/overlay\/[^\s]*\.apk$/.test(target)) e.overlay = true;
        else e.vfs = true;
      });
      return { total, expectLive, modules, planned };
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
      return "Blocked. The bootloop guard disabled the Suite, so nothing is injected. " +
             GUARD_HINT;
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

  // An error has to be readable: it stays long enough to read, a tap dismisses it, and a
  // long or multi-line one opens in full instead of vanishing after 2.4 s.
  function toast(msg, kind = "") {
    const t = $("toast");
    const full = String(msg == null ? "" : msg).replace(/^Failed: Error: /, "Failed: ");
    const lines = full.split("\n").map(s => s.trim()).filter(Boolean);
    const first = lines[0] || "";
    const more = lines.length > 1 || first.length > 160;
    t.textContent = more ? (first.length > 160 ? first.slice(0, 157) + "\u2026" : first) +
      " \u00b7 tap for details" : first;
    t._full = more ? full : "";
    t.className = "show " + kind;
    const ms = kind === "bad" ? Math.min(20000, 6000 + 50 * first.length) : 2400;
    clearTimeout(t._t); t._t = setTimeout(() => { t.className = ""; }, ms);
  }
  document.getElementById("toast").addEventListener("click", function () {
    const t = $("toast");
    clearTimeout(t._t); t.className = "";
    if (t._full) confirmAction("Details", t._full, "OK");
  });

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
  // Why this page's own rule read failed, from nm's stderr: "live", "absent" (no engine in
  // the kernel), "denied" (SELinux), "unreachable", or "error" (the page could not ask).
  let ENGINE_STATE = null;
  let ZIP_VARIANT = null;
  // The LKM zip points its updateJson at update-lkm.json; the lite zip does not.
  async function zipVariant() {
    if (ZIP_VARIANT) return ZIP_VARIANT;
    const r = await exec("grep -q update-lkm.json /data/adb/modules/meta-nomount/module.prop " +
                         "&& echo lkm || echo lite");
    if (r.errno === 0 && /^(lkm|lite)$/.test(r.stdout.trim())) ZIP_VARIANT = r.stdout.trim();
    return ZIP_VARIANT;
  }
  let GUARD_TRIPPED = null;
  let STATUS_GEN = 0;
  // Set by Reload when a system APK changed; refreshIncident shows it until a reboot.
  let REBOOT_NOTICE = "";
