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
                "s. It may still be running; reopen this pane to see the result",
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
      return "Blocked. The bootloop guard disabled the Suite, so nothing is injected. " +
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
