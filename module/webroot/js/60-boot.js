  "use strict";

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
                         $("wobody").classList.contains("u-hide") ? woChipOnly() : refreshWhiteouts()]);
      if (rulesShown) loadRules();
      loadPkgList();
    } finally {
      if (ic) ic.classList.remove("spin");
      REFRESH_RUNNING = false;
    }
  }

  // Every control used to carry onclick="...". script-src 'self' blocks an inline
  // event handler exactly as it blocks an inline <script>, so under the CSP that
  // makes a missed esc() inert, those attributes were inert too: the page rendered
  // and no button did anything. The markup now names an action, and the listeners
  // below are the only thing that can run it - a name that is not in this table
  // does nothing, so injected markup cannot reach a function either.
  const ACTIONS = {
    showTab: (el, ev, arg) => showTab(arg, el),
    setIsolated: (el, ev, arg) => setIsolated(arg),
    uidOp: (el, ev, arg) => uidOp(arg, el),
    toggleTheme: () => toggleTheme(),
    openDetail: () => openDetail(),
    toggleCard: (el) => toggleCard(el),
    toggleWhiteouts: (el) => toggleWhiteouts(el),
    toggleRules: (el) => toggleRules(el),
    toggleRuleGroup: (el) => toggleRuleGroup(el),
    toggleModules: (el) => toggleModules(el),
    toggleFileView: (el) => toggleFileView(el),
    usToggle: (el) => usToggle(el),
    uidScan: (el) => uidScan(el),
    woScan: (el) => woScan(el),
    woAdd: (el) => woAdd(el),
    abScan: (el) => abScan(el),
    abAbsorb: (el) => abAbsorb(el),
    addGlobs: (el) => addGlobs(el),
    runCheck: (el) => runCheck(el),
    runVerify: (el) => runVerify(el),
    runSnapshot: (el) => runSnapshot(el),
    runExport: (el) => runExport(el),
    copyReport: (el) => copyReport(el),
    reloadRules: (el) => reloadRules(el),
    clearRules: (el) => clearRules(el),
    clearIncident: (el) => clearIncident(el),
    rearm: (el) => rearm(el),
    renderFilesFull: () => renderFilesFull(),
    filterRules: () => filterRules(),
    pkgFilter: () => pkgFilter(),
    pkgBlur: () => pkgBlur(),
    pkgKey: (el, ev) => pkgKey(ev),
    refreshAllSafe: (el) => { refreshAll(el).catch(refreshFailed); },
    clearRuleFilter: () => {
      const f = $("rulefilter");
      if (f) f.value = "";
      filterRules();
    },
    activateOnEnter: (el, ev) => {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); el.click(); }
    },
  };

  function _delegate(attr) {
    return (ev) => {
      const t = ev.target;
      const src = t && t.closest ? t.closest("[" + attr + "]") : null;
      if (!src) return;
      const fn = ACTIONS[src.getAttribute(attr)];
      if (!fn) return;
      const to = src.getAttribute("data-target");
      fn(to ? ($(to) || src) : src, ev, src.getAttribute("data-arg"));
    };
  }

  document.addEventListener("click", _delegate("data-act"));
  document.addEventListener("input", _delegate("data-act-input"));
  document.addEventListener("keydown", _delegate("data-act-key"));
  document.addEventListener("focusin", _delegate("data-act-focus"));
  document.addEventListener("focusout", _delegate("data-act-blur"));

  (function restoreTab() {
    let t = null;
    try { t = sessionStorage.getItem("nm_tab"); } catch (e) {}
    if (t && document.getElementById("tab-" + t)) showTab(t, document.getElementById("nb-" + t));
  })();
  movePill(false);
  window.addEventListener("load", function () { movePill(false); });

  applyCardState();
  refreshAll().then(autoCheck).catch(refreshFailed);
