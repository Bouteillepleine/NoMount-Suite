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
                         $("wobody").classList.contains("none") ? woChipOnly() : refreshWhiteouts()]);
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
