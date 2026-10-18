  "use strict";

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
    if (!CHECK && !CHECK_RUNNING) runCheck(null);
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
    $("rulecount").classList.remove("u-hide");
    const vd = lines.filter(function (l) { return l.includes("(virtual dir)"); }).length;
    const wo = lines.filter(function (l) { return l.includes("(whiteout)"); }).length;
    $("rulecount").textContent = q
      ? keep.length + " of " + lines.length + " lines match"
      : (lines.length - vd - wo) + " rules" +
        (wo ? " · " + wo + " hidden path" + (wo === 1 ? "" : "s") : "") +
        (vd ? " · " + vd + " engine-made director" + (vd === 1 ? "y" : "ies") : "");
  }
