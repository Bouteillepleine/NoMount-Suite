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
  // Same IIFE position as the theme, and for the same reason: set before the first
  // paint or the bar renders as a capsule and then jumps to a dock.
  const NAV_STYLES = ["dock", "capsule", "compact", "liquid"];
  function navName(v) { return NAV_STYLES.indexOf(v) >= 0 ? v : "dock"; }
  (function initNav() {
    let v = null;
    try { v = localStorage.getItem("nm_nav"); } catch (e) {}
    document.documentElement.setAttribute("data-nav", navName(v));
  })();

  function navStyle() {
    return navName(document.documentElement.getAttribute("data-nav"));
  }
  function syncNavSeg() {
    const seg = document.getElementById("navSeg");
    if (!seg) return;
    const cur = navStyle();
    seg.querySelectorAll(".seg-b").forEach(function (b) {
      const on = b.getAttribute("data-v") === cur;
      b.classList.toggle("on", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
  }
  function setNav(v) {
    const nav = navName(v);
    document.documentElement.setAttribute("data-nav", nav);
    try { localStorage.setItem("nm_nav", nav); } catch (e) {}
    syncNavSeg();
    movePill(false);
  }

  function movePill(animate) {
    const pill = document.getElementById("navpill");
    const btn = document.querySelector(".navb.on");
    if (!pill || !btn) return;
    const st = navStyle();
    if (st !== "capsule" && st !== "liquid") { pill.style.opacity = "0"; return; }
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
    if (st === "liquid") lensRefresh();
  }
  window.addEventListener("resize", function () { movePill(false); });

  const LENS = { bar: { w: 0, h: 0 }, pill: { w: 0, h: 0 } };
  function lensMap(w, h, height, amount, span, depth) {
    const c = document.createElement("canvas");
    c.width = w; c.height = h;
    const ctx = c.getContext("2d");
    if (!ctx) return null;
    const img = ctx.createImageData(w, h);
    const d = img.data;
    const hw = w / 2, hh = h / 2, r = Math.min(hw, hh);
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const cx = x + 0.5 - hw, cy = y + 0.5 - hh;
        const qx = Math.abs(cx) - (hw - r), qy = Math.abs(cy) - (hh - r);
        const ox = Math.max(qx, 0), oy = Math.max(qy, 0);
        const on = Math.sqrt(ox * ox + oy * oy);
        let sd = on - r + Math.min(Math.max(qx, qy), 0);
        let dx = 0, dy = 0;
        if (-sd < height) {
          sd = Math.min(sd, 0);
          const t = 1 + sd / height;
          const dd = (1 - Math.sqrt(Math.max(0, 1 - t * t))) * amount;
          let gx, gy;
          if (qx >= 0 || qy >= 0) {
            gx = Math.sign(cx) * ox / (on || 1);
            gy = Math.sign(cy) * oy / (on || 1);
          } else {
            const gX = qx >= qy ? 1 : 0;
            gx = Math.sign(cx) * gX;
            gy = Math.sign(cy) * (1 - gX);
          }
          if (depth) {
            const cn = Math.sqrt(cx * cx + cy * cy) || 1;
            gx += cx / cn; gy += cy / cn;
            const gn = Math.sqrt(gx * gx + gy * gy) || 1;
            gx /= gn; gy /= gn;
          }
          dx = -dd * gx; dy = -dd * gy;
        }
        const i = (y * w + x) * 4;
        d[i] = Math.round((0.5 + dx / span) * 255);
        d[i + 1] = Math.round((0.5 + dy / span) * 255);
        d[i + 2] = 128;
        d[i + 3] = 255;
      }
    }
    ctx.putImageData(img, 0, 0);
    return c.toDataURL("image/png");
  }
  function lensSet(id, key, w, h, height, amount, span, depth) {
    const el = document.getElementById(id);
    if (!el || w < 2 || h < 2) return;
    if (LENS[key].w === w && LENS[key].h === h) return;
    const url = lensMap(w, h, height, amount, span, depth);
    if (!url) return;
    LENS[key] = { w: w, h: h };
    el.setAttribute("href", url);
  }
  function lensRefresh() {
    const nav = document.querySelector(".nav");
    const btn = document.querySelector(".navb.on");
    if (!nav) return;
    lensSet("nmlensmap", "bar", Math.round(nav.offsetWidth), Math.round(nav.offsetHeight), 24, 24, 48, false);
    if (btn) lensSet("nmlens2map", "pill", Math.round(btn.offsetWidth), Math.round(btn.offsetHeight), 10, 14, 28, true);
  }

  (function liquidDrag() {
    const nav = document.querySelector(".nav");
    const pill = document.getElementById("navpill");
    if (!nav || !pill || !window.PointerEvent) return;
    let id = null, x0 = 0, p0 = 0, pos = 0, drag = false, swallow = false;
    function tabs() { return Array.prototype.slice.call(nav.querySelectorAll(".navb")); }
    nav.addEventListener("pointerdown", function (ev) {
      if (navStyle() !== "liquid" || id !== null) return;
      if (ev.pointerType === "mouse" && ev.button !== 0) return;
      const hit = ev.target && ev.target.closest ? ev.target.closest(".navb") : null;
      if (!hit || !hit.classList.contains("on")) return;
      id = ev.pointerId; x0 = ev.clientX; p0 = hit.offsetLeft; pos = p0; drag = false;
      nav.classList.add("press");
    });
    nav.addEventListener("pointermove", function (ev) {
      if (ev.pointerId !== id) return;
      const dx = ev.clientX - x0;
      if (!drag) {
        if (Math.abs(dx) < 6) return;
        drag = true;
        pill.classList.add("noanim");
        try { nav.setPointerCapture(id); } catch (e) {}
      }
      const bs = tabs();
      const lo = bs[0].offsetLeft, hi = bs[bs.length - 1].offsetLeft;
      const want = p0 + dx;
      pos = Math.min(hi, Math.max(lo, want));
      const over = want - pos;
      const f = Math.min(1, Math.abs(over) / nav.clientWidth);
      nav.style.setProperty("--nmx", (4 * Math.sign(over) * (1 - (1 - f) * (1 - f))).toFixed(2) + "px");
      pill.style.transform = "translateX(" + pos + "px)";
    });
    function end(ev) {
      if (ev.pointerId !== id) return;
      id = null;
      nav.classList.remove("press");
      nav.style.setProperty("--nmx", "0px");
      if (!drag) return;
      drag = false;
      swallow = true;
      pill.classList.remove("noanim");
      const bs = tabs();
      let best = 0, bd = Infinity;
      bs.forEach(function (b, i) {
        const dd = Math.abs(b.offsetLeft - pos);
        if (dd < bd) { bd = dd; best = i; }
      });
      const b = bs[best];
      if (b.classList.contains("on")) movePill(true);
      else showTab(b.getAttribute("data-arg"), b);
    }
    nav.addEventListener("pointerup", end);
    nav.addEventListener("pointercancel", end);
    nav.addEventListener("click", function (ev) {
      if (!swallow) return;
      swallow = false;
      ev.stopPropagation();
      ev.preventDefault();
    }, true);
  })();

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
