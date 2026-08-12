/* ============================================================
   PhishGuard — advanced detection engine integration + mini SPA.
   Uses engine.js (25+ weighted signals: brand impersonation,
   homoglyph/punycode, typosquatting, entropy, kit patterns...).
   Accent: electric blue #409cff. Scans stay in localStorage only.
   ============================================================ */
(function () {
  "use strict";

  var KEY = "phishguard_scans_v2";
  var STORAGE_KEY_DAYS = 30;

  function analyzeUrl(raw) {
    if (!raw) return null;
    try {
      if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
      var u = new URL(raw);
    } catch (e) { return null; }

    var res = PhishGuardEngine.analyze(raw);
    return {
      url: raw,
      score: res.score,
      tier: res.tier,
      verdict: res.verdict,
      cls: res.cls,
      signals: res.signals,
      date: new Date().toISOString(),
      host: u.hostname
    };
  }

  /* ---------- storage ---------- */
  function loadScans() {
    try {
      var all = JSON.parse(localStorage.getItem(KEY) || "[]");
      var cutoff = Date.now() - STORAGE_KEY_DAYS * 86400000;
      return all.filter(function (s) { return new Date(s.date).getTime() > cutoff; });
    } catch (e) { return []; }
  }
  function saveScans(scans) {
    try { localStorage.setItem(KEY, JSON.stringify(scans)); } catch (e) {}
  }
  function addScan(res) {
    var scans = loadScans();
    scans.unshift(res);
    saveScans(scans);
    return scans;
  }

  /* ---------- SPA routing ---------- */
  var pages = ["dashboard", "scanner", "history", "about"];

  function go(page) {
    pages.forEach(function (p) {
      var el = document.getElementById("page-" + p);
      if (el) el.classList.toggle("active", p === page);
    });
    document.querySelectorAll(".nav-item").forEach(function (a) {
      a.classList.toggle("active", a.dataset.page === page);
    });
    if (page === "dashboard") renderDashboard();
    if (page === "history") renderHistory();
  }

  document.querySelectorAll(".nav-item").forEach(function (a) {
    a.addEventListener("click", function (e) {
      e.preventDefault();
      go(a.dataset.page);
    });
  });

  /* ---------- dashboard ---------- */
  function renderDashboard() {
    var scans = loadScans();
    var total = scans.length;
    var dangerous = scans.filter(function (s) { return s.cls === "scan-bad"; }).length;
    var caution = scans.filter(function (s) { return s.cls === "scan-warn"; }).length;
    var safe = scans.filter(function (s) { return s.cls === "scan-ok"; }).length;

    document.getElementById("stat-total").textContent = total;
    document.getElementById("stat-phish").textContent = dangerous;
    document.getElementById("stat-phish-pct").textContent = (total ? Math.round(dangerous / total * 100) : 0) + "% of total";
    document.getElementById("stat-susp").textContent = caution;
    document.getElementById("stat-safe").textContent = safe;

    // Volume chart: last 30 days
    var chart = document.getElementById("volumeChart");
    chart.innerHTML = "";
    var now = new Date();
    var dayCounts = [];
    for (var d = 29; d >= 0; d--) {
      var day = new Date(now.getFullYear(), now.getMonth(), now.getDate() - d).getTime();
      var next = day + 86400000;
      var c = scans.filter(function (s) { var t = new Date(s.date).getTime(); return t >= day && t < next; }).length;
      dayCounts.push(c);
    }
    var max = Math.max(1, Math.max.apply(null, dayCounts));
    dayCounts.forEach(function (c) {
      var bar = document.createElement("div");
      bar.className = "bar";
      bar.title = c + " scan(s)";
      bar.style.height = "3px";
      chart.appendChild(bar);
      requestAnimationFrame(function () {
        bar.style.height = Math.max(3, (c / max) * 100) + "px";
      });
    });

    // Verdict breakdown
    var vlist = document.getElementById("verdictList");
    vlist.innerHTML = "";
    [
      { label: "Dangerous", cls: "scan-bad", tag: "tag--phishing", count: dangerous },
      { label: "Caution", cls: "scan-warn", tag: "tag--suspicious", count: caution },
      { label: "Safe", cls: "scan-ok", tag: "tag--safe", count: safe }
    ].forEach(function (v) {
      var item = document.createElement("div");
      item.className = "verdict-item";
      item.innerHTML = '<span class="tag ' + v.tag + '">' + v.label + "</span>" +
        '<span class="stat-num ' + v.cls + '" style="font-size:20px;">' + v.count + "</span>";
      vlist.appendChild(item);
    });
    if (!total) vlist.innerHTML = '<div class="empty">No verdicts yet — run your first scan.</div>';

    // Domain list
    var dlist = document.getElementById("domainList");
    dlist.innerHTML = "";
    var domainMap = {};
    scans.forEach(function (s) {
      if (!domainMap[s.host]) domainMap[s.host] = { scans: 0, verdict: s.cls, score: s.score };
      domainMap[s.host].scans++;
      if (s.score > domainMap[s.host].score) {
        domainMap[s.host].verdict = s.cls;
        domainMap[s.host].score = s.score;
      }
    });
    var doms = Object.keys(domainMap).sort(function (a, b) { return domainMap[b].scans - domainMap[a].scans; }).slice(0, 6);
    if (!doms.length) dlist.innerHTML = '<div class="empty">No domains scanned yet.</div>';
    doms.forEach(function (h) {
      var d = domainMap[h];
      var item = document.createElement("div");
      item.className = "domain-item";
      item.innerHTML = '<span class="dom" title="' + h + '">' + h + "</span>" +
        '<span class="dmeta">' + d.scans + " scan" + (d.scans > 1 ? "s" : "") + " · " + d.score + "/100 · " +
        '<span class="tag tag--' + d.verdict + '">' + d.verdict + "</span></span>";
      dlist.appendChild(item);
    });
  }

  /* ---------- scanner ---------- */
  var scanInput = document.getElementById("scanInput");
  var scanBtn = document.getElementById("scanBtn");
  var scanResult = document.getElementById("scanResult");

  function tierColor(cls) {
    return cls === "scan-bad" ? "var(--red)" : cls === "scan-warn" ? "var(--yellow)" : "var(--green)";
  }

  function showResult(res) {
    if (!res) {
      scanResult.innerHTML = '<div class="empty">Could not parse that URL. Try a full link like https://example.com</div>';
      scanResult.classList.remove("hidden");
      return;
    }
    var track = document.createElement("div");
    track.className = "progress-track";
    track.innerHTML = '<div class="progress-fill" style="width:0%;background:' + tierColor(res.cls) + ';"></div>';

    var sigs = res.signals.length
      ? res.signals.map(function (s) {
          return '<div class="signal-row">' +
            '<span class="sname"><span class="sw">+' + s.weight + "</span> " + s.name + "</span>" +
            '<span class="sdesc">' + s.desc + "</span></div>";
        }).join("")
      : '<div class="signal-row"><span class="sname">✓ Clean</span><span class="sdesc">No phishing signals detected across the full engine analysis.</span></div>';

    var advice = "";
    if (res.cls === "scan-bad") {
      advice = "Recommendation: Do not enter credentials, payment info, or 2FA codes. Close the tab and report the link to your email provider or platform.";
    } else if (res.cls === "scan-warn") {
      advice = "Recommendation: Do not click through from an email or message. Type the service's real address manually and verify the sender first.";
    } else {
      advice = "Recommendation: Still confirm the URL matches the sender's claims — heuristics can't catch every zero-day campaign.";
    }

    scanResult.innerHTML =
      '<div class="result-head">' +
      '<div class="score-circle"><span class="sc">' + res.score + "</span><span class='sc-sub'>/ 100</span></div>" +
      '<div><div class="verdict">' + res.tier +
      ' <span class="tag tag--' + res.cls + '">' + res.tier + "</span></div>" +
      '<div class="verdict-sub">' + res.url + "</div></div></div>" +
      '<div class="verdict-sub" style="margin:10px 0 14px;">' + res.verdict + "</div>" +
      track.outerHTML +
      '<p style="font-family:var(--font-mono);font-size:11.5px;color:var(--text-faint);margin-bottom:14px;">' +
      res.signals.length + " of 25+ weighted signals triggered · brand impersonation, homoglyph, punycode, typosquatting, entropy &amp; kit-pattern analysis</p>" +
      '<div class="signals">' + sigs + "</div>" +
      '<div class="advice">' + advice + "</div>";
    scanResult.classList.remove("hidden");
    setTimeout(function () {
      var fill = track.querySelector(".progress-fill");
      if (fill) fill.style.width = res.score + "%";
    }, 50);
  }

  if (scanBtn) {
    scanBtn.addEventListener("click", function () {
      var res = analyzeUrl(scanInput.value.trim());
      if (!res) { scanInput.focus(); return; }
      addScan(res);
      showResult(res);
      scanInput.value = "";
    });
    scanInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); scanBtn.click(); }
    });
  }

  /* ---------- history ---------- */
  function renderHistory() {
    var list = document.getElementById("historyList");
    var scans = loadScans();
    if (!scans.length) {
      list.innerHTML = '<div class="empty">No scans yet. Head to the Scanner to run your first check.</div>';
      return;
    }
    list.innerHTML = scans.map(function (s) {
      var d = new Date(s.date);
      return '<div class="history-item">' +
        '<span class="hurl" title="' + s.url + '">' + s.url + "</span>" +
        '<span class="tag tag--' + s.cls + '">' + s.tier + "</span>" +
        '<span class="hmeta">' + s.score + "/100 · " +
        d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) +
        "</span></div>";
    }).join("");
  }

  /* ---------- init ---------- */
  go("dashboard");
})();
