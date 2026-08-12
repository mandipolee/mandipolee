/* ============================================================
   Mandip Oli — Portfolio
   Vanilla JS: particle canvas, nav, scroll reveals, demo scanner, form
   Accent: electric blue #409cff (matches style.css)
   ============================================================ */
(function () {
  "use strict";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  /* ---------- 1. Particle network canvas ---------- */
  var canvas = $("#particleCanvas");
  if (canvas && canvas.getContext) {
    var ctx = canvas.getContext("2d");
    var particles = [];
    var W, H;
    var COLOR = "64, 156, 255";

    function resize() {
      W = canvas.width = canvas.offsetWidth;
      H = canvas.height = canvas.offsetHeight;
    }

    function init() {
      particles = [];
      var count = Math.min(70, Math.floor((W * H) / 14000));
      for (var i = 0; i < count; i++) {
        particles.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.35,
          vy: (Math.random() - 0.5) * 0.35,
          r: Math.random() * 1.6 + 0.6
        });
      }
    }

    function frame() {
      ctx.clearRect(0, 0, W, H);
      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(" + COLOR + ", 0.55)";
        ctx.fill();
        for (var j = i + 1; j < particles.length; j++) {
          var q = particles[j];
          var dx = p.x - q.x, dy = p.y - q.y;
          var dist = dx * dx + dy * dy;
          if (dist < 14000) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = "rgba(" + COLOR + ", " + (0.5 * (1 - dist / 14000)).toFixed(2) + ")";
            ctx.lineWidth = 1.2;
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(frame);
    }

    resize(); init(); frame();
    var resizeTimer;
    window.addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () { resize(); init(); }, 200);
    });
  }

  /* ---------- 3. Nav: scroll state, active section, mobile toggle ---------- */
  var nav = $("#nav");
  var navToggle = $("#navToggle");
  var navLinks = $("#navLinks");

  function updateActiveNav() {
    var sections = $$("section[id]");
    var current = "";
    sections.forEach(function (sec) {
      var top = sec.getBoundingClientRect().top;
      if (top <= 140) current = sec.id;
    });
    $$(".nav-links a").forEach(function (link) {
      link.classList.toggle("active", link.getAttribute("href") === "#" + current);
    });
  }

  window.addEventListener("scroll", function () {
    nav.classList.toggle("scrolled", window.scrollY > 40);
    updateActiveNav();
  }, { passive: true });
  updateActiveNav();

  if (navToggle && navLinks) {
    navToggle.addEventListener("click", function () {
      var open = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    navLinks.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        navLinks.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ---------- 4. Scroll reveal ---------- */
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });
  $$(".reveal-up").forEach(function (el) { observer.observe(el); });

  /* ---------- 5. Full phishing scanner on the project card (advanced heuristic engine) ---------- */
  var scanInput = $("#demoScanInput");
  var scanBtn = $("#demoScanBtn");

  var historyLog = JSON.parse((localStorage.getItem("pg-history-v2") || "[]"));
  var MAX_HISTORY = 8;

  function tierColor(cls) {
    return cls === "scan-bad" ? "#ef4444" : cls === "scan-warn" ? "#f59e0b" : cls === "scan-warn2" ? "#f59e0b" : "#22c55e";
  }

  function renderResult(res) {
    var out = $("#demoScanResult");
    if (!out) return;
    var col = tierColor(res.cls);
    var signalsHtml = res.signals.length
      ? res.signals.map(function (s) {
          return "<div class='sig-row'><span class='sig-weight'>+" + s.weight + "</span><span class='sig-name'>" + s.name + "</span></div>";
        }).join("")
      : "<div class='sig-row sig-clean'><span class='sig-weight' style='color:#22c55e;'>✓</span><span class='sig-name'>No phishing signals detected across the full engine analysis.</span></div>";

    out.innerHTML =
      "<div class='result-head' style='border-color:" + col + ";'>" +
        "<div class='result-score'>" +
          "<div class='result-score-num' style='color:" + col + ";'>" + res.score + "</div>" +
          "<div class='result-score-sub'>/ 100</div>" +
        "</div>" +
        "<div>" +
          "<div class='result-tier' style='color:" + col + ";'>" + res.tier + "</div>" +
          "<div class='result-verdict'>" + res.verdict + "</div>" +
          "<div class='result-url'>" + escapeHtml(res.url) + "</div>" +
        "</div>" +
      "</div>" +
      "<div class='sig-list'>" + signalsHtml + "</div>" +
      (res.advice ? "<div class='result-advice'>" + escapeHtml(res.advice) + "</div>" : "");
    out.className = "";
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function renderHistory() {
    var box = $("#demoScanHistory");
    if (!box) return;
    if (!historyLog.length) { box.innerHTML = ""; return; }
    box.innerHTML =
      "<div class='history-head'>Recent scans</div>" +
      historyLog.map(function (h) {
        return "<div class='history-row' data-url='" + escapeHtml(h.url) + "'>" +
          "<span class='history-name' title='" + escapeHtml(h.url) + "'>" + escapeHtml(h.url) + "</span>" +
          "<span class='history-score' style='color:" + tierColor(h.cls) + ";'>" + h.score + " / " + h.tier + "</span>" +
        "</div>";
      }).join("");
    box.querySelectorAll(".history-row").forEach(function (row) {
      row.addEventListener("click", function () {
        var url = row.getAttribute("data-url");
        scanInput.value = url;
        scanBtn.click();
      });
    });
  }

  if (scanInput && scanBtn && typeof PhishGuardEngine !== "undefined") {
    scanBtn.addEventListener("click", function () {
      var raw = scanInput.value.trim();
      if (!raw) { scanInput.focus(); return; }
      var res = PhishGuardEngine.analyze(raw);
      if (!res) { scanInput.focus(); return; }
      scanInput.value = "";
      renderResult(res);
      historyLog.unshift({ url: res.url, score: res.score, tier: res.tier, cls: res.cls });
      if (historyLog.length > MAX_HISTORY) historyLog = historyLog.slice(0, MAX_HISTORY);
      try { localStorage.setItem("pg-history-v2", JSON.stringify(historyLog)); } catch (e) {}
      renderHistory();
    });
    scanInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); scanBtn.click(); }
    });
    renderHistory();
  }

  /* ---------- 6. Contact form (client-side validation + mailto fallback) ---------- */
  var form = $("#contactForm");
  var formStatus = $("#formStatus");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var name = (form.name.value || "").trim();
      var email = (form.email.value || "").trim();
      var subject = (form.subject.value || "").trim() || "Portfolio message from " + name;
      var message = (form.message.value || "").trim();

      if (!name || !email || !message) {
        formStatus.textContent = "// Missing required fields — name, email, and message are needed.";
        formStatus.className = "form-status error";
        return;
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        formStatus.textContent = "// Invalid email address format.";
        formStatus.className = "form-status error";
        return;
      }
      var body = encodeURIComponent(message + "\n\n— " + name);
      window.location.href = "mailto:olimandip74@gmail.com?subject=" + encodeURIComponent(subject) + "&body=" + body;
      formStatus.textContent = "// Opening your mail client to transmit the message...";
      formStatus.className = "form-status";
    });
  }

  /* ---------- 7. Back to top ---------- */
  var backTop = $("#backToTop");
  if (backTop) {
    backTop.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }
})();
