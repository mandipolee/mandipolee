/* =====================================================================
   Password Strength Engine — fully client-side, privacy-first.
   SECURITY CONTRACT (do not violate):
     - Never send the password anywhere (no fetch/XHR containing it).
     - Never store it (localStorage, sessionStorage, cookies, logs).
     - Never console.log() the password value.
     - Generated passwords use crypto.getRandomValues() only.
   ===================================================================== */
(function () {
  "use strict";

  /* ---------- Small top-common-pattern library (NOT a full word database) */
  var COMMON_PATTERNS = [
    "password", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwertyuiop", "abcabc", "abcdef", "abcdefg", "111111",
    "000000", "12345", "1234", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "login", "passw0rd", "p@ssword",
    "p@ssw0rd", "iloveyou", "football", "shadow", "sunshine",
    "trustno1", "hello", "charlie", "donald", "baseball", "batman",
    "access", "flower", "summer", "spring", "winter", "autumn",
    "love", "secret", "test", "guest", "pass", "root", "toor"
  ];
  /* Predictable substitutions map used to normalize before pattern check */
  var SUBS = { "@": "a", "$": "s", "0": "o", "1": "i", "!": "i", "3": "e", "7": "t", "4": "a" };

  /* Character classes */
  var CHARSETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digit: "0123456789",
    symbol: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
  };

  /* Guess rates (attempts per second) for crack-time education */
  var CRACK_RATES = {
    online: 100,          // throttled online login
    offline: 1e9,         // modern offline hash (bcrypt/argon2-class fast hash)
    fastOffline: 1e12     // high-speed offline (MD5-class, GPU cluster)
  };

  function charsetSize(pw) {
    var size = 0;
    if (/[a-z]/.test(pw)) size += CHARSETS.lower.length;
    if (/[A-Z]/.test(pw)) size += CHARSETS.upper.length;
    if (/[0-9]/.test(pw)) size += CHARSETS.digit.length;
    if (/[^A-Za-z0-9]/.test(pw)) size += CHARSETS.symbol.length;
    return size || 26;
  }

  /* ---------- Core analysis ---------- */
  function analyzePassword(pw) {
    /* NOTE: pw is used only within this local scope; never persisted or logged. */
    var len = pw ? pw.length : 0;
    var checks = {
      length12: len >= 12,
      length16: len >= 16,
      upper: /[A-Z]/.test(pw),
      lower: /[a-z]/.test(pw),
      digit: /[0-9]/.test(pw),
      symbol: /[^A-Za-z0-9]/.test(pw),
      variety: 0,
      repeated: false,
      sequential: false,
      common: false,
      keyboard: false
    };
    checks.variety =
      (checks.upper ? 1 : 0) + (checks.lower ? 1 : 0) +
      (checks.digit ? 1 : 0) + (checks.symbol ? 1 : 0);

    var patterns = detectPatterns(pw);
    checks.repeated = patterns.repeated;
    checks.sequential = patterns.sequential;
    checks.common = patterns.common !== null;
    checks.keyboard = patterns.keyboard;

    var score = calculateScore(len, checks);
    var entropy = calculateEntropy(pw);
    var crackTimes = estimateCrackTime(entropy);
    var tier = tierFor(score);
    var recommendations = buildRecommendations(len, checks, patterns, score);

    return {
      score: score,
      tier: tier,
      entropy: entropy,
      crackTimes: crackTimes,
      checks: checks,
      patterns: patterns,
      recommendations: recommendations
    };
  }

  /* ---------- Score 0-100 ---------- */
  function calculateScore(len, checks) {
    if (len === 0) return 0;
    var score = 0;
    /* Length dominates (aligned with research: length > complexity) */
    score += Math.min(len * 3, 45);          // up to 45 pts for length
    score += checks.variety * 8;             // up to 32 pts for variety
    if (checks.length16) score += 5;
    /* Penalties */
    if (checks.common) score -= 30;
    if (checks.keyboard) score -= 12;
    if (checks.repeated) score -= 8;
    if (checks.sequential) score -= 8;
    if (checks.lower && !checks.upper && !checks.digit && !checks.symbol && len < 8) score -= 10;
    return Math.min(100, Math.max(0, Math.round(score)));
  }

  /* ---------- Entropy (bits) — an estimate, NOT a guarantee ---------- */
  function calculateEntropy(pw) {
    if (!pw || pw.length === 0) return 0;
    var pool = charsetSize(pw);
    return Math.round(pw.length * Math.log2(pool));
  }

  /* ---------- Pattern detection ---------- */
  function detectPatterns(pw) {
    var res = { repeated: false, sequential: false, common: null, keyboard: false };
    if (!pw || pw.length < 4) return res;
    var low = pw.toLowerCase();

    /* Repeated chars: 4+ of the same character (e.g. "aaaa", "1111") */
    res.repeated = /(.)\1{3,}/.test(pw);

    /* Sequential: 4+ ascending/descending code steps */
    var seqRun = 1;
    for (var i = 1; i < pw.length; i++) {
      var diff = pw.charCodeAt(i) - pw.charCodeAt(i - 1);
      if (diff === 1 || diff === -1) {
        seqRun++;
        if (seqRun >= 4) { res.sequential = true; break; }
      } else seqRun = 1;
    }

    /* Common patterns (normalized for substitutions): p@ssw0rd -> password */
    var normalized = low.replace(/[ @$!01374]/g, function (ch) { return SUBS[ch] || ch; });
    for (var j = 0; j < COMMON_PATTERNS.length; j++) {
      if (normalized.indexOf(COMMON_PATTERNS[j]) !== -1) { res.common = COMMON_PATTERNS[j]; break; }
    }

    /* Keyboard patterns (QWERTY rows) */
    var rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
    for (var k = 0; k < rows.length; k++) {
      var run = 1;
      for (var m = 1; m < low.length; m++) {
        var a = rows[k].indexOf(low[m - 1]);
        var b = rows[k].indexOf(low[m]);
        if (a !== -1 && b !== -1 && Math.abs(b - a) === 1) {
          run++;
          if (run >= 4) { res.keyboard = true; break; }
        } else run = 1;
      }
      if (res.keyboard) break;
    }
    return res;
  }

  /* ---------- Crack-time estimation (educational, not a prediction) ---------- */
  function estimateCrackTime(entropy) {
    var combinations = Math.pow(2, entropy);
    var out = {};
    var keys = Object.keys(CRACK_RATES);
    for (var i = 0; i < keys.length; i++) {
      var secs = combinations / CRACK_RATES[keys[i]];
      out[keys[i]] = { rate: CRACK_RATES[keys[i]], seconds: secs, label: humanTime(secs) };
    }
    return out;
  }

  function humanTime(secs) {
    if (!isFinite(secs) || secs <= 0) return "Less than a second";
    if (secs < 1) return "Less than a second";
    if (secs < 60) return Math.round(secs) + " seconds";
    if (secs < 3600) return Math.round(secs / 60) + " minutes";
    if (secs < 86400) return Math.round(secs / 3600) + " hours";
    if (secs < 86400 * 365) return Math.round(secs / 86400) + " days";
    var years = secs / (86400 * 365);
    if (years < 1000) return Math.round(years) + " years";
    if (years < 1e6) return Math.round(years / 1000) + " thousand years";
    if (years < 1e9) return Math.round(years / 1e6) + " million years";
    return "Centuries+";
  }

  /* ---------- Tier ---------- */
  function tierFor(score) {
    if (score >= 85) return { text: "Very Strong", cls: "pt-strong" };
    if (score >= 70) return { text: "Strong", cls: "pt-strong" };
    if (score >= 50) return { text: "Moderate", cls: "pt-possible" };
    if (score >= 30) return { text: "Weak", cls: "pt-low" };
    return { text: "Very Weak", cls: "pt-low" };
  }

  /* ---------- Recommendations ---------- */
  function buildRecommendations(len, checks, patterns, score) {
    var recs = [];
    if (len < 12) recs.push("Use at least 12 characters — length matters more than complexity alone.");
    else if (len < 16) recs.push("Even stronger: try a 16+ character passphrase.");
    if (!checks.upper) recs.push("Add uppercase letters.");
    if (!checks.lower) recs.push("Add lowercase letters.");
    if (!checks.digit) recs.push("Add numbers.");
    if (!checks.symbol) recs.push("Add special characters.");
    if (patterns.common) recs.push("Avoid common words and predictable patterns (like '" + patterns.common + "').");
    if (patterns.repeated) recs.push("Avoid repeating the same character 4+ times.");
    if (patterns.sequential) recs.push("Avoid sequential characters (like 'abcd' or '1234').");
    if (patterns.keyboard) recs.push("Avoid keyboard rows (like 'qwerty').");
    if (recs.length === 0) recs.push("Great foundation. Use a unique password for every account, and enable MFA where available.");
    return recs;
  }

  /* ---------- Secure generator (crypto.getRandomValues only) ---------- */
  function generateSecurePassword(opts) {
    opts = opts || {};
    var len = Math.min(64, Math.max(12, opts.length || 16));
    var useUpper = opts.upper !== false, useLower = opts.lower !== false;
    var useDigit = opts.digits !== false, useSymbol = opts.symbols !== false;
    var pool = "";
    if (useLower) pool += CHARSETS.lower;
    if (useUpper) pool += CHARSETS.upper;
    if (useDigit) pool += CHARSETS.digit;
    if (useSymbol) pool += CHARSETS.symbol;
    if (!pool) { pool = CHARSETS.lower + CHARSETS.upper + CHARSETS.digit; }

    var arr = new Uint32Array(len);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(arr);
    } else {
      throw new Error("Cryptographic random number generator not available in this browser.");
    }
    var pw = "";
    for (var i = 0; i < len; i++) {
      pw += pool[arr[i] % pool.length];
    }
    return pw;
  }

  /* ---------- Public API ---------- */
  window.PasswordEngine = {
    analyze: analyzePassword,
    score: calculateScore,
    entropy: calculateEntropy,
    patterns: detectPatterns,
    crackTime: estimateCrackTime,
    generate: generateSecurePassword,
    tiers: {
      veryWeak: { text: "Very Weak", cls: "pt-low" },
      weak: { text: "Weak", cls: "pt-low" },
      moderate: { text: "Moderate", cls: "pt-possible" },
      strong: { text: "Strong", cls: "pt-strong" },
      veryStrong: { text: "Very Strong", cls: "pt-strong" }
    }
  };
})();
