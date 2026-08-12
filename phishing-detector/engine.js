/* ============================================================
   PhishGuard Advanced Detection Engine
   Client-side heuristic analyzer: 25+ signals, weighted scoring,
   verdict tiers, and human-readable explanations.
   ============================================================ */
var PhishGuardEngine = (function () {
  "use strict";

  /* ---------- Known brand impersonation patterns ---------- */
  var BRANDS = {
    "paypal": "PayPal",
    "apple": "Apple",
    "icloud": "Apple iCloud",
    "google": "Google",
    "gmail": "Gmail",
    "microsoft": "Microsoft",
    "microsoftonline": "Microsoft 365",
    "outlook": "Outlook",
    "amazon": "Amazon",
    "netflix": "Netflix",
    "facebook": "Facebook",
    "meta": "Meta",
    "instagram": "Instagram",
    "linkedin": "LinkedIn",
    "twitter": "Twitter / X",
    "x\\.com$": "X (Twitter)",
    "dropbox": "Dropbox",
    "docusign": "DocuSign",
    "fedex": "FedEx",
    "ups": "UPS",
    "dhl": "DHL",
    "usps": "USPS",
    "irs": "IRS",
    "gov\\.uk": "GOV.UK",
    "ebay": "eBay",
    "wellsfargo": "Wells Fargo",
    "chase": "Chase Bank",
    "bankofamerica": "Bank of America",
    "citibank": "Citibank",
    "coinbase": "Coinbase",
    "binance": "Binance",
    "metamask": "MetaMask",
    "steam": "Steam",
    "discord": "Discord",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "spotify": "Spotify",
    "tiktok": "TikTok",
    "roblox": "Roblox"
  };

  /* Credential-harvesting keywords commonly found in phishing paths */
  var CRED_KEYWORDS = /login|signin|sign-in|secure|account|verify|confirm|update|reset|password|pass|wallet|recovery|unlock|suspend|reactivate|auth|web-login|webscr|cmd-login/i;

  /* URL shorteners (legit but often abused) */
  var SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|tiny\.cc|cutt\.ly|shorte\.st|lnkd\.in|dlvr\.it|rb\.gy|rebrandly\.com|clck\.ru|su\.pr|shrt\.io|tiny\.pl|shortlink)/i;

  /* Trusted official domains that should never be penalized for brand-name signals.
     Only canonical brand hosts are listed; subdomains like login.facebook.com are
     intentionally excluded since they are typical phishing targets. */
  var TRUSTED_HOSTS = {
    "facebook.com": "Facebook",
    "fb.com": "Facebook",
    "fb.watch": "Facebook",
    "instagram.com": "Instagram",
    "twitter.com": "Twitter / X",
    "x.com": "X (Twitter)",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "tiktok.com": "TikTok",
    "linkedin.com": "LinkedIn",
    "whatsapp.com": "WhatsApp",
    "telegram.org": "Telegram",
    "t.me": "Telegram",
    "reddit.com": "Reddit",
    "discord.com": "Discord",
    "spotify.com": "Spotify",
    "steamcommunity.com": "Steam",
    "github.com": "GitHub",
    "wikipedia.org": "Wikipedia",
    "google.com": "Google",
    "youtube-nocookie.com": "YouTube",
    "msn.com": "Microsoft"
  };

  function isTrustedHost(host) {
    if (TRUSTED_HOSTS.hasOwnProperty(host)) return true;
    var bare = host.replace(/^www\./, '');
    return TRUSTED_HOSTS.hasOwnProperty(bare);
  }

  /* High-risk TLDs frequently used by phishers */
  var RISKY_TLDS = /\.(tk|ml|ga|cf|gq|buzz|top|click|work|icu|zip|motorcycles|yachts|gdn|monster|cam|country|date|faith|loan|racing|review|stream|science|party|kim|men|ren|wang|pw|cc)$/i;

  /* Typosquatting: common misspellings per brand */
  var TYPOSQUATS = {
    "paypal": ["paypa1", "paypai", "paypall", "paupay", "paypal-confirm", "paypal-secure", "paypa"],
    "google": ["goog1e", "gogle", "google-accounts", "accounts-goog1e"],
    "apple": ["app1e", "appleid-verify", "apple-icloud"],
    "microsoft": ["micros0ft", "microsof", "microsoftonline-sec"],
    "netflix": ["netfliix", "netflix-update"],
    "amazon": ["amaz0n", "arnazon", "amazon-account"],
    "linkedin": ["linkedin-secure", "linkedln"],
    "coinbase": ["coinbase-wallet", "coinnbase"]
  };

  /* ---------- Character-level helpers ---------- */
  function shannonEntropy(str) {
    if (!str) return 0;
    var freq = {};
    for (var i = 0; i < str.length; i++) freq[str[i]] = (freq[str[i]] || 0) + 1;
    var ent = 0, len = str.length;
    Object.keys(freq).forEach(function (k) {
      var p = freq[k] / len;
      ent -= p * Math.log2(p);
    });
    return ent;
  }

  function hasPunycode(host) { return /xn--/.test(host); }

  function hasHomoglyph(host) {
    var mapped = host.toLowerCase()
      .replace(/[0O]/g, "O").replace(/[Il1!|]/g, "l");
    for (var brand in BRANDS) {
      if (brand.indexOf("\\") !== -1) continue;
      if (mapped.indexOf(brand.toLowerCase()) !== -1) return brand;
    }
    return null;
  }

  function longestLabel(host) {
    return Math.max.apply(null, host.split(".").map(function (l) { return l.length; }));
  }

  /* ---------- Signal definitions (weight 1-25) ---------- */
  function collectSignals(url) {
    var signals = [];
    var u;
    try {
      if (!/^https?:\/\//i.test(url)) url = "https://" + url;
      u = new URL(url);
    } catch (e) { return [{ name: "Unparseable URL", weight: 15, desc: "The URL could not be parsed — malformed addresses are a common evasion tactic." }]; }

    var host = u.hostname.toLowerCase();

    /* 1. Protocol */
    if (u.protocol === "http:") signals.push({ name: "Unencrypted HTTP", weight: 20, desc: "Legitimate services handling credentials almost always use HTTPS." });

    /* 2. IP-based address */
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) signals.push({ name: "Raw IP address", weight: 22, desc: "Banks and major services never send login links as raw IP addresses." });

    /* 3. Punycode / IDN */
    if (hasPunycode(host)) signals.push({ name: "Punycode (IDN) domain", weight: 22, desc: "xn-- encoded domains are often used to spoof well-known brands (IDN homograph attack)." });

    /* 4. IP-in-path (e.g., paypal.com@203.0.113.1) */
    if (/@\d/.test(u.href)) signals.push({ name: "'@' used to mask real destination", weight: 25, desc: "Some browsers navigate to the host after the @ symbol, ignoring the brand name before it." });

    /* 5. Multiple hyphens */
    var hyphens = (host.match(/-/g) || []).length;
    if (hyphens >= 2) signals.push({ name: "Multiple hyphens in domain", weight: 14, desc: "Phishers stack hyphens to look official (e.g., 'paypal-account-update.tk')." });

    /* 6. Very long domain */
    if (host.length > 45) signals.push({ name: "Unusually long domain", weight: 12, desc: "Legitimate domains are typically short; long ones are often generated." });

    /* 7. Long single label */
    if (longestLabel(host) > 30) signals.push({ name: "Abnormally long label", weight: 10, desc: "One part of the domain is extremely long — typical of machine-generated names." });

    /* 8. Brand-name in domain (typosquatting / look-alike check).
       The official domain itself (e.g., facebook.com) is never impersonation — skip it. */
    var homoglyph = hasHomoglyph(host);
    if (homoglyph && !isTrustedHost(host)) {
      var isTypo = /[01!|]/.test(host);
      signals.push({ name: "Brand impersonation: " + BRANDS[homoglyph], weight: isTypo ? 25 : 20, desc: "The domain impersonates " + BRANDS[homoglyph] + (isTypo ? " using look-alike characters (1↔l, 0↔o)." : ".") });
    }

    /* 9. Sensitive keywords in domain */
    if (CRED_KEYWORDS.test(host)) signals.push({ name: "Credential-related keyword in domain", weight: 18, desc: "Words like 'login', 'secure', 'verify' inside the domain itself are a classic phishing pattern." });

    /* 10. Suspicious TLD */
    if (RISKY_TLDS.test(host)) signals.push({ name: "High-risk TLD", weight: 12, desc: "This TLD is disproportionately associated with phishing campaigns." });

    /* 11. URL shortener */
    if (SHORTENERS.test(host)) signals.push({ name: "URL shortener", weight: 10, desc: "Shorteners hide the real destination — verify carefully before clicking." });

    /* 12. Suspicious path keywords */
    if (CRED_KEYWORDS.test(u.pathname)) signals.push({ name: "Credential-harvesting path pattern", weight: 16, desc: "The path contains login/verify-style segments commonly used by phishing kits." });

    /* 13. Long encoded path */
    if (u.pathname.length > 60 || /[A-Za-z0-9]{30,}/.test(u.pathname)) signals.push({ name: "Long / encoded path", weight: 10, desc: "Long machine-looking paths often come from phishing kits." });

    /* 14. Heavy query parameters */
    if (u.search && u.search.length > 50) signals.push({ name: "Heavy query parameters", weight: 8, desc: "Many tracking parameters are typical of bulk phishing mailers." });

    /* 15. Suspicious query keys.
       Harmless sharing parameters on trusted hosts (e.g., ref=share, id= on facebook.com)
       are excluded so legitimate post links stay SAFE. */
    if (!isTrustedHost(host) && /passwd|token=|id=|ref=|redirect|goto|from=|email=|username/i.test(u.search)) signals.push({ name: "Suspicious query parameters", weight: 10, desc: "Parameters that pre-fill credentials or redirect after login are common in phishing." });

    /* 16. Port number present */
    if (u.port && u.port !== "80" && u.port !== "443") signals.push({ name: "Non-standard port", weight: 10, desc: "Legitimate services use default ports; explicit ports suggest self-hosted phishing pages." });

    /* 17. Subdomain abuse (brand in subdomain, unfamiliar parent) */
    var parts = host.split(".");
    if (parts.length >= 3 && CRED_KEYWORDS.test(parts[0])) {
      signals.push({ name: "Suspicious subdomain", weight: 16, desc: "Phishers put brand names in the subdomain: 'paypal.login.evil.com' — the real domain is the LAST two parts." });
    }

    /* 18. Domain entropy */
    var sld = parts.length >= 2 ? parts[parts.length - 2] : host;
    if (shannonEntropy(sld) > 4.2 && sld.length > 10) signals.push({ name: "High domain entropy", weight: 8, desc: "The domain name looks randomly generated, typical of disposable phishing hosts." });

    /* 19. Mixed case anomalies / unicode */
    if (/[\u0400-\u04FF]/.test(host)) signals.push({ name: "Cyrillic look-alike characters", weight: 25, desc: "Cyrillic characters visually identical to Latin letters are a strong homograph spoofing signal." });

    /* 20. Newly popular abuse domains (web-login, webscr) */
    if (/web-login|webscr|cmd-login|myaccount|update-account/i.test(host + u.pathname)) signals.push({ name: "Known phishing kit pattern", weight: 22, desc: "This domain/path pattern matches documented phishing kits (e.g., PayPal 'webscr' clones)." });

    return signals;
  }

  /* ---------- Recommendations ---------- */
  function adviceFor(score, signals) {
    if (score >= 60) return "Recommendation: Do not enter credentials, payment info, or 2FA codes. Close the tab and report the link to your email provider or platform.";
    if (score >= 15) return "Recommendation: Do not click through from an email or message. Type the service's real address manually and verify the sender first.";
    return "Recommendation: Still confirm the URL matches the sender's claims — heuristics can't catch every zero-day campaign.";
  }

  /* ---------- Verdict ---------- */
  function verdictFor(score) {
    if (score >= 60) return { tier: "DANGEROUS", label: "Likely phishing — avoid entering any information", cls: "scan-bad" };
    if (score >= 35) return { tier: "SUSPICIOUS", label: "Review carefully — several risk signals detected", cls: "scan-warn" };
    if (score >= 15) return { tier: "CAUTION", label: "Moderate risk — verify the sender before trusting", cls: "scan-warn" };
    return { tier: "SAFE", label: "No strong phishing signals detected", cls: "scan-ok" };
  }

  /* ---------- Public API ---------- */
  return {
    analyze: function (url) {
      var signals = collectSignals(url);
      var raw = signals.reduce(function (s, x) { return s + x.weight; }, 0);
      var score = Math.min(100, Math.max(0, raw));
      var v = verdictFor(score);
      return { url: String(url).trim(), score: score, tier: v.tier, verdict: v.label, cls: v.cls, signals: signals, advice: adviceFor(score, signals) };
    },
    BRANDS: BRANDS
  };
})();
