(function () {
  "use strict";

  const DEFAULT_CONFIG = {
    analyzerBaseUrl: "http://localhost:8501/",
    openAnalyzerOnClick: true,
    highlightSafeLinks: true,
    highlightNotFoundLinks: true
  };

  const TRUSTED_DOMAINS = [
    "mbank.pl",
    "pko-bp.pl",
    "santander.pl",
    "ing.pl",
    "millennium.pl",
    "bankmillennium.pl",
    "pekao.com.pl",
    "aliorbank.pl",
    "nestbank.pl",
    "bnpparibas.pl",
    "citibank.pl",
    "velobank.pl",
    "credit-agricole.pl",
    "bosbank.pl",
    "pocztowy.pl",
    "toyotabank.pl",
    "bankbps.pl",
    "sgb.pl",
    "allegro.pl",
    "olx.pl",
    "vinted.pl",
    "empik.com",
    "mediaexpert.pl",
    "x-kom.pl",
    "morele.net",
    "ceneo.pl",
    "inpost.pl",
    "dpd.com.pl",
    "dhl.com",
    "poczta-polska.pl",
    "blik.com",
    "payu.com",
    "przelewy24.pl",
    "tpay.com",
    "autopay.pl"
  ];

  const FALLBACK_BLACKLIST = new Set([
    "allegro-platnosc24.pl",
    "allegro-platnosc.pl",
    "mbank-logowanie.com",
    "mbank-login24.pl",
    "mbank-secure.pl",
    "pko-bp-login.pl",
    "ing-bank.pl",
    "olx-payment.pl",
    "inpost-delivery.pl",
    "vinted-pay.pl"
  ]);

  const PATH_KEYWORDS = [
    "blik",
    "platnosc",
    "payment",
    "pay",
    "logowanie",
    "login",
    "secure",
    "bezpieczny",
    "weryfikacja",
    "verify",
    "konto",
    "paczka"
  ];

  const SHORTENERS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly",
    "is.gd",
    "buff.ly",
    "tiny.cc",
    "shorturl.at",
    "lnkd.in"
  ]);

  const SUSPICIOUS_TLDS = new Set([
    "xyz",
    "top",
    "click",
    "icu",
    "monster",
    "quest",
    "shop",
    "support",
    "rest",
    "cam"
  ]);

  const COMMON_TWO_PART_SUFFIXES = new Set([
    "com.pl",
    "org.pl",
    "net.pl",
    "edu.pl",
    "gov.pl",
    "co.uk",
    "com.au",
    "co.nz"
  ]);

  const state = {
    config: { ...DEFAULT_CONFIG },
    stats: {
      scanned: 0,
      dangerous: 0,
      suspicious: 0,
      safe: 0,
      not_found: 0,
      unknown: 0
    },
    scanTimer: null
  };

  function normalizeText(value) {
    return decodeURIComponentSafe(value)
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[ąćęłńóśżź]/g, (char) => ({
        "ą": "a",
        "ć": "c",
        "ę": "e",
        "ł": "l",
        "ń": "n",
        "ó": "o",
        "ś": "s",
        "ż": "z",
        "ź": "z"
      }[char] || char));
  }

  function decodeURIComponentSafe(value) {
    try {
      return decodeURIComponent(value);
    } catch (_error) {
      return value;
    }
  }

  function splitDomain(hostname) {
    const parts = hostname.split(".").filter(Boolean);

    if (parts.length === 0) {
      return { subdomain: "", domain: "", suffix: "", registeredDomain: "" };
    }

    if (parts.length === 1) {
      return {
        subdomain: "",
        domain: parts[0],
        suffix: "",
        registeredDomain: parts[0]
      };
    }

    const lastTwo = parts.slice(-2).join(".");
    let suffixLength = 1;

    if (parts.length >= 3 && COMMON_TWO_PART_SUFFIXES.has(lastTwo)) {
      suffixLength = 2;
    }

    const suffix = parts.slice(-suffixLength).join(".");
    const domain = parts[parts.length - suffixLength - 1] || "";
    const subdomain = parts.slice(0, Math.max(0, parts.length - suffixLength - 1)).join(".");
    const registeredDomain = domain && suffix ? `${domain}.${suffix}` : hostname;

    return { subdomain, domain, suffix, registeredDomain };
  }

  function getUrlParts(href) {
    try {
      const url = new URL(href, window.location.href);
      const hostname = url.hostname.toLowerCase();
      const domainParts = splitDomain(hostname);
      return { url, hostname, ...domainParts };
    } catch (_error) {
      return null;
    }
  }

  function trustedSet() {
    return new Set(TRUSTED_DOMAINS.map((domain) => domain.toLowerCase()));
  }

  function brandTokens() {
    const tokens = new Set();

    for (const trusted of TRUSTED_DOMAINS) {
      const parts = splitDomain(trusted);
      if (parts.registeredDomain) {
        tokens.add(parts.registeredDomain);
      }
      if (parts.domain && parts.domain.length >= 4) {
        tokens.add(parts.domain);
      }
    }

    return tokens;
  }

  function containsBrand(value, token) {
    if (token.includes(".")) {
      return value.includes(token);
    }

    return new RegExp(`\\b${escapeRegExp(token)}\\b`, "i").test(value);
  }

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function isIpHostname(hostname) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
  }

  function classifyHref(href) {
    const parts = getUrlParts(href);

    if (!parts || !parts.url.protocol.startsWith("http")) {
      return {
        verdict: "not_found",
        score: 0,
        reasons: ["Unsupported, invalid, or non-web URL."],
        url: href,
        registeredDomain: ""
      };
    }

    const reasons = [];
    let score = 0;
    const trustedDomains = trustedSet();
    const isTrusted = trustedDomains.has(parts.registeredDomain);
    const normalizedTail = normalizeText(`${parts.url.pathname} ${parts.url.search} ${parts.url.hash}`);
    const tld = parts.suffix.split(".").pop() || "";

    function add(points, reason) {
      score += points;
      reasons.push(reason);
    }

    if (FALLBACK_BLACKLIST.has(parts.registeredDomain)) {
      add(100, "Domain is on the demo phishing blacklist.");
    }

    if (parts.url.protocol !== "https:") {
      add(10, "Link does not use HTTPS.");
    }

    if (parts.url.username || parts.url.password || parts.url.href.includes("@")) {
      add(30, "Link contains '@' or user-info trickery.");
    }

    if (isIpHostname(parts.hostname)) {
      add(25, "Link uses a raw IP address instead of a normal domain.");
    }

    if (SHORTENERS.has(parts.registeredDomain)) {
      add(15, "Link uses a URL shortener.");
    }

    if (SUSPICIOUS_TLDS.has(tld)) {
      add(10, `Link uses a commonly abused .${tld} domain.`);
    }

    if (parts.subdomain && !isTrusted) {
      const subdomainText = normalizeText(parts.subdomain);
      const domainText = normalizeText(parts.domain);
      const foundInSubdomain = Array.from(brandTokens()).filter((token) => containsBrand(subdomainText, token));
      const foundInDomain = Array.from(brandTokens()).filter((token) => containsBrand(domainText, token));

      if (foundInSubdomain.length && !foundInDomain.length) {
        add(80, `Trusted brand appears in subdomain, but real domain is ${parts.registeredDomain}.`);
      }
    }

    if (!isTrusted && normalizedTail) {
      const foundKeywords = PATH_KEYWORDS.filter((keyword) => {
        return new RegExp(`\\b${escapeRegExp(keyword)}\\b`, "i").test(normalizedTail);
      });
      const foundBrands = Array.from(brandTokens()).filter((token) => containsBrand(normalizedTail, token));

      if (foundBrands.length) {
        add(30, `URL path mentions trusted brand names: ${foundBrands.slice(0, 3).join(", ")}.`);
      }
      if (foundKeywords.length) {
        add(20, `URL path contains payment/login keywords: ${foundKeywords.slice(0, 5).join(", ")}.`);
      }
    }

    const hyphenCount = (parts.domain.match(/-/g) || []).length;

    if (hyphenCount >= 4 || parts.domain.length >= 30) {
      add(30, "Registered domain is very long or overloaded with hyphens.");
    } else if (hyphenCount >= 3 || parts.domain.length >= 25) {
      add(20, "Registered domain is unusually long or hyphen-heavy.");
    }

    if (parts.url.href.length >= 120) {
      add(10, "Link is unusually long.");
    }

    if (isTrusted && score < 50) {
      reasons.length = 0;
      score = 0;
      reasons.push("Registered domain is on the trusted list.");
    }

    const cappedScore = Math.min(score, 100);
    let verdict = "safe";

    if (cappedScore >= 50) {
      verdict = "dangerous";
    } else if (cappedScore >= 20) {
      verdict = "suspicious";
    }

    if (!reasons.length) {
      reasons.push("No strong local browser-extension indicators found.");
    }

    return {
      verdict,
      score: cappedScore,
      reasons,
      url: parts.url.href,
      hostname: parts.hostname,
      registeredDomain: parts.registeredDomain
    };
  }

  function analyzerUrl(targetUrl) {
    const base = state.config.analyzerBaseUrl || DEFAULT_CONFIG.analyzerBaseUrl;
    const url = new URL(base);
    url.searchParams.set("mode", "link");
    url.searchParams.set("url", targetUrl);
    url.searchParams.set("auto", "1");
    return url.href;
  }

  function shouldIgnoreLink(anchor) {
    return Boolean(anchor.closest(
      '[data-ss-ignore="1"], [data-signalshield-ignore="1"], .ss-ignore, .ss-no-extension'
    ));
  }

  function clearSignalShieldData(anchor) {
    for (const key of [
      "ssAnalyzed",
      "ssRawVerdict",
      "ssScore",
      "ssReasons",
      "ssUrl",
      "ssDomain",
      "ssVerdict"
    ]) {
      delete anchor.dataset[key];
    }

    if ((anchor.getAttribute("aria-label") || "").startsWith("SignalShield:")) {
      anchor.removeAttribute("aria-label");
    }
  }

  function annotateLink(anchor) {
    if (!anchor.href) {
      return;
    }

    if (shouldIgnoreLink(anchor)) {
      clearSignalShieldData(anchor);
      return;
    }

    if (anchor.dataset.ssAnalyzed === "1") {
      return;
    }

    const result = classifyHref(anchor.href);
    anchor.dataset.ssAnalyzed = "1";
    anchor.dataset.ssRawVerdict = result.verdict;
    anchor.dataset.ssScore = String(result.score);
    anchor.dataset.ssReasons = JSON.stringify(result.reasons);
    anchor.dataset.ssUrl = result.url;
    anchor.dataset.ssDomain = result.registeredDomain || "";

    if (result.verdict === "safe" && !state.config.highlightSafeLinks) {
      delete anchor.dataset.ssVerdict;
      return;
    }

    if (result.verdict === "not_found" && !state.config.highlightNotFoundLinks) {
      delete anchor.dataset.ssVerdict;
      return;
    }

    anchor.dataset.ssVerdict = result.verdict;
    anchor.setAttribute(
      "aria-label",
      `SignalShield: ${result.verdict}, risk ${result.score} percent. ${result.reasons.join(" ")}`
    );

    if (anchor.dataset.ssListeners !== "1") {
      anchor.addEventListener("mouseenter", showTooltip);
      anchor.addEventListener("mousemove", moveTooltip);
      anchor.addEventListener("mouseleave", hideTooltip);
      anchor.addEventListener("click", handleClick, true);
      anchor.dataset.ssListeners = "1";
    }
  }

  function resetStats() {
    state.stats = {
      scanned: 0,
      dangerous: 0,
      suspicious: 0,
      safe: 0,
      not_found: 0,
      unknown: 0
    };
  }

  function scanPage() {
    resetStats();

    for (const anchor of document.querySelectorAll("a[href]")) {
      if (shouldIgnoreLink(anchor)) {
        clearSignalShieldData(anchor);
        continue;
      }

      if (anchor.dataset.ssAnalyzed === "1") {
        delete anchor.dataset.ssAnalyzed;
      }
      annotateLink(anchor);

      state.stats.scanned += 1;
      const verdict = anchor.dataset.ssRawVerdict || anchor.dataset.ssVerdict || "safe";

      if (Object.prototype.hasOwnProperty.call(state.stats, verdict)) {
        state.stats[verdict] = (state.stats[verdict] || 0) + 1;
      }
    }
  }

  function scheduleScan() {
    window.clearTimeout(state.scanTimer);
    state.scanTimer = window.setTimeout(scanPage, 250);
  }

  function tooltipElement() {
    let tooltip = document.getElementById("ss-link-tooltip");

    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.id = "ss-link-tooltip";
      tooltip.hidden = true;
      document.documentElement.appendChild(tooltip);
    }

    return tooltip;
  }

  function showTooltip(event) {
    const anchor = event.currentTarget;

    if (shouldIgnoreLink(anchor) || !anchor.dataset.ssVerdict) {
      return;
    }

    const reasons = JSON.parse(anchor.dataset.ssReasons || "[]");
    const verdict = anchor.dataset.ssVerdict || "unknown";
    const score = anchor.dataset.ssScore || "0";
    const domain = anchor.dataset.ssDomain || "";
    const tooltip = tooltipElement();

    tooltip.innerHTML = [
      `<strong>SignalShield: ${escapeHtml(verdict.toUpperCase())} (${escapeHtml(score)}%)</strong>`,
      domain ? `<div>${escapeHtml(domain)}</div>` : "",
      "<ul>",
      ...reasons.slice(0, 6).map((reason) => `<li>${escapeHtml(reason)}</li>`),
      "</ul>",
      "<div>Click to open full analysis.</div>"
    ].join("");
    tooltip.hidden = false;
    moveTooltip(event);
  }

  function moveTooltip(event) {
    const tooltip = tooltipElement();
    const offset = 14;
    const x = Math.min(event.clientX + offset, window.innerWidth - tooltip.offsetWidth - offset);
    const y = Math.min(event.clientY + offset, window.innerHeight - tooltip.offsetHeight - offset);
    tooltip.style.left = `${Math.max(offset, x)}px`;
    tooltip.style.top = `${Math.max(offset, y)}px`;
  }

  function hideTooltip() {
    tooltipElement().hidden = true;
  }

  function handleClick(event) {
    if (shouldIgnoreLink(event.currentTarget)) {
      return;
    }

    if (!state.config.openAnalyzerOnClick) {
      return;
    }

    const targetUrl = event.currentTarget.dataset.ssUrl;

    if (!targetUrl) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    window.open(analyzerUrl(targetUrl), "_blank", "noopener,noreferrer");
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function loadConfig(callback) {
    if (!chrome.storage || !chrome.storage.sync) {
      callback();
      return;
    }

    chrome.storage.sync.get(DEFAULT_CONFIG, (config) => {
      state.config = { ...DEFAULT_CONFIG, ...config };
      callback();
    });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === "SS_RESCAN") {
      loadConfig(() => {
        scanPage();
        sendResponse({ ok: true, stats: state.stats });
      });
      return true;
    }

    if (message && message.type === "SS_GET_STATS") {
      sendResponse({ ok: true, stats: state.stats });
      return false;
    }

    return false;
  });

  loadConfig(() => {
    scanPage();
    const observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  });
}());
