(function () {
  "use strict";

  const DEFAULT_CONFIG = {
    analyzerBaseUrl: "http://localhost:8501/",
    apiBaseUrl: "http://127.0.0.1:8766/",
    useDeepAnalysis: true,
    openAnalyzerOnClick: true,
    highlightSafeLinks: true,
    highlightNotFoundLinks: true,
    trustedUrls: [],
    blockedUrls: []
  };

  const TRUSTED_DOMAINS = [
    "aliorbank.pl",
    "allianz.pl",
    "mbank.pl",
    "amazon.pl",
    "apaczka.pl",
    "apple.com",
    "apple.com.pl",
    "apple.pl",
    "autopay.pl",
    "bankbps.pl",
    "bankmillennium.pl",
    "banknowybfg.pl",
    "bfg.pl",
    "bgk.pl",
    "blik.com",
    "blue.pl",
    "bluemedia.pl",
    "bnpparibas.pl",
    "bosbank.pl",
    "cashbill.pl",
    "ceneo.pl",
    "centrum24.pl",
    "citibank.pl",
    "citihandlowy.pl",
    "cloudflare.com",
    "credit-agricole.pl",
    "db.com",
    "dhl.com",
    "dhlparcel.pl",
    "dnb.pl",
    "dotpay.pl",
    "dpd.com.pl",
    "eon.pl",
    "ecard.pl",
    "empik.com",
    "enea.pl",
    "energa.pl",
    "ergohestia.pl",
    "eservice.pl",
    "euro.com.pl",
    "fedex.com",
    "furgonetka.pl",
    "gaz-system.pl",
    "generali.pl",
    "gls-group.eu",
    "gls-poland.com",
    "google.com",
    "google.com.pl",
    "google.co.uk",
    "google.pl",
    "gov.pl",
    "hotpay.pl",
    "imoje.pl",
    "ing.pl",
    "inghipoteczny.pl",
    "innogy.pl",
    "inpost.pl",
    "inpost24.pl",
    "ipko.pl",
    "k24.pl",
    "knf.gov.pl",
    "link4.pl",
    "localhost",
    "mediaexpert.pl",
    "mediamarkt.pl",
    "mf.gov.pl",
    "milenet.pl",
    "millennium.pl",
    "millenniumbh.pl",
    "mhipoteczny.pl",
    "microsoft.com",
    "microsoft.com.pl",
    "microsoft.pl",
    "mojeid.pl",
    "morele.net",
    "mozilla.org",
    "multimedia.pl",
    "nbp.pl",
    "neonet.pl",
    "nestbank.pl",
    "netia.pl",
    "nju.pl",
    "olx.pl",
    "orange.pl",
    "orlen.pl",
    "orlenpaczka.pl",
    "otomoto.pl",
    "otodom.pl",
    "p24.pl",
    "paczkomaty.pl",
    "paybynet.pl",
    "paynow.pl",
    "payu.com",
    "pekao.com.pl",
    "pekao24.pl",
    "pekaobh.pl",
    "pfr.pl",
    "pge.pl",
    "pgnig.pl",
    "planetpay.pl",
    "play.pl",
    "plus.pl",
    "plusbank.pl",
    "plushbezlimitu.pl",
    "poczta-polska.pl",
    "pocztowy.pl",
    "pocztex.pl",
    "podatki.gov.pl",
    "pkobh.pl",
    "pkobp.pl",
    "pko-bp.pl",
    "polcard.pl",
    "przelewy24.pl",
    "pzu.pl",
    "rossmann.pl",
    "rtvagd.pl",
    "ruch.pl",
    "santander.pl",
    "santanderconsumer.pl",
    "sgb.pl",
    "t-mobile.pl",
    "tauron.pl",
    "toyotabank.pl",
    "tpay.com",
    "transferuj.pl",
    "unicredit.pl",
    "upc.pl",
    "ups.com",
    "vectra.pl",
    "velobank.pl",
    "vinted.pl",
    "vwbank.pl",
    "warta.pl",
    "x-kom.pl",
    "zalando.pl",
    "zus.pl",
    "allegro.pl",
    "allegrolokalnie.pl"
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

  const EMPTY_QUICK_RULES = Object.freeze({
    version: 0,
    generated_at: "",
    trusted_domains: TRUSTED_DOMAINS,
    fallback_blacklist: Array.from(FALLBACK_BLACKLIST)
  });

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

  const RISKY_FORM_VERDICTS = new Set(["dangerous", "suspicious"]);
  const state = {
    config: { ...DEFAULT_CONFIG },
    quickRules: { ...EMPTY_QUICK_RULES },
    rulesLoaded: false,
    stats: {
      scanned: 0,
      dangerous: 0,
      suspicious: 0,
      safe: 0,
      not_found: 0,
      trusted_by_user: 0,
      unknown: 0
    },
    analysis: {
      status: "quick_js",
      label: "Quick JS check",
      detail: "The page has been checked only by the browser extension.",
      deepChecked: 0,
      deepTotal: 0,
      updatedAt: ""
    },
    currentPage: {
      verdict: "unknown",
      score: 0,
      reasons: [],
      url: window.location.href,
      hostname: window.location.hostname,
      registeredDomain: "",
      localListType: "",
      analysisStage: "quick_js",
      updatedAt: ""
    },
    formActions: {},
    dismissedPageWarningSignature: "",
    scanTimer: null,
    deepTimer: null,
    lastDeepSignature: ""
  };

  const POLISH_DIACRITICS = /[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017c\u017a]/g;
  const POLISH_CHAR_MAP = {
    "\u0105": "a",
    "\u0107": "c",
    "\u0119": "e",
    "\u0142": "l",
    "\u0144": "n",
    "\u00f3": "o",
    "\u015b": "s",
    "\u017c": "z",
    "\u017a": "z"
  };

  function normalizeText(value) {
    return decodeURIComponentSafe(value)
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017c\u017a]/g, (char) => ({
        "\u0105": "a",
        "\u0107": "c",
        "\u0119": "e",
        "\u0142": "l",
        "\u0144": "n",
        "\u00f3": "o",
        "\u015b": "s",
        "\u017c": "z",
        "\u017a": "z"
      }[char] || char))
      .replace(/[\u0300-\u036f]/g, "")
      .replace(POLISH_DIACRITICS, (char) => POLISH_CHAR_MAP[char] || char);
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

  function normalizeQuickRules(payload) {
    const safePayload = payload || {};
    const trustedDomains = Array.isArray(safePayload.trusted_domains)
      ? safePayload.trusted_domains
      : [];
    const fallbackBlacklist = Array.isArray(safePayload.fallback_blacklist)
      ? safePayload.fallback_blacklist
      : [];

    return {
      version: Number(safePayload.version || 0),
      generated_at: String(safePayload.generated_at || ""),
      trusted_domains: trustedDomains
        .map((domain) => String(domain || "").toLowerCase().trim())
        .filter(Boolean),
      fallback_blacklist: fallbackBlacklist
        .map((domain) => String(domain || "").toLowerCase().trim())
        .filter(Boolean)
    };
  }

  function trustedSet() {
    return new Set(state.quickRules.trusted_domains);
  }

  function fallbackBlacklistSet() {
    return new Set(state.quickRules.fallback_blacklist);
  }

  function extensionListSet(key) {
    const values = Array.isArray(state.config[key]) ? state.config[key] : [];
    return new Set(values.map((value) => String(value || "").toLowerCase()));
  }

  function extensionListMatch(parts) {
    const urlValue = parts.url.href.toLowerCase();
    const hostname = parts.hostname.toLowerCase();
    const trusted = extensionListSet("trustedUrls");
    const blocked = extensionListSet("blockedUrls");

    if (blocked.has(urlValue) || blocked.has(hostname)) {
      return "blacklist";
    }

    if (trusted.has(urlValue) || trusted.has(hostname)) {
      return "trusted";
    }

    return "";
  }

  function brandTokens() {
    const tokens = new Set();

    for (const trusted of state.quickRules.trusted_domains) {
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
    const extensionMatch = extensionListMatch(parts);
    const trustedDomains = trustedSet();
    const isTrusted = trustedDomains.has(parts.registeredDomain);
    const normalizedTail = normalizeText(`${parts.url.pathname} ${parts.url.search} ${parts.url.hash}`);
    const tld = parts.suffix.split(".").pop() || "";

    function add(points, reason) {
      score += points;
      reasons.push(reason);
    }

    if (extensionMatch === "blacklist") {
      return {
        verdict: "dangerous",
        score: 100,
        reasons: ["URL is saved in the extension block list."],
        url: parts.url.href,
        hostname: parts.hostname,
        registeredDomain: parts.registeredDomain,
        localListType: "blacklist"
      };
    }

    if (extensionMatch === "trusted") {
      return {
        verdict: "trusted_by_user",
        score: 0,
        reasons: ["URL is saved in the extension trusted list."],
        url: parts.url.href,
        hostname: parts.hostname,
        registeredDomain: parts.registeredDomain,
        localListType: "trusted"
      };
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

  function normalizeVerdict(verdict) {
    return String(verdict || "unknown").toLowerCase();
  }

  function verdictLabel(verdict) {
    const normalized = normalizeVerdict(verdict);
    const labels = {
      dangerous: "Dangerous",
      suspicious: "Suspicious",
      safe: "Safe",
      not_found: "This link does not appear to exist",
      trusted_by_user: "Trusted by user",
      unknown: "Unknown"
    };
    return labels[normalized] || normalized.replace(/_/g, " ");
  }

  function isHttpUrl(value) {
    return /^https?:\/\//i.test(String(value || ""));
  }

  function normalizeAnalysisResult(result, fallbackUrl, stage = "quick_js") {
    const safeResult = result || {};
    const details = safeResult.details || {};
    const localMatch = details.local_list_match || {};
    const verdict = normalizeVerdict(safeResult.verdict);
    const score = Number(safeResult.score || 0);
    const reasons = Array.isArray(safeResult.reasons) ? safeResult.reasons : [];
    const parts = getUrlParts(safeResult.url || details.input_url || fallbackUrl);

    return {
      verdict,
      score,
      reasons,
      url: safeResult.url || details.input_url || fallbackUrl,
      hostname: safeResult.hostname || details.hostname || (parts ? parts.hostname : ""),
      registeredDomain: safeResult.registeredDomain || details.domain || (parts ? parts.registeredDomain : ""),
      localListType: safeResult.localListType || localMatch.list_type || "",
      analysisStage: stage,
      updatedAt: new Date().toLocaleTimeString()
    };
  }

  function pageWarningSignature(page = state.currentPage) {
    return `${page.url}|${page.verdict}|${page.score}|${page.analysisStage}`;
  }

  function pageAnalysisLabel(page = state.currentPage) {
    if (page.analysisStage === "python") {
      return "Python deep analysis completed for the current page.";
    }

    if (state.config.useDeepAnalysis) {
      if (state.analysis.status === "pending") {
        return "Current page has a quick browser check; Python analysis is still running.";
      }

      if (state.analysis.status === "api_unavailable") {
        return "Current page has only a quick browser check because the local API is unavailable.";
      }
    }

    return "Current page has a quick browser-side check.";
  }

  function pageWarningElement() {
    let warning = document.getElementById("ss-page-warning");

    if (!warning) {
      warning = document.createElement("div");
      warning.id = "ss-page-warning";
      warning.setAttribute("role", "alert");
      document.documentElement.appendChild(warning);
    }

    return warning;
  }

  function hidePageWarning() {
    const warning = document.getElementById("ss-page-warning");

    if (warning) {
      warning.remove();
    }
  }

  function renderPageWarning() {
    const page = state.currentPage;
    const signature = pageWarningSignature(page);

    if (!RISKY_FORM_VERDICTS.has(page.verdict) || state.dismissedPageWarningSignature === signature) {
      hidePageWarning();
      return;
    }

    const warning = pageWarningElement();

    if (warning.dataset.signature === signature) {
      return;
    }

    warning.dataset.signature = signature;
    warning.dataset.verdict = page.verdict;
    warning.innerHTML = [
      "<div>",
      `<strong>SignalShield warning: ${escapeHtml(verdictLabel(page.verdict))} (${escapeHtml(page.score)}%)</strong>`,
      `<span>${escapeHtml(pageAnalysisLabel(page))}</span>`,
      `<span>Data entered on this page may be sent to scammers.</span>`,
      page.reasons.length ? `<small>${escapeHtml(page.reasons.slice(0, 2).join(" "))}</small>` : "",
      "</div>",
      '<div class="ss-page-warning-actions">',
      '<button type="button" data-ss-action="analysis">Full analysis</button>',
      '<button type="button" data-ss-action="dismiss">Dismiss</button>',
      "</div>"
    ].join("");
  }

  function applyCurrentPageResult(result, stage = "quick_js") {
    state.currentPage = normalizeAnalysisResult(result, window.location.href, stage);
    renderPageWarning();
  }

  function applyFormActionResult(url, result, stage = "quick_js") {
    state.formActions[url] = normalizeAnalysisResult(result, url, stage);
  }

  function applyQuickCurrentPageResult() {
    if (
      state.config.useDeepAnalysis
      && state.currentPage.url === window.location.href
      && state.currentPage.analysisStage === "python"
    ) {
      renderPageWarning();
      return;
    }

    applyCurrentPageResult(classifyHref(window.location.href), "quick_js");
  }

  function setAnalysisStatus(status, label, detail, deepChecked = 0, deepTotal = 0) {
    state.analysis = {
      status,
      label,
      detail,
      deepChecked,
      deepTotal,
      updatedAt: new Date().toLocaleTimeString()
    };
    renderPageWarning();
  }

  function linkAnalysisLabel(anchor) {
    if (anchor.dataset.ssAnalysisStage === "python") {
      return "Python deep analysis completed.";
    }

    if (state.config.useDeepAnalysis) {
      if (state.analysis.status === "pending") {
        return "Quick browser check. Python deep analysis is still running.";
      }

      if (state.analysis.status === "api_unavailable") {
        return "Quick browser check only. Local API is unavailable.";
      }

      if (state.analysis.status === "complete") {
        return "Quick browser check. Python did not return a final result for this link.";
      }
    }

    return "Quick browser check only.";
  }

  function analyzerUrl(targetUrl) {
    const base = state.config.analyzerBaseUrl || DEFAULT_CONFIG.analyzerBaseUrl;
    const url = new URL(base);
    url.searchParams.set("mode", "link");
    url.searchParams.set("url", targetUrl);
    url.searchParams.set("auto", "1");
    return url.href;
  }

  function apiUrl(path, baseUrl) {
    const base = baseUrl || state.config.apiBaseUrl || DEFAULT_CONFIG.apiBaseUrl;
    return new URL(path, base).href;
  }

  function apiBaseCandidates() {
    const configured = state.config.apiBaseUrl || DEFAULT_CONFIG.apiBaseUrl;
    const candidates = [configured];

    try {
      const url = new URL(configured);

      if (url.hostname === "localhost") {
        url.hostname = "127.0.0.1";
        candidates.push(url.href);
      } else if (url.hostname === "127.0.0.1") {
        url.hostname = "localhost";
        candidates.push(url.href);
      }
    } catch (_error) {
      candidates.push(DEFAULT_CONFIG.apiBaseUrl);
    }

    return Array.from(new Set(candidates));
  }

  async function postAnalyzeBatch(links) {
    const response = await backgroundApiPost("/analyze-batch", {
      page_url: window.location.href,
      links,
      source: "extension"
    });

    if (!response.payload.ok || !Array.isArray(response.payload.results)) {
      throw new Error(`${response.baseUrl} returned an invalid response.`);
    }

    return response;
  }

  function backgroundApiPost(path, body) {
    return new Promise((resolve, reject) => {
      if (!chrome.runtime || !chrome.runtime.sendMessage) {
        reject(new Error("Extension background worker is unavailable."));
        return;
      }

      chrome.runtime.sendMessage({
        type: "SS_API_POST",
        path,
        body,
        baseUrls: apiBaseCandidates()
      }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        if (!response || !response.ok) {
          reject(new Error((response && response.error) || "Local API request failed."));
          return;
        }

        resolve({
          baseUrl: response.baseUrl,
          payload: response.payload
        });
      });
    });
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
      "ssLocalListType",
      "ssVerdict",
      "ssAnalysisStage"
    ]) {
      delete anchor.dataset[key];
    }

    if ((anchor.getAttribute("aria-label") || "").startsWith("SignalShield:")) {
      anchor.removeAttribute("aria-label");
    }
  }

  function shouldDisplayVerdict(verdict) {
    if (verdict === "safe" && !state.config.highlightSafeLinks) {
      return false;
    }

    if (verdict === "not_found" && !state.config.highlightNotFoundLinks) {
      return false;
    }

    return true;
  }

  function applyAnalysisResult(anchor, result, stage = "quick_js") {
    const verdict = normalizeVerdict(result.verdict);
    const reasons = Array.isArray(result.reasons) ? result.reasons : [];
    const details = result.details || {};
    const localMatch = details.local_list_match || {};

    anchor.dataset.ssAnalysisStage = stage;
    anchor.dataset.ssRawVerdict = verdict;
    anchor.dataset.ssScore = String(result.score || 0);
    anchor.dataset.ssReasons = JSON.stringify(reasons);
    anchor.dataset.ssUrl = result.url || details.input_url || anchor.href;
    anchor.dataset.ssDomain = result.registeredDomain || details.domain || "";
    anchor.dataset.ssLocalListType = result.localListType || localMatch.list_type || "";

    if (!shouldDisplayVerdict(verdict)) {
      delete anchor.dataset.ssVerdict;
      return;
    }

    anchor.dataset.ssVerdict = verdict;
    anchor.setAttribute(
      "aria-label",
      `SignalShield: ${verdictLabel(verdict)}, risk ${result.score || 0} percent. ${reasons.join(" ")}`
    );

    if (anchor.dataset.ssListeners !== "1") {
      anchor.addEventListener("mouseenter", showTooltip);
      anchor.addEventListener("mousemove", moveTooltip);
      anchor.addEventListener("mouseleave", hideTooltip);
      anchor.addEventListener("click", handleClick, true);
      anchor.dataset.ssListeners = "1";
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
    applyAnalysisResult(anchor, result, "quick_js");
  }

  function resetStats() {
    state.stats = {
      scanned: 0,
      dangerous: 0,
      suspicious: 0,
      safe: 0,
      not_found: 0,
      trusted_by_user: 0,
      unknown: 0
    };
  }

  function scanPage() {
    resetStats();
    applyQuickCurrentPageResult();
    setAnalysisStatus(
      state.config.useDeepAnalysis ? "quick_js" : "disabled",
      state.config.useDeepAnalysis ? "Quick JS check" : "Python deep analysis off",
      state.config.useDeepAnalysis
        ? "The extension has finished the instant browser-side scan."
        : "Only the browser-side scan is enabled in the popup."
    );

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

    scheduleDeepAnalysis();
  }

  function recomputeStatsFromAnchors() {
    resetStats();

    for (const anchor of document.querySelectorAll("a[href]")) {
      if (shouldIgnoreLink(anchor) || anchor.dataset.ssAnalyzed !== "1") {
        continue;
      }

      state.stats.scanned += 1;
      const verdict = anchor.dataset.ssRawVerdict || anchor.dataset.ssVerdict || "safe";

      if (Object.prototype.hasOwnProperty.call(state.stats, verdict)) {
        state.stats[verdict] = (state.stats[verdict] || 0) + 1;
      }
    }
  }

  function anchorsByUrl() {
    const mapping = new Map();

    for (const anchor of document.querySelectorAll("a[href]")) {
      if (shouldIgnoreLink(anchor) || !anchor.dataset.ssUrl) {
        continue;
      }

      const links = mapping.get(anchor.dataset.ssUrl) || [];
      links.push(anchor);
      mapping.set(anchor.dataset.ssUrl, links);
    }

    return mapping;
  }

  function currentPageUrl() {
    return isHttpUrl(window.location.href) ? window.location.href : "";
  }

  function formActionUrl(form, submitter = null) {
    const rawAction = (
      submitter
      && typeof submitter.getAttribute === "function"
      && submitter.getAttribute("formaction")
    ) || form.getAttribute("action") || window.location.href;

    try {
      const url = new URL(rawAction, window.location.href);
      return isHttpUrl(url.href) ? url.href : "";
    } catch (_error) {
      return "";
    }
  }

  function formActionUrls() {
    const urls = new Set();

    for (const form of document.querySelectorAll("form")) {
      const actionUrl = formActionUrl(form);

      if (actionUrl) {
        urls.add(actionUrl);
      }

      for (const submitter of form.querySelectorAll("button[formaction], input[formaction]")) {
        const submitterActionUrl = formActionUrl(form, submitter);

        if (submitterActionUrl) {
          urls.add(submitterActionUrl);
        }
      }
    }

    return urls;
  }

  function deepAnalysisTargets() {
    const mapping = anchorsByUrl();
    const pageUrl = currentPageUrl();
    const actionUrls = formActionUrls();
    const links = [
      pageUrl,
      ...Array.from(mapping.keys()),
      ...Array.from(actionUrls)
    ].filter(isHttpUrl);

    return {
      mapping,
      pageUrl,
      actionUrls,
      links: Array.from(new Set(links))
    };
  }

  function scheduleDeepAnalysis() {
    if (!state.config.useDeepAnalysis) {
      setAnalysisStatus(
        "disabled",
        "Python deep analysis off",
        "Only the browser-side scan is enabled in the popup."
      );
      return;
    }

    window.clearTimeout(state.deepTimer);
    state.deepTimer = window.setTimeout(runDeepAnalysis, 400);
  }

  async function runDeepAnalysis() {
    const { mapping, pageUrl, actionUrls, links } = deepAnalysisTargets();
    const signature = `${window.location.href}|${links.join("|")}`;

    if (!links.length) {
      setAnalysisStatus(
        "quick_js",
        "Quick JS check",
        "No HTTP or HTTPS links were available for Python deep analysis."
      );
      return;
    }

    if (signature === state.lastDeepSignature) {
      return;
    }

    setAnalysisStatus(
      "pending",
      "Python analysis running",
      "The extension is sending page links to the local SignalShield API.",
      0,
      links.length
    );

    try {
      const { baseUrl, payload } = await postAnalyzeBatch(links);

      state.lastDeepSignature = signature;

      for (const item of payload.results) {
        const anchors = mapping.get(item.url) || [];

        if (item.url === pageUrl) {
          applyCurrentPageResult(item.result || {}, "python");
        }

        if (actionUrls.has(item.url)) {
          applyFormActionResult(item.url, item.result || {}, "python");
        }

        for (const anchor of anchors) {
          applyAnalysisResult(anchor, item.result || {}, "python");
        }
      }

      recomputeStatsFromAnchors();
      setAnalysisStatus(
        "complete",
        "Python analysis complete",
        `Colors and reasons were updated with the local Python analyzer at ${baseUrl}.`,
        payload.results.length,
        links.length
      );
    } catch (error) {
      setAnalysisStatus(
        "api_unavailable",
        "Local API unavailable",
        `${error.message} Only the quick browser-side scan is available.`,
        0,
        links.length
      );
      return;
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
    const analysisLabel = linkAnalysisLabel(anchor);
    const tooltip = tooltipElement();

    tooltip.innerHTML = [
      `<strong>SignalShield: ${escapeHtml(verdictLabel(verdict))} (${escapeHtml(score)}%)</strong>`,
      domain ? `<div>${escapeHtml(domain)}</div>` : "",
      `<div>${escapeHtml(analysisLabel)}</div>`,
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

  function shouldIgnoreForm(form) {
    return Boolean(form.closest(
      '[data-ss-ignore="1"], [data-signalshield-ignore="1"], .ss-ignore, .ss-no-extension'
    ));
  }

  function formActionAnalysis(form, submitter = null) {
    const actionUrl = formActionUrl(form, submitter);

    if (!actionUrl) {
      return null;
    }

    if (actionUrl === state.currentPage.url && state.currentPage.verdict !== "unknown") {
      return state.currentPage;
    }

    if (!state.formActions[actionUrl]) {
      applyFormActionResult(actionUrl, classifyHref(actionUrl), "quick_js");
    }

    return state.formActions[actionUrl];
  }

  function formWarningMessage(form, submitter = null) {
    const page = state.currentPage;
    const action = formActionAnalysis(form, submitter);
    const pageIsRisky = RISKY_FORM_VERDICTS.has(page.verdict);
    const actionIsRisky = action && RISKY_FORM_VERDICTS.has(action.verdict);

    if (!pageIsRisky && !actionIsRisky) {
      return "";
    }

    const lines = [
      "SignalShield warning",
      "",
      "Data typed into this form may be sent to scammers."
    ];

    if (pageIsRisky) {
      lines.push(`Current page: ${verdictLabel(page.verdict)} (${page.score}%).`);
      lines.push(`Page domain: ${page.registeredDomain || page.hostname || page.url}.`);
    }

    if (action) {
      lines.push(`Form destination: ${action.url}.`);

      if (actionIsRisky) {
        lines.push(`Destination verdict: ${verdictLabel(action.verdict)} (${action.score}%).`);
      }

      if (
        action.registeredDomain
        && page.registeredDomain
        && action.registeredDomain !== page.registeredDomain
      ) {
        lines.push(`The form submits outside the current domain: ${action.registeredDomain}.`);
      }
    }

    const reasons = [
      ...(pageIsRisky ? page.reasons : []),
      ...(actionIsRisky && action ? action.reasons : [])
    ].slice(0, 4);

    if (reasons.length) {
      lines.push("");
      lines.push("Reasons:");
      for (const reason of reasons) {
        lines.push(`- ${reason}`);
      }
    }

    lines.push("");
    lines.push("Press OK to submit anyway, or Cancel to stay on this page.");
    return lines.join("\n");
  }

  function submitterFromEvent(event) {
    if (event.submitter instanceof HTMLElement) {
      return event.submitter;
    }

    return null;
  }

  function handleFormSubmit(event) {
    const form = event.target;

    if (!(form instanceof HTMLFormElement) || shouldIgnoreForm(form)) {
      return;
    }

    const warning = formWarningMessage(form, submitterFromEvent(event));

    if (!warning) {
      return;
    }

    if (!window.confirm(warning)) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }

  function handlePageWarningClick(event) {
    if (!(event.target instanceof Element)) {
      return;
    }

    const button = event.target.closest("#ss-page-warning button");

    if (!button) {
      return;
    }

    const action = button.dataset.ssAction;

    if (action === "analysis") {
      window.open(analyzerUrl(state.currentPage.url), "_blank", "noopener,noreferrer");
    }

    if (action === "dismiss") {
      state.dismissedPageWarningSignature = pageWarningSignature();
      hidePageWarning();
    }
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  async function loadQuickRules() {
    let rules = normalizeQuickRules(EMPTY_QUICK_RULES);

    try {
      const bundledResponse = await fetch(chrome.runtime.getURL("rules.json"));

      if (bundledResponse.ok) {
        rules = normalizeQuickRules(await bundledResponse.json());
      }
    } catch (_error) {
      // Bundled rules.json is the offline fallback.
    }

    for (const baseUrl of apiBaseCandidates()) {
      try {
        const response = await fetch(apiUrl("/quick-rules", baseUrl), {
          method: "GET",
          cache: "no-store"
        });

        if (!response.ok) {
          continue;
        }

        const payload = await response.json();

        if (payload.ok && payload.rules) {
          rules = normalizeQuickRules(payload.rules);
          break;
        }
      } catch (_error) {
        continue;
      }
    }

    state.quickRules = rules;
    state.rulesLoaded = true;
  }

  function loadConfig(callback) {
    if (!chrome.storage || !chrome.storage.sync) {
      loadQuickRules().finally(callback);
      return;
    }

    chrome.storage.sync.get(DEFAULT_CONFIG, (config) => {
      state.config = { ...DEFAULT_CONFIG, ...config };
      loadQuickRules().finally(callback);
    });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === "SS_RESCAN") {
      state.lastDeepSignature = "";
      loadConfig(() => {
        scanPage();
        sendResponse({
          ok: true,
          stats: state.stats,
          analysis: state.analysis,
          page: state.currentPage
        });
      });
      return true;
    }

    if (message && message.type === "SS_GET_STATS") {
      sendResponse({
        ok: true,
        stats: state.stats,
        analysis: state.analysis,
        page: state.currentPage
      });
      return false;
    }

    return false;
  });

  loadConfig(() => {
    scanPage();
    document.addEventListener("submit", handleFormSubmit, true);
    document.addEventListener("click", handlePageWarningClick, true);
    const observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  });
}());
