const DEFAULT_CONFIG = {
  analyzerBaseUrl: "http://localhost:8501/",
  apiBaseUrl: "http://127.0.0.1:8766/",
  useDeepAnalysis: true,
  openAnalyzerOnClick: true,
  highlightSafeLinks: true,
  highlightNotFoundLinks: true
};

const elements = {
  analyzerBaseUrl: document.getElementById("analyzerBaseUrl"),
  apiBaseUrl: document.getElementById("apiBaseUrl"),
  useDeepAnalysis: document.getElementById("useDeepAnalysis"),
  openAnalyzerOnClick: document.getElementById("openAnalyzerOnClick"),
  highlightSafeLinks: document.getElementById("highlightSafeLinks"),
  highlightNotFoundLinks: document.getElementById("highlightNotFoundLinks"),
  save: document.getElementById("save"),
  rescan: document.getElementById("rescan"),
  trustCurrentUrl: document.getElementById("trustCurrentUrl"),
  blockCurrentUrl: document.getElementById("blockCurrentUrl"),
  status: document.getElementById("status"),
  scanned: document.getElementById("scanned"),
  dangerous: document.getElementById("dangerous"),
  suspicious: document.getElementById("suspicious"),
  safe: document.getElementById("safe"),
  notFound: document.getElementById("notFound"),
  trusted: document.getElementById("trusted"),
  analysisState: document.getElementById("analysisState"),
  analysisLabel: document.getElementById("analysisLabel"),
  analysisDetail: document.getElementById("analysisDetail"),
  currentPageState: document.getElementById("currentPageState"),
  pageLabel: document.getElementById("pageLabel"),
  pageDetail: document.getElementById("pageDetail"),
  currentPageUrl: document.getElementById("currentPageUrl"),
  databaseButtons: document.querySelector(".database-actions div")
};

let statsTimer = null;
let latestPage = null;

function setStatus(message) {
  elements.status.textContent = message;
}

function normalizeBaseUrl(value, fallback) {
  const trimmed = value.trim() || fallback;
  const url = new URL(trimmed);
  return url.href;
}

function activeTab(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    callback(tabs[0]);
  });
}

function isHttpUrl(value) {
  return /^https?:\/\//i.test(value || "");
}

function currentPageListState(page) {
  const safePage = page || latestPage || {};

  if (safePage.localListType === "trusted" || safePage.verdict === "trusted_by_user") {
    return "trusted";
  }

  if (safePage.localListType === "blacklist") {
    return "blacklist";
  }

  return "available";
}

function setDatabaseButtonsEnabled(enabled) {
  const page = latestPage || {};
  const displayUrl = page.url || "";
  const hasHttpUrl = isHttpUrl(displayUrl);
  const listState = hasHttpUrl ? currentPageListState(page) : "disabled";

  elements.databaseButtons.dataset.state = listState;
  elements.trustCurrentUrl.disabled = !enabled || !hasHttpUrl || listState === "trusted";
  elements.blockCurrentUrl.disabled = !enabled || !hasHttpUrl || listState === "blacklist";
}

function updateCurrentPageUrl(value) {
  const displayUrl = value || "";
  elements.currentPageUrl.textContent = displayUrl || "No current page URL detected.";
  setDatabaseButtonsEnabled(true);
}

function updateStats(stats) {
  const safeStats = stats || {};
  elements.scanned.textContent = safeStats.scanned || 0;
  elements.dangerous.textContent = safeStats.dangerous || 0;
  elements.suspicious.textContent = safeStats.suspicious || 0;
  elements.safe.textContent = safeStats.safe || 0;
  elements.notFound.textContent = safeStats.not_found || 0;
  elements.trusted.textContent = safeStats.trusted_by_user || 0;
}

function updateAnalysisState(analysis) {
  const safeAnalysis = analysis || {};
  const status = safeAnalysis.status || "quick_js";
  const label = safeAnalysis.label || "Quick JS check";
  const detail = safeAnalysis.detail || "The current page has only browser-side scan data.";
  const checked = safeAnalysis.deepChecked || 0;
  const total = safeAnalysis.deepTotal || 0;
  const suffix = total ? ` (${checked}/${total})` : "";

  elements.analysisState.dataset.status = status;
  elements.analysisLabel.textContent = `${label}${suffix}`;
  elements.analysisDetail.textContent = detail;
}

function updateCurrentPage(page) {
  const safePage = page || {};
  latestPage = safePage;
  const verdict = safePage.verdict || "unknown";
  const score = safePage.score || 0;
  const stage = safePage.analysisStage === "python" ? "Python" : "Quick JS";
  const domain = safePage.registeredDomain || safePage.hostname || "current page";
  const reasons = Array.isArray(safePage.reasons) ? safePage.reasons : [];

  elements.currentPageState.dataset.verdict = verdict;
  elements.pageLabel.textContent = `Current page: ${verdict.toUpperCase()} (${score}%)`;
  elements.pageDetail.textContent = `${stage} analysis for ${domain}. ${reasons.slice(0, 2).join(" ")}`;
  updateCurrentPageUrl(safePage.url || "");
}

function applyLocalListState(url, listType) {
  const trusted = listType === "trusted";
  updateCurrentPage({
    ...(latestPage || {}),
    verdict: trusted ? "trusted_by_user" : "dangerous",
    score: trusted ? 0 : 100,
    reasons: [
      trusted
        ? "Current URL is saved in your trusted list."
        : "Current URL is saved in your blacklist."
    ],
    url,
    localListType: listType,
    analysisStage: "python"
  });
}

function requestStats() {
  activeTab((tab) => {
    if (!tab || !tab.id) {
      return;
    }

    chrome.tabs.sendMessage(tab.id, { type: "SS_GET_STATS" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        setStatus("Open a normal web page to scan links.");
        return;
      }

      updateStats(response.stats);
      updateAnalysisState(response.analysis);
      updateCurrentPage(response.page);
    });
  });
}

function loadConfig() {
  chrome.storage.sync.get(DEFAULT_CONFIG, (config) => {
    elements.analyzerBaseUrl.value = config.analyzerBaseUrl;
    elements.apiBaseUrl.value = config.apiBaseUrl;
    elements.useDeepAnalysis.checked = Boolean(config.useDeepAnalysis);
    elements.openAnalyzerOnClick.checked = Boolean(config.openAnalyzerOnClick);
    elements.highlightSafeLinks.checked = Boolean(config.highlightSafeLinks);
    elements.highlightNotFoundLinks.checked = Boolean(config.highlightNotFoundLinks);
    requestStats();
  });
}

function apiUrl(path, baseUrl) {
  return new URL(path, baseUrl).href;
}

function apiBaseCandidates(baseUrl) {
  const candidates = [baseUrl];

  try {
    const url = new URL(baseUrl);

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

async function postListEntry(entry, apiBaseUrl) {
  let lastError = "Local API request failed.";

  for (const baseUrl of apiBaseCandidates(apiBaseUrl)) {
    try {
      const response = await fetch(apiUrl("/list-entry", baseUrl), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry)
      });

      if (!response.ok) {
        lastError = `${baseUrl} returned HTTP ${response.status}.`;
        continue;
      }

      const payload = await response.json();

      if (!payload.ok) {
        lastError = payload.error || `${baseUrl} returned an invalid response.`;
        continue;
      }

      return payload.entry;
    } catch (_error) {
      lastError = `${baseUrl} is not reachable from the extension.`;
    }
  }

  throw new Error(lastError);
}

function saveConfig(callback) {
  let analyzerBaseUrl;
  let apiBaseUrl;

  try {
    analyzerBaseUrl = normalizeBaseUrl(
      elements.analyzerBaseUrl.value,
      DEFAULT_CONFIG.analyzerBaseUrl
    );
    apiBaseUrl = normalizeBaseUrl(
      elements.apiBaseUrl.value,
      DEFAULT_CONFIG.apiBaseUrl
    );
  } catch (_error) {
    setStatus("Analyzer or API URL is invalid.");
    return;
  }

  const config = {
    analyzerBaseUrl,
    apiBaseUrl,
    useDeepAnalysis: elements.useDeepAnalysis.checked,
    openAnalyzerOnClick: elements.openAnalyzerOnClick.checked,
    highlightSafeLinks: elements.highlightSafeLinks.checked,
    highlightNotFoundLinks: elements.highlightNotFoundLinks.checked
  };

  chrome.storage.sync.set(config, () => {
    setStatus("Saved.");
    if (callback) {
      callback();
    }
  });
}

function reloadActivePage() {
  activeTab((tab) => {
    if (!tab || !tab.id) {
      setStatus("Saved. No active tab to reload.");
      return;
    }

    chrome.tabs.reload(tab.id, () => {
      setStatus("Saved. Page reloading.");
    });
  });
}

function currentPageUrl(callback) {
  if (latestPage && isHttpUrl(latestPage.url)) {
    callback(latestPage.url);
    return;
  }

  activeTab((tab) => {
    callback(tab && isHttpUrl(tab.url) ? tab.url : "");
  });
}

function addCurrentPageToList(listType) {
  currentPageUrl(async (url) => {
    if (!url) {
      setStatus("Open a normal http or https page first.");
      return;
    }

    let apiBaseUrl;

    try {
      apiBaseUrl = normalizeBaseUrl(
        elements.apiBaseUrl.value,
        DEFAULT_CONFIG.apiBaseUrl
      );
    } catch (_error) {
      setStatus("API URL is invalid.");
      return;
    }

    setDatabaseButtonsEnabled(false);
    setStatus("Saving current URL to the local database...");

    try {
      const label = listType === "trusted" ? "Trusted from extension" : "Blocked from extension";
      await postListEntry({
        list_type: listType,
        scope: "url",
        value: url,
        label,
        note: "Added from the browser extension.",
        expires_in: "Never"
      }, apiBaseUrl);
      applyLocalListState(url, listType);
      setStatus("Saved to local database. Page reloading.");
      reloadActivePage();
    } catch (error) {
      setStatus(error.message || "Cannot save to local database.");
      setDatabaseButtonsEnabled(true);
    }
  });
}

function rescanPage() {
  activeTab((tab) => {
    if (!tab || !tab.id) {
      setStatus("No active tab.");
      return;
    }

    chrome.tabs.sendMessage(tab.id, { type: "SS_RESCAN" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        setStatus("Cannot scan this page.");
        return;
      }

      updateStats(response.stats);
      updateAnalysisState(response.analysis);
      updateCurrentPage(response.page);
      setStatus("Page rescanned.");
    });
  });
}

elements.save.addEventListener("click", () => saveConfig(reloadActivePage));
elements.rescan.addEventListener("click", () => saveConfig(rescanPage));
elements.trustCurrentUrl.addEventListener("click", () => addCurrentPageToList("trusted"));
elements.blockCurrentUrl.addEventListener("click", () => addCurrentPageToList("blacklist"));
document.addEventListener("DOMContentLoaded", () => {
  setDatabaseButtonsEnabled(false);
  loadConfig();
  statsTimer = window.setInterval(requestStats, 1200);
});
window.addEventListener("unload", () => {
  window.clearInterval(statsTimer);
});
