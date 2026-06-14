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
  pageDetail: document.getElementById("pageDetail")
};

let statsTimer = null;

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
  const verdict = safePage.verdict || "unknown";
  const score = safePage.score || 0;
  const stage = safePage.analysisStage === "python" ? "Python" : "Quick JS";
  const domain = safePage.registeredDomain || safePage.hostname || "current page";
  const reasons = Array.isArray(safePage.reasons) ? safePage.reasons : [];

  elements.currentPageState.dataset.verdict = verdict;
  elements.pageLabel.textContent = `Current page: ${verdict.toUpperCase()} (${score}%)`;
  elements.pageDetail.textContent = `${stage} analysis for ${domain}. ${reasons.slice(0, 2).join(" ")}`;
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
document.addEventListener("DOMContentLoaded", () => {
  loadConfig();
  statsTimer = window.setInterval(requestStats, 1200);
});
window.addEventListener("unload", () => {
  window.clearInterval(statsTimer);
});
