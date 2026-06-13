const DEFAULT_CONFIG = {
  analyzerBaseUrl: "http://localhost:8501/",
  openAnalyzerOnClick: true,
  highlightSafeLinks: true,
  highlightNotFoundLinks: true
};

const elements = {
  analyzerBaseUrl: document.getElementById("analyzerBaseUrl"),
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
  notFound: document.getElementById("notFound")
};

function setStatus(message) {
  elements.status.textContent = message;
}

function normalizeBaseUrl(value) {
  const trimmed = value.trim() || DEFAULT_CONFIG.analyzerBaseUrl;
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
    });
  });
}

function loadConfig() {
  chrome.storage.sync.get(DEFAULT_CONFIG, (config) => {
    elements.analyzerBaseUrl.value = config.analyzerBaseUrl;
    elements.openAnalyzerOnClick.checked = Boolean(config.openAnalyzerOnClick);
    elements.highlightSafeLinks.checked = Boolean(config.highlightSafeLinks);
    elements.highlightNotFoundLinks.checked = Boolean(config.highlightNotFoundLinks);
    requestStats();
  });
}

function saveConfig(callback) {
  let analyzerBaseUrl;

  try {
    analyzerBaseUrl = normalizeBaseUrl(elements.analyzerBaseUrl.value);
  } catch (_error) {
    setStatus("Analyzer URL is invalid.");
    return;
  }

  const config = {
    analyzerBaseUrl,
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
      setStatus("Page rescanned.");
    });
  });
}

elements.save.addEventListener("click", () => saveConfig(reloadActivePage));
elements.rescan.addEventListener("click", () => saveConfig(rescanPage));
document.addEventListener("DOMContentLoaded", loadConfig);
