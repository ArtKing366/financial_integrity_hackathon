(function () {
  "use strict";

  const DEFAULT_API_BASE_URL = "http://127.0.0.1:8766/";
  const ALLOWED_POST_PATHS = new Set([
    "/analyze-batch"
  ]);

  function apiUrl(path, baseUrl) {
    return new URL(path, baseUrl || DEFAULT_API_BASE_URL).href;
  }

  async function postJson(path, body, baseUrls) {
    if (!ALLOWED_POST_PATHS.has(path)) {
      throw new Error("Unsupported SignalShield API path.");
    }

    let lastError = "Local API request failed.";
    const candidates = Array.from(new Set(baseUrls && baseUrls.length ? baseUrls : [DEFAULT_API_BASE_URL]));

    for (const baseUrl of candidates) {
      try {
        const response = await fetch(apiUrl(path, baseUrl), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body || {})
        });

        if (!response.ok) {
          lastError = `${baseUrl} returned HTTP ${response.status}.`;
          continue;
        }

        const payload = await response.json();
        return { baseUrl, payload };
      } catch (_error) {
        lastError = `${baseUrl} is not reachable from the extension background worker.`;
      }
    }

    throw new Error(lastError);
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || message.type !== "SS_API_POST") {
      return false;
    }

    postJson(message.path, message.body, message.baseUrls)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

    return true;
  });
}());
