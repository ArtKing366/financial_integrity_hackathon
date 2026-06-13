# SignalShield Browser Extension

Manifest V3 extension that highlights links on the current page with a quick local JavaScript risk pass.

## What It Does

- Scans every `<a href>` on the current page.
- Highlights links:
  - red: dangerous
  - amber: suspicious
  - green: safe
  - gray: not found, unknown, or unsupported
  - blue: trusted by user
- Shows a hover tooltip with the reasons.
- Opens the Streamlit SignalShield analyzer when a highlighted link is clicked.
- Sends links to the local SignalShield API for Python deep analysis when enabled.
- Shows whether the current page is only quick JS checked, waiting for Python, Python-complete, or API-unavailable.

The extension uses lightweight browser-side heuristics for real-time feedback. The full Python analysis still happens in the Streamlit app.

## Local Setup

1. Start the Streamlit app:

   ```bash
   cd signalshield
   streamlit run app.py
   ```

2. Start the local API in a second terminal:

   ```powershell
   .\scripts\run_api.ps1
   ```

3. Open Chrome or Edge and go to `chrome://extensions`.
4. Enable Developer mode.
5. Click "Load unpacked".
6. Select this folder:

   ```text
   signalshield/browser_extension
   ```

7. Open the extension popup and keep the analyzer URL as:

   ```text
   http://localhost:8501/
   ```

   Keep the local API URL as:

   ```text
   http://127.0.0.1:8766/
   ```

## Notes

- The extension highlights links immediately with browser-side heuristics, then upgrades results through the local API when it is running.
- Click-through opens `http://localhost:8501/?mode=link&url=...&auto=1`, which pre-fills and runs the existing full analyzer.
- Safe-link highlighting, NOT_FOUND highlighting, and click interception can be changed in the popup.
- The Save button stores settings and reloads the active page so the new highlighting rules apply immediately.
- If the local API is not running, the extension falls back to the instant browser-side scan.
