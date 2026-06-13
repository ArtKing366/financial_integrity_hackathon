# SignalShield Browser Extension

Manifest V3 extension that highlights links on the current page with a quick local JavaScript risk pass.

## What It Does

- Scans every `<a href>` on the current page.
- Highlights links:
  - red: dangerous
  - amber: suspicious
  - green: safe
  - gray: not found, unknown, or unsupported
- Shows a hover tooltip with the reasons.
- Opens the Streamlit SignalShield analyzer when a highlighted link is clicked.

The extension uses lightweight browser-side heuristics for real-time feedback. The full Python analysis still happens in the Streamlit app.

## Local Setup

1. Start the Streamlit app:

   ```bash
   cd signalshield
   streamlit run app.py
   ```

2. Open Chrome or Edge and go to `chrome://extensions`.
3. Enable Developer mode.
4. Click "Load unpacked".
5. Select this folder:

   ```text
   signalshield/browser_extension
   ```

6. Open the extension popup and keep the analyzer URL as:

   ```text
   http://localhost:8501/
   ```

## Notes

- The extension does not call the Python engine for every link, so it stays fast and does not need a backend API.
- Click-through opens `http://localhost:8501/?mode=link&url=...&auto=1`, which pre-fills and runs the existing full analyzer.
- Safe-link highlighting, NOT_FOUND highlighting, and click interception can be changed in the popup.
- The Save button stores settings and reloads the active page so the new highlighting rules apply immediately.
