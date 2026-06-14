# Testing SignalShield

This project has two test layers: automated checks for Python and JavaScript, and a manual browser-extension fixture for behavior that needs Chrome or Edge.

## One-time setup

Create a virtual environment and install dependencies:

```powershell
cd C:\Users\arina\financial_integrity_hackathon\signalshield
.\scripts\setup_dev.ps1
```

If Windows cannot find Python, install Python 3.11+ from `https://www.python.org/downloads/windows/`, enable the `py` launcher or `Add python.exe to PATH`, then run the setup script again.

## Automated checks

Run all local checks:

```powershell
.\scripts\run_checks.ps1
```

The script validates dependencies, compiles Python files, runs pytest, and checks extension JavaScript syntax when Node.js is available.

You can also run individual checks:

```powershell
.\.venv\Scripts\python.exe scripts\check_env.py
.\.venv\Scripts\python.exe -m pytest
node --check browser_extension\content.js
node --check browser_extension\popup.js
```

## Streamlit smoke test

Start the local API in one PowerShell window:

```powershell
.\scripts\run_api.ps1
```

From Command Prompt, use:

```bat
scripts\run_api.cmd
```

Start the app:

```powershell
.\.venv\Scripts\streamlit.exe run app.py
```

Open `http://localhost:8501` and test these flows:

- Single link mode with `https://allegro.pl`
- Single link mode with `https://mbank-login24.pl`
- Single link mode with `https://vasiapupkin.xyz/allegro.pl/pay/blik-secure`
- Full message mode with a message that contains several links
- Full message mode with `Kup teraz crypto 100x profit, ostatnia szansa, to the moon.` and no links
- `Open checked page` on SAFE, SUSPICIOUS, DANGEROUS, and NOT_FOUND results
- Lists page with an exact URL entry and an exact hostname entry
- Lists page shows the SQLite database path and active trusted/blacklist counts
- Analytics page after several Streamlit or extension checks
- Analytics page shows page-domain totals, local list totals, and last scan time

With the local API running, these endpoints should return JSON:

```text
http://127.0.0.1:8766/database/status
http://127.0.0.1:8766/list-entries
http://127.0.0.1:8766/list-entries?include_system=1
```

To force SQLite import of the built-in CERT Polska blacklist and trusted-brand list:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8766/database/sync `
  -ContentType "application/json" `
  -Body '{"force":true}'
```

Expected local-list behavior:

- Adding a URL or hostname to the trusted list deactivates a matching user blacklist entry.
- Adding a URL or hostname to the blacklist deactivates a matching user trusted-list entry.
- User entries take priority over managed system entries.

## Browser extension fixture

Keep the local API running if you want Python deep analysis and SQLite analytics from the extension.

Serve the local fixture page:

```powershell
.\scripts\serve_fixtures.ps1
```

Open `http://localhost:8765/extension_test_page.html`.

In Chrome or Edge:

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable Developer mode.
3. Load unpacked extension from `browser_extension`.
4. Reload the extension after every code change.
5. Reload the fixture page.

Expected behavior:

- Dangerous links are red.
- Suspicious links are amber.
- Safe links are green when safe highlighting is enabled.
- NOT_FOUND links are gray when NOT_FOUND highlighting is enabled.
- User-trusted links are blue after a matching trusted-list entry exists in SQLite and the local API is running.
- The popup shows a separate current-page verdict in addition to link counts.
- The popup can save the current URL to the trusted list or blacklist when the local API is running.
- After using either local-database button in the popup, the active page reloads and reflects the new list state.
- A suspicious or dangerous current page shows a SignalShield warning banner even if the page has no links.
- Submitting a form on a suspicious or dangerous current page shows a confirmation warning.
- Submitting a form whose `action` URL is suspicious or dangerous also shows a confirmation warning.
- Submitting with a button-level `formaction` to a suspicious or dangerous URL shows the same warning.
- Links with `data-ss-ignore="1"` are not highlighted, do not show SignalShield tooltips, and are not intercepted.
- Clicking a highlighted link opens the Streamlit analyzer when click interception is enabled.
- Clicking an ignored service link follows the original URL.
