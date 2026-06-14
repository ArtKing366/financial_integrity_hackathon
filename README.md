# SignalShield PL

Link safety checker for Polish e-commerce and banking - helps users avoid phishing before payment.

## Architecture

```text
signalshield/
|-- api_server.py          # Local API for the browser extension and analytics
|-- app.py                 # Streamlit UI
|-- browser_extension/     # Chrome/Edge extension GUI
|-- core/
|   |-- analysis_cache.py  # Short-lived shared TTL cache for expensive checks
|   |-- blacklist.py       # Stage 1 - CERT Polska blacklist
|   |-- local_db.py        # SQLite trusted/blacklist entries and analytics
|   |-- message_analyzer.py
|   |-- market_manipulation.py
|   |-- subdomain_spoofing.py
|   |-- page_existence.py
|   |-- dns_infrastructure.py
|   |-- whois_check.py     # Domain age via WHOIS
|   |-- html_crawler.py    # Lightweight HTML scan
|   |-- url_heuristics.py  # Path keywords and domain ugliness rules
|   |-- similarity.py      # Typosquatting and brand mimicry
|   |-- page_rules.py      # Optional page content rules
|   `-- verdict.py         # Unified verdict API
|-- data/
|   |-- cert_blacklist.csv # Cached CERT domain list
|   `-- trusted_brands.json
|-- tests/
|   |-- test_cases.py
|   |-- test_url_heuristics.py
|   `-- test_similarity.py
|-- requirements.txt
`-- README.md
```

Independent check modules feed `analyze_url()` for links and `analyze_message()` for full SMS/email/chat text. The browser extension uses link and form analysis only; full-message analysis stays in the Streamlit UI and local API.

## Pipeline

1. **blacklist** - O(1) lookup against the CERT Polska list, with a local cache and offline demo fallback.
2. **subdomain_spoofing** - catches URLs such as `mbank.pl.secure-pay.com`, where the trusted brand is only in the subdomain.
3. **page_existence** - separates missing domains/pages from reachable pages without overriding stronger phishing signals.
4. **dns_infrastructure** - checks whether untrusted domains resolve and have MX records configured; missing MX is treated as a weak signal.
5. **whois_check** - uses domain registration age when WHOIS data is available.
6. **html_crawler** - quickly fetches HTML and looks for password fields or Polish login/payment markers on untrusted domains; these signals are capped to reduce false positives.
7. **url_heuristics** - checks suspicious path keywords on untrusted domains and unusually long or hyphen-heavy domains.
8. **similarity** - detects typosquatting, brand substrings, and homograph attacks against trusted brands.
9. **page_rules** - optional Microsoft-specific content rules for fake Microsoft login pages.
10. **market_manipulation** - detects pump-and-dump, insider-tip, unrealistic-return, and signal-group language even when a message has no links.
11. **message_analyzer** - extracts every link from a message, analyzes each URL, and adds social-engineering context such as urgency, BLIK/SMS code requests, remote access requests, market manipulation, and investment-scam language.

Expensive primitives are cached conservatively inside the local API process: DNS/MX for 10 minutes, WHOIS age for 30 minutes, page existence for 90 seconds, and HTML fetches for 60 seconds. Final verdicts, analytics writes, and user-managed trusted/blacklist entries are not cached.

Verdict thresholds: score >= 50 -> DANGEROUS, score >= 20 -> SUSPICIOUS, else SAFE.

## Setup

```bash
.venv\Scripts\activate.bat
cd signalshield
pip install -r requirements.txt
```

## Run

```bash
scripts\run_app.cmd
```

From PowerShell you can also run:

```powershell
.\scripts\run_app.ps1
```

For browser-extension deep analysis, SQLite analytics, and local trusted/blacklist management, run the local API in a second terminal:

```powershell
.\scripts\run_api.ps1
```

If you are using Command Prompt (`C:\...>` instead of `PS C:\...>`), run:

```bat
scripts\run_api.cmd
```

## Docker

From the repository root:

```bash
docker compose up --build
```

This starts:

- Streamlit app: `http://localhost:8501`
- Local API: `http://127.0.0.1:8766`

The same setup is also available through the explicit compose file name:

```bash
docker compose -f docker.yml up --build
```

Runtime state is stored in Docker volumes:

- `signalshield-runtime` for SQLite analytics and local lists.
- `signalshield-home` for the local API token.

For the browser extension popup, keep the local API URL set to:

```text
http://127.0.0.1:8766/
```

The Streamlit analyzer also supports direct links from the browser extension:

```text
http://localhost:8501/?mode=link&url=https%3A%2F%2Fexample.pl&auto=1
```

## Browser Extension

The local API exposes `GET /database/status`, `GET /list-entries`, `GET /list-entries?include_system=1`, `POST /list-entry`, `POST /database/sync`, and `DELETE /list-entry?id=...` for SQLite diagnostics and list management. Trusted and blacklisted entries are matched only by exact URL or exact hostname. User entries are mutually exclusive for the same target: trusting a URL disables the matching user blacklist entry, and blocking it disables the matching user trusted entry. Built-in CERT Polska blacklist and trusted-brand domains are synced into the same SQLite table as managed system entries, while user decisions keep priority over system entries.

The `browser_extension/` folder contains a Manifest V3 Chrome/Edge extension. It scans the current page in real time, checks the page URL itself, highlights links by risk color, shows hover explanations, warns before risky form submissions, and opens the Streamlit analyzer with the selected URL pre-filled. When the local API is running, the extension also upgrades quick JS results with Python analysis and records per-page analytics in SQLite. The popup lets users toggle safe-link and NOT_FOUND highlighting, save the current URL to the trusted list or blacklist, and saving settings reloads the active page.

Install it through `chrome://extensions` -> Developer mode -> Load unpacked -> `signalshield/browser_extension`.

## Tests

```bash
pytest
```

For full local setup, extension fixture checks, and smoke-test steps, see [docs/testing.md](docs/testing.md).

## Demo URLs

| URL | Expected |
|-----|----------|
| `https://mbank.pl` | SAFE |
| `https://mbank-login24.pl` | DANGEROUS |
| `https://allegro.pl` | SAFE |
| `https://allegro-platnosc24.pl` | DANGEROUS |
| `https://vasiapupkin.xyz/allegro.pl/pay/blik-secure` | SUSPICIOUS |
| `https://inpost-paczka-za-pobraniem-24.pl` | DANGEROUS |

Message mode also supports full texts such as:

```text
Pilne: dopłata do paczki 1.99 zł. Zaloguj się: vasiapupkin.xyz/allegro.pl/pay/blik-secure
```

Market-manipulation checks also work without links:

```text
Kup teraz crypto 100x profit, ostatnia szansa, to the moon.
```

## Browser Extension Details

The browser extension is a second GUI for the same project. It performs a fast local JavaScript pass on the current page URL and every link in the page, colors links by risk, shows hover explanations, warns before risky form submissions, and opens the Streamlit analyzer with the selected URL pre-filled and auto-run.

See [browser_extension/README.md](browser_extension/README.md) for installation steps.
