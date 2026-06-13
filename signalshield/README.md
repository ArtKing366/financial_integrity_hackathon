# SignalShield PL

Link safety checker for Polish e-commerce and banking - helps users avoid phishing before payment.

## Architecture

```text
signalshield/
|-- app.py                 # Streamlit UI
|-- browser_extension/     # Chrome/Edge extension GUI
|-- core/
|   |-- blacklist.py       # Stage 1 - CERT Polska blacklist
|   |-- message_analyzer.py
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

Independent check modules feed a single `analyze_url()` API for links and `analyze_message()` for full SMS/email/chat text. The same APIs can power the Streamlit UI today and a browser extension tomorrow.

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
10. **message_analyzer** - extracts every link from a message, analyzes each URL, and adds social-engineering context such as urgency, BLIK/SMS code requests, remote access requests, and investment-scam language.

Verdict thresholds: score >= 50 -> DANGEROUS, score >= 20 -> SUSPICIOUS, else SAFE.

## Setup

```bash
.venv\Scripts\activate.bat
cd signalshield
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

For browser-extension deep analysis and SQLite analytics, run the local API in a second terminal:

```powershell
.\scripts\run_api.ps1
```

If you are using Command Prompt (`C:\...>` instead of `PS C:\...>`), run:

```bat
scripts\run_api.cmd
```

The Streamlit analyzer also supports direct links from the browser extension:

```text
http://localhost:8501/?mode=link&url=https%3A%2F%2Fexample.pl&auto=1
```

## Browser Extension

The `browser_extension/` folder contains a Manifest V3 Chrome/Edge extension. It scans the current page in real time, highlights links by risk color, shows hover explanations, and opens the Streamlit analyzer with the selected URL pre-filled. When the local API is running, the extension also upgrades quick JS results with Python analysis and records per-page analytics in SQLite. The popup lets users toggle safe-link and NOT_FOUND highlighting; saving settings reloads the active page.

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

## Browser Extension Details

The browser extension is a second GUI for the same project. It performs a fast local JavaScript pass on every link in the current page, colors links by risk, shows hover explanations, and opens the Streamlit analyzer with the selected URL pre-filled and auto-run.

See [browser_extension/README.md](browser_extension/README.md) for installation steps.
