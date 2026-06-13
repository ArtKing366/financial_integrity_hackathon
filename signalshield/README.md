# SignalShield PL

Link safety checker for Polish e-commerce and banking - helps users avoid phishing before payment.

## Architecture

```text
signalshield/
|-- app.py                 # Streamlit UI
|-- core/
|   |-- blacklist.py       # Stage 1 - CERT Polska blacklist
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

Independent check modules feed a single `analyze_url()` API. The same API can power the Streamlit UI today and a browser extension tomorrow.

## Pipeline

1. **blacklist** - O(1) lookup against the CERT Polska list, with a local cache and offline demo fallback.
2. **subdomain_spoofing** - catches URLs such as `mbank.pl.secure-pay.com`, where the trusted brand is only in the subdomain.
3. **page_existence** - separates missing domains/pages from reachable pages without overriding stronger phishing signals.
4. **dns_infrastructure** - checks whether untrusted domains resolve and have MX records configured.
5. **whois_check** - uses domain registration age when WHOIS data is available.
6. **html_crawler** - quickly fetches HTML and looks for password fields or Polish login/payment markers on untrusted domains.
7. **url_heuristics** - checks suspicious path keywords on untrusted domains and unusually long or hyphen-heavy domains.
8. **similarity** - detects typosquatting, brand substrings, and homograph attacks against trusted brands.
9. **page_rules** - optional content rules for Microsoft-like login pages and credential forms.

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

## Tests

```bash
pytest
```

## Demo URLs

| URL | Expected |
|-----|----------|
| `https://mbank.pl` | SAFE |
| `https://mbank-login24.pl` | DANGEROUS |
| `https://allegro.pl` | SAFE |
| `https://allegro-platnosc24.pl` | DANGEROUS |
| `https://vasiapupkin.xyz/allegro.pl/pay/blik-secure` | SUSPICIOUS |
| `https://inpost-paczka-za-pobraniem-24.pl` | DANGEROUS |

## Future: browser extension

The modular `core/` package exposes a stable verdict API. A Chrome/Firefox extension can call the same logic via a thin HTTP wrapper or bundled Python runtime.
