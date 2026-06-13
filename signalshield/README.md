# SignalShield PL

Link safety checker for Polish e-commerce and banking — helps users avoid phishing before payment.

## Architecture

```
signalshield/
├── app.py                 # Streamlit UI
├── core/
│   ├── blacklist.py       # Stage 1 — CERT Polska blacklist
│   ├── whois_check.py     # Stage 2 — domain age via WHOIS
│   ├── similarity.py      # Stage 3 — typosquatting & brand mimicry
│   └── verdict.py         # Unified verdict API
├── data/
│   ├── cert_blacklist.csv # Cached CERT domain list
│   └── trusted_brands.json
├── tests/
│   └── test_cases.py
├── requirements.txt
└── README.md
```

Three independent check modules feed a single `analyze_url()` API. The same API can power the Streamlit UI today and a browser extension tomorrow.

## Pipeline

1. **blacklist** — O(1) lookup against CERT Polska list (cached locally, fallback list for offline demo)
2. **whois_check** — domain registration age (high risk if < 14 days, medium if < 90 days)
3. **similarity** — Levenshtein distance + brand substring + homograph detection against trusted brands

Verdict thresholds: score ≥ 50 → DANGEROUS, ≥ 20 → SUSPICIOUS, else SAFE.

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

## Future: browser extension

The modular `core/` package exposes a stable verdict API. A Chrome/Firefox extension can call the same logic via a thin HTTP wrapper or bundled Python runtime.
