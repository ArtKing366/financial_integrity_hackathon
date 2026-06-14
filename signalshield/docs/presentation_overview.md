# SignalShield PL: Presentation Notes

## One-line idea

SignalShield PL is a local anti-phishing assistant for Polish financial links, payment flows, SMS/chat/email text, and browser browsing sessions.

## Problem

Financial phishing often looks almost identical to a real banking, delivery, marketplace, or payment page.

Common attacker patterns:

- Similar domains: `go0gle.com`, `mbank-login24.pl`, `allegro-platnosc.pl`.
- Trusted brand names hidden in URL paths or subdomains.
- Payment and delivery pressure: BLIK, small parcel surcharge, invoice, account lock.
- Short links and unusual TLDs.
- Forms that submit sensitive data to a different or suspicious domain.
- Non-existing pages/domains used as disposable scam infrastructure.

## User Workflows

### 1. Single Link Analysis

The user pastes a URL into the Streamlit app.

Implemented in:

- `signalshield/app.py`
- `signalshield/core/verdict.py`
- `signalshield/core/*`

Output:

- Verdict: Safe, Suspicious, Dangerous, Trusted by user, or "This link does not appear to exist".
- Risk score.
- Human-readable reasons.
- Technical evidence in expandable sections.

### 2. Full Message Analysis

The user copies the full SMS, chat message, or email text and pastes it into the Streamlit app.

Implemented in:

- `signalshield/app.py`
- `signalshield/core/message_analyzer.py`
- `signalshield/core/market_manipulation.py`
- `signalshield/core/verdict.py`

The analyzer extracts links from the text, checks each link through the URL pipeline, and combines that with message-level social engineering signals.

Signals include:

- Urgency or account-lock pressure.
- Payment, delivery, invoice, BLIK, transfer language.
- Sensitive data requests: password, PIN, PESEL, SMS code, card data.
- Remote access requests: AnyDesk, TeamViewer, QuickSupport.
- Market manipulation language: unrealistic gains, pump-and-dump, signal groups.
- Visible email authenticity headers when pasted: SPF, DKIM, DMARC, From/Reply-To/Return-Path mismatch.

### 3. Browser Extension

The browser extension highlights links on the current page.

Implemented in:

- `signalshield/browser_extension/manifest.json`
- `signalshield/browser_extension/content.js`
- `signalshield/browser_extension/content.css`
- `signalshield/browser_extension/background.js`
- `signalshield/browser_extension/popup.html`
- `signalshield/browser_extension/popup.js`
- `signalshield/browser_extension/popup.css`

Main behavior:

- Quick JavaScript scan runs immediately in the page.
- Local Python deep analysis runs through the local API.
- `background.js` proxies localhost API calls from the extension context, avoiding page CORS issues.
- Hovering a highlighted link shows a short explanation.
- Clicking a highlighted link opens the full Streamlit report.
- Risky forms trigger a confirm warning before submission.
- The popup shows scan status and lets the user trust or block the current URL.

Highlighting:

- Dangerous: red.
- Suspicious: amber.
- Safe: subtle green outline only, so real buttons keep their original design.
- Link does not appear to exist: gray.
- Trusted by user: blue.

### 4. Local API

The browser extension talks to a local HTTP API.

Implemented in:

- `signalshield/api_server.py`
- `signalshield/scripts/run_api.cmd`
- `signalshield/scripts/run_api.ps1`

Endpoints:

- `GET /health`
- `POST /analyze-url`
- `POST /analyze-batch`
- `POST /analyze-message`
- `POST /analyze-messages`
- Auth-protected local list and analytics endpoints.

The API reuses a shared TTL cache so repeated checks of the same domain, DNS, HTML, and page existence data are faster.

### 5. Local Lists

Users can override decisions with local trusted and blocked entries.

Implemented in:

- `signalshield/core/local_db.py`
- `signalshield/app.py`
- `signalshield/browser_extension/popup.js`

Storage:

- SQLite database: local trusted and blocked entries.
- Browser extension fallback storage: `chrome.storage.sync` for current URL trust/block if the API database is unavailable.

The trusted list is exact-scope based:

- Exact URL.
- Exact hostname.

Subdomains are not trusted automatically.

## Analysis Pipeline Order

The main URL pipeline is in `signalshield/core/verdict.py`.

Order:

1. Normalize the URL and extract hostname and registered domain.
2. Check local user/system lists.
3. Check CERT Polska blacklist.
4. Detect subdomain spoofing.
5. Check page/domain existence.
6. Analyze DNS/MX infrastructure.
7. Check WHOIS domain age.
8. Check domain entropy.
9. Fetch page HTML once and share it across HTML-based modules.
10. Scan HTML for risky login/payment markers.
11. Run URL shape and path heuristics.
12. Run trusted-brand similarity.
13. Run page content rules.
14. Combine score and produce final verdict.

## Trusted Payment Gateway Handling

Payment transaction URLs often contain long tokens, random IDs, and status paths, for example:

`https://secure.tpay.com/Transaction/Status/show/?title=...&token=...`

The important distinction is the registered domain:

- `secure.tpay.com` has registered domain `tpay.com`.
- `tpay.com` is a trusted payment domain.
- Long transaction tokens are expected for payment status links.
- Therefore the system should not mark it as phishing just because the URL is long or contains a random token.

Fix implemented:

- Exact trusted domains are excluded from cross-brand similarity checks.
- `tpay.com` is not compared against `payu.com`.
- `go0gle.com` is still detected because it is not an exact trusted domain and remains similar to `google.com`.

Implemented in:

- `signalshield/core/similarity.py`
- `signalshield/tests/test_similarity.py`
- `signalshield/tests/test_cases.py`

## Key Algorithms and Modules

### Domain and URL Parsing

Files:

- `signalshield/core/domain_utils.py`
- `signalshield/core/url_heuristics.py`

Purpose:

- Normalize URLs.
- Extract hostnames and registered domains.
- Detect risky path keywords.
- Detect long or hyphen-heavy domains.

### Similarity / Typosquatting

File:

- `signalshield/core/similarity.py`

Purpose:

- Detect domains visually or textually close to trusted brands.
- Catch examples like `go0gle.com` and `mbank-login24.pl`.
- Avoid false positives for exact trusted domains like `tpay.com`.

### Subdomain Spoofing

File:

- `signalshield/core/subdomain_spoofing.py`

Purpose:

- Detect URLs where a brand appears in the subdomain but the registered domain is different.

Example:

`allegro.pl.evil-example.com`

The real registered domain is `evil-example.com`.

### Page Existence

File:

- `signalshield/core/page_existence.py`

Purpose:

- Separate existing pages, missing pages, missing domains, and temporarily unreachable pages.
- Missing links are shown to users as: "This link does not appear to exist".

### HTML and Page Rules

Files:

- `signalshield/core/html_crawler.py`
- `signalshield/core/page_rules.py`

Purpose:

- Look for password fields, hidden credential fields, payment/login words, suspicious forms, and Microsoft-login impersonation patterns.

### DNS and Infrastructure

Files:

- `signalshield/core/dns_infrastructure.py`
- `signalshield/core/whois_check.py`

Purpose:

- Check whether a domain resolves.
- Check MX infrastructure.
- Estimate domain age when WHOIS data is available.

### Message and Scam Context

Files:

- `signalshield/core/message_analyzer.py`
- `signalshield/core/market_manipulation.py`

Purpose:

- Extract links from copied text.
- Analyze all links.
- Add social engineering and financial manipulation context.

## Frontend Technologies

### Streamlit App

File:

- `signalshield/app.py`

Used for:

- Manual link analysis.
- Full copied message analysis.
- Technical details.
- Local list management.
- Analytics view.

### Browser Extension

Files:

- `signalshield/browser_extension/*`

Used for:

- Real-time link highlighting.
- Form submit warnings.
- Local API integration.
- Popup controls.

### Playwright Tests

Files:

- `signalshield/tests/signalshield.spec.js`
- `signalshield/playwright.config.js`

Used for:

- Testing extension link colors.
- Testing popup trust behavior.
- Testing risky form warning.

## Backend Technologies

- Python standard library HTTP server: local API.
- SQLite: local trusted/blocked lists and analytics.
- Streamlit: analyst UI.
- Requests/DNS/WHOIS-related modules: network evidence.
- JavaScript Manifest V3 extension: browser integration.
- Playwright: browser extension E2E tests.
- Pytest: Python unit and integration tests.

## Demo Script

1. Start the Streamlit app.
2. Start the API with `scripts/run_api.cmd`.
3. Load the browser extension.
4. Open a test page with safe, suspicious, dangerous, and missing links.
5. Show subtle SAFE outline that does not destroy button styling.
6. Hover a dangerous link and show reasons.
7. Click a link and open full analysis in Streamlit.
8. Paste a full SMS/email/chat text into the Full message tab.
9. Show extracted links, message context, and combined verdict.
10. Show local trusted/block list override.
11. Show the Tpay payment status example as a legitimate trusted payment gateway link.
12. Show `go0gle.com` as a still-detected typosquatting example.

## Final Test Status

Current verification commands:

- `python -m pytest -q`
- `node --check browser_extension/background.js`
- `node --check browser_extension/content.js`
- `node --check browser_extension/popup.js`
- `npx playwright test -c signalshield/playwright.config.js --project=chromium`

