import re


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Design principles:
# 1. Use \b word boundaries to avoid partial-word matches.
# 2. Context-sensitive phrases: financial words required around ambiguous terms
#    (moon, rocket, coin, entry, stock, exchange, broker, telegram).
# 3. Single weak signals (≤10 pts) stay below SUSPICIOUS (≥35) on their own.
# 4. Combination bonuses fire when multiple independent signals align.
# ---------------------------------------------------------------------------

RULES = [
    {
        "id": "guaranteed_profit",
        "weight": 30,
        "pattern": (
            r"(gwarantowan[yae]?\s+zysk"
            r"|guaranteed\s+(profit|return|gain|income)"
            r"|pewny\s+zysk"
            r"|bez\s+ryzyka"
            r"|risk[- ]?free\s+(return|profit|investment|trade)"
            r"|100\s*%\s*(pewn|sure|certain|guaranteed)"
            r"|без\s+риска"
            r"|гарантированн\w+\s+(доход|прибыл))"
        ),
        "reason": "Message promises guaranteed or risk-free profit.",
    },
    {
        "id": "unrealistic_return",
        "weight": 30,
        # "to the moon" only when financial context appears within ±40 chars.
        # Bare "moon" in astronomy context won't trigger this.
        # x\d+ only when followed/preceded by financial words OR is explicitly
        # one of the well-known multiplier shorthands used in crypto (10x, 100x, 1000x).
        "pattern": (
            r"(\b\d{2,4}\s?%\s*(zwrot|zysk|profit|return|gain)"
            r"|\b\d+\s*x\s+(profit|zysk|zwrot|return|gain|more|wi[eę]cej)"
            r"|\b(10|20|50|100|500|1000)x\b"
            r"|(crypto|coin|token|btc|eth|invest|profit|zysk|gain|krypto).{0,40}to\s+the\s+moon"
            r"|to\s+the\s+moon.{0,40}(crypto|coin|token|btc|eth|invest|profit|zysk|gain|krypto)"
            r"|\bmoonshot\b)"
        ),
        "reason": "Message promises unrealistic returns.",
    },
    {
        "id": "time_pressure",
        "weight": 20,
        # "tylko dziś" / "buy now" only in financial context within the same phrase.
        "pattern": (
            r"(kup\s+teraz\s+.{0,30}(crypto|krypto|coin|akcj|token|btc|eth|invest)"
            r"|buy\s+now\s+.{0,30}(crypto|coin|token|invest|profit)"
            r"|teraz\s+albo\s+nigdy"
            r"|last\s+chance\s+.{0,30}(invest|profit|trade|crypto|coin)"
            r"|ostatnia\s+szansa\s+.{0,30}(invest|krypto|zysk|zakup)"
            r"|tylko\s+dzi[sś]\s+.{0,60}(krypto|bitcoin|token|invest|zysk|profit)"
            r"|w\s+ci[aą]gu\s+\d+\s*(minut|godzin|h)\s+.{0,30}(invest|krypto|zysk)"
            r"|natychmiast\s+.{0,30}(kup|invest|buy|wejd)"
            r"|срочно\s+.{0,30}(купи|инвест)"
            r"|только\s+сегодня\s+.{0,30}(купи|инвест|крипт))"
        ),
        "reason": "Message uses time pressure to force quick investment decision.",
    },
    {
        "id": "investment_call_to_action",
        "weight": 20,
        "pattern": (
            r"(kupuj\s+(teraz|natychmiast|szybko)"
            r"|kup\s+teraz"
            r"|wchodzimy\s+(w|do|na)"
            r"|wej[sś]cie\s+na\s+(rynek|pozycj)"
            r"|buy\s+signal"
            r"|sygnał\s+kupna"
            r"|otwieramy\s+pozycj"
            r"|dołącz\s+teraz\s+.{0,30}(grup|invest|zysk|sygnał)"
            r"|invest\s+now"
            r"|zainwestuj\s+(teraz|natychmiast|szybko))"
        ),
        "reason": "Message contains direct investment call to action.",
    },
    {
        "id": "inside_information",
        "weight": 40,
        "pattern": (
            r"(inside\s+info"
            r"|\binsider\s+(tip|info|trading|deal)"
            r"|tajna\s+informacja"
            r"|poufna\s+informacja"
            r"|niepubliczna\s+informacja"
            r"|wiemy\s+co[sś]\s+.{0,30}(rynek|akcj|krypto|stock)"
            r"|инсайд"
            r"|секретная\s+информация)"
        ),
        "reason": "Message claims to have secret or inside information.",
    },
    {
        "id": "pump_language",
        "weight": 35,
        # "moon" and "rocket" require surrounding financial context.
        # "to the moon" (multi-word) requires financial context (handled in unrealistic_return).
        # Standalone pump-specific slang (pumpujemy, pompka) is clear enough.
        "pattern": (
            r"(pumpujemy"
            r"|pompujemy"
            r"|pompka\s+.{0,20}(kurs|akcj|crypto|coin|token)"
            r"|wystrzeli\s+(kurs|cena|bitcoin|eth|token|akcj)"
            r"|rakieta\s+.{0,20}(kurs|zysk|invest|krypto)"
            r"|rocket\s+.{0,20}(profit|gain|crypto|coin|price|kurs)"
            r"|(crypto|coin|token|btc|eth|akcj)\s+.{0,15}moon\b"
            r"|\bmoon\b\s+.{0,15}(crypto|coin|token|btc|eth|profit|gain)"
            r"|爆|памп|ракета)"
        ),
        "reason": "Message uses pump-style market manipulation language.",
    },
    {
        "id": "signal_group",
        "weight": 35,
        # Telegram/Discord/WhatsApp alone are general-purpose apps.
        # Only score when combined with investment/VIP/signal wording.
        "pattern": (
            r"((telegram|discord|whatsapp)\s+.{0,30}(vip|sygnał|signal|invest|pump|zysk|profit|group|gruppe|grupa))"
            r"|(vip\s+group"
            r"|grupa\s+vip"
            r"|signal\s+group"
            r"|grupa\s+sygnałowa"
            r"|zamknięta\s+grupa\s+.{0,20}(invest|krypto|trading|zysk)"
            r"|private\s+(signal|investment|crypto|trading)\s+group)"
        ),
        "reason": "Message promotes a private signal or investment group.",
    },
    {
        "id": "low_liquidity_asset",
        "weight": 15,
        "pattern": (
            r"(low\s+cap\s+.{0,20}(coin|token|crypto|gem)"
            r"|niska\s+kapitalizacja"
            r"|penny\s+stock"
            r"|meme\s+coin"
            r"|shitcoin"
            r"|mała\s+spółka\s+.{0,20}(pump|wzrost|invest|kup)"
            r"|small\s+cap\s+.{0,20}(gem|crypto|coin|pump|buy))"
        ),
        "reason": "Message refers to low-liquidity or easily manipulated assets.",
    },
    {
        "id": "hype_language",
        "weight": 15,
        # Speculative promotion language used to build irrational excitement
        # around an asset without making an explicit profit promise.
        "pattern": (
            r"(next\s+(gem|moonshot|bitcoin|btc|eth|100x|1000x)"
            r"|hidden\s+gem"
            r"|sleeping\s+giant"
            r"|undervalued\s+(coin|token|gem|project)"
            r"|the\s+next\s+(bitcoin|btc|ethereum|eth|solana)\b"
            r"|ukryty\s+klejnot"
            r"|niedowarto[sś]ciowany\s+(token|coin|projekt)"
            r"|następny\s+bitcoin)"
        ),
        "reason": "Message uses speculative hype language to promote an asset.",
    },
    {
        "id": "trading_context",
        "weight": 10,
        # Tightly scoped: only clearly financial terms, not everyday words.
        "pattern": (
            r"(\bakcje\b"
            r"|\bcrypto(currency)?\b"
            r"|\bkrypto(waluta)?\b"
            r"|\btoken\b"
            r"|\b(meme|shit|alt)coin\b"
            r"|\bcrypto\s+coin"
            r"|\bcoin\s+(market|price|wallet|trading)"
            r"|\bforex\b"
            r"|\bgiełda\s+(krypto|akcji|walut)"
            r"|\btrading\b"
            r"|\bcrypto\s+exchange"
            r"|\bcoin\s+exchange"
            r"|\bcrypto\s+wallet"
            r"|\bstock\s+(market|trading|exchange|price|chart)"
            r"|\bshares\s+(in|of)\b"
            r"|\bbroker\s+(account|trading|crypto|forex)"
            r"|\bdefi\b|\bnft\b|\bweb3\b"
            r"|\bbtc\b|\beth\b|\bbnb\b|\bsol\b|\bxrp\b)"
        ),
        "reason": "Message contains financial trading context.",
    },
    {
        "id": "ticker_symbol",
        "weight": 10,
        "pattern": (
            r"(\$[A-Z]{2,8}\b"
            r"|\b[A-Z]{2,8}/USDT\b"
            r"|\b[A-Z]{2,8}/USD\b"
            r"|\b[A-Z]{2,8}/BTC\b)"
        ),
        "reason": "Message contains ticker or trading pair.",
    },
]


def detect_market_manipulation(text: str) -> dict:
    """
    Detect possible market manipulation / pump-and-dump style content.

    Returns:
    {
        "status": "SAFE" | "SUSPICIOUS" | "MARKET_MANIPULATION_RISK",
        "score": 0-100,
        "matched_rules": [...],
        "reasons": [...]
    }
    """
    text = text or ""
    normalized_text = text.lower()

    score = 0
    matched_rules: list[str] = []
    reasons: list[str] = []

    for rule in RULES:
        if re.search(rule["pattern"], normalized_text, flags=re.IGNORECASE):
            score += rule["weight"]
            matched_rules.append(rule["id"])
            reasons.append(rule["reason"])

    # ------------------------------------------------------------------
    # Combination bonuses — strong when multiple independent signals fire.
    # ------------------------------------------------------------------
    has_trading_context = "trading_context" in matched_rules or "ticker_symbol" in matched_rules
    has_profit_promise = "guaranteed_profit" in matched_rules or "unrealistic_return" in matched_rules
    has_pressure = "time_pressure" in matched_rules or "investment_call_to_action" in matched_rules
    has_coordination = "signal_group" in matched_rules or "pump_language" in matched_rules

    if has_trading_context and has_profit_promise and has_pressure:
        score += 25
        reasons.append(
            "Combination of trading context, profit promise, and time pressure "
            "indicates possible manipulation."
        )

    if has_trading_context and has_coordination:
        score += 20
        reasons.append(
            "Trading content combined with group coordination or pump language "
            "indicates possible pump-and-dump activity."
        )

    if "inside_information" in matched_rules and has_trading_context:
        score += 25
        reasons.append(
            "Trading recommendation based on alleged inside information is a "
            "strong manipulation indicator."
        )

    score = min(score, 100)

    if score >= 70:
        status = "MARKET_MANIPULATION_RISK"
    elif score >= 35:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    if not reasons:
        reasons.append("No strong market manipulation indicators detected.")

    return {
        "status": status,
        "score": score,
        "matched_rules": matched_rules,
        "reasons": reasons,
    }