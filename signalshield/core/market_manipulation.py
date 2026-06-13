import re


RULES = [
    {
        "id": "guaranteed_profit",
        "weight": 30,
        "pattern": r"(gwarantowan[yae]?|guaranteed|pewny zysk|bez ryzyka|risk[- ]?free|100%\s*pewne|без риска|гарантированн)",
        "reason": "Message promises guaranteed or risk-free profit.",
    },
    {
        "id": "unrealistic_return",
        "weight": 30,
        "pattern": r"(\b\d{2,4}\s?%\b|x\d+|\b\d+x\b|10x|100x|1000x|to the moon|moonshot)",
        "reason": "Message promises unrealistic returns.",
    },
    {
        "id": "time_pressure",
        "weight": 20,
        "pattern": r"(kup teraz|buy now|teraz albo nigdy|last chance|ostatnia szansa|tylko dziś|w ciągu \d+\s*(minut|godzin|h)|natychmiast|срочно|только сегодня)",
        "reason": "Message uses time pressure to force quick investment decision.",
    },
    {
        "id": "investment_call_to_action",
        "weight": 20,
        "pattern": r"(kupuj|kup teraz|wchodzimy|wejście|entry|buy signal|sygnał kupna|otwieramy pozycję|dołącz teraz|invest now|zainwestuj)",
        "reason": "Message contains direct investment call to action.",
    },
    {
        "id": "inside_information",
        "weight": 40,
        "pattern": r"(inside info|insider|tajna informacja|poufna informacja|niepubliczna informacja|wiemy coś|инсайд|секретная информация)",
        "reason": "Message claims to have secret or inside information.",
    },
    {
        "id": "pump_language",
        "weight": 35,
        "pattern": r"(pump|pumpujemy|pompujemy|pompka|wystrzeli|rocket|rakieta|moon|to the moon|爆|памп|ракета)",
        "reason": "Message uses pump-style market manipulation language.",
    },
    {
        "id": "signal_group",
        "weight": 25,
        "pattern": r"(telegram|discord|whatsapp|vip group|grupa vip|signal group|grupa sygnałowa|zamknięta grupa|private group)",
        "reason": "Message promotes a private signal or investment group.",
    },
    {
        "id": "low_liquidity_asset",
        "weight": 15,
        "pattern": r"(low cap|niska kapitalizacja|penny stock|meme coin|shitcoin|mała spółka|small cap)",
        "reason": "Message refers to low-liquidity or easily manipulated assets.",
    },
    {
        "id": "trading_context",
        "weight": 10,
        "pattern": r"(akcje|stock|shares|crypto|krypto|token|coin|forex|giełda|trading|exchange|wallet|broker)",
        "reason": "Message contains financial trading context.",
    },
    {
        "id": "ticker_symbol",
        "weight": 10,
        "pattern": r"(\$[A-Z]{2,8}\b|\b[A-Z]{2,8}/USDT\b|\b[A-Z]{2,8}/USD\b)",
        "reason": "Message contains ticker or trading pair.",
    },
]


def detect_market_manipulation(text: str) -> dict:
    """
    Detects possible market manipulation / pump-and-dump style content.

    Returns:
    {
        "status": "SAFE" / "SUSPICIOUS" / "MARKET_MANIPULATION_RISK",
        "score": 0-100,
        "matched_rules": [...],
        "reasons": [...]
    }
    """
    text = text or ""
    normalized_text = text.lower()

    score = 0
    matched_rules = []
    reasons = []

    for rule in RULES:
        if re.search(rule["pattern"], normalized_text, flags=re.IGNORECASE):
            score += rule["weight"]
            matched_rules.append(rule["id"])
            reasons.append(rule["reason"])

    # Kombinacja kilku sygnałów jest silniejsza niż pojedyncze słowo.
    has_trading_context = "trading_context" in matched_rules or "ticker_symbol" in matched_rules
    has_profit_promise = "guaranteed_profit" in matched_rules or "unrealistic_return" in matched_rules
    has_pressure = "time_pressure" in matched_rules or "investment_call_to_action" in matched_rules
    has_coordination = "signal_group" in matched_rules or "pump_language" in matched_rules

    if has_trading_context and has_profit_promise and has_pressure:
        score += 25
        reasons.append(
            "Combination of trading context, profit promise and time pressure indicates possible manipulation."
        )

    if has_trading_context and has_coordination:
        score += 20
        reasons.append(
            "Trading content combined with group coordination or pump language indicates possible pump-and-dump activity."
        )

    if "inside_information" in matched_rules and has_trading_context:
        score += 25
        reasons.append(
            "Trading recommendation based on alleged inside information is a strong manipulation indicator."
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