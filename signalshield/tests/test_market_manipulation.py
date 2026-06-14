from core.market_manipulation import detect_market_manipulation


def test_plain_market_context_is_low_risk() -> None:
    result = detect_market_manipulation("crypto")

    assert result["status"] == "SAFE"
    assert result["score"] == 10
    assert result["matched_rules"] == ["trading_context"]


def test_buy_signal_is_suspicious() -> None:
    result = detect_market_manipulation("Kup teraz akcje $ABC, wejscie na pozycje.")

    assert result["status"] == "SUSPICIOUS"
    assert result["score"] == 60
    assert "investment_call_to_action" in result["matched_rules"]
    assert "ticker_symbol" in result["matched_rules"]


def test_pump_language_with_unrealistic_return_is_high_risk() -> None:
    result = detect_market_manipulation(
        "Kup teraz crypto 100x profit, ostatnia szansa, to the moon."
    )

    assert result["status"] == "MARKET_MANIPULATION_RISK"
    assert result["score"] == 100
    assert "unrealistic_return" in result["matched_rules"]
