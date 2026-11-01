from main import analyse_transcript


def test_sensitive_otp_and_urgency_flags():
    result = analyse_transcript("Aapka bank account block ho jayega. Apna OTP abhi bataiye.")
    ids = {item["id"] for item in result["findings"]}
    assert "secret_credentials" in ids
    assert "urgent_threat" in ids
    assert result["risk_score"] > 0


def test_benign_text_does_not_get_false_positive_flags():
    result = analyse_transcript("Namaste, aapka service appointment kal subah das baje hai.")
    assert result["findings"] == []
    assert result["risk_level"] == "low_signal"


def test_multiple_patterns_are_capped_at_100():
    result = analyse_transcript(
        "RBI officer bol raha hoon. Account block ho jayega. OTP aur PIN bataiye. "
        "AnyDesk install karo aur paise transfer karo. Click this link for lottery prize."
    )
    assert result["risk_score"] == 100
    assert len(result["findings"]) >= 4


def test_empty_transcript_rejected():
    try:
        analyse_transcript("   ")
    except ValueError:
        return
    raise AssertionError("Expected ValueError")


def test_safe_advice_about_otp_is_not_flagged_as_a_credential_request():
    result = analyse_transcript("Never share your OTP or bank details with a caller. Use the official number.")
    assert result["findings"] == []


def test_explicitly_negated_payment_request_is_not_flagged():
    result = analyse_transcript("Do not transfer money or approve this UPI request.")
    assert result["findings"] == []


def test_conditional_sim_block_warning_is_detected():
    result = analyse_transcript("Main telecom department se bol raha hoon. KYC verify nahi ki to aapki SIM band ho jayegi.")
    assert any(item["id"] == "urgent_threat" for item in result["findings"])
