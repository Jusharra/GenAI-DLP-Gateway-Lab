from dlp_utils import detect_pii, evaluate_policy


def test_detect_pii_no_pii():
    text = "Just a normal prompt with no sensitive data."
    findings = detect_pii(text)
    assert findings == []


def test_detect_pii_detects_ssn():
    text = "User mentioned SSN in the prompt."
    findings = detect_pii(text)
    assert any(f["type"] == "SSN" for f in findings)


def test_evaluate_policy_allow_without_pii():
    decision = evaluate_policy("analyst", [])
    assert decision == "allow"


def test_evaluate_policy_block_for_non_privileged_with_pii():
    decision = evaluate_policy("analyst", [{"type": "SSN"}])
    assert decision == "block"


def test_evaluate_policy_mask_for_privileged_with_pii():
    decision = evaluate_policy("dlp-admin", [{"type": "SSN"}])
    assert decision == "mask"
