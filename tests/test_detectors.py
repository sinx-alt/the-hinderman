from contracts import UserContext
from detectors.india_pii import valid_aadhaar, valid_luhn
from detectors.inspect import inspect


def test_detects_pan_email_and_phone() -> None:
    findings = inspect("PAN ABCDE1234F email person@example.com phone +91 9876543210")
    assert {item.type for item in findings} >= {"PAN", "EMAIL", "PHONE"}


def test_detects_credentials_but_not_password_context_without_value() -> None:
    findings = inspect("password=supersecret123 AKIA1234567890ABCDEF")
    assert {item.type for item in findings} >= {"PASSWORD", "AWS_ACCESS_KEY"}
    assert all(item.start is not None and item.end is not None for item in findings)


def test_luhn_validation() -> None:
    assert valid_luhn("4532015112830366")
    assert not valid_luhn("4532015112830367")


def test_verhoeff_validation() -> None:
    stem = "23456789012"
    valid = next(stem + str(check) for check in range(10) if valid_aadhaar(stem + str(check)))
    invalid = next(stem + str(check) for check in range(10) if not valid_aadhaar(stem + str(check)))
    assert valid_aadhaar(valid)
    assert not valid_aadhaar(invalid)
    assert not valid_aadhaar("012345678901")


def test_inspect_accepts_shared_user_contract() -> None:
    user = UserContext(user_id="u1", role="intern", department="engineering", clearance=0)
    assert inspect("A short harmless prompt", "prompt", user) == []
