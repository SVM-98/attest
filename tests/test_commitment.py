import unicodedata

import pytest

from attest import commitment, keys

SALT = bytes(range(16))  # TEST ONLY


def test_normalize_email() -> None:
    assert commitment.normalize("  José@Example.COM \t", "email") == unicodedata.normalize(
        "NFC", "josé@example.com"
    )


def test_normalize_email_ascii_lowercase_only() -> None:
    # Only A-Z are lowercased (byte-deterministic); non-ASCII case preserved.
    assert commitment.normalize("İstanbul@Ex.COM", "email") == unicodedata.normalize(
        "NFC", "İstanbul@ex.com"
    )


def test_normalize_issuer_account_nfc_only() -> None:
    # issuer-account: NFC only, exact string otherwise (no trim, no lowercase)
    assert commitment.normalize("ACC-42", "issuer-account") == "ACC-42"
    assert commitment.normalize("Acc-42", "issuer-account") == "Acc-42"
    decomposed = "é"  # "é" in NFD form
    assert commitment.normalize(decomposed, "issuer-account") == unicodedata.normalize(
        "NFC", decomposed
    )


def test_normalize_rejects_nul_and_unknown_type() -> None:
    with pytest.raises(ValueError):
        commitment.normalize("a\x00b", "email")
    with pytest.raises(ValueError):
        commitment.normalize("x", "phone")


def test_compute_is_deterministic_and_salt_sensitive() -> None:
    c1 = commitment.compute("user@example.com", "email", SALT)
    c2 = commitment.compute("user@example.com", "email", SALT)
    c3 = commitment.compute("user@example.com", "email", bytes(16))
    assert c1 == c2 and len(c1) == 32 and c1 != c3


def test_compute_requires_16_byte_salt() -> None:
    with pytest.raises(ValueError):
        commitment.compute("a@b.c", "email", bytes(15))


def test_challenge_roundtrip_and_nonce_binding() -> None:
    kp = keys.from_seed(bytes([3]) * 32)  # TEST ONLY
    nonce = bytes(range(16))
    sig = commitment.sign_challenge("01J1V5B4M9", nonce, kp)
    assert commitment.verify_challenge("01J1V5B4M9", nonce, sig, kp.pub)
    assert not commitment.verify_challenge("01J1V5B4M9", bytes(16), sig, kp.pub)
    assert not commitment.verify_challenge("01J1V5B4MX", nonce, sig, kp.pub)
