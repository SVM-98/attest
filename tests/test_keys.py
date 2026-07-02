import pytest

from attest import keys

SEED = bytes([1]) * 32  # TEST ONLY — NEVER USE IN PRODUCTION
MSG = b"attest test message"


def test_sign_verify_roundtrip() -> None:
    kp = keys.from_seed(SEED)
    sig = keys.sign(MSG, kp)
    assert len(sig) == 64
    assert keys.verify_strict(MSG, sig, kp.pub)


def test_tampered_message_fails() -> None:
    kp = keys.from_seed(SEED)
    sig = keys.sign(MSG, kp)
    assert not keys.verify_strict(MSG + b"x", sig, kp.pub)


def test_wrong_key_fails() -> None:
    kp = keys.from_seed(SEED)
    other = keys.from_seed(bytes([2]) * 32)
    sig = keys.sign(MSG, kp)
    assert not keys.verify_strict(MSG, sig, other.pub)


def test_noncanonical_s_rejected() -> None:
    kp = keys.from_seed(SEED)
    sig = keys.sign(MSG, kp)
    s_int = int.from_bytes(sig[32:], "little")
    malleated = sig[:32] + (s_int + keys.L).to_bytes(32, "little")
    assert not keys.verify_strict(MSG, malleated, kp.pub)


def test_small_order_pubkey_rejected() -> None:
    identity = bytes([1]) + bytes(31)  # small-order point encoding
    sig = bytes(64)
    assert not keys.verify_strict(MSG, sig, identity)


def test_wrong_lengths_raise() -> None:
    with pytest.raises(ValueError):
        keys.verify_strict(MSG, bytes(63), bytes(32))
    with pytest.raises(ValueError):
        keys.verify_strict(MSG, bytes(64), bytes(31))


def test_b64u_roundtrip_no_padding() -> None:
    data = bytes(range(16))
    s = keys.b64u(data)
    assert "=" not in s
    assert keys.b64u_decode(s) == data
