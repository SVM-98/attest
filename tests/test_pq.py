from attest import keys, pq


def test_generate_roundtrip_sign_verify() -> None:
    kp = pq.generate()
    assert len(kp.pub) == pq.ML_DSA_65_PK_LEN
    assert len(kp.sk) == pq.ML_DSA_65_SK_LEN
    sig = pq.sign(b"payload bytes", kp)
    assert len(sig) == pq.ML_DSA_65_SIG_LEN
    assert pq.verify_strict(b"payload bytes", sig, kp.pub)


def test_tampered_message_rejected() -> None:
    kp = pq.generate()
    sig = pq.sign(b"payload bytes", kp)
    assert not pq.verify_strict(b"tampered", sig, kp.pub)


def test_wrong_length_sig_rejected_without_raising() -> None:
    kp = pq.generate()
    assert not pq.verify_strict(b"m", b"\x00" * 10, kp.pub)


def test_wrong_length_pub_rejected_without_raising() -> None:
    kp = pq.generate()
    sig = pq.sign(b"m", kp)
    assert not pq.verify_strict(b"m", sig, b"\x00" * 10)


def test_corrupted_sig_rejected() -> None:
    kp = pq.generate()
    sig = bytearray(pq.sign(b"m", kp))
    sig[0] ^= 0xFF
    assert not pq.verify_strict(b"m", bytes(sig), kp.pub)


def test_oracle_cross_verify_dilithium_py() -> None:
    # dev-only oracle: deterministic dilithium-py signature must verify under pqcrypto
    from dilithium_py.ml_dsa import ML_DSA_65

    pk, sk = ML_DSA_65.key_derive(bytes([1]) * 32)
    sig = ML_DSA_65.sign(sk, b"cross", deterministic=True)
    assert pq.verify_strict(b"cross", sig, pk)


def test_hybrid_signing_keys_dataclass() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    assert len(hk.ed.pub) == 32 and len(hk.mldsa.pub) == pq.ML_DSA_65_PK_LEN
