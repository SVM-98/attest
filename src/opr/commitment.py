"""Buyer binding: scrypt commitment and Ed25519 challenge-response (§3.2)."""

from __future__ import annotations

import hashlib
import unicodedata

from opr import keys

LABEL_COMMITMENT = b"OPR-buyer-commitment-v1"
LABEL_CHALLENGE = b"OPR-binding-challenge-v1"
IDENTIFIER_TYPES = ("issuer-account", "email")

_SCRYPT_N = 32768
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_ASCII_WS = " \t\n\r"


def normalize(identifier: str, identifier_type: str) -> str:
    if identifier_type not in IDENTIFIER_TYPES:
        raise ValueError(f"unknown identifier_type: {identifier_type!r}")
    if identifier_type == "email":
        identifier = identifier.strip(_ASCII_WS)
        identifier = unicodedata.normalize("NFC", identifier)
        identifier = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in identifier)
    else:  # issuer-account: NFC only, exact string otherwise
        identifier = unicodedata.normalize("NFC", identifier)
    if "\x00" in identifier:
        raise ValueError("normalized identifier must not contain 0x00")
    return identifier


def compute(identifier: str, identifier_type: str, salt: bytes) -> bytes:
    if len(salt) != 16:
        raise ValueError("salt must be exactly 16 raw bytes")
    norm = normalize(identifier, identifier_type)
    password = LABEL_COMMITMENT + b"\x00" + identifier_type.encode() + b"\x00" + norm.encode()
    return hashlib.scrypt(
        password,
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM,
        dklen=_SCRYPT_DKLEN,
    )


def challenge_message(receipt_id: str, nonce: bytes) -> bytes:
    if len(nonce) < 16:
        raise ValueError("nonce must be at least 16 bytes")
    return LABEL_CHALLENGE + b"\x00" + receipt_id.encode() + b"\x00" + nonce


def sign_challenge(receipt_id: str, nonce: bytes, kp: keys.SigningKeyPair) -> bytes:
    return keys.sign(challenge_message(receipt_id, nonce), kp)


def verify_challenge(receipt_id: str, nonce: bytes, sig: bytes, pub: bytes) -> bool:
    return keys.verify_strict(challenge_message(receipt_id, nonce), sig, pub)
