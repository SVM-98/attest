"""JSON Schema (draft 2020-12) validation of attest payloads."""

from __future__ import annotations

import importlib.resources
import json
from typing import Any

import jsonschema

with importlib.resources.files("attest.schema").joinpath("attest-receipt.schema.json").open(
    "rb"
) as f:
    SCHEMA: dict[str, Any] = json.load(f)

_VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def validate_payload(payload: object) -> list[str]:
    """Validate `payload` against the attest v0.1 receipt schema.

    Returns an empty list when valid; otherwise one human-readable violation
    per schema error, sorted by JSON path for deterministic output.
    """
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(_VALIDATOR.iter_errors(payload), key=lambda e: list(e.absolute_path))
    ]
