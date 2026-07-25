"""ProductCatalog: product_key -> ProductTemplate, hard-fail on unmapped key."""

from __future__ import annotations

import dataclasses

import pytest
from attest_bridge.catalog import ProductCatalog, ProductTemplate
from attest_bridge.model import UnmappedProduct


def _template(**overrides: object) -> ProductTemplate:
    base: dict[str, object] = dict(
        title="Example Game",
        publisher="Example Publisher srl",
        identifiers={"issuer_sku": "EXG-001"},
        artifact_series="store.example.com/works/EXG-001",
        terms_uri="https://store.example.com/attest/license-templates/standard-v1",
        legal_text_sha256="0" * 64,
    )
    base.update(overrides)
    return ProductTemplate(**base)  # type: ignore[arg-type]


def test_resolve_hit_returns_the_template() -> None:
    template = _template()
    catalog = ProductCatalog({"price_1PxYzEXAMPLE": template})
    assert catalog.resolve("price_1PxYzEXAMPLE") is template


def test_resolve_miss_raises_unmapped_product_naming_the_key() -> None:
    catalog = ProductCatalog({})
    with pytest.raises(UnmappedProduct, match="price_missing"):
        catalog.resolve("price_missing")


def test_keys_returns_sorted_product_keys() -> None:
    catalog = ProductCatalog(
        {
            "price_zzz": _template(),
            "price_aaa": _template(),
            "price_mmm": _template(),
        }
    )
    assert catalog.keys() == ("price_aaa", "price_mmm", "price_zzz")


def test_product_template_defaults_match_spec() -> None:
    template = _template()
    assert template.grant == "perpetual"
    assert template.revocability == "none"
    assert template.drm == "drm-free"
    assert template.edition is None


def test_product_template_is_frozen() -> None:
    template = _template()
    with pytest.raises(dataclasses.FrozenInstanceError):
        template.title = "Other Title"  # type: ignore[misc]
