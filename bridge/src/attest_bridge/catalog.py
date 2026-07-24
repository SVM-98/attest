"""Product catalog: merchant product/price identifier -> receipt line-item template.

`ProductCatalog.resolve` never guesses: a miss is a hard failure
(`UnmappedProduct`), not a fallback to a default template. Issuing a receipt
with the wrong title, publisher, or license terms because the catalog was
incomplete is worse than refusing to issue at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from attest_bridge.model import UnmappedProduct


@dataclass(frozen=True, slots=True)
class ProductTemplate:
    """The receipt line-item fields that are the same for every sale of a product."""

    title: str
    publisher: str
    identifiers: dict[str, str]
    artifact_series: str
    terms_uri: str
    legal_text_sha256: str
    grant: str = "perpetual"
    revocability: str = "none"
    drm: str = "drm-free"
    edition: str | None = None


class ProductCatalog:
    """Read-only mapping from a platform's product/price key to its `ProductTemplate`."""

    def __init__(self, products: Mapping[str, ProductTemplate]) -> None:
        self._products = dict(products)

    def resolve(self, product_key: str) -> ProductTemplate:
        """Return the template for `product_key`, or raise `UnmappedProduct`."""
        try:
            return self._products[product_key]
        except KeyError:
            raise UnmappedProduct(
                f"no product mapping for {product_key!r} — refusing to issue with guessed terms"
            ) from None

    def keys(self) -> tuple[str, ...]:
        """All mapped product keys, sorted for deterministic listing/diffing."""
        return tuple(sorted(self._products))
