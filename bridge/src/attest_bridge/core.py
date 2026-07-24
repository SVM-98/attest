"""IssuingCore: turns a `NormalizedPurchase` into a signed v0.2 attest receipt.

Reuse 1:1 (Global Constraint 3, `the internal implementation plan
bridge.md`): payload assembly is `issue.build_payload(...)`, signing is
`issue.issue(...)` — the bridge NEVER constructs `buyer`/`license`/
`signatures` by hand and never touches `canon`/`keys`/`pq` for issuance
itself. The real verifier is the test oracle (`test_bridge_core_oracle.py`):
every envelope this class returns must pass `attest.verify.verify`.

Buyer binding (Global Constraint 6): a fresh 16-byte salt + email commitment
on every receipt (computed by `build_payload`, never by the bridge);
`license.transferable = (buyer_pubkey is not None)` — the §17.8/D1 invariant.
A malformed pubkey fails BEFORE anything is signed — the gate in `issue_for`
step 0 is defense-in-depth: `attest_bridge.model.decode_buyer_pubkey` already
rejects a malformed pubkey at the adapter boundary, but `IssuingCore` never
trusts a caller to have done so.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Any

from attest import issue
from attest_bridge.catalog import ProductCatalog
from attest_bridge.ledger import Ledger
from attest_bridge.model import NormalizedPurchase, PurchaseRejected
from attest_bridge.signing import IssuerIdentity

_ED25519_PUBKEY_LEN = 32


class Delivery:
    """Placeholder for the T6 delivery type (`attest_bridge.delivery`, not yet
    implemented). `IssuingCore` only stores what it is given here — nothing in
    T5 reads it — so the constructor shape stays stable once T6 lands and
    replaces this stub with the real class."""


@dataclass(frozen=True, slots=True)
class IssueOutcome:
    receipt_id: str
    envelope: dict[str, Any]
    duplicate: bool  # True: (platform, purchase_id) already had a receipt — returned, not re-issued


class IssuingCore:
    """Platform-agnostic issuance core: `NormalizedPurchase` in, signed v0.2
    attest receipt envelope out. Consumes `attest.issue.build_payload`/
    `attest.issue.issue` 1:1 — see module docstring."""

    def __init__(
        self,
        *,
        catalog: ProductCatalog,
        issuer: IssuerIdentity,
        ledger: Ledger,
        public_base_url: str,
        delivery: Delivery | None = None,
    ) -> None:
        self._catalog = catalog
        self._issuer = issuer
        self._ledger = ledger
        self._public_base_url = public_base_url
        self._delivery = delivery

    def issue_for(self, purchase: NormalizedPurchase) -> IssueOutcome:
        """Issue (or return the already-issued) receipt for `purchase`.

        Raises `PurchaseRejected` on a malformed buyer pubkey (before any
        signing) and `UnmappedProduct` when `purchase.product_key` has no
        catalog entry (propagated from `ProductCatalog.resolve`, never
        guessed). Any `attest.issue.IssueError` escapes as-is — a bug, not a
        purchase-input problem (500 path, T8).
        """
        # (0) Defense-in-depth re-gate: the adapter boundary already rejects a
        # malformed pubkey (`model.decode_buyer_pubkey`), but this class never
        # trusts that gate alone — nothing may be signed for a bad pubkey.
        if purchase.buyer_pubkey is not None and len(purchase.buyer_pubkey) != _ED25519_PUBKEY_LEN:
            raise PurchaseRejected(
                f"buyer pubkey must be {_ED25519_PUBKEY_LEN} bytes, "
                f"got {len(purchase.buyer_pubkey)}"
            )

        # (1) Idempotency: a (platform, purchase_id) pair that already has a
        # stored receipt is returned verbatim, never re-issued.
        stored = self._ledger.get_receipt(purchase.platform, purchase.platform_purchase_id)
        if stored is not None:
            return IssueOutcome(
                receipt_id=stored.receipt_id,
                envelope=json.loads(stored.envelope_json),
                duplicate=True,
            )

        # (2) Catalog resolution — UnmappedProduct propagates untouched.
        template = self._catalog.resolve(purchase.product_key)

        # (3) Fresh, unique salt for this receipt's buyer-binding commitment.
        salt = secrets.token_bytes(16)

        # (4) Assemble the payload — 1:1 via `issue.build_payload`, never
        # hand-built.
        payload = issue.build_payload(
            attest_version="0.2",
            issuer_id=self._issuer.issuer_id,
            display_name=self._issuer.display_name,
            buyer_identifier=purchase.buyer_identifier,
            buyer_identifier_type=purchase.identifier_type,
            buyer_salt=salt,
            buyer_pubkey=purchase.buyer_pubkey,
            transferable=purchase.buyer_pubkey is not None,
            title=template.title,
            publisher=template.publisher,
            identifiers=dict(template.identifiers),
            artifact_series=template.artifact_series,
            terms_uri=template.terms_uri,
            legal_text_sha256=template.legal_text_sha256,
            grant=template.grant,
            revocability=template.revocability,
            drm=template.drm,
            edition=template.edition,
        )

        # (5) Sign — 1:1 via `issue.issue`, never hand-signed.
        envelope = issue.issue(
            payload,
            self._issuer.signing_keys,
            self._issuer.kid,
            salt=salt,
            manifest_snapshot=self._issuer.manifest_snapshot,
        )

        # (6) Record in the Ledger before returning (Global Constraint 9:
        # issue + ledger-record first, delivery — T6 — happens after).
        receipt_id: str = payload["receipt_id"]
        self._ledger.record_receipt(
            platform=purchase.platform,
            purchase_id=purchase.platform_purchase_id,
            receipt_id=receipt_id,
            envelope=envelope,
            buyer_email=purchase.buyer_identifier,
            download_token=secrets.token_urlsafe(32),
            issued_at=payload["issued_at"],
        )

        return IssueOutcome(receipt_id=receipt_id, envelope=envelope, duplicate=False)
