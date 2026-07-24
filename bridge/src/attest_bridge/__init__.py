"""attest-bridge: a self-hosted facilitator that turns purchase events into
signed attest receipts.

Founding constraint: this is a facilitator, never a server, in attest's trust
model. It runs on infrastructure the merchant already controls (their own
webhook handler), holds only that merchant's own signing keys, and never sits
between a buyer and the receipts they hold — a receipt issued through the
bridge is byte-for-byte the same offline-verifiable artifact issued by the CLI,
and it keeps verifying long after the bridge process that minted it is gone.
"""

from __future__ import annotations

__version__ = "0.1.0"
