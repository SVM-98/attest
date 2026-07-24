"""Tests for `attest_bridge._http`: the shared https-only, redirect-refusing
GET primitive both platform adapters route their `_default_http_get` through
(Codex T9 review, FIX 3). The Bearer token these adapters send must never be
replayed across a redirect to another (or non-https) origin -- see the
module docstring in `_http.py` for the full argument. Hermetic: no network.
"""

from __future__ import annotations

import pytest
from attest_bridge import _http


def test_https_get_refuses_redirects() -> None:
    # Pins the never-follow contract directly on the handler: whatever
    # `urlopen` would pass in on a 3xx response, `redirect_request` must
    # always return None (which `HTTPRedirectHandler` turns into a plain
    # `HTTPError` instead of a followed redirect).
    handler = _http._NoRedirect()
    result = handler.redirect_request(
        None,  # req
        None,  # fp
        302,  # code
        "redirected",  # msg
        {},  # headers
        "https://attacker.example.test/steal-the-bearer-token",  # newurl
    )
    assert result is None


def test_https_get_rejects_non_https_url() -> None:
    with pytest.raises(ValueError, match="non-https"):
        _http.https_get("http://api.example.test/purchases", {})
