"""Entry point for `python -m attest_bridge`."""

from __future__ import annotations

import sys

from attest_bridge.cli import main

if __name__ == "__main__":
    sys.exit(main())
