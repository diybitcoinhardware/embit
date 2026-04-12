# this should run with python3
"""Backward-compatible entrypoint; runs pytest slices only (`poe prepare-integration-daemons` first, or `poe integration-tests`)."""

import sys

if sys.implementation.name == "micropython":
    print("This file should run with python3, not micropython!")
    sys.exit(1)


def main() -> None:
    import pytest

    base = ["tests/integration/tests"]
    extra = sys.argv[1:]
    # Separate pytest processes: one chain daemon per session (matches poe integration-tests).
    for expr in ("integration and bitcoin", "integration and liquid"):
        code = pytest.main([*base, "-m", expr, *extra])
        if code != 0:
            raise SystemExit(code)


if __name__ == "__main__":
    main()
