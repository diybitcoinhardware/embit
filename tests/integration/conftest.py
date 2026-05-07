"""Integration RPC tests: start only the chain daemon(s) required by collected tests."""

from __future__ import annotations

import logging
import os

import pytest

_started: dict[str, bool] = {"bitcoin": False, "liquid": False}


def pytest_configure(config: pytest.Config) -> None:
    """Tune log levels for the embit package and integration RPC helpers."""
    if os.environ.get("EMBIT_TEST_LOG") == "1":
        level = logging.DEBUG
    else:
        level = logging.INFO
    for name in (
        "embit",
        "util",
        "util.bitcoin",
        "util.liquid",
        "util.rpc",
    ):
        logging.getLogger(name).setLevel(level)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if os.environ.get("EMBIT_TEMP_DIR"):
        return
    reason = "EMBIT_TEMP_DIR not set — run `uv run poe integration-tests`"
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if item.get_closest_marker("integration"):
            item.add_marker(skip)


def pytest_collection_finish(session: pytest.Session) -> None:
    # pytest_sessionstart runs *before* collection, so session.items is empty
    # and daemons never started. Start chain backends once items are known.
    if not os.environ.get("EMBIT_TEMP_DIR"):
        return
    if getattr(session.config.option, "collectonly", False):
        return
    items = session.items
    need_btc = any(item.get_closest_marker("bitcoin") for item in items)
    need_liq = any(item.get_closest_marker("liquid") for item in items)
    if not need_btc and not need_liq:
        return
    # Imported here so collecting unit tests never imports daemon binaries.
    from util.bitcoin import daemon as bitcoind
    from util.liquid import daemon as elementsd

    if need_btc:
        bitcoind.start()
        _started["bitcoin"] = True
    if need_liq:
        elementsd.start()
        _started["liquid"] = True


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not os.environ.get("EMBIT_TEMP_DIR"):
        return
    from util.bitcoin import daemon as bitcoind
    from util.liquid import daemon as elementsd

    if _started["liquid"]:
        elementsd.stop()
        _started["liquid"] = False
    if _started["bitcoin"]:
        bitcoind.stop()
        _started["bitcoin"] = False


@pytest.fixture
def logger(request: pytest.FixtureRequest) -> logging.Logger:
    """Per-test logger (node id)."""
    return logging.getLogger(request.node.nodeid)
