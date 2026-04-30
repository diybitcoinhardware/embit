# this should run with python3
import sys
import time
import unittest
from pathlib import Path

if sys.implementation.name == "micropython":
    print("This file should run with python3, not micropython!")
    sys.exit(1)

from util.bitcoin import daemon as bitcoind
from util.liquid import daemon as elementsd


ROOT = Path(__file__).resolve().parent


def discover(*parts):
    return unittest.defaultTestLoader.discover(
        str(ROOT.joinpath(*parts)), top_level_dir=str(ROOT)
    )


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode not in ("all", "core", "ext", "liquid"):
        raise SystemExit("usage: run_tests.py [all|core|ext|liquid]")

    suite = unittest.TestSuite()
    daemons = []
    if mode in ("all", "core"):
        daemons.append(bitcoind)
        suite.addTests(discover("core"))
    if mode in ("all", "ext", "liquid"):
        daemons.append(elementsd)
        suite.addTests(discover("ext", "liquid"))

    try:
        for daemon in daemons:
            daemon.start()
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        time.sleep(10)
        if not result.wasSuccessful():
            raise SystemExit(1)
    finally:
        for daemon in reversed(daemons):
            daemon.stop()


if __name__ == "__main__":
    main()
