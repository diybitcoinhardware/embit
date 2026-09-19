"""Subprocess helper for `WrapperImportTest` in `test_bindings.py`.

Run as ``python _helper_libsecp_load_failure.py``. Installs a meta-path
entry that makes ``embit.util.ctypes_secp256k1`` raise at import time
(simulating the real-world "libsecp256k1 not found" scenario, which is
how ``ctypes_secp256k1``'s module-level ``_secp = _init()`` fails in
production), then triggers the selector module's import to exercise the
fail-fast path.

Output (one per line on stdout, exit 0):
  1. Fully-qualified exception type from the selector's import-time raise.
  2. ``__cause__`` exception type, or ``NO_CAUSE`` if absent.
  3. ``str(__cause__)``, or empty string if absent.

Exits 1 if the import unexpectedly succeeded (treat that as a test failure
in the calling test case).

The underscore-prefixed filename keeps pytest from auto-collecting this
file as a test module while still letting it live next to the test that
uses it.
"""

import importlib.abc
import importlib.util
import sys


class _FailLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None

    def exec_module(self, module):
        raise RuntimeError("simulated libsecp loader failure")


class _FailFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name == "embit.util.ctypes_secp256k1":
            return importlib.util.spec_from_loader(name, _FailLoader())
        return None


def main():
    sys.meta_path.insert(0, _FailFinder())
    try:
        from embit.util import secp256k1  # noqa: F401
    except Exception as exc:
        print("{0}.{1}".format(type(exc).__module__, type(exc).__name__))
        cause = exc.__cause__
        print(type(cause).__name__ if cause is not None else "NO_CAUSE")
        print(str(cause) if cause is not None else "")
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()
