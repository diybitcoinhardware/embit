import sys

if sys.implementation.name == "micropython":
    # Ensure local sources take precedence over frozen/std lib packages.
    sys.path.insert(0, "../src")
import unittest

if __name__ == "__main__":
    unittest.main("tests")
