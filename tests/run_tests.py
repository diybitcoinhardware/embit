import sys
if sys.implementation.name == "micropython":
    sys.path.append("../src")
import unittest

unittest.main("tests")
