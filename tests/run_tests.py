import sys

if sys.implementation.name == "micropython":
    sys.path.append("../src")
import unittest

if __name__ == '__main__':
    unittest.main("tests")
