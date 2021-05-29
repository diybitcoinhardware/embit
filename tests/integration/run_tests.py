# this should run with python3
import sys
if sys.implementation.name == 'micropython':
    print("This file should run with python3, not micropython!")
    sys.exit(1)

from util.bitcoin import daemon as bitcoind
from util.liquid import daemon as elementsd
import unittest
import time

def main():
    try:
        # bitcoind.start()
        elementsd.start()
        unittest.main('tests')
        time.sleep(10)
    finally:
        # bitcoind.stop()
        elementsd.stop()

if __name__ == '__main__':
    main()
