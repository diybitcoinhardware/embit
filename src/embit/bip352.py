"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

TODO:
* Add support for SP labels.
* Implement deriving a destination addr for a given output and recipient SP address.
* Implement check to determine if a given output is an SP output for a given SP address.
* Implement signing SP spends (once psbt format is settled).
"""

from embit import bech32, ec


def generate_silent_payment_address(B_scan: ec.PublicKey, B_m: ec.PublicKey, network: str = "main", version: int = 0) -> str:
    """
    Adapted from https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py

    Generates the recipient's reusable silent payment address for a given:
        * scanning pubkey `B_scan`
        * spending pubkey `B_m`
    """
    data = bech32.convertbits(B_scan.sec() + B_m.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)
