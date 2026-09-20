"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

TODO:
* Implement deriving a destination addr for a given output and recipient SP address.
* Implement check to determine if a given output is an SP output for a given SP address.
* Implement signing SP spends (once psbt format is settled).
"""
from embit import bech32, ec
from embit.util import secp256k1
from embit.hashes import tagged_hash



def generate_silent_payment_address(B_scan: ec.PublicKey, B_spend: ec.PublicKey, network: str = "main", version: int = 0) -> str:
    """
    Adapted from https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py
    """
    data = bech32.convertbits(B_scan.sec() + B_spend.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)



def generate_labeled_silent_payment_address(b_scan: ec.PrivateKey, B_spend: ec.PublicKey, label, network: str = "main", version: int = 0) -> str:
    """
    The spending key is tweaked with the label to generate a labeled silent payment address.
    see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#address-encoding

    `label` must be an int, str, or bytes.
    """
    if isinstance(label, int):
        label_bytes = label.to_bytes(4, "big")
    elif isinstance(label, str):
        label_bytes = label.encode()
    elif isinstance(label, bytes):
        label_bytes = label
    else:
        raise Exception("Label must be an int, str, or bytes.")

    tweak = tagged_hash("BIP0352/Label", b_scan.secret + label_bytes)
    label_pubkey = ec.PublicKey(secp256k1.ec_pubkey_add(secp256k1.ec_pubkey_parse(B_spend.sec()), tweak))

    return generate_silent_payment_address(b_scan.get_public_key(), label_pubkey, network=network, version=version)
