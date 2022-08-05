from . import base58, bip32, bip39
from .bip32 import HDKey
from .networks import NETWORKS
from .wordlists.bip39 import WORDLIST

from io import BytesIO

"""
    BIP-47: https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki
"""

def get_payment_code(root: HDKey):
    """
        Generates the recipient's BIP-47 shareable payment code (version 1)
        for the input root private key.
    """
    bip47_child = root.derive("m/47'/0'/0'")

    buf = BytesIO()
    buf.write(b'\x01')      # bip47 version
    buf.write(b'\x00')      # Bitmessage; always zero
    buf.write(bip47_child.get_public_key().serialize())
    buf.write(bip47_child.chain_code)
    buf.write(b'\00' * 13)  # bytes reserved for future expansion

    return base58.encode_check(b"\x47" + buf.getvalue())



def get_payment_code_from_mnemonic(mnemonic: str, password: str = "", wordlist=WORDLIST, version=NETWORKS["main"]["xprv"]):
    """
        Convenience method
    """
    seed_bytes = bip39.mnemonic_to_seed(mnemonic, password=password, wordlist=wordlist)
    root = bip32.HDKey.from_seed(seed_bytes, version=version)
    return get_payment_code(root)



"""
    TODO: Methods to support notification address, create notification transactions,
    send to payment code, etc.
"""