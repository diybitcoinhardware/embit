from . import bip32, bip39, ec
from .bip32 import HARDENED_INDEX
import hmac

BIP85_MAGIC = b"bip-entropy-from-k"

class LANGUAGES:
    """
    Tuples: (bip85 derivation index, wordlist).
    """
    ENGLISH = (0, bip39.WORDLIST)

def derive_entropy(root, app_index, path):
    """
    Derive app-specific bip85 entropy using path m/83696968'/app_index'/...path'
    """
    assert max(path) < HARDENED_INDEX
    derivation = [
        HARDENED_INDEX + 83696968, 
        HARDENED_INDEX + app_index
    ] + [ p + HARDENED_INDEX for p in path ]
    derived = root.derive(derivation)
    return hmac.new(BIP85_MAGIC, derived.secret, digestmod='sha512').digest()

def derive_mnemonic(root, num_words=12, index=0, language=LANGUAGES.ENGLISH):
    """Derive a new mnemonic with num_words using language (code, wordlist)"""
    assert num_words in [12, 18, 24]
    langcode, wordlist = language
    path = [langcode, num_words, index]
    entropy = derive_entropy(root, 39, path)
    entropy_part = entropy[:num_words*4//3]
    return bip39.mnemonic_from_bytes(entropy_part, wordlist=wordlist)

def derive_wif(root, index=0):
    """Derive ec.PrivateKey"""
    entropy = derive_entropy(root, 2, [index])
    return ec.PrivateKey(entropy[:32])

def derive_xprv(root, index=0):
    """Derive bip32.HDKey"""
    entropy = derive_entropy(root, 32, [index])
    return bip32.HDKey(ec.PrivateKey(entropy[32:]),entropy[:32])

def derive_hex(root, num_bytes=32, index=0):
    """Derive raw entropy from 16 to 64 bytes long"""
    assert num_bytes <= 64
    assert num_bytes >= 16
    entropy = derive_entropy(root, 128169, [num_bytes, index])
    return entropy[:num_bytes]
