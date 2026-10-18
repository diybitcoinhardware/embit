# Mnemonic convertion to seed and to/from bytes
import hashlib
from .misc import const

from .wordlists.bip39 import WORDLIST

PBKDF2_ROUNDS = const(2048)


def _nfkd(text: str, strict: bool = True) -> str:
    """Normalizes text to NFKD as BIP39 requires.
    Where unicodedata is not available (MicroPython),
    non-ASCII text raises if strict, or is returned as is otherwise.
    """
    # ASCII is already NFKD
    if len(text.encode("utf-8")) == len(text):
        return text
    try:
        from unicodedata import normalize
    except ImportError:
        if strict:
            raise ValueError(
                "No unicodedata to NFKD-normalize a non-ASCII mnemonic or password, "
                "pass NFKD text with assume_nfkd=True"
            ) from None
        return text
    return normalize("NFKD", text)


def mnemonic_to_bytes(mnemonic: str, ignore_checksum: bool = False, wordlist=WORDLIST):
    # this function is copied from Jimmy Song's HDPrivateKey.from_mnemonic() method

    # not strict: a phrase in another form can only fail the wordlist check
    words = _nfkd(mnemonic, strict=False).split(" ")
    if len(words) % 3 != 0 or not 12 <= len(words) <= 24:
        raise ValueError("Invalid recovery phrase")

    binary_seed = bytearray()
    offset = 0
    for word in words:
        if word not in wordlist:
            raise ValueError("Word '%s' is not in the dictionary" % word)
        index = wordlist.index(word)
        remaining = 11
        while remaining > 0:
            bits_needed = 8 - offset
            if remaining == bits_needed:
                if bits_needed == 8:
                    binary_seed.append(index)
                else:
                    binary_seed[-1] |= index
                offset = 0
                remaining = 0
            elif remaining > bits_needed:
                if bits_needed == 8:
                    binary_seed.append(index >> (remaining - 8))
                else:
                    binary_seed[-1] |= index >> (remaining - bits_needed)
                remaining -= bits_needed
                offset = 0
                # lop off the top 8 bits
                index &= (1 << remaining) - 1
            else:
                binary_seed.append(index << (8 - remaining))
                offset = remaining
                remaining = 0

    checksum_length_bits = len(words) * 11 // 33
    num_remainder = checksum_length_bits % 8
    if num_remainder:
        checksum_length = checksum_length_bits // 8 + 1
        bits_to_ignore = 8 - num_remainder
    else:
        checksum_length = checksum_length_bits // 8
        bits_to_ignore = 0
    raw = bytes(binary_seed)
    data, checksum = raw[:-checksum_length], raw[-checksum_length:]
    computed_checksum = bytearray(hashlib.sha256(data).digest()[:checksum_length])

    # ignore the last bits_to_ignore bits
    computed_checksum[-1] &= 256 - (1 << (bits_to_ignore + 1) - 1)
    if not ignore_checksum and checksum != bytes(computed_checksum):
        raise ValueError("Checksum verification failed")
    return data


def mnemonic_is_valid(mnemonic: str, wordlist=WORDLIST):
    """Checks if mnemonic is valid (checksum and words)"""
    try:
        mnemonic_to_bytes(mnemonic, wordlist=wordlist)
        return True
    except Exception:
        return False


def mnemonic_to_seed(
    mnemonic: str, password: str = "", wordlist=WORDLIST, assume_nfkd: bool = False
):
    mnemonic = _nfkd(mnemonic, strict=not assume_nfkd)
    password = _nfkd(password, strict=not assume_nfkd)
    # first we try to convert mnemonic to bytes
    # and raise a correct error if it is invalid
    # If wordlist is None - don't check mnemonic.
    if wordlist is not None:
        mnemonic_to_bytes(mnemonic, wordlist=wordlist)
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        ("mnemonic" + password).encode("utf-8"),
        PBKDF2_ROUNDS,
        64,
    )


def _extract_index(bits, b, n):
    value = 0
    for pos in range(n * bits, (n + 1) * bits):
        value = value << 1
        if b[pos // 8] & (1 << (7 - pos % 8)):
            value += 1
    return value


def mnemonic_from_bytes(entropy, wordlist=WORDLIST):
    if len(entropy) % 4 != 0 or not 16 <= len(entropy) <= 32:
        raise ValueError("Byte array should be multiple of 4 long (16, 20, ..., 32)")
    total_bits = len(entropy) * 8
    checksum_bits = total_bits // 32
    total_mnemonics = (total_bits + checksum_bits) // 11
    # no need to truncate checksum - we already know total_mnemonics
    checksum = bytearray(hashlib.sha256(entropy).digest())
    entropy += checksum
    mnemonic = []
    for i in range(0, total_mnemonics):
        idx = _extract_index(11, entropy, i)
        mnemonic.append(wordlist[idx])
    return " ".join(mnemonic)


def find_candidates(word_part, nmax=5, wordlist=WORDLIST):
    candidates = []
    for w in wordlist:
        if w.startswith(word_part):
            candidates.append(w)
        if len(candidates) >= nmax:
            break
    return candidates
