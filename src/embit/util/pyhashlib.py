import hmac
import hashlib

# xor two arrays
def binxor(a, b):
    return bytes([x ^ y for (x, y) in zip(a, b)])


# https://en.wikipedia.org/wiki/PBKDF2
def pbkdf2_hmac(password, salt, iterations: int, bytes_to_read: int, digestmod):
    # convert to bytes
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    # result
    r = b""
    for i in range(1, bytes_to_read // 64 + 1 + int(bool(bytes_to_read % 64))):
        current = hmac.new(
            password, salt + i.to_bytes(4, "big"), digestmod=digestmod
        ).digest()
        result = current
        for j in range(2, 1 + iterations):
            current = hmac.new(password, current, digestmod=digestmod).digest()
            result = binxor(result, current)
        r += result
    return r[:bytes_to_read]


def pbkdf2_hmac_sha512(password, salt, iterations: int, bytes_to_read: int):
    return pbkdf2_hmac(password, salt, iterations, bytes_to_read, hashlib.sha512)


def pbkdf2_hmac_sha256(password, salt, iterations: int, bytes_to_read: int):
    return pbkdf2_hmac(password, salt, iterations, bytes_to_read, hashlib.sha256)


def ripemd160(*args, **kwargs):
    return hashlib.new("ripemd160", *args, **kwargs)


def hmac_sha512(key, msg):
    return hmac.new(key, msg, digestmod=hashlib.sha512).digest()
