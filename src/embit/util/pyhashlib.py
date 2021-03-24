import hmac
import hashlib

# https://en.wikipedia.org/wiki/PBKDF2
def pbkdf2_hmac_sha512(password, salt, iterations: int, bytes_to_read: int):
    # xor two arrays
    def binxor(a, b):
        return bytes([x ^ y for (x, y) in zip(a, b)])

    # convert to bytes
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    # result
    r = b""
    for i in range(1, bytes_to_read // 64 + 1 + int(bool(bytes_to_read % 64))):
        U = hmac.new(
            password, salt + i.to_bytes(4, "big"), digestmod=hashlib.sha512
        ).digest()
        result = U
        for j in range(2, 1 + iterations):
            U = hmac.new(password, U, digestmod=hashlib.sha512).digest()
            result = binxor(result, U)
        r += result
    return r[:bytes_to_read]


def ripemd160(*args, **kwargs):
    return hashlib.new("ripemd160", *args, **kwargs)


def hmac_sha512(key, msg):
    return hmac.new(key, msg, digestmod=hashlib.sha512).digest()
