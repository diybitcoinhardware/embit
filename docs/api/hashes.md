# Hash functions

One-line variants of the common Bitcoin hash functions. For convenience.

API is common - pass a bytes object and get a hash of it.

Functions:
- `sha256(msg)`
- `double_sha256(msg)` - same as `sha256(sha256(msg))`
- `ripemd160(msg)`
- `hash160(msg)` - same as `ripemd160(sha256(msg))`
- `tagged_hash(tag, data)` - taproot hash function. `tag` is a string, `data` is bytes. It's basically `sha256(sha256(tag) + sha256(tag) + data)`

Tagged hash helper function:
- `tagged_hash_init(tag, data)` - initializes the tagged hash and returns a hash object that can be updated with more data.

**Example**

```python
from embit import hashes

hashes.sha256(b"I'm sha256")
hashes.ripemd160("Hash me gently".encode())

hashes.tagged_hash("TapMessage", b"Taproot is coming!")

h = hashes.tagged_hash_init("TapMessage", b"Taproot")
h.update(b" is coming!")
result = h.digest()
```
## `sha256(msg)`

Hashes a message using SHA-256 algorithm.

**Arguments**

- `msg` - bytes to hash

**Returns**

`32`-byte hash of the message

## `double_sha256(msg)`

Hashes a message twice using SHA-256 algorithm.

**Arguments**

- `msg` - bytes to hash

**Returns**

`32`-byte hash of the message

## `ripemd160(msg)`

Hashes a message using RIPEMD-160 algorithm.

**Arguments**

- `msg` - bytes to hash

**Returns**

`20`-byte hash of the message


## `hash160(msg)`

Hashes a message using SHA-256 algorithm and then using RIPEMD-160.

**Arguments**

- `msg` - bytes to hash

**Returns**

`20`-byte hash of the message

## `tagged_hash(tag, msg)`

Hashes a message with a tag using tagged hash defined in taproot update *add ref*.

Different tags are used for different application, for example in taproot `"BIP0340/nonce"` is used for nonce generation, `"BIP0340/challenge"` for signing etc.

This allows reusing of the hash function without worrying about getting the same hashes for different applications.

Internaly does `sha256(sha256(tag) + sha256(tag) + data)`

**Arguments**

- `tag` - a tag string uniquie for your application.
- `msg` - bytes to hash

**Returns**

`32`-byte hash of the message.

## `tagged_hash_init(tag, msg=b"")`

Initializes a tagged hash object for more data.

**Arguments**

- `tag` - a tag string uniquie for your application
- `msg` - first bytes to hash, `b""` by default

**Retuns**

a hash object that can be used to `.update()` with more data and `digest()` at the end.

After `digest()` the result will be `32`-bytes.

**Example**

```python
from embit import hashes

h = hashes.tagged_hash_init("TapMessage", b"Taproot")
h.update(b" is coming!")
result = h.digest()
```