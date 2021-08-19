# BIP-32 key derivation

[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) defines how to derive infinite amount of keys from a single master key. This module contains an [`HDKey`](#HDKey) class that implements key derivation.

There are also a few handy functions:
- [`parse_path(path)`](#parse_path) - converts a string like `"m/44h/18"` or `"m/44'/18"` to a list of integers.
- [`path_to_str(path, fingerprint=None)`](#path_to_str) - converts a list of integers to human-readable path.
- [`detect_version(path, default="xprv", network=None)`](#detect_version) - tries to guess a correct [slip132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md) version for the key depending on it's derivation.

**Example**

```python
from embit import bip32, hashes, script
from embit.networks import NETWORKS

net = NETWORKS['main']
seed = hashes.sha256(b"hello bitcoin")

root = bip32.HDKey.from_seed(seed)
# use correct coin type:
bip84_derivation = "m/84h/%dh/0h" % net["bip32"]

account_prv = root.derive(bip84_derivation)
# convert to public key
account = account_prv.to_public()
print(account)
# >>> xpub6DNXxQY6Z14cCuGLZWn8y23FnN7sKdJnbHyFxL85E51wGL7W5YdTxrE1URDoLmGBXv8qzdHtbWEfhkuxmsKbiZcD5xYkiaR3EtLXocsJ2g2
# if we want zpub:
print(account.to_string(net['zpub']))
# >>> zpub6s34ZjsvrN9ZuVeaEEMPPCEG8JQmCsHnRX1hX7uqz5mhNXjxarxbCyYHWq8yLaa2MCNTVaV1WpwmUL96DG9dK2yQpdwbtQ41nLTpaqTTP25

# derive first 5 receiving addresses:
for i in range(5):
    xpub = account.derive([0, i])
    print(script.p2wpkh(xpub).address(net))

# >>> bc1q7x7azsadquwx8k7spn9jxf4mufaajz4wntelrt
# >>> bc1qr38lduepednsc8y0l2cakhsvmypkvfzq63en59
# >>> bc1qrf9pl8cd2sz5jwrcwutgmh6zt8csa762hnpufp
# >>> bc1qr2dua836l2sfwckk5ncckqa06evupqkxatxeyk
# >>> bc1qfqp53fh6s3tn06q9cv6sgnhzl9u370gujv4cfs
```

# `HDKey`

## Constructor

Default constructor is probably not what you want to use. Take a look at the [`HDKey.from_seed()`](#hdkeyfrom_seed) method.

```python
HDKey(key, chain_code, version=None, depth=0, fingerprint=b"\x00\x00\x00\x00", child_number=0)`
```

- `key` - internal key: `PrivateKey` or `PublicKey`
- `chain_code` - `32`-bytes chain code
- `version = None` - `4`-byte version, optional. Mainnet version bytes are used by default (`NETWORKS['main']['xprv']` for private, `NETWORKS['main']['xpub']` for public).
- `depth = 0` - depth of this key from the root.
- `fingerprint = b"\x00\x00\x00\x00"` - `4` bytes of the parent fingerprint. Zeroes for the root key.
- `child_number = 0` - derivation index used to derive this key from parent.

### `HDKey.from_seed()`

Class method, converts a seed to an instance of `HDKey` (private key).

**Arguments**

- `seed` - bytes sequence to use. Normally `32`-byte or `64`-byte seeds are used.
- `version` - version to use, by default it's `NETOWRKS['main']['xprv']`

**Returns**

a root private `HDKey`

**Example**

```python
from embit import bip32, bip39
from embit.networks import NETWORKS

seed = bip39.mnemonic_to_seed("abandon "*11+"about")

root = bip32.HDKey.from_seed(seed)
print(root)
# >>> xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu

root = bip32.HDKey.from_seed(seed, version=NETWORKS['test']['xprv'])
print(root)
# >>> tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd
```

## Serialization

`78`-byte sequence: `<version><depth><fingerprint><child_number><chain_code><public_key.sec() or 00 | private_key>`.

**Parsing (class methods):**

- `HDKey.parse(bytes)` - parses a `78`-byte serialized hd key.
- `HDKey.read_from(stream)` - reads `78` bytes from stream and parses them.

**Serialization:**

- `hd.serialize()` - returns `78` bytes with serialized hd key.
- `hd.write_to(stream)` - writes `78` bytes with the hd key to stream.

## String representation

Base58 encoded string - see [`to_base58`](#to_base58) and [`from_base58`](#from_base58) methods.

Can receive desired version bytes as an optional argument (i.e. `hd.to_string(NETWORKS['test']['Zprv'])`).

- `HDKey.from_base58("xprv...")` - decodes extended key from base58 string
- `HDKey.from_string("xprv...")` - same as `from_base58()`


- `hd.to_base58(version=None)` - encodes extended key to base58 string. Optional argument is 4-byte version to use for conversion.
- `hd.to_string(network=None)` - same as `hd.to_base58(network)`
- `str(hd)` - same as `hd.to_base58()` using internal version bytes.

**Example**

```python
from embit import bip32
from embit.networks import NETWORKS

hd = bip32.HDKey.from_string("xpub6E9ZNSc5cMXcmgeCuNZLyUtQknqXvJuZM8rddhJBNgDvpGuRsTmttsnL4vfFoqzA7Y5WhmnvEYFg8CTnqx3dKQbMkPtB9qqtwVkpE1fddqQ")
print(hd)
# >>> xpub6E9ZNSc5cMXcmgeCuNZLyUtQknqXvJuZM8rddhJBNgDvpGuRsTmttsnL4vfFoqzA7Y5WhmnvEYFg8CTnqx3dKQbMkPtB9qqtwVkpE1fddqQ

# print for testnet
print(hd.to_string(NETWORKS["test"]["xpub"]))
# >>> tpubDEXBtgRmKdV53Uq4MZYSBQDn5uwBuhQctmSvzFMKiaypZZa8wgcz3KTAJxk3LLwPuScRKMJnme5ipNxQEotsCr3eozdUqNW8XTMDz3HX6F8

# print zpub - for wallets that use slip132 prefixes to determine wallet types. (zpub - nested segwit)
print(hd.to_string(NETWORKS["main"]["zpub"]))
# >>> zpub6sp5ymwuuicaUH2Sa68bPf5R6j8RoYtZBMu5CV5x8gygvUXtNn72916c7LaRofHzvpK8Ciz39rxmtmgvHLseusxZV5H2KfUsUwt71AX1Uff
```

Parse zpub and normalize to xpub:

```python
from embit import bip32
from embit.networks import NETWORKS

hd = bip32.HDKey.from_string("zpub6sp5ymwuuicaUH2Sa68bPf5R6j8RoYtZBMu5CV5x8gygvUXtNn72916c7LaRofHzvpK8Ciz39rxmtmgvHLseusxZV5H2KfUsUwt71AX1Uff")

# overwrite version with correct bytes
hd.version = NETWORKS["main"]["xpub"]

# now it will print properly
print(hd)
# >>> xpub6E9ZNSc5cMXcmgeCuNZLyUtQknqXvJuZM8rddhJBNgDvpGuRsTmttsnL4vfFoqzA7Y5WhmnvEYFg8CTnqx3dKQbMkPtB9qqtwVkpE1fddqQ
```

## Attributes

You can change them at any time.

- `version` - 4 version bytes, that define how the key will look when converted into string. See [string representation](#string-representation).
- `chain_code` - chain code of the key. Only `chain_code` and `key` define how child keys are derived, everything else is just metadata.
- `key` - internal key - either `PrivateKey` or `PublicKey`.
- `depth` - derivation depth of the key.
- `fingerprint` - parent fingerprint. For every `child()` of this key `fingerprint` will be equal to this key's `my_fingerprint` property.
- `child_number` - derivation index that was used to derive this key from parent.

## Properties

These properties only implement getter, so you can't change them.

- `my_fingerprint` - `4`-byte fingerprint of the key itself (first 4 bytes of the `hash160(pubkey)`).
- `is_private` - `bool`, returns `True` if it's internal key is private, `False` otherwise.
- `secret` - `32`-byte big-endian scalar of the internal private key. It will raise an error if hd key is public.

## Methods

- [`derive(path)`](#derive) - derives a child using path. `path` can be a string or a list of ints. For example `"m/1h/2"`, or `[0x80000001, 2]`.
- [`child(index, hardened=False)`](#child) - derives a child key using index `index`. `hd.child(0x80000000+index)` and `hd.child(index, hardened=True)` do the same.
- [`to_public()`](#to_public) - for private keys only. Returns corresponding public `HDKey`.
- [`taproot_tweak(tweak=b"")`](#taproot_tweak) - returns an `HDKey` where internal key is tweaked according to taproot rules.

### `derive()`

Derives a child using derivation path.

**Arguments**

- `path` - a string or a list of ints. For example `"m/1h/2"`, or `[0x80000001, 2]`.

**Returns**

an `HDKey` instance that is a child derived from current key according to the path.

**Example**

```python
from embit import bip32

root = bip32.HDKey.from_string("xprv9s21ZrQH143K2hVFVMNwgd5ihtjdqEAXhVemEBMHUgBeaBysy1UF6RA3wicT7JDiUMqrQnPmdqe93s1AcpxYLEGer1hrgZGcF4L2nFo17Xc")
print(root.depth)
# >>> 0

# account key
acc = root.derive("m/84h/1h/0h")
print(acc)
# >>> xprv9z95vPexopxFTcxk1Fs4LxiVNKjeMd9pgsPGsPgq9djfou6wzWwdBr3EjwhwdPfxGcd7EANDd2pUZVzLezYymQKB2kuSW3yhM32fjgFXbiu
print(acc.depth)
# >>> 3

# key for the first address
first = acc.derive([0, 0])
# internal key (individual private key)
print(first.key)
# >>> KxgpTzgC3zXeHvVocyGsKSuxvDSRFjouDKCTM74URbTYc7J4TK3e
print(first.depth)
# >>> 5
```

### `child()`

Derives a direct child with provided index. Hardened derivation is possible only if the extended key is private.

**Arguments**

- `index` - an index to use for derivation.
- `hardened = False` - whether to use hardened derivation or not. If `index >= 0x80000000` it will be hardened anyways.

**Returns**

an `HDKey` instance that is a child derived from current key according to the path.

**Example**

```python
from embit import bip32

root = bip32.HDKey.from_string("xprv9s21ZrQH143K2hVFVMNwgd5ihtjdqEAXhVemEBMHUgBeaBysy1UF6RA3wicT7JDiUMqrQnPmdqe93s1AcpxYLEGer1hrgZGcF4L2nFo17Xc")

c1 = root.child(44, hardened=True)
c2 = c1.child(0x80000001) # the same as index=1, hardened=True
c3 = c2.child(0)
print(c3)
# >>> xprv9yPvAjKBw9N9UUCs6t22bTmvqzqu2FrfZxYNeHd5WzCSMHVWYymiNpg6adJxxYsDAGYWvyV8uKK3bHsFfcskK8GVymNtaj2gmgwupbfNKQ5

# same using derive() function
print(root.derive("m/44h/1h/0") == c3)
# >>> True
```

### `to_public()`

Converts extended private key to public. Raises an error if applied to hd public key.

**Arguments**

- `version = None` - what version bytes to use in hd public key, by default it's using corresponding version - `xpub` for `xprv`, `Ypub` for `Yprv` etc.

**Returns**

an instance of `HDKey` where internal key is public.

**Example**

```python
from embit import bip32
from embit.networks import NETWORKS

hd = bip32.HDKey.from_string("xprv9s21ZrQH143K2hVFVMNwgd5ihtjdqEAXhVemEBMHUgBeaBysy1UF6RA3wicT7JDiUMqrQnPmdqe93s1AcpxYLEGer1hrgZGcF4L2nFo17Xc")

xpub = hd.to_public()
print(xpub)
# >>> xpub661MyMwAqRbcFBZibNux3m2TFva8EgtP4iaN2Zku31idSzK2WYnVeDUXo1ouwsUfHXTdK5QMXPR8P64j48bunMKNPetYMGaZji93WWsN481

print(hd.to_public(NETWORKS['test']['Zpub']))
# >>> Vpub5dEvVGKn7251yALrsKogTfBFdnKVZoayYmBbP3EfemoGxyFUmdqeVD2BZJrDWVPihiHzgiDMVH6XjgTMuxvqLN4qVSc6arQb5zHdKHT1AEJ
```

## Aliases

From `PrivateKey` class (available only if internal key is private):

- [`get_public_key()`](./ec/private_key.md#get_public_key) - returns a `PublicKey` corresponding to internal key.
- [`sign(msg)`](./ec/private_key.md#sign) - signs a 32-byte message hash and returns ECDSA `Signature`.
- [`schnorr_sign(msg)`](./ec/private_key.md#schnorr_sign) - signs a 32-byte message hash and returns `SchnorrSig`.

From `PublicKey` class:

- [`sec()`](./ec/public_key.md#sec) - SEC serialization of the public key.
- [`xonly()`](./ec/public_key.md#xonly) - x-only serialization of the public key (for taproot).
- [`verify(sig, msg)`](./ec/public_key.md#verify) - verifies ECDSA signature for the message.
- [`schnorr_verify(schnorrsig, msg)`](./ec/public_key.md#schnorr_verify) - verifies schnorr signature for the message.

Other:

- `taproot_tweak()` - tweak internal key, see corresponding method for [`PrivateKey`](./ec/private_key.md#taproot_tweak) and [`PublicKey`](./ec/public_key.md#taproot_tweak)

# Helper functions

## `parse_path()`

Parses a string with derivation path, raises an error if the path is wrong.

**Arguments**

- `path` - a string to parse

**Returns**

A `list` of indexes

**Example**

```python
from embit import bip32

bip32.parse_path("m/55h/123/42'/1")
# >>> [2147483703, 123, 2147483690, 1]

bip32.parse_path("123/456/7/")
# >>> [123, 456, 7]

bip32.parse_path("123q/456/7/")
# >>> raises an error as `123q` is not a valid index
```

## `path_to_str()`

Converts list of indexes to human-readable path.

**Arguments**

- `path` - a list of indexes
- `fingerprint = None` - `4`-byte fingeprint to prepend to the derivation path

**Returns**

a string in the form like `"m/123/45h/7"` or with hex of the fingerprint instead of `m` if provided.

**Example**

```python
from embit import bip32

bip32.path_to_str([1,2,3])
# >>> "m/1/2/3"

bip32.path_to_str([1,2,3], fingerprint=b"\xF0\x0D\xBA\xBE")
# >>> "foodbabe/1/2/3"
```

## `detect_version()`

Finds what [slip132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md) version should be used for provided derivation path:

- for BIP-84 - `zpub/zprv` version
- for BIP-49 - `ypub/yprv` version
- for multisig - `Ypub/Yprv` for nested segwit, `Zpub/Zprv` for native segwit
- for any other - returns provided default

**Arguments**

- `path` - derivation path - a string or a list
- `default = "xprv"` - what key to use for version lookup if we didn't detect a proper one. Pass `xpub` if you have a public key, `xprv` if private.
- `network = None` - network dict to use for lookups, by default it detects network itself using coin derivation type. 

**Returns**

4-byte version that can be passed to the `HDKey` string conversion.

**Example**

```python
from embit import bip32
from embit.networks import NETWORKS

root = bip32.HDKey.from_string("xprv9s21ZrQH143K2hVFVMNwgd5ihtjdqEAXhVemEBMHUgBeaBysy1UF6RA3wicT7JDiUMqrQnPmdqe93s1AcpxYLEGer1hrgZGcF4L2nFo17Xc")
derivations = [
    "m/84h/1h/0h", # bip84 testnet account
    "m/49h/0h/1h/1", # receiving xpub for bip49 mainnet, account 1
    "m/48h/1h/0h/2h", # multisig wsh testnet derivation path
]

for der in derivations:
    ver = bip32.detect_version(der)
    print(der, ":", root.derive(der).to_string(version=ver))

# >>> m/84h/1h/0h : vprv9LUZK4K8WTsHm2aWLYHovnXV2PSkUPApreLqJbu4PcyuhhUVVCcVwiixhXnmdaN7TLPVjDB6hi7NnvmDDbixAvwyJ5WbLELioauNxZVmss9
# >>> m/49h/0h/1h/1 : yprvALkzynQU5H3AAM5MMGNRd8Y3vGFQfVuWUa1oeG5j3uTdT2KutTvueWYR9ahE62FbcDXiCBJVXjQUz36ySapNNph7jfDvpBLhD4JVgzu8Tcn
# >>> m/48h/1h/0h/2h : Vprv1Es21YXuYDmZYRJmPW9FLqMobRfAzN4heN4nER4DSU2ddz6XCgsPUNT1DwsevXbE85rJVePHMBruuue1RuRqa8qRC6npvGDZJ43skygKRe3


# same for xpubs - pass default="xpub" in this case:
for der in derivations:
    ver = bip32.detect_version(der, default="xpub")
    print(der, ":", root.derive(der).to_public().to_string(version=ver))

# >>> m/84h/1h/0h : vpub5ZTuiZr2LqRayWeySZppHvUDaRHEsqtgDsGS6zJfwxWtaVoe2jvkVX3SYmT43BJTJ8fEGngwJ2iFMkBMdun1MRRP7mURPgDrthx6FamTTNL
# >>> m/49h/0h/1h/1 : ypub6ZkMPHwMuebTNq9pTHuRzGUnUJ5u4xdMqnwQSeVLcEzcKpf4S1FACJrtztRbiFvXN7NfQ4h4XvkB7f4AxZc5ryemduENF7xpYwh7uHweTS1
# >>> m/48h/1h/0h/2h : Vpub5mZ49xa9gbTERtLZH9oqkF1vATB79hFcDffZWw6Wrjq2UUMHq5gyes4sQ4GbWwJ5EPv4uaw8KgeMR6pG4FNDMRQDsS5gtuoT4mF6q1CG8AA
```
