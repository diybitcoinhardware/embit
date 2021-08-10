# Bech32 encoding

Supports both bech32 and bech32m (taproot) encoding.

## `encode(hrp, ver, witprog)`

Encodes a segwit address

**Arguments**

- `hrp` - human readable prefix of segwit address, i.e. `bc` or `embit.networks.NETWORKS['test']['bech32']`
- `ver` - version of the witness script, `0` for segwit, `1` for taproot
- `witprog` - witness program (i.e. `pkh(pubkey)`, `sha256(witness_script)` or `tweaked_pubkey` for taproot)

**Returns**

bech32(m) encoded string. For `ver=0` uses `bech32` encoding, for larger versions uses `bech32m`.

**Example**

```python
from embit import bech32
from embit import hashes, ec

pubkey = ec.PrivateKey(b"1"*32).get_public_key()
pkh = hashes.hash160(pubkey.sec())

# segwitv0 address
addr = bech32.encode('bc', 0, pkh)
# >>> bc1qsvsxz8lsxg3rc86tk8am6g53l54n7s7eg2999j

# segwitv1 address
xonly = pubkey.taproot_tweak().xonly()
addr = bech32.encode('bc', 1, xonly)
# >>> bc1p0wtdhnjpfpndcs6y459tqfs3rsksycxs53cv8msa23yyr55lay2q0jm74p
```

## `decode(hrp, addr)`

Decodes segwit address from bech32(m) encoding

**Arguments**

- `hrp` - human readable part of the address (can be obtained as `addr.split('1')[0]`)
- `addr` - address to decode

**Returns**

a tuple `(ver, witprog)` where `ver` is segwit version (0-16) and `witprog` is a witness program (list of ints).

If decoding fails returns `(None, None)`.

**Example**

```python
from embit import bech32

ver, prog = bech32.decode("bc", "bc1qsvsxz8lsxg3rc86tk8am6g53l54n7s7eg2999j")
# >>> (0, [131, 32, 97, 31, 240, 50, 34, 60, 31, 75, 177, 251, 189, 34, 145, 253, 43, 63, 67, 217])

addr = "bc1p0wtdhnjpfpndcs6y459tqfs3rsksycxs53cv8msa23yyr55lay2q0jm74p"
hrp = addr.split("1")[0]
ver, prog = bech32.decode(hrp, addr)
# >>> (1, [123, 150, 219, 206, 65, 72, 102, 220, 67, 68, 173, 10, 176, 38, 17, 28, 45, 2, 96, 208, 164, 112, 195, 238, 29, 84, 72, 65, 210, 159, 233, 20])

ver, prog = bech32.decode("bc", "bc1qsvsxz8lsxg3rc86t")
# >>> (None, None)
```
