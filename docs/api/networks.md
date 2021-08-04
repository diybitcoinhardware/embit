# Networks

`embit.networks` module stores a list of dictionaries called `NETWORKS` with all constants for different bitcoin networks.

Available networks: `main`, `test`, `regtest`, `signet`.

Every network stores a bunch of constants necessary for serializations or converting things to strings.

Here is a list of keys for `NETWORKS['main']`:

```python
{
    "name": "Mainnet", # human-readable name of the network
    "wif": b"\x80",    # byte for private key to WIF conversion
    "p2pkh": b"\x00",  # byte for pay-to-pubkeyhash address encoding
    "p2sh": b"\x05",   # byte for pay-to-scripthash address encoding
    "bech32": "bc",    # hrp for segwit addresses
    "xprv": b"\x04\x88\xad\xe4", # version bytes for bip32 privkey
    "xpub": b"\x04\x88\xb2\x1e", # version bytes for bip32 pubkey
    # slip-132 version bytes for some software wallets (zpub/ypub....)
    "yprv": b"\x04\x9d\x78\x78", # nested segwit privkey
    "zprv": b"\x04\xb2\x43\x0c", # native segwit privkey
    "Yprv": b"\x02\x95\xb0\x05", # nested segwit multisig privkey
    "Zprv": b"\x02\xaa\x7a\x99", # native segwit multisig privkey
    "ypub": b"\x04\x9d\x7c\xb2", # nested segwit pubkey
    "zpub": b"\x04\xb2\x47\x46", # native segwit pubkey
    "Ypub": b"\x02\x95\xb4\x3f", # nested segwit multisig pubkey
    "Zpub": b"\x02\xaa\x7e\xd3", # native segwit multisig pubkey
    # coin type for bip32 derivation, m/purpose'/coin'/account'
    # coin = 0 for mainnet, 1 for all test networks
    "bip32": const(0),
}
```

> If you are using Liquid you should also check out [`liquid.networks`](./liquid/networks.md) module.

If you want to add any bitcoin-compatible altcoin (doge, litecoin, whatever) - just add a new network dict to `embit.networks.NETWORKS`.

## Examples

Getting correct derivation path for master public key and serializing it to zpub:

```python
from embit.bip32 import HDKey
from embit.networks import NETWORKS

# using regtest network
net = NETWORKS['regtest']

# root key
root = HDKey.from_string("xprv9s21ZrQH143K4aeaQbwbZ7GhNQB25FDKmjk74dwURkbEYLCAnVgoFiSRtdvnjr8Ji14j4A4iuFuBfNjTYSCo3C84nsrLuTAs82RMUbbJcdW")

# derivation for native segwit on regtest
derivation = "m/84h/%dh/0h" % net['bip32']
xpub = root.derive(derivation).to_public()

# using slip132 version for zpub on regtest
print(xpub.to_string(net['zpub']))
# >>> vpub5Y7s5qS3ZCBKbSTv6tTdBVbhfpYa7RvRGtHkQpXga7fuMmyDkGH5r96pg4fVmkeFxdUxUZSXSpQUZyRseVzNELBXQs1EnAf3RgWCAVwaDzB
```

Printing regtest addresses
```python
from embit import ec, script
from embit.networks import NETWORKS

# using regtest network
net = NETWORKS['regtest']

# private key
prv = ec.PrivateKey(b"1"*32)

# nested segwit
sc = script.p2sh(script.p2wpkh(prv))
# print address for correct network
print(sc.address(net))
# >>> 2N48D2its4X4y3RDf3rESionB45SwGTVLeU

# native segwit
sc = script.p2wpkh(prv)
# print address for correct network
print(sc.address(net))
# >>> bcrt1qsvsxz8lsxg3rc86tk8am6g53l54n7s7eq98mfg

```