import sys
if sys.implementation.name == 'micropython':
    from micropython import const
else:
    from .util import const

NETWORKS = {
    "main": {
        "name":   "Mainnet",
        "wif":    b'\x80',
        "p2pkh":  b'\x00',
        "p2sh":   b'\x05',
        "bech32":  "bc",
        "xprv":   b'\x04\x88\xad\xe4',
        "xpub":   b'\x04\x88\xb2\x1e',
        "yprv":   b'\x04\x9d\x78\x78',
        "zprv":   b'\x04\xb2\x43\x0c',
        "Yprv":   b'\x02\x95\xb0\x05',
        "Zprv":   b'\x02\xaa\x7a\x99',
        "ypub":   b'\x04\x9d\x7c\xb2',
        "zpub":   b'\x04\xb2\x47\x46',
        "Ypub":   b'\x02\x95\xb4\x3f',
        "Zpub":   b'\x02\xaa\x7e\xd3',
        "bip32":  const(0) # coin type for bip32 derivation
    },
    "test": {
        "name":   "Testnet",
        "wif":    b'\xEF',
        "p2pkh":  b'\x6F',
        "p2sh":   b'\xC4',
        "bech32":  "tb",
        "xprv":   b'\x04\x35\x83\x94',
        "xpub":   b'\x04\x35\x87\xcf',
        "yprv":   b'\x04\x4a\x4e\x28',
        "zprv":   b'\x04\x5f\x18\xbc',
        "Yprv":   b'\x02\x42\x85\xb5',
        "Zprv":   b'\x02\x57\x50\x48',
        "ypub":   b'\x04\x4a\x52\x62',
        "zpub":   b'\x04\x5f\x1c\xf6',
        "Ypub":   b'\x02\x42\x89\xef',
        "Zpub":   b'\x02\x57\x54\x83',
        "bip32":  const(1)
    },
    "regtest": {
        "name":   "Regtest",
        "wif":    b'\xEF',
        "p2pkh":  b'\x6F',
        "p2sh":   b'\xC4',
        "bech32":  "bcrt",
        "xprv":   b'\x04\x35\x83\x94',
        "xpub":   b'\x04\x35\x87\xcf',
        "yprv":   b'\x04\x4a\x4e\x28',
        "zprv":   b'\x04\x5f\x18\xbc',
        "Yprv":   b'\x02\x42\x85\xb5',
        "Zprv":   b'\x02\x57\x50\x48',
        "ypub":   b'\x04\x4a\x52\x62',
        "zpub":   b'\x04\x5f\x1c\xf6',
        "Ypub":   b'\x02\x42\x89\xef',
        "Zpub":   b'\x02\x57\x54\x83',
        "bip32":  const(1)
    },
    "signet": {
        "name":   "Signet",
        "wif":    b'\xEF',
        "p2pkh":  b'\x6F',
        "p2sh":   b'\xC4',
        "bech32":  "tb",
        "xprv":   b'\x04\x35\x83\x94',
        "xpub":   b'\x04\x35\x87\xcf',
        "yprv":   b'\x04\x4a\x4e\x28',
        "zprv":   b'\x04\x5f\x18\xbc',
        "Yprv":   b'\x02\x42\x85\xb5',
        "Zprv":   b'\x02\x57\x50\x48',
        "ypub":   b'\x04\x4a\x52\x62',
        "zpub":   b'\x04\x5f\x1c\xf6',
        "Ypub":   b'\x02\x42\x89\xef',
        "Zpub":   b'\x02\x57\x54\x83',
        "bip32":  const(1)
    }
}
