# Ellictic curve keys and signatures

This module includes classes for signatures and individual private and public keys.

Defined classes:
- [`PrivateKey`](./private_key.md)
- [`PublicKey`](./public_key.md)
- [`Signature`](./signature.md) - ECDSA signature
- [`SchnorrSig`](./schnorr_sig.md) - Schnorr signature

!> Schnorr and taproot support is experimental and API is not stable yet!

**Example**

```python
from embit import ec
from embit.networks import NETWORKS

# pass 32-byte big-endian secret key to the constructor
pk = ec.PrivateKey(b"1"*32)
# string representation is WIF
print(pk)
# >>> KxsLKrFM2X4k...ni3DeKDcDFeS3DU

# pass network to get WIF for it
print(pk.to_string(NETWORKS['test']))
# >>> cPEKnmFCTam1...ypDAYikyDrxLXSx4Z

# load from WIF
pk = PrivateKey.from_string("KxsLKrFM2X4kK4zkxGtmTaWv2tvyNLdZmuMWhni3DeKDcDFeS3DU")

# get corresponding public key
pub = pk.get_public_key()
# serialize to SEC format (33-byte repr)
pub.sec()
# serialize as x-only public key (taproot)
pub.xonly()
# string representation is hex of SEC
print(pub)
# >>> 036930f46dd0b1...1cafceb82

# sign a message using ECDSA
msg = b"5"*32
sig = pk.sign(msg)
# serialization - DER encoding
# string repr - hex of DER serialization
print(sig)
# >>> 304402200f735678a171...5a30e4f2f5bfd

# verify the signature
pub.verify(sig, msg)
# >>> True

# tweak private key (taproot)
# argument is hash of tapscript
tweak = b"3"*32
tweaked_pk = pk.taproot_tweak(tweak)
# sign a message with Schnorr
schnorrsig = tweaked_pk.schnorr_sign(msg)
# serialization - 64 byte encoded sig
# string repr - hex of serialization
print(schnorrsig)
# >>> 2b81e113a3a1498...13952ece745513

# verify schnorr signature
tweaked_pub = pub.taproot_tweak(tweak)
tweaked_pub.schnorr_verify(schnorrsig, msg)
# >>> True
```
