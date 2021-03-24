from embit import script
from embit import bip32
from embit import bip39
from embit.networks import NETWORKS
from binascii import unhexlify, hexlify
import random

# example of key and address derivations from mnemonic
# you can check that everything works right
# on https://iancoleman.io/bip39/


def main():
    # generate 16 bytes of entropy and
    # convert to a mnemonic phrase (12 words)
    entropy = bytes([random.getrandbits(8) for i in range(16)])
    mnemonic = bip39.mnemonic_from_bytes(entropy)
    # or just define hardcoded:
    mnemonic = "alien visual jealous source coral memory embark certain radar capable clip edit"
    print(mnemonic)
    # convert to seed, empty password
    seed = bip39.mnemonic_to_seed(mnemonic)
    # convert to the root key
    # you can define the version - x/y/zprv for desired network
    root = bip32.HDKey.from_seed(seed, version=NETWORKS["test"]["xprv"])
    print(root.to_base58())

    print("\nBIP-44 - legacy")
    # derive account according to bip44
    bip44_xprv = root.derive("m/44h/1h/0h")
    print(bip44_xprv.to_base58())
    # corresponding master public key:
    bip44_xpub = bip44_xprv.to_public()
    print(bip44_xpub.to_base58())
    # first 5 receiving addresses
    for i in range(5):
        # .key member is a public key for HD public keys
        #            and a private key for HD private keys
        pub = bip44_xpub.derive("m/0/%d" % i).key
        sc = script.p2pkh(pub)
        print(sc.address(NETWORKS["test"]))

    print("\nBIP-84 - native segwit")
    # derive account according to bip84
    bip84_xprv = root.derive("m/84h/1h/0h")
    # you can also change version of the key to get zpub (vpub on testnet)
    bip84_xprv.version = NETWORKS["test"]["zprv"]
    print(bip84_xprv.to_base58())
    # corresponding master public key:
    bip84_xpub = bip84_xprv.to_public()
    print(bip84_xpub.to_base58())
    # first 5 receiving addresses
    for i in range(5):
        pub = bip84_xpub.derive("m/0/%d" % i).key
        sc = script.p2wpkh(pub)
        print(sc.address(NETWORKS["test"]))

    print("\nBIP-49 - nested segwit")
    # derive account according to bip49
    bip49_xprv = root.derive("m/49h/1h/0h")
    # you can also change version of the key to get ypub (upub on testnet)
    bip49_xprv.version = NETWORKS["test"]["yprv"]
    print(bip49_xprv.to_base58())
    # corresponding master public key:
    bip49_xpub = bip49_xprv.to_public()
    print(bip49_xpub.to_base58())
    # first 5 receiving addresses
    for i in range(5):
        pub = bip49_xpub.derive("m/0/%d" % i).key
        # use p2sh(p2wpkh(pubkey)) to get nested segwit scriptpubkey
        sc = script.p2sh(script.p2wpkh(pub))
        print(sc.address(NETWORKS["test"]))


if __name__ == "__main__":
    main()
