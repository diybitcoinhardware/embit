from embit import script
from embit import ec
from embit.networks import NETWORKS
from binascii import unhexlify, hexlify

def main():
    # all from the same private key
    prv = ec.PrivateKey.from_wif("L2e5y14ZD3U1J7Yr62t331RtYe2hRW2TBBP8qNQHB8nSPBNgt6dM")
    pub = prv.get_public_key()
    print("Public key:")
    print(hexlify(pub.serialize()))

    # we will generate regtest addresses
    network = NETWORKS['regtest']

    print("Legacy (pay to pubkey hash):")
    sc = script.p2pkh(pub)
    # default network is main
    print(sc.address(network))

    print("Segwit (pay to witness pubkey hash):")
    sc = script.p2wpkh(pub)
    print(sc.address(network))

    print("Nested segwit (p2sh-p2wpkh):")
    sc = script.p2sh(script.p2wpkh(pub))
    print(sc.address(network))

    print("\nMiltisig address (2 of 3):")
    # unsorted
    pubs = [
        ec.PublicKey.parse(unhexlify("02edd7a58d2ff1e483d35f92a32e53607423f936b29bf95613cab24b0b7f92e0f1")),
        ec.PublicKey.parse(unhexlify("03a4a6d360acc45cb281e0022b03218fad6ee93881643488ae39d22b854d9fa261")),
        ec.PublicKey.parse(unhexlify("02e1fdc3b011effbba4b0771eb0f7193dee24cfe101ab7e8b64516d83f7116a615")),
    ]
    # 2 of 3 multisig script
    sc = script.multisig(2, pubs)
    print("Legacy, unsorted (p2sh):")
    redeem_sc = script.p2sh(sc)
    print(redeem_sc.address(network))

    print("Native segwit, sorted (p2wsh):")
    sc = script.multisig(2, sorted(pubs))
    witness_sc = script.p2wsh(sc)
    print(witness_sc.address(network))

    print("Nested segwit, sorted (p2sh-p2wsh):")
    sc = script.multisig(2, sorted(pubs))
    witness_sc = script.p2wsh(sc)
    redeem_sc = script.p2sh(witness_sc)
    print(redeem_sc.address(network))

if __name__ == '__main__':
    main()