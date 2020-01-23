from embit import script
from embit import bip32
from embit import bip39
from embit.networks import NETWORKS
from embit import psbt
from binascii import unhexlify, hexlify
# base64 encoding
from binascii import a2b_base64, b2a_base64

# example of key and address derivations from mnemonic
# you can check that everything works right 
# on https://iancoleman.io/bip39/

def main():
    # get root key from the mnemonic
    mnemonic = "alien visual jealous source coral memory embark certain radar capable clip edit"
    seed = bip39.mnemonic_to_seed(mnemonic)
    root = bip32.HDKey.from_seed(seed, version=NETWORKS["test"]["xprv"])

    # get bip84-xpub to import to Bitcoin Core:
    # we will use the form [fingerprint/derivation]xpub
    # to import to Bitcoin Core with descriptors

    # first let's get the root fingerprint
    # we can get it from any child of the root key
    fingerprint = root.child(0).fingerprint
    hardened_derivation = "m/84h/1h/0h"
    # derive account according to bip84
    bip84_xprv = root.derive(hardened_derivation)
    # corresponding master public key:
    bip84_xpub = bip84_xprv.to_public()
    print("[%s%s]%s" % (
                hexlify(fingerprint).decode('utf-8'),
                hardened_derivation[1:],
                bip84_xpub.to_base58())
        )

    # parse psbt transaction
    b64_psbt = "cHNidP8BAHICAAAAAY3LB6teEH6qJHluFYG3AQe8n0HDUcUSEuw2WIJ1ECDUAAAAAAD/////AoDDyQEAAAAAF6kU882+nVMDKGj4rKzjDB6NjyJqSBCHaPMhCgAAAAAWABQUbW8/trQg4d3PKL8WLi2kUa1BqAAAAAAAAQEfAMLrCwAAAAAWABTR6Cr4flM2A0LMGjGiaZ+fhod37SIGAhHf737H1jCUjkJ1K5DqFkaY0keihxeWBQpm1kDtVZyxGLMX7IZUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDPtTTi27VFw59jdmWDV8b1YciQzhYGO7m8zB9CvD0brcYsxfshlQAAIABAACAAAAAgAEAAAAAAAAAAA=="
    # first convert it to binary
    raw = a2b_base64(b64_psbt)
    # then parse
    tx = psbt.PSBT.parse(raw)

    # print how much we are spending and where
    total_in = 0
    for inp in tx.inputs:
        total_in += inp.witness_utxo.value
    print("Inputs:", total_in, "satoshi")
    change_out = 0 # value that goes back to us
    send_outputs = []
    for i, out in enumerate(tx.outputs):
        # check if it is a change or not:
        change = False
        # should be one or zero for single-key addresses
        for pub in out.bip32_derivations:
            # check if it is our key
            if out.bip32_derivations[pub].fingerprint == fingerprint:
                hdkey = root.derive(out.bip32_derivations[pub].derivation)
                mypub = hdkey.key.get_public_key()
                if mypub != pub:
                    raise ValueError("Derivation path doesn't look right")
                # now check if provided scriptpubkey matches
                sc = script.p2wpkh(mypub)
                if sc == tx.tx.vout[i].script_pubkey:
                    change = True
                    continue
        if change:
            change_out += tx.tx.vout[i].value
        else:
            send_outputs.append(tx.tx.vout[i])
    print("Spending", total_in-change_out, "satoshi")
    fee = total_in-change_out
    for out in send_outputs:
        fee -= out.value
        print(out.value,"to",out.script_pubkey.address(NETWORKS["test"]))
    print("Fee:",fee,"satoshi")

    # sign the transaction
    tx.sign_with(root)
    raw = tx.serialize()
    # convert to base64
    b64_psbt = b2a_base64(raw)
    # somehow b2a ends with \n...
    if b64_psbt[-1:] == b"\n":
        b64_psbt = b64_psbt[:-1]
    # print
    print("\nSigned transaction:")
    print(b64_psbt.decode('utf-8'))
    # now transaction is ready to be finalized and broadcasted
    # it can be done with Bitcoin Core
    # bitcoin-cli finalizepsbt
    # bitcoin-cli sendrawtransaction

if __name__ == '__main__':
    main()