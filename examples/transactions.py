from embit import script
from embit import ec
from embit.networks import NETWORKS
from binascii import unhexlify, hexlify
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit import compact


def main():
    # all from the same private key
    prv = ec.PrivateKey.from_wif("L2e5y14ZD3U1J7Yr62t331RtYe2hRW2TBBP8qNQHB8nSPBNgt6dM")
    pub = prv.get_public_key()
    inputs = [
        # legacy
        {
            "txid": unhexlify(
                "7f0c7538e898bbe5531fa47d4057b52c914ec45e20ae1a5572ea1005a8ba50f8"
            ),
            "vout": 0,
            "value": int(1e8),
            "script": script.p2pkh(pub),
        },
        # native segwit
        {
            "txid": unhexlify(
                "f51e6fc2392558a70ae970e93538f368828ad2800a7370f372a652de463429fc"
            ),
            "vout": 0,
            "value": int(2e8),
            "script": script.p2wpkh(pub),
        },
        # nested segwit
        {
            "txid": unhexlify(
                "2e4cb680ed008b6e529c4c83f00d55326a2e68b48ddf11267e3f5323006966a6"
            ),
            "vout": 1,
            "value": int(3e8),
            "script": script.p2sh(script.p2wpkh(pub)),
            "redeem": script.p2wpkh(pub),
        },
    ]
    # sending back almost the same amount
    vin = [TransactionInput(inp["txid"], inp["vout"]) for inp in inputs]
    vout = [TransactionOutput(inp["value"] - 1500, inp["script"]) for inp in inputs]
    tx = Transaction(vin=vin, vout=vout)
    print("Unsigned transaction:")
    print(hexlify(tx.serialize()).decode("utf-8"))

    for i in range(len(inputs)):
        inp = inputs[i]
        script_type = inp["script"].script_type()
        # legacy input
        if script_type == "p2pkh":
            h = tx.sighash_legacy(i, inp["script"])
            sig = prv.sign(h)
            tx.vin[i].script_sig = script.script_sig_p2pkh(sig, pub)
        # native segwit
        elif script_type == "p2wpkh":
            sc = script.p2pkh_from_p2wpkh(inp["script"])
            h = tx.sighash_segwit(i, sc, inp["value"])
            sig = prv.sign(h)
            tx.vin[i].witness = script.witness_p2wpkh(sig, pub)
        # nested segwit
        elif script_type == "p2sh":
            if "redeem" in inp and inp["redeem"].script_type() == "p2wpkh":
                sc = script.p2pkh_from_p2wpkh(inp["redeem"])
                h = tx.sighash_segwit(i, sc, inp["value"])
                sig = prv.sign(h)
                tx.vin[i].script_sig = script.script_sig_p2sh(inp["redeem"])
                tx.vin[i].witness = script.witness_p2wpkh(sig, pub)
            else:
                raise NotImplementedError("Script type is not supported")
        else:
            raise NotImplementedError("Script type is not supported")

    print("Signed transaction:")
    print(hexlify(tx.serialize()).decode("utf-8"))


if __name__ == "__main__":
    main()
