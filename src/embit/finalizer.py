from . import ec
from .script import Witness, Script
from .transaction import Transaction


def parse_multisig(sc):
    """Parse Script containing multisig and return threshold and pubkeys"""
    d = sc.data
    if d[-1] != 0xAE:
        raise RuntimeError("Not multisig")
    m = d[0] - 80
    n = d[-2] - 80
    if m > n or m < 1 or n < 1 or m > 16 or n > 16:
        raise RuntimeError("Invalid m or n in multisig script")
    pubs = d[1:-2]
    if len(pubs) % 34 != 0:
        raise RuntimeError("Pubkeys of strange length")
    if len(pubs) != 34 * n:
        raise RuntimeError("Not enough pubkeys")
    pubkeys = [ec.PublicKey.parse(pubs[i * 34 + 1 : (i + 1) * 34]) for i in range(n)]
    return m, pubkeys


def finalize_psbt(psbt, ignore_missing=False):
    """
    Extract final transaction from a signed psbt,
    when common single-sig or multisig scripts are used.

    Call on psbt containing not all sigs will return None.
    Doesn't work on miniscript scripts or some custom scripts.

    UNRELIABLE! MAY FAIL ON VARIOUS EDGE CASES!
    """
    # ugly copy
    ttx = Transaction.parse(psbt.tx.serialize())
    done = 0
    for i, inp in enumerate(ttx.vin):
        pinp = psbt.inputs[i]
        if pinp.final_scriptwitness is not None and pinp.final_scriptwitness:
            inp.witness = pinp.final_scriptwitness
            done += 1
            if pinp.final_scriptsig is not None and pinp.final_scriptsig:
                inp.script_sig = pinp.final_scriptsig
            continue
        if pinp.final_scriptsig is not None and pinp.final_scriptsig:
            inp.script_sig = pinp.final_scriptsig
            done += 1
            continue
        if psbt.utxo(i).script_pubkey.script_type() == "p2pkh":
            if not psbt.inputs[i].partial_sigs:
                continue
            d = b""
            # meh, ugly, doesn't check pubkeys
            for k in psbt.inputs[i].partial_sigs:
                v = psbt.inputs[i].partial_sigs[k]
                d += bytes([len(v)]) + v + bytes([len(k.sec())]) + k.sec()
            ttx.vin[i].script_sig = Script(d)
            done += 1
            continue

        if psbt.inputs[i].redeem_script is not None:
            ttx.vin[i].script_sig = Script(psbt.inputs[i].redeem_script.serialize())

        # if multisig
        if psbt.inputs[i].witness_script is not None:
            m, pubs = parse_multisig(psbt.inputs[i].witness_script)
            sigs = []
            for pub in pubs:
                if pub in psbt.inputs[i].partial_sigs:
                    sigs.append(psbt.inputs[i].partial_sigs[pub])
                if len(sigs) == m:
                    break
            if len(sigs) == m or ignore_missing:
                inp.witness = Witness(
                    [b""] + sigs + [psbt.inputs[i].witness_script.data]
                )
                done += 1
            continue

        # meh, ugly, doesn't check pubkeys
        for k in psbt.inputs[i].partial_sigs:
            v = psbt.inputs[i].partial_sigs[k]
            arr = [v, k.sec()]
            # if psbt.inputs[i].redeem_script:
            #     arr = [psbt.inputs[i].redeem_script.data] + arr
            inp.witness = Witness(arr)
            done += 1

        # TODO: legacy multisig
    if not ignore_missing and done < len(ttx.vin):
        return None
    return ttx
