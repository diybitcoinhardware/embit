"""
Multisig transaction verification example:
- parses PSBT transaction
- checks that all inputs are from the same wallet (policy)
- checks that change output is from the same wallet as well
- prints out transaction information for the user
"""
from embit import bip39, bip32, psbt, script, ec
from binascii import a2b_base64, b2a_base64
from io import BytesIO

def parse_multisig(sc):
    """Takes a script and extracts m,n and pubkeys from it"""
    # OP_m <len:pubkey> ... <len:pubkey> OP_n OP_CHECKMULTISIG
    # check min size
    if len(sc.data) < 37 or sc.data[-1] != 0xae:
        raise ValueError("Not a multisig script")
    m = sc.data[0] - 0x50
    if m < 1 or m > 16:
        raise ValueError("Invalid multisig script")
    n = sc.data[-2] - 0x50
    if n < m or n > 16:
        raise ValueError("Invalid multisig script")
    s = BytesIO(sc.data)
    # drop first byte
    s.read(1)
    # read pubkeys
    pubkeys = []
    for i in range(n):
        char = s.read(1)
        if char != b"\x21":
            raise ValueError("Invlid pubkey")
        pubkeys.append(ec.PublicKey.parse(s.read(33)))
    # check that nothing left
    if s.read() != sc.data[-2:]:
        raise ValueError("Invalid multisig script")
    return m, n, pubkeys

def get_cosigners(pubkeys, derivations, xpubs):
    """Returns xpubs used to derive pubkeys using global xpub field from psbt"""
    cosigners = []
    for i, pubkey in enumerate(pubkeys):
        if pubkey not in derivations:
            raise ValueError("Missing derivation")
        der = derivations[pubkey]
        for xpub in xpubs:
            origin_der = xpubs[xpub]
            # check fingerprint
            if origin_der.fingerprint == der.fingerprint:
                # check derivation - last two indexes give pub from xpub
                if origin_der.derivation == der.derivation[:-2]:
                    # check that it derives to pubkey actually
                    if xpub.derive(der.derivation[-2:]).key == pubkey:
                        # append strings so they can be sorted and compared
                        cosigners.append(xpub.to_base58())
                        break
    if len(cosigners) != len(pubkeys):
        raise RuntimeError("Can't get all cosigners")
    return sorted(cosigners)

def get_policy(scope, scriptpubkey, xpubs):
    """Parse scope and get policy"""
    # we don't know the policy yet, let's parse it
    script_type = scriptpubkey.script_type()
    # p2sh can be either legacy multisig, or nested segwit multisig
    # or nested segwit singlesig
    if script_type == "p2sh":
        if scope.witness_script is not None:
            script_type = "p2sh-p2wsh"
        elif scope.redeem_script.script_type() == "p2wpkh":
            script_type = "p2sh-p2wpkh"
    policy = { "type": script_type }
    # expected multisig
    if "p2wsh" in script_type and scope.witness_script is not None:
        m, n, pubkeys = parse_multisig(scope.witness_script)
        # check pubkeys are derived from cosigners
        cosigners = get_cosigners(pubkeys, scope.bip32_derivations, xpubs)
        policy.update({
            "m": m, "n": n, "cosigners": cosigners
        })
    return policy

def main():
    # mnemonic we use
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = bip39.mnemonic_to_seed(mnemonic)
    root = bip32.HDKey.from_seed(seed)

    # A few transactions
    b64psbts = [
        # p2wsh, 2 inputs
        "cHNidP8BALICAAAAAq1DhxRK+mUH4T6uUNob8bUaZ7MP+44MW4+Y9bOxpjhZAAAAAAD9////aWclWQ+45HKrI07r878E2UrAupT2paT4QurbmtNjYNQBAAAAAP3///8CQEIPAAAAAAAiACCpkDPDhmIzPlkJrjw9A71xjbIUWf3VUB7ooFJhTVm04tjSIQEAAAAAIgAgjQKFDauIXsV5u23LBdYgOwX1FwGGrLiQfWzBtFKZ7dIAAAAATwEENYfPBD5i336AAAACQStJhNVJul7vHKbo83VdmuAW2m0WaXLKDlFANn7dUNoCNbhLMdw4Knz7Q7o6exdL6UFhQegW9nJb0SUStbLEpawUAgjLdzAAAIABAACAAAAAgAIAAIBPAQQ1h88EnbHQAIAAAAI/2Nc7x7iMpJNapTe/OJTV4oifqzQcYY9KV2+PGRjCdQJoww1WnSNqfcxXGyux0q1PqfmzUqgJNqKJCpmqI9t47BQmu4PEMAAAgAEAAIAAAACAAgAAgE8BBDWHzwS6wUg5gAAAAh1Pvr3ZZ+GvcUwJl9OPz2cLXOnTAcBEC7zDtqIOt3IcA1aOofNgUZFu0baQw54SqOcGA7KAvTDOXygfKRilU2OqFHPF2gowAACAAQAAgAAAAIACAACAAAEBK4CWmAAAAAAAIgAgiYAxcG7dnrEiZ4VHFVHOo18XCalvhZYuMqBr9n7HESQBBWlSIQJOjQgMfX26XEf+trHIEk3rYkEX5Y2NfrFKQARPcd2X8iEDBWHUgq25PfHvE+hlcBryJG7wo2y8jKUSPY7sd85OOMchA2iVcuKLD+2p1pgcAjfZ5d7b/sFt5xQ/aAoC7V0Vn3WHU64iBgJOjQgMfX26XEf+trHIEk3rYkEX5Y2NfrFKQARPcd2X8hwmu4PEMAAAgAEAAIAAAACAAgAAgAAAAAABAAAAIgYDBWHUgq25PfHvE+hlcBryJG7wo2y8jKUSPY7sd85OOMccAgjLdzAAAIABAACAAAAAgAIAAIAAAAAAAQAAACIGA2iVcuKLD+2p1pgcAjfZ5d7b/sFt5xQ/aAoC7V0Vn3WHHHPF2gowAACAAQAAgAAAAIACAACAAAAAAAEAAAAAAQErgJaYAAAAAAAiACAzd60wM9EFnPHSNbsSJfyipL8myVLVP2/vwzotVUSNxQEFaVIhAiKCMRLlzIhLkRbLIUIMx5KYJM0v6LcjW/mS6K7eFGwiIQKDzUflU23LeecRgzDo5IBCEvaWGfHW7JkNxzXvuc7FdCEDC5DtLoa61/Kk/pdpu0F9e6nKoRJIB9v7Ni377rZefgFTriIGAiKCMRLlzIhLkRbLIUIMx5KYJM0v6LcjW/mS6K7eFGwiHAIIy3cwAACAAQAAgAAAAIACAACAAAAAAAAAAAAiBgKDzUflU23LeecRgzDo5IBCEvaWGfHW7JkNxzXvuc7FdBwmu4PEMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIgYDC5DtLoa61/Kk/pdpu0F9e6nKoRJIB9v7Ni377rZefgEcc8XaCjAAAIABAACAAAAAgAIAAIAAAAAAAAAAAAABAWlSIQKtIdmtKKuZrH7f2R4iIU8RWVOrCdHVWBCS+0e9pZJy/iEDoH074LrWPIA10hyXtBCJDT06GdLkA6+z/PxoJqomPHYhA6GoQ/otQdk71nUpYZFfbkSKdBkkSj4CuPTPYrzGp6JrU64iAgKtIdmtKKuZrH7f2R4iIU8RWVOrCdHVWBCS+0e9pZJy/hwCCMt3MAAAgAEAAIAAAACAAgAAgAEAAAAAAAAAIgIDoH074LrWPIA10hyXtBCJDT06GdLkA6+z/PxoJqomPHYcc8XaCjAAAIABAACAAAAAgAIAAIABAAAAAAAAACICA6GoQ/otQdk71nUpYZFfbkSKdBkkSj4CuPTPYrzGp6JrHCa7g8QwAACAAQAAgAAAAIACAACAAQAAAAAAAAAAAA==",
        # p2sh-p2wsh
        "cHNidP8BAHICAAAAAR30J629i3Y/R8woRpLQ9JUa31rKxyM+Ny4NEsme48GWAAAAAAD9////Atw5XQUAAAAAF6kUdSESczdYagEyToVUSXyT8VTNz+OHgJaYAAAAAAAWABTmav7/w4OOcfCiewfjsA7eaujhYAAAAABPAQQ1h88EPmLffoAAAAHdXEj2dn8EYJ+rRdXEYu5laq6lJI5Mp+3t63ckwty05QKrJBNPewhwQaGPYRif6+XaxozFXvTXn7pU24H6fRy1FxQCCMt3MAAAgAEAAIAAAACAAQAAgE8BBDWHzwSdsdAAgAAAAeeOv56oeaaFTrNonMKDHk1C8brbWGFvdlecVue+v0/RAn/g4yI3oYsyen7OOcT7caYl4Mn7nQbyonHcusUR+GhzFCa7g8QwAACAAQAAgAAAAIABAACATwEENYfPBLrBSDmAAAABpzrb4oeEh2NNy/w/fr3osfyZTx7AaGDPAcP+LqeR3bYC5ioqmXPuazp69HwimlvecLylm9BLuyl/VpPXqiVrl20Uc8XaCjAAAIABAACAAAAAgAEAAIAAAQEgAOH1BQAAAAAXqRSv3gkn8731qcPbSDu4TJOlJJZ/PocBBCIAIOeiFBX5x0vX6CacrAUVovrs1DDCcKJS5qptFS3sjpDpAQVpUiECZ+pFYkOTVjB+eG+vQFA3MNjZWiA6DjRcs1Wl36A/zgMhA2Ygckuwjah29wiVRgA6wFx51+6ayrzeCIQ2eE4zfxPtIQOnUlBn22cn2CPCZkMSI6cDaZK2SlLV20rT6pqMoQCJsFOuIgYCZ+pFYkOTVjB+eG+vQFA3MNjZWiA6DjRcs1Wl36A/zgMcc8XaCjAAAIABAACAAAAAgAEAAIAAAAAAAAAAACIGA2Ygckuwjah29wiVRgA6wFx51+6ayrzeCIQ2eE4zfxPtHCa7g8QwAACAAQAAgAAAAIABAACAAAAAAAAAAAAiBgOnUlBn22cn2CPCZkMSI6cDaZK2SlLV20rT6pqMoQCJsBwCCMt3MAAAgAEAAIAAAACAAQAAgAAAAAAAAAAAAAEAIgAgZBwTq05RkpqKv6FV6LQjuM07Qv0/bYfWVc9NUQOFvwQBAWlSIQI32jVSdTgeu7+YZKrWfgOZ2J/LV36c5rBoApTzhrNlDCEC+hEqm3XmRt862AFFeyJ7p1m8A+V7czj6OajUNgCfg4EhA/MUVfxGh4k3Po3LB8CmMRsvIHcGNO0elUgETaITZA3UU64iAgI32jVSdTgeu7+YZKrWfgOZ2J/LV36c5rBoApTzhrNlDBwCCMt3MAAAgAEAAIAAAACAAQAAgAEAAAAAAAAAIgIC+hEqm3XmRt862AFFeyJ7p1m8A+V7czj6OajUNgCfg4EcJruDxDAAAIABAACAAAAAgAEAAIABAAAAAAAAACICA/MUVfxGh4k3Po3LB8CmMRsvIHcGNO0elUgETaITZA3UHHPF2gowAACAAQAAgAAAAIABAACAAQAAAAAAAAAAAA==",
        # p2wpkh
        "cHNidP8BAHECAAAAAc88WMMpgq4gUIjZvUnrmwKs3009rnalFsazBrFd46FOAAAAAAD9////Anw/XQUAAAAAFgAULzSqHPAKU7BVopGgOn1F8KaYi1KAlpgAAAAAABYAFOZq/v/Dg45x8KJ7B+OwDt5q6OFgAAAAAAABAR8A4fUFAAAAABYAFNDEo+8J6Ze26Z45flGP4+QaEYyhIgYC56slN7XUnpcDCargbp5J82zhyf671E7I4NHMoLT5wxkYc8XaClQAAIABAACAAAAAgAAAAAAAAAAAACICA11J7M1U0AmeQ2did8em1GJdYR2oil30m/lReneRp3elGHPF2gpUAACAAQAAgAAAAIABAAAAAAAAAAAA",
        # p2sh-p2wpkh
        "cHNidP8BAHICAAAAAXbva/K90EDzwdg6zLl0OfGrsaVWrR0PUpaB/6foypSKAQAAAAD9////Apw9XQUAAAAAF6kUJR3RFFeiWcO6R+XMo3F/5CFOApiHgJaYAAAAAAAWABTmav7/w4OOcfCiewfjsA7eaujhYAAAAAAAAQEgAOH1BQAAAAAXqRQzbKoT4IuWCAoytdgY1ZtKs7NnQocBBBYAFDiXH3OTD2wUHZd6xP1KcnyFSTWzIgYDoa+ASsEIqKUXghmMLQNLKL+QyIA/WlP3Ynb6aaTq538Yc8XaCjEAAIABAACAAAAAgAAAAAAAAAAAAAEAFgAUcL6x4EpQCUDp86uqZuGkmsVbjzUiAgKi/ImWxSYiSLXa78Wk0M3NAMEwR9DLEwKBNupjDYdahxhzxdoKMQAAgAEAAIAAAACAAQAAAAAAAAAAAA==",
    ]
    for i, b64psbt in enumerate(b64psbts):
        print("\nTransaction #%d" % (i+1))
        raw = a2b_base64(b64psbt)
        tx = psbt.PSBT.parse(raw)

        # Check inputs of the transaction and check that they use the same script type
        # For multisig parsed policy will look like this:
        # { script_type: p2wsh, cosigners: [xpubs strings], m: 2, n: 3}
        policy = None
        inp_amount = 0
        for inp in tx.inputs:
            inp_amount += inp.witness_utxo.value
            # get policy of the input
            inp_policy = get_policy(inp, inp.witness_utxo.script_pubkey, tx.xpubs)
            # if policy is None - assign current
            if policy is None:
                policy = inp_policy
            # otherwise check that everything in the policy is the same
            else:
                # check policy is the same
                if policy != inp_policy:
                    raise RuntimeError("Mixed inputs in the transaction")

        wallet = "Native Segwit "
        if "p2sh-" in policy["type"]:
            wallet = "Nested Segwit "
        if "m" in policy:
            wallet += "Multisig (%d of %d)" % (policy["m"], policy["n"])
        else:
            wallet += "Single sig"
        print("Spending from: %s" % wallet)
        print("Input amount: %d sat" % inp_amount)
        # now go through outputs and check if they are change
        spending = 0
        change = 0
        for i, out in enumerate(tx.outputs):
            out_policy = get_policy(out, tx.tx.vout[i].script_pubkey, tx.xpubs)
            is_change = False
            # if policy is the same - probably change
            if out_policy == policy:
                # double-check that it's change
                # we already checked in get_cosigners and parse_multisig 
                # that pubkeys are generated from cosigners, 
                # and witness script is corresponding multisig
                # so we only need to check that scriptpubkey is generated from
                # witness script

                # empty script by default
                sc = script.Script(b"")
                # multisig, we know witness script
                if policy["type"] == "p2wsh":
                    sc = script.p2wsh(out.witness_script)
                elif policy["type"] == "p2sh-p2wsh":
                    sc = script.p2sh(script.p2wsh(out.witness_script))
                # single-sig
                elif "pkh" in policy["type"]:
                    if len(out.bip32_derivations.values()) > 0:
                        der = list(out.bip32_derivations.values())[0].derivation
                        my_pubkey = root.derive(der)
                    if policy["type"] == "p2wpkh":
                        sc = script.p2wpkh(my_pubkey)
                    elif policy["type"] == "p2sh-p2wpkh":
                        sc = script.p2sh(script.p2wpkh(my_pubkey))
                if sc.data == tx.tx.vout[i].script_pubkey.data:
                    is_change = True
            if is_change:
                change += tx.tx.vout[i].value
                print("Change %d sats" % tx.tx.vout[i].value)
            else:
                spending += tx.tx.vout[i].value
                print("Spending %d sats to %s" % (tx.tx.vout[i].value, tx.tx.vout[i].script_pubkey.address()))

        fee = inp_amount - change - spending
        print("Fee: %d sats" % fee)

if __name__ == '__main__':
    main()