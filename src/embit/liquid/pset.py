import sys

if sys.implementation.name == "micropython":
    import secp256k1
else:
    from ..util import secp256k1

from ..psbt import *
from collections import OrderedDict
from io import BytesIO
from .transaction import LTransaction, LTransactionOutput

class LInputScope(InputScope):
    TX_CLS = LTransaction
    TXOUT_CLS = LTransactionOutput

    def __init__(self, unknown: dict = {}, **kwargs):
        # liquid-specific fields:
        self.value = None
        self.value_blinding_factor = None
        self.asset = None
        self.asset_blinding_factor = None
        super().__init__(unknown, **kwargs)

    def read_value(self, stream, k):
        if b'\xfc\x08elements' not in k:
            super().read_value(stream, k)
        else:
            v = read_string(stream)
            # liquid-specific fields
            if k == b'\xfc\x08elements\x00':
                self.value = int.from_bytes(v, 'little')
            elif k == b'\xfc\x08elements\x01':
                self.value_blinding_factor = v
            elif k == b'\xfc\x08elements\x02':
                self.asset = v
            elif k == b'\xfc\x08elements\x03':
                self.asset_blinding_factor = v
            else:
                self.unknown[k] = v

    def write_to(self, stream, skip_separator=False) -> int:
        r = super().write_to(stream, skip_separator=True)
        # liquid-specific keys
        if self.value is not None:
            r += ser_string(stream, b'\xfc\x08elements\x00')
            r += ser_string(stream, self.value.to_bytes(8, 'little'))
        if self.value_blinding_factor is not None:
            r += ser_string(stream, b'\xfc\x08elements\x01')
            r += ser_string(stream, self.value_blinding_factor)
        if self.asset is not None:
            r += ser_string(stream, b'\xfc\x08elements\x02')
            r += ser_string(stream, self.asset)
        if self.asset_blinding_factor is not None:
            r += ser_string(stream, b'\xfc\x08elements\x03')
            r += ser_string(stream, self.asset_blinding_factor)
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


class LOutputScope(OutputScope):
    def __init__(self, unknown: dict = {}, **kwargs):
        # liquid stuff
        self.value_commitment = None
        self.value_blinding_factor = None
        self.asset_commitment = None
        self.asset_blinding_factor = None
        self.range_proof = None
        self.surjection_proof = None
        self.nonce_commitment = None
        self.blinding_pubkey = None
        # super calls parse_unknown() at the end
        super().__init__(unknown, **kwargs)

    def read_value(self, stream, k):
        if b'\xfc\x08elements' not in k:
            super().read_value(stream, k)
        else:
            v = read_string(stream)
            # liquid-specific fields
            if k == b'\xfc\x08elements\x00':
                self.value_commitment = v
            elif k == b'\xfc\x08elements\x01':
                self.value_blinding_factor = v
            elif k == b'\xfc\x08elements\x02':
                self.asset_commitment = v
            elif k == b'\xfc\x08elements\x03':
                self.asset_blinding_factor = v
            elif k == b'\xfc\x08elements\x04':
                self.range_proof = v
            elif k == b'\xfc\x08elements\x05':
                self.surjection_proof = v
            elif k == b'\xfc\x08elements\x06':
                self.blinding_pubkey = v
            elif k == b'\xfc\x08elements\x07':
                self.nonce_commitment = v
            else:
                self.unknown[k] = v


    def write_to(self, stream, skip_separator=False) -> int:
        # TODO: super.write_to()
        r = super().write_to(stream, skip_separator=True)
        # liquid-specific keys
        if self.value_commitment is not None:
            r += ser_string(stream, b'\xfc\x08elements\x00')
            r += ser_string(stream, self.value_commitment)
        if self.value_blinding_factor is not None:
            r += ser_string(stream, b'\xfc\x08elements\x01')
            r += ser_string(stream, self.value_blinding_factor)
        if self.asset_commitment is not None:
            r += ser_string(stream, b'\xfc\x08elements\x02')
            r += ser_string(stream, self.asset_commitment)
        if self.asset_blinding_factor is not None:
            r += ser_string(stream, b'\xfc\x08elements\x03')
            r += ser_string(stream, self.asset_blinding_factor)
        if self.blinding_pubkey is not None:
            r += ser_string(stream, b'\xfc\x08elements\x06')
            r += ser_string(stream, self.blinding_pubkey)
        if self.nonce_commitment is not None:
            r += ser_string(stream, b'\xfc\x08elements\x07')
            r += ser_string(stream, self.nonce_commitment)
        # for some reason keys 04 and 05 are serialized after 07
        if self.range_proof is not None:
            r += ser_string(stream, b'\xfc\x08elements\x04')
            r += ser_string(stream, self.range_proof)
        if self.surjection_proof is not None:
            r += ser_string(stream, b'\xfc\x08elements\x05')
            r += ser_string(stream, self.surjection_proof)
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

class PSET(PSBT):
    MAGIC = b"pset\xff"
    PSBTIN_CLS = LInputScope
    PSBTOUT_CLS = LOutputScope
    TX_CLS = LTransaction

    @classmethod
    def read_from(cls, *args, **kwargs):
        res = super().read_from(*args, **kwargs)
        res.verify()
        return res

    def sign_with(self, root) -> int:
        """
        Signs psbt with root key (HDKey or similar).
        Returns number of signatures added to PSBT
        """
        # TODO: rebase to psbt implementation
        fingerprint = root.child(0).fingerprint
        counter = 0
        # TODO: ugly, make it with super()
        txx = LTransaction.parse(self.tx.serialize())
        for i, out in enumerate(txx.vout):
            if self.outputs[i].nonce_commitment:
                out.nonce = self.outputs[i].nonce_commitment
                out.value = self.outputs[i].value_commitment
                out.asset = self.outputs[i].asset_commitment
        for i, inp in enumerate(self.inputs):
            for pub in inp.bip32_derivations:
                # check if it is root key
                if inp.bip32_derivations[pub].fingerprint == fingerprint:
                    hdkey = root.derive(inp.bip32_derivations[pub].derivation)
                    mypub = hdkey.key.get_public_key()
                    if mypub != pub:
                        raise ValueError("Derivation path doesn't look right")
                    sig = None
                    utxo = None
                    if inp.non_witness_utxo is not None:
                        if inp.non_witness_utxo.txid() != self.tx.vin[i].txid:
                            raise ValueError("Invalid utxo")
                        utxo = inp.non_witness_utxo.vout[self.tx.vin[i].vout]
                    elif inp.witness_utxo is not None:
                        utxo = inp.witness_utxo
                    else:
                        raise ValueError("We need at least one utxo field")
                    value = utxo.value
                    sc = utxo.script_pubkey
                    if inp.redeem_script is not None:
                        sc = inp.redeem_script
                    if inp.witness_script is not None:
                        sc = inp.witness_script
                    if sc.script_type() == "p2wpkh":
                        sc = script.p2pkh_from_p2wpkh(sc)
                    # detect if it is a segwit input
                    # tx.input[i] doesn't have any info about that in raw psbt
                    if (
                        inp.witness_script is not None
                        or inp.witness_utxo is not None
                        or utxo.script_pubkey.script_type() in {"p2wpkh", "p2wsh"}
                        or (
                            inp.redeem_script is not None
                            and inp.redeem_script.script_type() in {"p2wpkh", "p2wsh"}
                        )
                    ):
                        h = txx.sighash_segwit(i, sc, value)
                    else:
                        h = txx.sighash_legacy(i, sc)
                    sig = hdkey.key.sign(h)
                    counter += 1
                    if sig is not None:
                        # sig plus sighash_all
                        inp.partial_sigs[mypub] = sig.serialize() + b"\x01"
        return counter

    def verify(self):
        """Checks that all commitments, values and assets are consistent"""
        super().verify()
        for i, vout in enumerate(self.tx.vout):
            out = self.outputs[i]
            if out.nonce_commitment:
                gen = secp256k1.generator_generate_blinded(vout.asset[1:], out.asset_blinding_factor)
                if secp256k1.generator_serialize(gen) != out.asset_commitment:
                    raise ValueError("asset commitment is invalid")
                commit = secp256k1.pedersen_commit(out.value_blinding_factor, vout.value, gen)
                sec = secp256k1.pedersen_commitment_serialize(commit)
                if sec != out.value_commitment:
                    raise ValueError("value commitment is invalid")
