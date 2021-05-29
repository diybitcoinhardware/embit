import sys

if sys.implementation.name == "micropython":
    import secp256k1
else:
    from ..util import secp256k1

from .. import compact
from ..psbt import *
from collections import OrderedDict
from io import BytesIO
from .transaction import LTransaction, LTransactionOutput, LTransactionInput, TxOutWitness, Proof, LSIGHASH
import hashlib

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

    @property
    def vin(self):
        return LTransactionInput(self.txid, self.vout, sequence=(self.sequence or 0xFFFFFFFF))

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

    def write_to(self, stream, skip_separator=False, **kwargs) -> int:
        r = super().write_to(stream, skip_separator=True, **kwargs)
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
    def __init__(self, unknown: dict = {}, vout=None, **kwargs):
        # liquid stuff
        self.value_commitment = None
        self.value_blinding_factor = None
        self.asset_commitment = None
        self.asset_blinding_factor = None
        self.range_proof = None
        self.surjection_proof = None
        self.nonce_commitment = None
        self.blinding_pubkey = None
        self.asset = None
        self.ecdh_pubkey = None
        if vout:
            self.asset = vout.asset
        # super calls parse_unknown() at the end
        super().__init__(unknown, vout=vout, **kwargs)

    @property
    def vout(self):
        return LTransactionOutput(self.asset or self.asset_commitment, self.value or self.value_commitment, self.script_pubkey, self.nonce_commitment)

    def read_value(self, stream, k):
        if (b'\xfc\x08elements' not in k) and (b"\xfc\x04pset" not in k):
            super().read_value(stream, k)
        else:
            v = read_string(stream)
            # liquid-specific fields
            if k in [b'\xfc\x08elements\x00', b'\xfc\x04pset\x01']:
                self.value_commitment = v
            elif k == b'\xfc\x08elements\x01':
                self.value_blinding_factor = v
            elif k == b'\xfc\x04pset\x02':
                self.asset = v
            elif k in [b'\xfc\x08elements\x02', b'\xfc\x04pset\x03']:
                self.asset_commitment = v
            elif k == b'\xfc\x08elements\x03':
                self.asset_blinding_factor = v
            elif k in [b'\xfc\x08elements\x04', b'\xfc\x04pset\x04']:
                self.range_proof = v
            elif k in [b'\xfc\x08elements\x05', b'\xfc\x04pset\x05']:
                self.surjection_proof = v
            elif k in [b'\xfc\x08elements\x06', b'\xfc\x04pset\x06']:
                self.blinding_pubkey = v
            elif k == b'\xfc\x08elements\x07':
                self.nonce_commitment = v
            elif k == b'\xfc\x04pset\x07':
                self.ecdh_pubkey = v
            else:
                self.unknown[k] = v

    @property
    def is_blinded(self):
        # TODO: not great
        return self.value_blinding_factor or self.asset_blinding_factor

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        # TODO: super.write_to()
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)
        # liquid-specific keys
        if self.asset is not None and version == 2:
            r += ser_string(stream, b'\xfc\x04pset\x02')
            r += ser_string(stream, self.asset)
        if self.value_commitment is not None:
            if version == 2:
                r += ser_string(stream, b'\xfc\x04pset\x01')
            else:
                r += ser_string(stream, b'\xfc\x08elements\x00')
            r += ser_string(stream, self.value_commitment)
        if self.value_blinding_factor is not None:
            r += ser_string(stream, b'\xfc\x08elements\x01')
            r += ser_string(stream, self.value_blinding_factor)
        if self.asset_commitment is not None:
            if version == 2:
                r += ser_string(stream, b'\xfc\x04pset\x03')
            else:
                r += ser_string(stream, b'\xfc\x08elements\x02')
            r += ser_string(stream, self.asset_commitment)
        if self.asset_blinding_factor is not None:
            r += ser_string(stream, b'\xfc\x08elements\x03')
            r += ser_string(stream, self.asset_blinding_factor)
        if self.blinding_pubkey is not None:
            if version == 2:
                r += ser_string(stream, b'\xfc\x04pset\x06')
            else:
                r += ser_string(stream, b'\xfc\x08elements\x06')
            r += ser_string(stream, self.blinding_pubkey)
        if self.nonce_commitment is not None:
            r += ser_string(stream, b'\xfc\x08elements\x07')
            r += ser_string(stream, self.nonce_commitment)
        # for some reason keys 04 and 05 are serialized after 07
        if self.range_proof is not None:
            if version == 2:
                r += ser_string(stream, b'\xfc\x04pset\x04')
            else:
                r += ser_string(stream, b'\xfc\x08elements\x04')
            r += ser_string(stream, self.range_proof)
        if self.surjection_proof is not None:
            if version == 2:
                r += ser_string(stream, b'\xfc\x04pset\x05')
            else:
                r += ser_string(stream, b'\xfc\x08elements\x05')
            r += ser_string(stream, self.surjection_proof)
        if self.ecdh_pubkey is not None:
            r += ser_string(stream, b'\xfc\x04pset\x07')
            r += ser_string(stream, self.ecdh_pubkey)
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

class PSET(PSBT):
    MAGIC = b"pset\xff"
    PSBTIN_CLS = LInputScope
    PSBTOUT_CLS = LOutputScope
    TX_CLS = LTransaction

    def __init__(self, *args, **kwargs):
        self._hash_outputs = None
        self._hash_outputs_rangeproofs = None
        super().__init__(*args, **kwargs)

    def fee(self):
        fee = 0
        for out in self.tx.vout:
            if out.script_pubkey.data == b"":
                fee += out.value
        return fee

    def hash_outputs(self, recalculate=False):
        if self._hash_outputs is None or recalculate:
            hprevout = hashlib.sha256()
            for out in self.outputs:
                if out.is_blinded:
                    hprevout.update(out.asset_commitment)
                    hprevout.update(out.value_commitment)
                    hprevout.update(out.nonce_commitment)
                    hprevout.update(out.script_pubkey.serialize())
                else:
                    hprevout.update(out.serialize())
            self._hash_outputs = hprevout.digest()
        return self._hash_outputs

    def hash_outputs_rangeproofs(self, recalculate=False):
        if self._hash_outputs_rangeproofs is None or recalculate:
            hrangeproof = hashlib.sha256()
            for out in self.outputs:
                if out.is_blinded:
                    hrangeproof.update(compact.to_bytes(len(out.range_proof)))
                    hrangeproof.update(out.range_proof)
                    hrangeproof.update(compact.to_bytes(len(out.surjection_proof)))
                    hrangeproof.update(out.surjection_proof)
                else:
                    hrangeproof.update(Proof().serialize())
                    hrangeproof.update(Proof().serialize())
            self._hash_outputs_rangeproofs = hrangeproof.digest()
        return self._hash_outputs_rangeproofs

    def sighash_segwit(self, input_index, script_pubkey, value, sighash=(LSIGHASH.ALL | LSIGHASH.RANGEPROOF)):
        tx = self.tx
        tx._hash_outputs = self.hash_outputs()
        tx._hash_outputs_rangeproofs = self.hash_outputs_rangeproofs()
        if isinstance(value, int):
            value = b"\x01" + value.to_bytes(8, 'little')
        return tx.sighash_segwit(input_index, script_pubkey, value, sighash)

    def sighash_legacy(self, *args, **kwargs):
        return self.tx.sighash_legacy(*args, **kwargs)

    def verify(self):
        """Checks that all commitments, values and assets are consistent"""
        super().verify()
        for i, vout in enumerate(self.tx.vout):
            out = self.outputs[i]
            if out.is_blinded:
                gen = secp256k1.generator_generate_blinded(vout.asset[1:], out.asset_blinding_factor)
                if out.asset_commitment:
                    if secp256k1.generator_serialize(gen) != out.asset_commitment:
                        raise ValueError("asset commitment is invalid")
                else:
                    out.asset_commitment = secp256k1.generator_serialize(gen)
                commit = secp256k1.pedersen_commit(out.value_blinding_factor, vout.value, gen)
                sec = secp256k1.pedersen_commitment_serialize(commit)
                if out.value_commitment:
                    if sec != out.value_commitment:
                        raise ValueError("value commitment is invalid")
                else:
                    out.value_commitment = sec
