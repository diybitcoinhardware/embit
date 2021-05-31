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
        if vout:
            self.asset = vout.asset
        # super calls parse_unknown() at the end
        super().__init__(unknown, vout=vout, **kwargs)

    @property
    def vout(self):
        return LTransactionOutput(
                    self.asset or self.asset_commitment,
                    self.value or self.value_commitment,
                    self.script_pubkey,
                    None if self.asset else self.nonce_commitment)

    @property
    def blinded_vout(self):
        return LTransactionOutput(
                    self.asset_commitment or self.asset,
                    self.value_commitment or self.value,
                    self.script_pubkey,
                    self.nonce_commitment,
                    None if not self.surjection_proof else TxOutWitness(Proof(self.surjection_proof), Proof(self.range_proof))
        )

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
            elif k in [b'\xfc\x08elements\x07', b'\xfc\x04pset\x07']:
                self.nonce_commitment = v
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
            if version == 2:
                r += ser_string(stream, b'\xfc\x04pset\x07')
            else:
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
        # separator
        if not skip_separator:
            r += stream.write(b"\x00")
        return r

class PSET(PSBT):
    MAGIC = b"pset\xff"
    PSBTIN_CLS = LInputScope
    PSBTOUT_CLS = LOutputScope
    TX_CLS = LTransaction

    def fee(self):
        fee = 0
        for out in self.tx.vout:
            if out.script_pubkey.data == b"":
                fee += out.value
        return fee

    @property
    def blinded_tx(self):
        return self.TX_CLS(version=self.tx_version or 2,
                           locktime=self.locktime or 0,
                           vin=[inp.vin for inp in self.inputs],
                           vout=[out.blinded_vout for out in self.outputs])

    def sighash_segwit(self, input_index, script_pubkey, value, sighash=(LSIGHASH.ALL | LSIGHASH.RANGEPROOF)):
        return self.blinded_tx.sighash_segwit(input_index, script_pubkey, value, sighash)

    def sighash_legacy(self, *args, **kwargs):
        return self.blinded_tx.sighash_legacy(*args, **kwargs)

    # def sign_with(self, root, sighash=(LSIGHASH.ALL | LSIGHASH.RANGEPROOF)) -> int:
    # TODO: change back to sighash rangeproof when deployed
    def sign_with(self, root, sighash=LSIGHASH.ALL) -> int:
        super().sign_with(root, sighash)

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
