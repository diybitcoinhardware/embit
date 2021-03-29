import io
from .. import compact
from ..script import Script, Witness
from .. import hashes
from ..util import hashlib
from ..transaction import *
from ..base import EmbitBase
import hashlib

class LTransactionError(TransactionError):
    pass

def read_commitment(stream):
    c = stream.read(1)
    assert len(c) == 1
    if c == b"\x00": # None
        return None
    if c == b"\x01": # unconfidential
        r = stream.read(8)
        assert len(r) == 8
        return int.from_bytes(r, "big")
    # confidential
    r = stream.read(32)
    assert len(r) == 32
    return c+r

def write_commitment(c):
    if c is None:
        return b"\x00"
    if isinstance(c, int):
        return b"\x01"+c.to_bytes(8, 'big')
    return c

class Proof(EmbitBase):
    def __init__(self, data=b""):
        self.data = data

    @property
    def is_empty(self):
        return len(self.data) == 0

    def write_to(self, stream):
        res = stream.write(compact.to_bytes(len(self.data)))
        res += stream.write(self.data)
        return res

    @classmethod
    def read_from(cls, stream):
        l = compact.read_from(stream)
        data = stream.read(l)
        return cls(data)


class TxInWitness(EmbitBase):
    def __init__(self, amount_proof=None, token_proof=None, script_witness=None, pegin_witness=None):
        self.amount_proof = amount_proof if amount_proof is not None else Proof()
        self.token_proof = token_proof if token_proof is not None else Proof()
        self.script_witness = script_witness if script_witness is not None else Witness([])
        self.pegin_witness = pegin_witness if pegin_witness is not None else Witness([])

    def write_to(self, stream):
        res = self.amount_proof.write_to(stream)
        res += self.token_proof.write_to(stream)
        res += self.script_witness.write_to(stream)
        res += self.pegin_witness.write_to(stream)
        return res

    @property
    def is_empty(self):
        return self.amount_proof.is_empty and self.token_proof.is_empty and len(self.script_witness.items)==0 and len(self.pegin_witness.items)==0

    @classmethod
    def read_from(cls, stream):
        return cls(Proof.read_from(stream), Proof.read_from(stream), Witness.read_from(stream), Witness.read_from(stream))

class TxOutWitness(EmbitBase):
    def __init__(self, surjection_proof=None, range_proof=None):
        self.surjection_proof = surjection_proof if surjection_proof is not None else Proof()
        self.range_proof = range_proof if range_proof is not None else Proof()

    def write_to(self):
        res += self.surjection_proof.write_to(stream)
        res += self.range_proof.write_to(stream)
        return res

    @property
    def is_empty(self):
        return self.surjection_proof.is_empty and self.range_proof.is_empty

    @classmethod
    def read_from(cls, stream):
        return cls(Proof.read_from(stream), Proof.read_from(stream))


class LTransaction(Transaction):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def has_witness(self):
        for inp in self.vin:
            if not inp.witness.is_empty:
                return True
        for out in self.vout:
            if not out.witness.is_empty:
                return True
        return False

    def write_to(self, stream):
        """Returns the byte serialization of the transaction"""
        res = stream.write(self.version.to_bytes(4, "little"))
        # should be segwit marker, but not sure, maybe all txs are segwit in Liquid?
        res += stream.write(b"\x01" if self.has_witness else b"\x00")
        res += stream.write(compact.to_bytes(len(self.vin)))
        for inp in self.vin:
            res += inp.write_to(stream)
        res += stream.write(compact.to_bytes(len(self.vout)))
        for out in self.vout:
            res += out.write_to(stream)
        res += stream.write(self.locktime.to_bytes(4, "little"))
        if self.has_witness:
            for inp in self.vin:
                res += inp.witness.write_to(stream)
            for out in self.vout:
                res += out.witness.write_to(stream)
        return res

    @classmethod
    def read_vout(cls, stream, idx):
        """Returns a tuple TransactionOutput, tx_hash without storing the whole tx in memory"""
        h = hashlib.sha256()
        h.update(stream.read(4))
        has_witness = False
        flag = stream.read(1)
        if flag == b"\x01":
            has_witness = True
        h.update(flag)
        num_vin = compact.read_from(stream)
        h.update(compact.to_bytes(num_vin))
        for i in range(num_vin):
            txin = LTransactionInput.read_from(stream)
            h.update(txin.serialize())
        num_vout = compact.read_from(stream)
        h.update(compact.to_bytes(num_vout))
        if idx >= num_vout or idx < 0:
            raise TransactionError("Invalid vout index %d, max is %d" (idx, num_vout-1))
        res = None
        for i in range(num_vout):
            vout = LTransactionOutput.read_from(stream)
            if idx == i:
                res = vout
            h.update(vout.serialize())
        h.update(stream.read(4))
        if has_witness:
            for i in range(num_vin):
                TxInWitness.read_from(stream)
            for i in range(num_vout):
                TxOutWitness.read_from(stream)
        return res, hashlib.sha256(h.digest()).digest()

    @classmethod
    def read_from(cls, stream):
        ver = int.from_bytes(stream.read(4), "little")
        has_witness = False
        if stream.read(1) == b"\x01":
            has_witness = True
        num_vin = compact.read_from(stream)
        vin = []
        for i in range(num_vin):
            vin.append(LTransactionInput.read_from(stream))
        num_vout = compact.read_from(stream)
        vout = []
        for i in range(num_vout):
            vout.append(LTransactionOutput.read_from(stream))
        locktime = int.from_bytes(stream.read(4), "little")
        # something more
        if has_witness:
            for inp in vin:
                inp.witness = TxInWitness.read_from(stream)
            # surj proofs
            for out in vout:
                out.witness = TxOutWitness.read_from(stream)
        return cls(version=ver, vin=vin, vout=vout, locktime=locktime)

    def hash_issuances(self):
        return hashlib.sha256(b"\x00"*len(self.vin)).digest()

    def sighash_segwit(self, input_index, script_pubkey, value):
        # TODO: SIGHASHES???
        inp = self.vin[input_index]
        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
        h.update(hashlib.sha256(self.hash_prevouts()).digest())
        h.update(hashlib.sha256(self.hash_sequence()).digest())
        # hash issuance ( b"\x00" per input without issuance )
        h.update(hashlib.sha256(self.hash_issuances()).digest())
        h.update(bytes(reversed(inp.txid)))
        h.update(inp.vout.to_bytes(4, "little"))
        h.update(script_pubkey.serialize())
        h.update(value)
        h.update(inp.sequence.to_bytes(4, "little"))
        h.update(hashlib.sha256(self.hash_outputs()).digest())
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(SIGHASH_ALL.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()


class AssetIssuance(EmbitBase):
    def __init__(self, nonce, entropy, amount_commitment, token_commitment=None):
        self.nonce = nonce
        self.entropy = entropy
        self.amount_commitment = amount_commitment
        self.token_commitment = token_commitment

    @classmethod
    def read_from(cls, stream):
        nonce = stream.read(32)
        assert len(nonce) == 32
        entropy = stream.read(32)
        assert len(entropy) == 32
        amount_commitment = read_commitment(stream)
        token_commitment = read_commitment(stream)
        return cls(nonce, entropy, amount_commitment, token_commitment)

    def write_to(self, stream):
        res = stream.write(self.nonce)
        res += stream.write(self.entropy)
        res += stream.write(write_commitment(self.amount_commitment))
        res += stream.write(write_commitment(self.token_commitment))
        return res

class LTransactionInput(TransactionInput):
    def __init__(self, txid, vout, script_sig=None, sequence=0xFFFFFFFF, witness=None, is_pegin=False, asset_issuance=None):
        super().__init__(txid, vout, script_sig, sequence, witness)
        self.is_pegin = is_pegin
        self.asset_issuance = asset_issuance
        self.witness = witness if witness is not None else TxInWitness()

    def write_to(self, stream, script_sig=None):
        if script_sig is None:
            script_sig = self.script_sig
        vout = self.vout
        if self.has_issuance:
            vout += (1<<31)
        if self.is_pegin:
            vout += (1<<30)
        res = stream.write(bytes(reversed(self.txid)))
        res += stream.write(vout.to_bytes(4, "little"))
        res += script_sig.write_to(stream)
        res += stream.write(self.sequence.to_bytes(4, "little"))
        if self.has_issuance:
            res += self.asset_issuance.write_to(stream)
        return res

    @classmethod
    def read_from(cls, stream):
        txid = bytes(reversed(stream.read(32)))
        vout = int.from_bytes(stream.read(4), "little")
        script_sig = Script.read_from(stream)
        sequence = int.from_bytes(stream.read(4), "little")
        is_pegin = False
        asset_issuance = None
        if vout != 0xFFFFFFFF:
            is_pegin = vout & (1 << 30) != 0
            has_issuance = vout & (1 << 31) != 0
            if has_issuance:
                asset_issuance = AssetIssuance.read_from(stream)
            # remove issue and pegin flags 
            vout &= 0x3FFFFFFF
        return cls(txid, vout, script_sig, sequence, is_pegin=is_pegin, asset_issuance=asset_issuance)

    @property
    def has_issuance(self):
        return self.asset_issuance is not None
    

class LTransactionOutput(TransactionOutput):
    def __init__(self, asset, value, script_pubkey, nonce=None, witness=None):
        self.asset = asset
        self.value = value
        self.script_pubkey = script_pubkey
        self.nonce = nonce
        self.witness = witness if witness is not None else TxOutWitness()

    def write_to(self, stream):
        res = stream.write(self.asset)
        if self.nonce:
            res += stream.write(self.value)
            res += stream.write(self.nonce)
        else:
            res += stream.write(b"\x01")
            res += stream.write(self.value.to_bytes(8, "big"))
            res += stream.write(b"\x00")
        res += self.script_pubkey.write_to(stream)
        return res

    @classmethod
    def read_from(cls, stream):
        asset = stream.read(33)
        blinded = False
        nonce = None
        c = stream.read(1)
        if c != b"\x01":
            blinded = True
        if blinded:
            value = c + stream.read(32)
            nonce = stream.read(33)
        else:
            value = int.from_bytes(stream.read(8), "big")
            if stream.read(1) != b"\x00":
                raise Exception("Invalid output format")
        script_pubkey = Script.read_from(stream)
        return cls(asset, value, script_pubkey, nonce)
