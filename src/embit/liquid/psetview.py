from ..psbtview import *
from .pset import *
import hashlib

def skip_commitment(stream):
    c = stream.read(1)
    assert len(c) == 1
    if c == b"\x00": # None
        return 1
    if c == b"\x01": # unconfidential
        r = stream.seek(8, 1)
        return 9
    # confidential
    r = stream.seek(32, 1)
    return 33

class GlobalLTransactionView(GlobalTransactionView):
    """
    Global liquid transaction in PSET is
    - unsigned (with empty scriptsigs)
    - doesn't have witness
    """
    NUM_VIN_OFFSET = 5 # version + marker

    def __init__(self, *args, **kwargs):
        self._num_vout_offset = None
        super().__init__(*args, **kwargs)

    @property
    def num_vout_offset(self):
        if self._num_vout_offset is None:
            off = self.vin0_offset
            self.stream.seek(off)
            # skip vins
            for i in range(self.num_vin):
                off += self._skip_input()
            self._num_vout_offset = off
        return self._num_vout_offset

    @property
    def num_vout(self):
        if self._num_vout is None:
            self.stream.seek(self.num_vout_offset)
            self._num_vout = compact.read_from(self.stream)
        return self._num_vout

    @property
    def vout0_offset(self):
        if self._vout0_offset is None:
            self._vout0_offset = self.num_vout_offset + len(compact.to_bytes(self.num_vout))
        return self._vout0_offset

    def vin(self, i):
        if i < 0 or i >= self.num_vin:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vin0_offset)
        for j in range(i):
            self._skip_input()
        return LTransactionInput.read_from(self.stream)

    def _skip_input(self):
        off = 32 + 4 + 5
        self.stream.seek(32, 1) # txid
        vout = int.from_bytes(self.stream.read(4), "little")
        self.stream.seek(5, 1) # scriptsig, sequence
        is_pegin = False
        if vout != 0xFFFFFFFF:
            is_pegin = vout & (1 << 30) != 0
            has_issuance = vout & (1 << 31) != 0
            if has_issuance:
                self.stream.seek(32+32, 1) # nonce, entropy
                off += 64
                off += skip_commitment(self.stream) # amount commitment
                off += skip_commitment(self.stream) # token commitment
        return off

    def _skip_output(self):
        """Seeks over one output"""
        self.stream.seek(33, 1) # asset
        c = self.stream.read(1)
        if c != b"\x01":
            self.stream.seek(32, 1) # confidential
        else:
            self.stream.seek(8, 1) # unconfidential
        c = self.stream.read(1)
        if c != b"\x00":
            self.stream.seek(32, 1) # ecdh_pubkey
        l = compact.read_from(self.stream)
        self.stream.seek(l, 1) # scriptpubkey

    def vout(self, i):
        if i < 0 or i >= self.num_vout:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vout0_offset)
        n = i
        while n:
            self._skip_output()
            n -= 1
        return LTransactionOutput.read_from(self.stream)

class PSETView(PSBTView):
    """
    Constructor shouldn't be used directly. PSBTView.view_from(stream) should be used instead.
    Either version should be 2 or tx_offset should be int, otherwise you get an error
    """
    MAGIC = b"pset\xff"
    PSBTIN_CLS = LInputScope
    PSBTOUT_CLS = LOutputScope
    TX_CLS = GlobalLTransactionView

    def clear_cache(self):
        # cache for digests
        super().clear_cache()
        self._hash_rangeproofs = None
        self._hash_issuances = None

    def vin(self, i, compress=None):
        return self.input(i, True).vin

    def blinded_vin(self, i, compress=None):
        return self.input(i, compress).blinded_vin

    def vout(self, i, compress=None):
        return self.output(i, compress=compress).vout

    def blinded_vout(self, i, compress=None):
        return self.output(i, compress=compress).blinded_vout

    def hash_issuances(self):
        if self._hash_issuances is None:
            h = hashlib.sha256()
            for i in range(self.num_inputs):
                inp = self.input(i, compress=True)
                if inp.has_issuance:
                    inp.asset_issuance.hash_to(h)
                else:
                    h.update(b"\x00")
            self._hash_issuances = h.digest()
        return self._hash_issuances

    def _hash_to(self, h, l):
        while l > 32:
            h.update(self.stream.read(32))
            l -= 32
        h.update(self.stream.read(l))

    def hash_rangeproofs(self):
        if self._hash_rangeproofs is None:
            h = hashlib.sha256()
            for i in range(self.num_outputs):
                off = self.seek_to_scope(self.num_inputs + i)
                rangeproof_offset = self.seek_to_value(b'\xfc\x04pset\x04', from_current=True)
                if not rangeproof_offset:
                    self.stream.seek(off)
                    rangeproof_offset = self.seek_to_value(b'\xfc\x08elements\x04', from_current=True)
                if not rangeproof_offset:
                    h.update(b"\x00")
                else:
                    l = compact.read_from(self.stream)
                    h.update(compact.to_bytes(l))
                    self._hash_to(h, l)

                self.stream.seek(off)
                surj_proof_offset = self.seek_to_value(b'\xfc\x04pset\x05', from_current=True)
                if not surj_proof_offset:
                    self.stream.seek(off)
                    surj_proof_offset = self.seek_to_value(b'\xfc\x08elements\x05', from_current=True)
                if not surj_proof_offset:
                    h.update(b"\x00")
                else:
                    l = compact.read_from(self.stream)
                    h.update(compact.to_bytes(l))
                    self._hash_to(h, l)
            self._hash_rangeproofs = h.digest()
        return self._hash_rangeproofs

    def hash_outputs(self):
        if self._hash_outputs is None:
            h = hashlib.sha256()
            for i in range(self.num_outputs):
                out = self.blinded_vout(i)
                h.update(out.serialize())
            self._hash_outputs = h.digest()
        return self._hash_outputs

    def sighash_segwit(self, input_index, script_pubkey, value, sighash=(LSIGHASH.ALL | LSIGHASH.RANGEPROOF)):
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay, hash_rangeproofs = LSIGHASH.check(sighash)
        inp = self.blinded_vin(input_index, compress=True)
        zero = b"\x00"*32 # for sighashes
        h = hashlib.sha256()
        h.update(self.tx_version.to_bytes(4, "little"))
        if anyonecanpay:
            h.update(zero)
        else:
            h.update(hashlib.sha256(self.hash_prevouts()).digest())
        if anyonecanpay or sh in [SIGHASH.NONE, SIGHASH.SINGLE]:
            h.update(zero)
        else:
            h.update(hashlib.sha256(self.hash_sequence()).digest())
        h.update(hashlib.sha256(self.hash_issuances()).digest())
        h.update(bytes(reversed(inp.txid)))
        h.update(inp.vout.to_bytes(4, "little"))
        h.update(script_pubkey.serialize())
        if isinstance(value, int):
            h.update(b"\x01"+value.to_bytes(8, 'big'))
        else:
            h.update(value)
        h.update(inp.sequence.to_bytes(4, "little"))
        if inp.has_issuance:
            inp.asset_issuance.hash_to(h)
        if not (sh in [SIGHASH.NONE, SIGHASH.SINGLE]):
            h.update(hashlib.sha256(self.hash_outputs()).digest())
            if hash_rangeproofs:
                h.update(hashlib.sha256(self.hash_rangeproofs()).digest())
        elif sh == SIGHASH.SINGLE and input_index < self.num_outputs:
            h.update(hashlib.sha256(hashlib.sha256(self.blinded_vout(input_index).serialize()).digest()).digest())
            if hash_rangeproofs:
                h.update(hashlib.sha256(hashlib.sha256(self.blinded_vout(input_index).witness.serialize()).digest()).digest())
        else:
            h.update(zero)
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash_legacy(self, input_index, script_pubkey, sighash=SIGHASH.ALL):
        raise NotImplementedError()

    def sighash_taproot(self, input_index, script_pubkeys, values, sighash=SIGHASH.DEFAULT):
        """check out bip-341"""
        raise NotImplementedError()
