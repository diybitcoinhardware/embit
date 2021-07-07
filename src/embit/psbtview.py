"""
PSBTView class is RAM-friendly implementation of PSBT that reads required data from a stream on request.
The PSBT transaction itself passed to the class is a readable stream - it can be a file stream or a BytesIO object.
When using files make sure they are in trusted storage - when using SD card or other untrusted source make sure
to copy the file to a trusted media (flash, QSPI or SPIRAM for example).
Otherwise you expose yourself to time-of-check-time-of-use style of attacks where SD card MCU can trick you
to sign a wrong transactions.
Makes sense to run gc.collect() after processing of each scope to free memory.
"""
from .psbt import *
import hashlib

def skip_string(stream) -> bytes:
    l = compact.read_from(stream)
    stream.seek(l, 1)
    return len(compact.to_bytes(l)) + l

def read_write(sin, sout, l=None, chunk_size=32) -> int:
    """Reads l or all bytes from sin and writes to sout"""
    # number of bytes written
    res = 0
    barr = bytearray(chunk_size)
    while True:
        if l and l < chunk_size:
            r = sin.read(l)
            sout.write(r)
            return res + len(r)
        else:
            r = sin.readinto(barr)
            if r == 0:
                return res
            res += r
            if r == chunk_size:
                sout.write(barr)
            else:
                sout.write(barr[:r])
            if l:
                l -= r
    return res

class GlobalTransactionView:
    """
    Global transaction in PSBT is
    - unsigned (with empty scriptsigs)
    - doesn't have witness 
    """
    LEN_VIN = 32 + 4 + 1 + 4 # txid, vout, scriptsig, sequence
    def __init__(self, stream, offset):
        self.stream = stream
        self.offset = offset
        self._num_vin = None
        self._vin0_offset = None
        self._num_vout = None
        self._vout0_offset = None
        self._locktime = None
        self._version = None

    @property
    def version(self):
        if self._version is None:
            self.stream.seek(self.offset)
            self._version = int.from_bytes(self.stream.read(4), "little")
        return self._version

    @property
    def num_vin(self):
        if self._num_vin is None:
            self.stream.seek(self.offset + 4)
            self._num_vin = compact.read_from(self.stream)
        return self._num_vin

    @property
    def num_vout(self):
        if self._num_vout is None:
            # version, n_vin, n_vin * len(vin)
            self.stream.seek(self.vin0_offset + self.LEN_VIN * self.num_vin)
            self._num_vout = compact.read_from(self.stream)
        return self._num_vout

    @property
    def vin0_offset(self):
        if self._vin0_offset is None:
            self._vin0_offset = self.offset + 4 + len(compact.to_bytes(self.num_vin))
        return self._vin0_offset

    @property
    def vout0_offset(self):
        if self._vout0_offset is None:
            self._vout0_offset = self.vin0_offset + self.LEN_VIN * self.num_vin + len(compact.to_bytes(self.num_vout))
        return self._vout0_offset

    @property
    def locktime(self):
        if self._locktime is None:
            self.stream.seek(self.vout0_offset)
            n = self.num_vout
            while n:
                self._skip_output()
                n -= 1
            self._locktime = int.from_bytes(self.stream.read(4), "little")
        return self._locktime

    def vin(self, i):
        if i < 0 or i >= self.num_vin:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vin0_offset + self.LEN_VIN * i)
        return TransactionInput.read_from(self.stream)

    def _skip_output(self):
        """Seeks over one output"""
        self.stream.seek(8, 1)
        l = compact.read_from(self.stream)
        self.stream.seek(l, 1)

    def vout(self, i):
        if i < 0 or i >= self.num_vout:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vout0_offset)
        n = i
        while n:
            self._skip_output()
            n -= 1
        return TransactionOutput.read_from(self.stream)

class PSBTView:
    """
    Constructor shouldn't be used directly. PSBTView.view_from(stream) should be used instead.
    Either version should be 2 or tx_offset should be int, otherwise you get an error
    """
    # for subclasses like PSET
    MAGIC = b"psbt\xff"
    PSBTIN_CLS = InputScope
    PSBTOUT_CLS = OutputScope
    TX_CLS = GlobalTransactionView

    def __init__(self, stream,
            num_inputs, num_outputs,
            offset, first_scope,
            version=None, tx_offset=None,
            compress=False,
        ):
        if version != 2 and tx_offset is None:
            raise PSBTError("Global tx is not found, but PSBT version is %d" % version)
        self.version = version
        self.stream = stream
        # by default we use provided offset, tell() or 0 as default value
        self.offset = offset or 0
        self.num_inputs = num_inputs
        self.num_outputs = num_outputs
        self.tx_offset = tx_offset
        # tx class
        self.tx = self.TX_CLS(stream, tx_offset) if self.tx_offset else None
        self.first_scope = first_scope
        self.compress = compress
        self._tx_version = self.tx.version if self.tx else None
        self._locktime = self.tx.locktime if self.tx else None
        self._hash_prevouts = None
        self._hash_outputs = None
        self._hash_sequence = None

    @classmethod
    def view(cls, stream, offset=None, compress=False):
        if offset is None and hasattr(stream, 'tell'):
            offset = stream.tell()
        offset = offset or 0
        # current offset
        cur = offset
        # check magic
        if stream.read(len(cls.MAGIC)) != cls.MAGIC:
            raise PSBTError("Invalid PSBT magic")
        cur += len(cls.MAGIC)
        # first we parse the global scope and see if we have tx there
        version = None
        num_inputs = None
        num_outputs = None
        tx_offset = None
        while True:
            # read key and update cursor
            key = read_string(stream)
            cur += len(key) + len(compact.to_bytes(len(key)))
            # separator
            if len(key) == 0:
                break
            if key in [b"\xfb", b"\x04", b"\x05"]:
                value = read_string(stream)
                cur += len(value) + len(compact.to_bytes(len(value)))
                if key == b"\xfb":
                    version = int.from_bytes(value, 'little')
                elif key == b"\x04":
                    num_inputs = compact.from_bytes(value)
                elif key == b"\x05":
                    num_outputs = compact.from_bytes(value)
            elif key == b"\x00":
                # we found global transaction
                assert version != 2
                assert (num_inputs is None) and (num_outputs is None)
                tx_len = compact.read_from(stream)
                cur += len(compact.to_bytes(tx_len))
                tx_offset = cur
                tx = cls.TX_CLS(stream, tx_offset)
                num_inputs = tx.num_vin
                num_outputs = tx.num_vout
                # seek to the end of transaction
                stream.seek(tx_offset + tx_len)
                cur += tx_len
            else:
                cur += skip_string(stream)
        first_scope = cur
        if None in [version or tx_offset, num_inputs, num_outputs]:
            raise PSBTError("Missing something important in PSBT")
        return cls(stream, num_inputs, num_outputs, offset,
                   first_scope, version, tx_offset, compress)

    def _skip_scope(self):
        while True:
            # read key and update cursor
            key = read_string(self.stream)
            # separator
            if len(key) == 0:
                break
            skip_string(self.stream)

    def seek_to_scope(self, n):
        """
        Moves the stream cursor to n'th scope.
        n can be from 0 to num_inputs+num_outputs or None.
        If n = None it seeks to global scope.
        If n = num_inputs + num_outputs it seeks to the end of PSBT.
        This can be useful to check that nothing is left in the stream (i.e. for tests)
        """
        if n is None:
            self.stream.seek(self.offset)
        if n > self.num_inputs + self.num_outputs:
            raise PSBTError("Invalid scope number")
        # seek to first scope
        self.stream.seek(self.first_scope)
        while n:
            self._skip_scope()
            n -= 1

    def input(self, i):
        """Reads, parses and returns PSBT InputScope #i"""
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input index")
        vin = self.tx.vin(i) if self.tx else None
        self.seek_to_scope(i)
        return self.PSBTIN_CLS.read_from(self.stream, vin=vin, compress=self.compress)

    def output(self, i):
        """Reads, parses and returns PSBT OutputScope #i"""
        if i < 0 or i >= self.num_outputs:
            raise PSBTError("Invalid output index")
        vout = self.tx.vout(i) if self.tx else None
        self.seek_to_scope(self.num_inputs + i)
        return self.PSBTOUT_CLS.read_from(self.stream, vout=vout, compress=self.compress)

    def vin(self, i):
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input index")
        if self.tx:
            return self.tx.vin(i)

        self.seek_to_scope(i)
        v = self._get_value(b"\x0e", from_current=True)
        txid = bytes(reversed(v))

        self.seek_to_scope(i)
        v = self._get_value(b"\x0f", from_current=True)
        vout = int.from_bytes(v, 'little')

        self.seek_to_scope(i)
        v = self._get_value(b"\x10", from_current=True) or b"\xFF\xFF\xFF\xFF"
        sequence = int.from_bytes(v, 'little')

        return TransactionInput(txid, vout, sequence=sequence)

    def vout(self, i):
        if i < 0 or i >= self.num_outputs:
            raise PSBTError("Invalid output index")
        if self.tx:
            return self.tx.vout(i)

        self.seek_to_scope(self.num_inputs + i)
        v = self._get_value(b"\x03", from_current=True)
        value = int.from_bytes(v, 'little')

        self.seek_to_scope(self.num_inputs + i)
        v = self._get_value(b"\x04", from_current=True)
        script_pubkey = Script(v)

        return TransactionOutput(value, script_pubkey)

    @property
    def locktime(self):
        if self._locktime is None:
            v = self._get_value(b"\x03")
            self._locktime = int.from_bytes(v, 'little') if v is not None else 0
        return self._locktime

    @property
    def tx_version(self):
        if self._tx_version is None:
            v = self._get_value(b"\x02")
            self._tx_version = int.from_bytes(v, 'little') if v is not None else 0
        return self._tx_version

    def _get_value(self, key_start, from_current=False):
        if not from_current:
            # go to the start
            self.stream.seek(self.offset + len(self.MAGIC))
        while True:
            key = read_string(self.stream)
            # separator - not found
            if len(key) == 0:
                return None
            # matches
            if key.startswith(key_start):
                return read_string(self.stream)
            # continue to the next key
            skip_string(self.stream)

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            h = hashlib.sha256()
            for i in range(self.num_inputs):
                inp = self.vin(i)
                h.update(bytes(reversed(inp.txid)))
                h.update(inp.vout.to_bytes(4, "little"))
            self._hash_prevouts = h.digest()
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            h = hashlib.sha256()
            for i in range(self.num_inputs):
                inp = self.vin(i)
                h.update(inp.sequence.to_bytes(4, "little"))
            self._hash_sequence = h.digest()
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            h = hashlib.sha256()
            for i in range(self.num_outputs):
                out = self.vout(i)
                h.update(out.serialize())
            self._hash_outputs = h.digest()
        return self._hash_outputs

    def sighash_segwit(self, input_index, script_pubkey, value, sighash=SIGHASH.ALL):
        """check out bip-143"""
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        inp = self.vin(input_index)
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
        h.update(bytes(reversed(inp.txid)))
        h.update(inp.vout.to_bytes(4, "little"))
        h.update(script_pubkey.serialize())
        h.update(int(value).to_bytes(8, "little"))
        h.update(inp.sequence.to_bytes(4, "little"))
        if not (sh in [SIGHASH.NONE, SIGHASH.SINGLE]):
            h.update(hashlib.sha256(self.hash_outputs()).digest())
        elif sh == SIGHASH.SINGLE and input_index < len(self.vout):
            h.update(hashlib.sha256(
                hashlib.sha256(self.vout(input_index).serialize()).digest()
            ).digest())
        else:
            h.update(zero)
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash_legacy(self, input_index, script_pubkey, sighash=SIGHASH.ALL):
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        # no corresponding output for this input, we sign 00...01
        if sh == SIGHASH.SINGLE and input_index >= self.num_outputs:
            return b"\x00"*31+b"\x01"

        h = hashlib.sha256()
        h.update(self.tx_version.to_bytes(4, "little"))
        # ANYONECANPAY - only one input is serialized
        if anyonecanpay:
            h.update(compact.to_bytes(1))
            h.update(self.vin(input_index).serialize(script_pubkey))
        else:
            h.update(compact.to_bytes(self.num_inputs))
            for i in range(self.num_inputs):
                inp = self.vin(i)
                if input_index == i:
                    h.update(inp.serialize(script_pubkey))
                else:
                    h.update(inp.serialize(Script(b""), sighash))
        # no outputs
        if sh == SIGHASH.NONE:
            h.update(compact.to_bytes(0))
        # one output on the same index, others are empty
        elif sh == SIGHASH.SINGLE:
            h.update(compact.to_bytes(input_index+1))
            empty = TransactionOutput(0xFFFFFFFF, Script(b"")).serialize()
            # this way we commit to input index
            for i in range(input_index):
                h.update(empty)
            # last is ours
            h.update(self.vout(input_index).serialize())
        elif sh == SIGHASH.ALL:
            h.update(compact.to_bytes(self.num_outputs))
            for i in range(self.num_outputs):
                out = self.vout(i)
                h.update(out.serialize())
        else:
            # shouldn't happen
            raise PSBTError("Invalid sighash")
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash(self, i, sighash=SIGHASH.ALL, input_scope=None):
        inp = self.input(i) if input_scope is None else input_scope

        value = inp.utxo.value
        sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

        # detect if it is a segwit input
        is_segwit = (inp.witness_script
                    or inp.witness_utxo
                    or inp.utxo.script_pubkey.script_type() in {"p2wpkh", "p2wsh"}
                    or (
                        inp.redeem_script
                        and inp.redeem_script.script_type() in {"p2wpkh", "p2wsh"}
                    )
        )
        # convert to p2pkh according to bip143
        if sc.script_type() == "p2wpkh":
            sc = script.p2pkh_from_p2wpkh(sc)

        if is_segwit:
            h = self.sighash_segwit(i, sc, value, sighash=sighash)
        else:
            h = self.sighash_legacy(i, sc, sighash=sighash)
        return h

    def sign_input(self, i, root, sig_stream, sighash=SIGHASH.ALL, extra_scope_data=None) -> int:
        """
        Signs input taking into account additional derivation information for this input.
        It's helpful if your wallet knows more than provided in PSBT.
        As PSBTView is read-only it can't change anything in PSBT, that's why you may need extra_scope_data
        """
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input number")

        # if WIF - fingerprint is None
        fingerprint = None if not hasattr(root, "my_fingerprint") else root.my_fingerprint
        if not fingerprint:
            pub = root.get_public_key()
            sec = pub.sec()
            pkh = hashes.hash160(sec)

        inp = self.input(i)
        if extra_scope_data is not None:
            inp.update(extra_scope_data)
        # check which sighash to use
        inp_sighash = inp.sighash_type or sighash or SIGHASH.ALL
        # if input sighash is set and is different from kwarg - skip input
        if sighash is not None and inp_sighash != sighash:
            return 0

        h = self.sighash(i, sighash=inp_sighash, input_scope=inp)

        sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

        counter = 0
        partial_sigs = OrderedDict()
        # if we have individual private key
        if not fingerprint:
            # check if we are included in the script
            if sec in sc.data or pkh in sc.data:
                sig = root.sign(h)
                # sig plus sighash flag
                partial_sigs[pub] = sig.serialize() + bytes([inp_sighash])
                counter += 1
        # if we use HDKey
        else:
            for pub in inp.bip32_derivations:
                # check if it is root key
                if inp.bip32_derivations[pub].fingerprint == fingerprint:
                    hdkey = root.derive(inp.bip32_derivations[pub].derivation)
                    mypub = hdkey.key.get_public_key()
                    if mypub != pub:
                        raise PSBTError("Derivation path doesn't look right")
                    sig = hdkey.key.sign(h)
                    # sig plus sighash flag
                    partial_sigs[mypub] = sig.serialize() + bytes([inp_sighash])
                    counter += 1
        for pub in partial_sigs:
            ser_string(sig_stream, b"\x02" + pub.serialize())
            ser_string(sig_stream, partial_sigs[pub])
        return counter

    def sign_with(self, root, sig_stream, sighash=SIGHASH.ALL) -> int:
        """
        Signs psbtview with root key (HDKey or similar) and writes per-input signatures to the sig_stream.
        It can be either a simple BytesIO object or a file stream open for writing.
        Returns number of signatures added to PSBT.
        Sighash kwarg is set to SIGHASH.ALL by default,
        so if PSBT is asking to sign with a different sighash this function won't sign.
        If you want to sign with sighashes provided in the PSBT - set sighash=None.
        """
        counter = 0
        for i in range(self.num_inputs):
            counter += self.sign_input(i, root, sig_stream, sighash=sighash)
            # add separator
            sig_stream.write(b"\x00")
        return counter

    def write_to(self, writable_stream, compress=False,
            extra_input_streams=[],
            extra_output_streams=[],
    ):
        """
        Writes PSBTView to stream.
        extra_input_streams and extra_output_streams
        are streams with extra per-input and per-output data that should be written to stream as well.
        For example they can contain signatures or extra derivations.

        If compressed flag is used then only minimal number of fields will be writen:
        For psbtv0 it will have global tx and partial sigs for all inputs
        For psbtv2 it will have version, tx_version, locktime, per-vin data, per-vout data and partial sigs
        """
        # first we write global scope
        self.stream.seek(self.offset)
        res = read_write(self.stream, writable_stream, self.first_scope-self.offset)

        # write all inputs
        for i in range(self.num_inputs):
            inp = self.input(i)
            # add extra data from extra input streams
            for s in extra_input_streams:
                extra = InputScope.read_from(s)
                inp.update(extra)
            if compress:
                inp.clear_metadata()
            res += inp.write_to(writable_stream, version=self.version)

        # write all outputs
        for i in range(self.num_outputs):
            out = self.output(i)
            # add extra data from extra input streams
            for s in extra_output_streams:
                extra = OutputScope.read_from(s)
                out.update(extra)
            if compress:
                out.clear_metadata()
            res += out.write_to(writable_stream, version=self.version)

        return res
