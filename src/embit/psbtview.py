"""
PSBTView class is RAM-friendly implementation of PSBT
that reads required data from a stream on request.

The PSBT transaction itself passed to the class
is a readable stream - it can be a file stream or a BytesIO object.
When using files make sure they are in trusted storage - when using SD card
or other untrusted source make sure to copy the file to a trusted media
(flash, QSPI or SPIRAM for example).

Otherwise you expose yourself to time-of-check-time-of-use style of attacks
where SD card MCU can trick you to sign a wrong transactions.

Makes sense to run gc.collect() after processing of each scope to free memory.
"""

# TODO: refactor, a lot of code is duplicated here from transaction.py
from collections import OrderedDict
from binascii import hexlify
import hashlib
from . import compact
from . import ec
from . import script
from .script import Script, Witness
from . import hashes
from .psbt import (
    PSBT,
    PSBTError,
    CompressMode,
    InputScope,
    OutputScope,
    LOCKTIME_THRESHOLD,
    choose_locktime,
    next_tx_modifiable,
    read_string,
    ser_string,
    skip_string,
    read_compact,
    read_exact,
    skip_exact,
    _PARSE_ERRORS,
    _GLOBAL_COUNT_FIELDS,
    _GLOBAL_FIXED_VALUE_LENGTHS,
    _validate_global_fields,
    _validate_global_key,
)
from .transaction import (
    TransactionOutput,
    TransactionInput,
    SIGHASH,
    hash_amounts,
    hash_script_pubkeys,
)

# global key order used by PSBT.write_to after the xpubs
_GLOBAL_V2_ORDER = (b"\x02", b"\x03", b"\x04", b"\x05", b"\x06", b"\xfb")


def _read_global_value(stream, key):
    value_len = read_compact(stream)
    if key in _GLOBAL_FIXED_VALUE_LENGTHS:
        if value_len != _GLOBAL_FIXED_VALUE_LENGTHS[key]:
            raise PSBTError("Invalid global field length")
    elif key in _GLOBAL_COUNT_FIELDS and value_len > 9:
        raise PSBTError("Invalid global count length")
    value = read_exact(stream, value_len)
    return value, len(compact.to_bytes(value_len)) + value_len


def read_write(sin, sout, sz=None, chunk_size=32) -> int:
    """Reads l or all bytes from sin and writes to sout"""
    # number of bytes written
    res = 0
    barr = bytearray(chunk_size)
    while True:
        if sz == 0:  # nothing else to read
            return res
        elif sz and sz < chunk_size:  # read less than full chunk
            r = sin.read(sz)
            sout.write(r)
            return res + len(r)
        # reading full chunk
        r = sin.readinto(barr)
        if r == 0:
            return res
        res += r
        if r == chunk_size:
            sout.write(barr)
        else:
            sout.write(barr[:r])
        if sz:
            sz -= r


class GlobalTransactionView:
    """
    Global transaction in PSBT is
    - unsigned (with empty scriptsigs)
    - doesn't have witness
    """

    LEN_VIN = 32 + 4 + 1 + 4  # txid, vout, scriptsig, sequence
    NUM_VIN_OFFSET = 4  # version

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
            self.stream.seek(self.offset + self.NUM_VIN_OFFSET)
            self._num_vin = read_compact(self.stream)
        return self._num_vin

    @property
    def num_vout(self):
        if self._num_vout is None:
            # version, n_vin, n_vin * len(vin)
            self.stream.seek(self.vin0_offset + self.LEN_VIN * self.num_vin)
            self._num_vout = read_compact(self.stream)
        return self._num_vout

    @property
    def vin0_offset(self):
        if self._vin0_offset is None:
            self._vin0_offset = (
                self.offset + self.NUM_VIN_OFFSET + len(compact.to_bytes(self.num_vin))
            )
        return self._vin0_offset

    @property
    def vout0_offset(self):
        if self._vout0_offset is None:
            self._vout0_offset = (
                self.vin0_offset
                + self.LEN_VIN * self.num_vin
                + len(compact.to_bytes(self.num_vout))
            )
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

    def _read_vin(self):
        try:
            return TransactionInput.read_from(self.stream)
        except _PARSE_ERRORS as e:
            raise PSBTError("Invalid global transaction input: %s" % e)

    def _read_vout(self):
        try:
            return TransactionOutput.read_from(self.stream)
        except _PARSE_ERRORS as e:
            raise PSBTError("Invalid global transaction output: %s" % e)

    def vin(self, i):
        if i < 0 or i >= self.num_vin:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vin0_offset + self.LEN_VIN * i)
        return self._read_vin()

    def iter_vin(self):
        """Yields every input in one sequential pass over the stream."""
        self.stream.seek(self.vin0_offset)
        for _ in range(self.num_vin):
            yield self._read_vin()

    def iter_vout(self):
        """Yields every output in one sequential pass over the stream."""
        self.stream.seek(self.vout0_offset)
        for _ in range(self.num_vout):
            yield self._read_vout()

    def _skip_output(self):
        """Seeks over one output"""
        self.stream.seek(8, 1)
        skip_exact(self.stream, read_compact(self.stream))

    def vout(self, i):
        if i < 0 or i >= self.num_vout:
            raise PSBTError("Invalid input index")
        self.stream.seek(self.vout0_offset)
        n = i
        while n:
            self._skip_output()
            n -= 1
        return self._read_vout()


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
    # provides the per-scope PSBTv2 validation hooks shared with PSBT
    PSBT_CLS = PSBT
    # PSBTv2 fields needed to rebuild a TransactionInput / TransactionOutput
    _V2_VIN_KEYS = (b"\x0e", b"\x0f", b"\x10")
    _V2_VOUT_KEYS = (b"\x03", b"\x04")

    def __init__(
        self,
        stream,
        num_inputs,
        num_outputs,
        offset,
        first_scope,
        version=None,
        tx_offset=None,
        compress=CompressMode.KEEP_ALL,
        global_kvs=None,
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
        # For PSBTv2: dict of all global key→value pairs (excluding the \x00 global tx).
        # This is the single source of truth for every global field, including
        # PSBT_GLOBAL_TX_MODIFIABLE (\x06). None for PSBTv0 where the global
        # scope is streamed verbatim.
        self._global_kvs = global_kvs
        self.clear_cache()

    @property
    def tx_modifiable_flags(self):
        """PSBT_GLOBAL_TX_MODIFIABLE byte (PSBTv2 only). None when absent or for PSBTv0."""
        if self._global_kvs is None:
            return None
        v = self._global_kvs.get(b"\x06")
        if v is None:
            return None
        if len(v) != 1:
            raise PSBTError("Invalid PSBT_GLOBAL_TX_MODIFIABLE length")
        return int.from_bytes(v, "little")

    @tx_modifiable_flags.setter
    def tx_modifiable_flags(self, value):
        """Setting to None removes the field; ignored for PSBTv0."""
        if self._global_kvs is None:
            return
        if value is None:
            self._global_kvs.pop(b"\x06", None)
        else:
            self._global_kvs[b"\x06"] = bytes([value])

    def clear_cache(self):
        # cache for digests
        self._tx_locktime = None
        self._utxo_cache = None
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
        self._hash_amounts = None
        self._hash_script_pubkeys = None

    @classmethod
    def view(cls, stream, offset=None, compress=CompressMode.KEEP_ALL):
        if offset is None and hasattr(stream, "tell"):
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
        # Collect all non-global-tx key-value pairs for PSBTv2 global scope rewriting.
        # The global scope is small, so materialising it avoids byte-level injection.
        global_kvs = OrderedDict()
        # key -> (value_offset, value_len) for globals whose value is only needed
        # if this turns out to be a PSBTv2. PSBTView is RAM-constrained, so we
        # skip them on the first pass and read them back below only when used.
        deferred_kvs = OrderedDict()
        while True:
            # read key and update cursor
            key = read_string(stream)
            cur += len(key) + len(compact.to_bytes(len(key)))
            # separator
            if len(key) == 0:
                break
            _validate_global_key(key)
            if key == b"\x00":
                # we found global transaction; defer version==2 check until after the loop
                # so that PSBT_GLOBAL_UNSIGNED_TX is rejected even when it appears before
                # PSBT_GLOBAL_VERSION (key order is not guaranteed).
                if tx_offset is not None:
                    raise PSBTError("Duplicate global transaction")
                if b"\x04" in global_kvs or b"\x05" in global_kvs:
                    raise PSBTError("Invalid global transaction")
                tx_len = read_compact(stream)
                cur += len(compact.to_bytes(tx_len))
                tx_offset = cur
                tx = cls.TX_CLS(stream, tx_offset)
                try:
                    num_inputs = tx.num_vin
                    num_outputs = tx.num_vout
                except (OverflowError, ValueError, OSError):
                    raise PSBTError("Invalid global transaction")
                # every input takes at least 41 bytes and every output 9,
                # so the counts must fit in the declared transaction length
                if tx.vout0_offset + 9 * num_outputs > cur + tx_len:
                    raise PSBTError("Invalid global transaction")
                # seek to the end of transaction
                try:
                    stream.seek(tx_offset + tx_len)
                except (OverflowError, ValueError, OSError):
                    raise PSBTError("Invalid global transaction length")
                cur += tx_len
            else:
                if key in global_kvs or key in deferred_kvs:
                    raise PSBTError("Duplicate global key: %s" % hexlify(key).decode())
                if key in _GLOBAL_FIXED_VALUE_LENGTHS or key in _GLOBAL_COUNT_FIELDS:
                    value, value_size = _read_global_value(stream, key)
                    cur += value_size
                    global_kvs[key] = value
                    if key == b"\xfb":
                        version = int.from_bytes(value, "little")
                else:
                    value_len = read_compact(stream)
                    header = len(compact.to_bytes(value_len))
                    deferred_kvs[key] = (cur + header, value_len)
                    skip_exact(stream, value_len)
                    cur += header + value_len
        first_scope = cur
        if version not in (None, 0, 2):
            raise PSBTError("Unsupported PSBT_GLOBAL_VERSION value: %d" % version)
        if version == 0:
            version = None
        # PSBTv2 must not have a global unsigned transaction, regardless of key order
        if tx_offset is not None and version == 2:
            raise PSBTError("Global transaction with version 2 PSBT")
        # Canonical-encoding, fixed-length, and required-field checks for every
        # global key, shared with PSBT.read_from's two-pass parse.
        _validate_global_fields(version, tx_offset is not None, global_kvs)
        if tx_offset is None:
            num_inputs = compact.from_bytes(global_kvs[b"\x04"])
            num_outputs = compact.from_bytes(global_kvs[b"\x05"])
        if None in [version or tx_offset, num_inputs, num_outputs]:
            raise PSBTError("Missing something important in PSBT")
        if version == 2:
            # PSBTv2 rebuilds its global scope from _global_kvs on write, so now
            # (and only now) we need the values we skipped over above.
            for k, (v_off, v_len) in deferred_kvs.items():
                stream.seek(v_off)
                global_kvs[k] = read_exact(stream, v_len)
        res = cls(
            stream,
            num_inputs,
            num_outputs,
            offset,
            first_scope,
            version,
            tx_offset,
            compress,
            global_kvs=global_kvs if version == 2 else None,
        )
        # Walk every input and output map once, reading only the key/value
        # lengths: the declared counts must match the maps actually present
        # and nothing may follow the last one, like PSBT.parse enforces.
        res.seek_to_scope(res.num_inputs + res.num_outputs)
        if len(stream.read(1)) > 0:
            raise PSBTError("Unexpected extra bytes")
        return res

    def _skip_scope(self):
        off = 0
        while True:
            # read key and update cursor
            keylen = skip_string(self.stream)
            off += keylen
            # separator: zero-length key, has actual len of 1
            if keylen == 1:
                break
            # not separator - skip value as well
            off += skip_string(self.stream)
        return off

    def _scan_scope_values(self, keys, scope_cls=None):
        """Reads the scope at the current cursor and returns {key: value} for the
        requested (exact-match) keys. Leaves the cursor at the next scope.

        Keys are matched exactly, so a keyless BIP-370 field carrying keydata
        (e.g. 0x0e||xx) never stands in for the real one, a duplicate of a
        requested key is rejected, and when scope_cls is given every key in the
        scope is checked with its _validate_key() - the same checks the full
        scope parser applies."""
        found = {}
        while True:
            key = read_string(self.stream)
            # separator - end of scope
            if len(key) == 0:
                return found
            if scope_cls is not None:
                scope_cls._validate_key(key)
            if key in keys:
                if key in found:
                    raise PSBTError("Duplicated key: %s" % hexlify(key).decode())
                found[key] = read_string(self.stream)
            else:
                skip_string(self.stream)

    def seek_to_scope(self, n):
        """
        Moves the stream cursor to n'th scope.
        n can be from 0 to num_inputs+num_outputs or None.
        If n = None it seeks to global scope.
        If n = num_inputs + num_outputs it seeks to the end of PSBT.
        This can be useful to check that nothing is left in the stream (i.e. for tests).
        Returns an offset at this scope.
        """
        if n is None:
            off = self.offset + len(self.MAGIC)
            self.stream.seek(off)
            return off
        if n > self.num_inputs + self.num_outputs:
            raise PSBTError("Invalid scope number")
        # seek to first scope
        self.stream.seek(self.first_scope)
        off = self.first_scope
        while n:
            off += self._skip_scope()
            n -= 1
        return off

    def input(self, i, compress=None):
        """Reads, parses and returns PSBT InputScope #i"""
        if compress is None:
            compress = self.compress
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input index")
        vin = self.tx.vin(i) if self.tx else None
        self.seek_to_scope(i)
        inp = self.PSBTIN_CLS.read_from(
            self.stream, vin=vin, compress=compress, version=self.version
        )
        if self.version == 2:
            self.PSBT_CLS._validate_v2_input(inp, i)
        return inp

    def output(self, i, compress=None):
        """Reads, parses and returns PSBT OutputScope #i"""
        if compress is None:
            compress = self.compress
        if i < 0 or i >= self.num_outputs:
            raise PSBTError("Invalid output index")
        vout = self.tx.vout(i) if self.tx else None
        self.seek_to_scope(self.num_inputs + i)
        out = self.PSBTOUT_CLS.read_from(
            self.stream, vout=vout, compress=compress, version=self.version
        )
        if self.version == 2:
            self.PSBT_CLS._validate_v2_output(out, i)
        return out

    def _v2_vin(self, found, i):
        """Builds a TransactionInput from the PSBTv2 fields of input scope i."""
        v = found.get(b"\x0e")
        if v is None:
            raise PSBTError(
                "PSBTv2 input %d missing required PSBT_IN_PREVIOUS_TXID (0x0e)" % i
            )
        if len(v) != 32:
            raise PSBTError("PSBT_IN_PREVIOUS_TXID must be 32 bytes")
        txid = bytes(reversed(v))

        v = found.get(b"\x0f")
        if v is None:
            raise PSBTError(
                "PSBTv2 input %d missing required PSBT_IN_OUTPUT_INDEX (0x0f)" % i
            )
        if len(v) != 4:
            raise PSBTError("PSBT_IN_OUTPUT_INDEX must be 4 bytes")
        vout = int.from_bytes(v, "little")

        v = found.get(b"\x10")
        if v is None:
            v = b"\xff\xff\xff\xff"
        elif len(v) != 4:
            raise PSBTError("PSBT_IN_SEQUENCE must be 4 bytes")
        sequence = int.from_bytes(v, "little")

        return TransactionInput(txid, vout, sequence=sequence)

    def _v2_vout(self, found, i):
        """Builds a TransactionOutput from the PSBTv2 fields of output scope i."""
        v = found.get(b"\x03")
        if v is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_AMOUNT (0x03)" % i
            )
        if len(v) != 8:
            raise PSBTError("PSBT_OUT_AMOUNT must be 8 bytes")
        # BIP370: PSBT_OUT_AMOUNT is a signed int64, so the top half is negative
        value = int.from_bytes(v, "little")
        if value >= 2**63:
            raise PSBTError("PSBT_OUT_AMOUNT must be non-negative")

        v = found.get(b"\x04")
        if v is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_SCRIPT (0x04)" % i
            )
        return TransactionOutput(value, Script(v))

    # compress is not used here, but may be used by subclasses (liquid)
    def vin(self, i, compress=None):
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input index")
        if self.tx:
            return self.tx.vin(i)
        self.seek_to_scope(i)
        found = self._scan_scope_values(self._V2_VIN_KEYS, self.PSBTIN_CLS)
        return self._v2_vin(found, i)

    def _iter_vins(self):
        """Yields the TransactionInput of every input in one sequential pass,
        instead of seeking from the first scope for each of them."""
        if self.tx:
            for vin in self.tx.iter_vin():
                yield vin
            return
        self.seek_to_scope(0)
        for i in range(self.num_inputs):
            found = self._scan_scope_values(self._V2_VIN_KEYS, self.PSBTIN_CLS)
            yield self._v2_vin(found, i)

    def _iter_vouts(self):
        """Yields the TransactionOutput of every output in one sequential pass."""
        if self.tx:
            for vout in self.tx.iter_vout():
                yield vout
            return
        self.seek_to_scope(self.num_inputs)
        for i in range(self.num_outputs):
            found = self._scan_scope_values(self._V2_VOUT_KEYS, self.PSBTOUT_CLS)
            yield self._v2_vout(found, i)

    def _utxo_values_and_scripts(self):
        """(values, script_pubkeys) of every input's utxo, parsed once per view.

        Taproot sighashes commit to all of them, so without the cache every
        signed input re-parsed every input scope."""
        if self._utxo_cache is None:
            values = []
            scripts = []
            # walk the input scopes sequentially when the stream can tell()
            # where a parsed scope ended; otherwise seek to each one
            sequential = hasattr(self.stream, "tell")
            off = self.seek_to_scope(0) if sequential else None
            for i in range(self.num_inputs):
                if sequential:
                    # tx.vin(i) moves the cursor, so restore it before parsing
                    vin = self.tx.vin(i) if self.tx else None
                    self.stream.seek(off)
                    inp = self.PSBTIN_CLS.read_from(
                        self.stream,
                        vin=vin,
                        compress=CompressMode.PARTIAL,
                        version=self.version,
                    )
                    off = self.stream.tell()
                else:
                    inp = self.input(i, compress=CompressMode.PARTIAL)
                if inp.utxo is None:
                    raise PSBTError("Missing previous utxo on input %d" % i)
                values.append(inp.utxo.value)
                scripts.append(inp.utxo.script_pubkey)
            self._utxo_cache = (values, scripts)
        return self._utxo_cache

    # compress is not used here, but may be used by subclasses (liquid)
    def vout(self, i, compress=None):
        if i < 0 or i >= self.num_outputs:
            raise PSBTError("Invalid output index")
        if self.tx:
            return self.tx.vout(i)
        self.seek_to_scope(self.num_inputs + i)
        found = self._scan_scope_values(self._V2_VOUT_KEYS, self.PSBTOUT_CLS)
        return self._v2_vout(found, i)

    @property
    def locktime(self):
        """Same meaning as PSBT.locktime: the global transaction locktime for
        PSBTv0 and PSBT_GLOBAL_FALLBACK_LOCKTIME (or None) for PSBTv2.
        The locktime of the transaction being signed is determine_locktime()."""
        if self.version == 2:
            v = self._global_kvs.get(b"\x03")
            return int.from_bytes(v, "little") if v is not None else None
        return self._locktime

    def determine_locktime(self):
        """The transaction locktime, derived per BIP-370 for PSBTv2."""
        if self._tx_locktime is None:
            if self.version == 2:
                self._tx_locktime = self._determine_locktime_v2()
            else:
                self._tx_locktime = self._locktime or 0
        return self._tx_locktime

    def _determine_locktime_v2(self):
        """BIP370 locktime determination for PSBTv2.

        Derives the transaction locktime from per-input required locktime fields.
        Falls back to PSBT_GLOBAL_FALLBACK_LOCKTIME (or 0) when no input imposes
        a requirement.
        """
        # lengths of the v2 globals were already checked by _validate_global_fields
        v = self._global_kvs.get(b"\x03")
        fallback = int.from_bytes(v, "little") if v is not None else 0

        height_locktimes = []
        time_locktimes = []
        inputs_with_requirements = 0

        # One sequential pass: _scan_scope_values() stops on the scope separator,
        # which is where the next scope begins, so no O(n^2) re-seeking per input.
        self.seek_to_scope(0)
        for _ in range(self.num_inputs):
            found = self._scan_scope_values((b"\x11", b"\x12"), self.PSBTIN_CLS)
            v_height = found.get(b"\x12")
            v_time = found.get(b"\x11")

            has_requirement = False
            if v_height is not None:
                if len(v_height) != 4:
                    raise PSBTError("PSBT_IN_REQUIRED_HEIGHT_LOCKTIME must be 4 bytes")
                height_locktime = int.from_bytes(v_height, "little")
                if height_locktime == 0 or height_locktime >= LOCKTIME_THRESHOLD:
                    raise PSBTError(
                        "Height-based locktime must be > 0 and < %d"
                        % LOCKTIME_THRESHOLD
                    )
                height_locktimes.append(height_locktime)
                has_requirement = True
            if v_time is not None:
                if len(v_time) != 4:
                    raise PSBTError("PSBT_IN_REQUIRED_TIME_LOCKTIME must be 4 bytes")
                time_locktime = int.from_bytes(v_time, "little")
                if time_locktime < LOCKTIME_THRESHOLD:
                    raise PSBTError(
                        "Time-based locktime must be >= %d" % LOCKTIME_THRESHOLD
                    )
                time_locktimes.append(time_locktime)
                has_requirement = True
            if has_requirement:
                inputs_with_requirements += 1

        return choose_locktime(
            height_locktimes, time_locktimes, inputs_with_requirements, fallback
        )

    @property
    def tx_version(self):
        if self._tx_version is None:
            # only reached for PSBTv2 - v0 takes it from the global tx.
            # _validate_global_fields already checked presence and length.
            self._tx_version = int.from_bytes(self._global_kvs[b"\x02"], "little")
        return self._tx_version

    def seek_to_value(self, key_start, from_current=False):
        """
        Seeks to value with key starting with key_start.
        Returns offset - relative if from_current=True, absolute otherwise.
        If key is not found - returns None.
        """
        off = 0
        if not from_current:
            # go to the start
            self.stream.seek(self.offset + len(self.MAGIC))
            off = self.offset + len(self.MAGIC)
        while True:
            key = read_string(self.stream)
            off += len(key) + len(compact.to_bytes(len(key)))
            # separator - not found
            if len(key) == 0:
                return None
            # matches
            if key.startswith(key_start):
                return off
            # continue to the next key
            off += skip_string(self.stream)

    def get_value(self, key_start, from_current=False):
        off = self.seek_to_value(key_start, from_current)
        if off:
            return read_string(self.stream)

    def _hash_prevouts_and_sequence(self):
        """Both digests need the same walk over the inputs, so do it once."""
        hp = hashlib.sha256()
        hs = hashlib.sha256()
        for inp in self._iter_vins():
            hp.update(bytes(reversed(inp.txid)))
            hp.update(inp.vout.to_bytes(4, "little"))
            hs.update(inp.sequence.to_bytes(4, "little"))
        self._hash_prevouts = hp.digest()
        self._hash_sequence = hs.digest()

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            self._hash_prevouts_and_sequence()
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self._hash_prevouts_and_sequence()
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            h = hashlib.sha256()
            for out in self._iter_vouts():
                h.update(out.serialize())
            self._hash_outputs = h.digest()
        return self._hash_outputs

    def hash_amounts(self, amounts):
        if self._hash_amounts is None:
            self._hash_amounts = hash_amounts(amounts)
        return self._hash_amounts

    def hash_script_pubkeys(self, script_pubkeys):
        if self._hash_script_pubkeys is None:
            self._hash_script_pubkeys = hash_script_pubkeys(script_pubkeys)
        return self._hash_script_pubkeys

    def sighash_taproot(
        self,
        input_index,
        script_pubkeys,
        values,
        sighash=SIGHASH.DEFAULT,
        ext_flag=0,
        annex=None,
        script=None,
        leaf_version=0xC0,
        codeseparator_pos=None,
    ):
        """check out bip-341"""
        # TODO: refactor, it's almost a complete copy of tx.sighash_taproot
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        if len(values) != self.num_inputs:
            raise PSBTError("All spent amounts are required")
        sh, anyonecanpay = SIGHASH.check(sighash)
        h = hashes.tagged_hash_init("TapSighash", b"\x00")
        h.update(bytes([sighash]))
        h.update(self.tx_version.to_bytes(4, "little"))
        h.update(self.determine_locktime().to_bytes(4, "little"))
        if not anyonecanpay:
            h.update(self.hash_prevouts())
            h.update(self.hash_amounts(values))
            h.update(self.hash_script_pubkeys(script_pubkeys))
            h.update(self.hash_sequence())
        if sh not in [SIGHASH.SINGLE, SIGHASH.NONE]:
            h.update(self.hash_outputs())
        # data about this input
        h.update(bytes([2 * ext_flag + int(annex is not None)]))
        if anyonecanpay:
            vin = self.vin(input_index)
            h.update(vin.serialize())
            h.update(values[input_index].to_bytes(8, "little"))
            h.update(script_pubkeys[input_index].serialize())
            h.update(vin.sequence.to_bytes(4, "little"))
        else:
            h.update(input_index.to_bytes(4, "little"))
        if annex is not None:
            h.update(hashes.sha256(compact.to_bytes(len(annex)) + annex))
        if sh == SIGHASH.SINGLE:
            h.update(self.vout(input_index).serialize())
        if script is not None:
            h.update(
                hashes.tagged_hash(
                    "TapLeaf", bytes([leaf_version]) + script.serialize()
                )
            )
            h.update(b"\x00")
            h.update(
                b"\xff\xff\xff\xff"
                if codeseparator_pos is None
                else codeseparator_pos.to_bytes(4, "little")
            )
        return h.digest()

    def sighash_segwit(self, input_index, script_pubkey, value, sighash=SIGHASH.ALL):
        """check out bip-143"""
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        # default sighash is used only in taproot
        if sh == SIGHASH.DEFAULT:
            sh = SIGHASH.ALL
        inp = self.vin(input_index)
        zero = b"\x00" * 32  # for sighashes
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
        if sh not in {SIGHASH.NONE, SIGHASH.SINGLE}:
            h.update(hashlib.sha256(self.hash_outputs()).digest())
        elif sh == SIGHASH.SINGLE and input_index < self.num_outputs:
            h.update(
                hashlib.sha256(
                    hashlib.sha256(self.vout(input_index).serialize()).digest()
                ).digest()
            )
        else:
            h.update(zero)
        h.update(self.determine_locktime().to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash_legacy(self, input_index, script_pubkey, sighash=SIGHASH.ALL):
        if input_index < 0 or input_index >= self.num_inputs:
            raise PSBTError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        # default sighash is used only in taproot
        if sh == SIGHASH.DEFAULT:
            sh = SIGHASH.ALL
        # no corresponding output for this input, we sign 00...01
        if sh == SIGHASH.SINGLE and input_index >= self.num_outputs:
            return b"\x00" * 31 + b"\x01"

        h = hashlib.sha256()
        h.update(self.tx_version.to_bytes(4, "little"))
        # ANYONECANPAY - only one input is serialized
        if anyonecanpay:
            h.update(compact.to_bytes(1))
            h.update(self.vin(input_index).serialize(script_pubkey))
        else:
            h.update(compact.to_bytes(self.num_inputs))
            for i, inp in enumerate(self._iter_vins()):
                if input_index == i:
                    h.update(inp.serialize(script_pubkey))
                else:
                    h.update(inp.serialize(Script(b""), sighash))
        # no outputs
        if sh == SIGHASH.NONE:
            h.update(compact.to_bytes(0))
        # one output on the same index, others are empty
        elif sh == SIGHASH.SINGLE:
            h.update(compact.to_bytes(input_index + 1))
            empty = TransactionOutput(0xFFFFFFFF, Script(b"")).serialize()
            # this way we commit to input index
            for i in range(input_index):
                h.update(empty)
            # last is ours
            h.update(self.vout(input_index).serialize())
        elif sh == SIGHASH.ALL:
            h.update(compact.to_bytes(self.num_outputs))
            for out in self._iter_vouts():
                h.update(out.serialize())
        else:
            # shouldn't happen
            raise PSBTError("Invalid sighash")
        h.update(self.determine_locktime().to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash(self, i, sighash=SIGHASH.ALL, input_scope=None, **kwargs):
        inp = self.input(i) if input_scope is None else input_scope
        if inp.utxo is None:
            raise PSBTError("Missing previous utxo on input %d" % i)

        if inp.is_taproot:
            values, scripts = self._utxo_values_and_scripts()
            return self.sighash_taproot(
                i,
                script_pubkeys=scripts,
                values=values,
                sighash=sighash,
                **kwargs,
            )

        value = inp.utxo.value
        sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

        # detect if it is a segwit input
        is_segwit = (
            inp.witness_script
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

    def sign_input_with_tapkey(
        self,
        key: ec.PrivateKey,
        input_index: int,
        inp=None,
        sighash=SIGHASH.DEFAULT,
    ) -> int:
        """Sign taproot input with key. Signs with internal or leaf key."""
        # get input ourselves if not provided
        inp = inp or self.input(input_index)
        if not inp.is_taproot:
            return 0
        # check if key is internal key
        pk = key.taproot_tweak(inp.taproot_merkle_root or b"")
        if pk.xonly() in inp.utxo.script_pubkey.data:
            h = self.sighash(input_index, sighash=sighash, input_scope=inp)
            sig = pk.schnorr_sign(h)
            sigdata = sig.serialize()
            if sighash != SIGHASH.DEFAULT:
                sigdata += bytes([sighash])
            # same fields PSBT._sign_taproot_keypath fills
            inp.taproot_key_sig = sigdata
            inp.final_scriptwitness = Witness([sigdata])
            # no need to sign anything else
            return 1
        counter = 0
        # negate if necessary
        pub = ec.PublicKey.from_xonly(key.xonly())
        # iterate over leafs and sign
        for ctrl, sc in inp.taproot_scripts.items():
            if pub.xonly() not in sc:
                continue
            leaf_version = sc[-1]
            script = Script(sc[:-1])
            h = self.sighash(
                input_index,
                sighash=sighash,
                input_scope=inp,
                ext_flag=1,
                script=script,
                leaf_version=leaf_version,
            )
            sig = key.schnorr_sign(h)
            leaf = hashes.tagged_hash(
                "TapLeaf", bytes([leaf_version]) + script.serialize()
            )
            sigdata = sig.serialize()
            # append sighash if necessary
            if sighash != SIGHASH.DEFAULT:
                sigdata += bytes([sighash])
            inp.taproot_sigs[(pub, leaf)] = sigdata
            counter += 1
        return counter

    def _update_tx_modifiable(self, inp_sighash: int) -> None:
        if self.version != 2:
            return
        self.tx_modifiable_flags = next_tx_modifiable(
            self.tx_modifiable_flags, inp_sighash
        )

    def sign_input(
        self, i, root, sig_stream, sighash=SIGHASH.DEFAULT, extra_scope_data=None
    ) -> int:
        """
        Signs input taking into account additional
        derivation information for this input.

        It's helpful if your wallet knows more than provided in PSBT.
        As PSBTView is read-only it can't change anything in PSBT,
        that's why you may need extra_scope_data.
        """
        if i < 0 or i >= self.num_inputs:
            raise PSBTError("Invalid input number")

        # if WIF - fingerprint is None
        fingerprint = None
        # if descriptor key
        if hasattr(root, "origin"):
            if not root.is_private:  # pubkey can't sign
                return 0
            if root.is_extended:  # use fingerprint only for HDKey
                fingerprint = root.fingerprint
            else:
                root = root.key  # WIF key
        # if HDKey
        if not fingerprint and hasattr(root, "my_fingerprint"):
            fingerprint = root.my_fingerprint

        rootpub = root.get_public_key()
        sec = rootpub.sec()
        pkh = hashes.hash160(sec)

        inp = self.input(i)
        if extra_scope_data is not None:
            inp.update(extra_scope_data)

        # SIGHASH.DEFAULT is only for taproot, fallback to SIGHASH.ALL for other inputs
        required_sighash = sighash
        if not inp.is_taproot and required_sighash == SIGHASH.DEFAULT:
            required_sighash = SIGHASH.ALL

        # check which sighash to use
        inp_sighash = inp.sighash_type
        if inp_sighash is None:
            inp_sighash = required_sighash or SIGHASH.DEFAULT
        if not inp.is_taproot and inp_sighash == SIGHASH.DEFAULT:
            inp_sighash = SIGHASH.ALL

        # if input sighash is set and is different from required sighash
        # we don't sign this input
        # except DEFAULT is functionally the same as ALL
        if required_sighash is not None and inp_sighash != required_sighash:
            if inp_sighash not in {
                SIGHASH.DEFAULT,
                SIGHASH.ALL,
            } or required_sighash not in {SIGHASH.DEFAULT, SIGHASH.ALL}:
                return 0

        # get all possible derivations with matching fingerprint
        bip32_derivations = OrderedDict()
        if fingerprint:
            # if taproot derivations are present add them
            for pub in inp.taproot_bip32_derivations:
                _leafs, derivation = inp.taproot_bip32_derivations[pub]
                if derivation.fingerprint == fingerprint:
                    # Add only if not already present
                    if (pub, derivation) not in bip32_derivations:
                        bip32_derivations[(pub, derivation)] = True

            # segwit and legacy derivations
            for pub in inp.bip32_derivations:
                derivation = inp.bip32_derivations[pub]
                if derivation.fingerprint == fingerprint:
                    if (pub, derivation) not in bip32_derivations:
                        bip32_derivations[(pub, derivation)] = True

        # get derived keys for signing
        derived_keypairs = OrderedDict()  # (prv, pub)
        for pub, derivation in bip32_derivations:
            der = derivation.derivation
            # descriptor key has origin derivation that we take into account
            if hasattr(root, "origin"):
                if root.origin:
                    if root.origin.derivation != der[: len(root.origin.derivation)]:
                        # derivation doesn't match - go to next input
                        continue
                    der = der[len(root.origin.derivation) :]
                hdkey = root.key.derive(der)
            else:
                hdkey = root.derive(der)

            if hdkey.xonly() != pub.xonly():
                raise PSBTError("Derivation path doesn't look right")
            # Insert into derived_keypairs if not present
            if (hdkey.key, pub) not in derived_keypairs:
                derived_keypairs[(hdkey.key, pub)] = True

        counter = 0
        # sign with taproot key
        if inp.is_taproot:
            # try to sign with individual private key (WIF)
            # or with root without derivations
            counter += self.sign_input_with_tapkey(
                root,
                i,
                inp,
                sighash=inp_sighash,
            )
            # sign with all derived keys
            for prv, pub in derived_keypairs:
                counter += self.sign_input_with_tapkey(
                    prv,
                    i,
                    inp,
                    sighash=inp_sighash,
                )
            if inp.final_scriptwitness:
                ser_string(sig_stream, b"\x08")
                ser_string(sig_stream, inp.final_scriptwitness.serialize())
            if inp.taproot_key_sig:
                ser_string(sig_stream, b"\x13")
                ser_string(sig_stream, inp.taproot_key_sig)

            for pub, leaf in inp.taproot_sigs:
                ser_string(sig_stream, b"\x14" + pub.xonly() + leaf)
                ser_string(sig_stream, inp.taproot_sigs[(pub, leaf)])
            if counter > 0:
                self._update_tx_modifiable(inp_sighash)
            return counter

        h = self.sighash(i, sighash=inp_sighash, input_scope=inp)
        sc = inp.witness_script or inp.redeem_script or inp.utxo.script_pubkey

        # check if root is included in the script
        if sec in sc.data or pkh in sc.data:
            sig = root.sign(h)
            # sig plus sighash flag
            inp.partial_sigs[rootpub] = sig.serialize() + bytes([inp_sighash])
            counter += 1
            self._update_tx_modifiable(inp_sighash)
        for prv, pub in derived_keypairs:
            sig = prv.sign(h)
            # sig plus sighash flag
            inp.partial_sigs[pub] = sig.serialize() + bytes([inp_sighash])
            counter += 1
            self._update_tx_modifiable(inp_sighash)
        for pub in inp.partial_sigs:
            ser_string(sig_stream, b"\x02" + pub.serialize())
            ser_string(sig_stream, inp.partial_sigs[pub])
        return counter

    def sign_with(self, root, sig_stream, sighash=SIGHASH.DEFAULT) -> int:
        """
        Signs psbtview with root key (HDKey or similar) and writes per-input signatures to the sig_stream.
        It can be either a simple BytesIO object or a file stream open for writing.
        Returns number of signatures added to PSBT.
        Sighash kwarg is set to SIGHASH.DEFAULT, for segwit and legacy it's replaced to SIGHASH.ALL
        so if PSBT is asking to sign with a different sighash this function won't sign.
        If you want to sign with sighashes provided in the PSBT - set sighash=None.

        The sig_stream only carries per-input fields. For PSBTv2 the signer
        also has to update PSBT_GLOBAL_TX_MODIFIABLE (BIP-370); that update is
        kept on this view (tx_modifiable_flags) and emitted by write_to(), so
        write the signed PSBT with the same view that produced the signatures.
        """
        counter = 0
        for i in range(self.num_inputs):
            # check if it's a descriptor, and sign with
            # all private keys in this descriptor
            if hasattr(root, "keys"):
                for k in root.keys:
                    if hasattr(k, "is_private") and k.is_private:
                        counter += self.sign_input(i, k, sig_stream, sighash=sighash)
            else:
                # just sign with the key
                counter += self.sign_input(i, root, sig_stream, sighash=sighash)
            # add separator
            sig_stream.write(b"\x00")
        return counter

    def write_to(
        self,
        writable_stream,
        compress=None,
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
        if compress is None:
            compress = self.compress

        # first we write global scope
        if self._global_kvs is not None:
            # PSBTv2: reconstruct global scope from the materialised key-value dict
            # in the same order PSBT.write_to uses: xpubs, the BIP-370 fields,
            # then the unknown fields as they appeared in the source.
            writable_stream.write(self.MAGIC)
            res = len(self.MAGIC)
            keys = [k for k in self._global_kvs if k[:1] == b"\x01"]
            keys += [k for k in _GLOBAL_V2_ORDER if k in self._global_kvs]
            keys += [
                k
                for k in self._global_kvs
                if k[:1] != b"\x01" and k not in _GLOBAL_V2_ORDER
            ]
            for k in keys:
                res += ser_string(writable_stream, k)
                res += ser_string(writable_stream, self._global_kvs[k])
            writable_stream.write(b"\x00")  # global scope separator
            res += 1
        else:
            # PSBTv0: stream global scope directly from source (includes global tx).
            self.stream.seek(self.offset)
            res = read_write(
                self.stream, writable_stream, self.first_scope - self.offset
            )

        # write all inputs
        for i in range(self.num_inputs):
            inp = self.input(i)
            # add extra data from extra input streams
            for s in extra_input_streams:
                extra = InputScope.read_from(s, version=self.version)
                inp.update(extra)
            if compress:
                inp.clear_metadata(compress=compress)
            res += inp.write_to(writable_stream, version=self.version)

        # write all outputs
        for i in range(self.num_outputs):
            out = self.output(i)
            # add extra data from extra input streams
            for s in extra_output_streams:
                extra = OutputScope.read_from(s, version=self.version)
                out.update(extra)
            if compress:
                out.clear_metadata(compress=compress)
            res += out.write_to(writable_stream, version=self.version)

        return res
