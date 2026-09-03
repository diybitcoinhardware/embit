import hashlib
from . import compact
from . import hashes
from .base import EmbitBase, EmbitError
from .script import Script, Witness
from .misc import const


class TransactionError(EmbitError):
    pass


# micropython doesn't support typing and Enum
class SIGHASH:
    DEFAULT = const(0)
    ALL = const(1)
    NONE = const(2)
    SINGLE = const(3)
    # Opt-in to the unified signature hash; see Tx.sighash_unified().
    UNIFIED = const(0x20)
    ANYONECANPAY = const(0x80)

    @classmethod
    def check(cls, sighash: int):
        anyonecanpay = False
        if sighash & cls.ANYONECANPAY:
            # remove ANYONECANPAY flag
            sighash = sighash ^ cls.ANYONECANPAY
            anyonecanpay = True
        if sighash not in [cls.DEFAULT, cls.ALL, cls.NONE, cls.SINGLE]:
            raise TransactionError("Invalid SIGHASH type")
        return sighash, anyonecanpay

    @classmethod
    def check_unified(cls, sighash: int, script_type: int = 0):
        """Validate a hash type for the unified algorithm.

        The opt-in bit must be set. Beyond that each script type keeps the
        reading it has today: bare and witness v0 take the legacy one, where
        anything that is not NONE or SINGLE means ALL, while taproot and
        tapscript keep BIP341's, which refuses a hash type it does not define.
        """
        # Consensus only ever sees the last byte of a signature, so anything
        # outside that range is a caller error rather than a hash type.
        if not 0 <= sighash <= 0xFF:
            raise TransactionError("SIGHASH type out of range")
        if not sighash & cls.UNIFIED:
            raise TransactionError("SIGHASH_UNIFIED is not set")
        anyonecanpay = bool(sighash & cls.ANYONECANPAY)
        sh = sighash & 0x1F
        if script_type in (2, 3):
            if sighash & ~(0x1F | cls.UNIFIED | cls.ANYONECANPAY):
                raise TransactionError("Undefined bits set in SIGHASH type")
            if sh not in [cls.ALL, cls.NONE, cls.SINGLE]:
                raise TransactionError("Invalid SIGHASH type")
        return sh, anyonecanpay


class UNIFIED_SCRIPT_TYPE:
    """Domain separation, so a signature made for one script type can never be
    valid for another."""

    BARE = const(0)  # bare and P2SH
    WITNESS_V0 = const(1)
    TAPROOT = const(2)  # key path
    TAPSCRIPT = const(3)


# util functions


def hash_amounts(amounts):
    h = hashlib.sha256()
    for a in amounts:
        h.update(a.to_bytes(8, "little"))
    return h.digest()


def hash_script_pubkeys(script_pubkeys):
    h = hashlib.sha256()
    for sc in script_pubkeys:
        h.update(sc.serialize())
    return h.digest()


# API similar to bitcoin-cli decoderawtransaction


class Transaction(EmbitBase):
    def __init__(self, version=2, vin=[], vout=[], locktime=0):
        self.version = version
        self.locktime = locktime
        self.vin = vin
        self.vout = vout
        self.clear_cache()

    def clear_cache(self):
        # cache for digests
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
        self._hash_amounts = None
        self._hash_script_pubkeys = None

    @property
    def is_segwit(self):
        # transaction is segwit if at least one input is segwit
        for inp in self.vin:
            if inp.is_segwit:
                return True
        return False

    def write_to(self, stream):
        """Returns the byte serialization of the transaction"""
        res = stream.write(self.version.to_bytes(4, "little"))
        if self.is_segwit:
            res += stream.write(b"\x00\x01")  # segwit marker and flag
        res += stream.write(compact.to_bytes(len(self.vin)))
        for inp in self.vin:
            res += inp.write_to(stream)
        res += stream.write(compact.to_bytes(len(self.vout)))
        for out in self.vout:
            res += out.write_to(stream)
        if self.is_segwit:
            for inp in self.vin:
                res += inp.witness.write_to(stream)
        res += stream.write(self.locktime.to_bytes(4, "little"))
        return res

    def hash(self):
        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
        h.update(compact.to_bytes(len(self.vin)))
        for inp in self.vin:
            h.update(inp.serialize())
        h.update(compact.to_bytes(len(self.vout)))
        for out in self.vout:
            h.update(out.serialize())
        h.update(self.locktime.to_bytes(4, "little"))
        hsh = hashlib.sha256(h.digest()).digest()
        return hsh

    def txid(self):
        return bytes(reversed(self.hash()))

    @classmethod
    def read_vout(cls, stream, idx):
        """Returns a tuple TransactionOutput, tx_hash without storing the whole tx in memory"""
        h = hashlib.sha256()
        h.update(stream.read(4))
        num_vin = compact.read_from(stream)
        # if num_vin is zero it is a segwit transaction
        is_segwit = num_vin == 0
        if is_segwit:
            marker = stream.read(1)
            if marker != b"\x01":
                raise TransactionError("Invalid segwit marker")
            num_vin = compact.read_from(stream)
        h.update(compact.to_bytes(num_vin))
        for i in range(num_vin):
            txin = TransactionInput.read_from(stream)
            h.update(txin.serialize())
        num_vout = compact.read_from(stream)
        h.update(compact.to_bytes(num_vout))
        if idx >= num_vout or idx < 0:
            raise TransactionError(
                "Invalid vout index %d, max is %d" % (idx, num_vout - 1)
            )
        res = None
        for i in range(num_vout):
            vout = TransactionOutput.read_from(stream)
            if idx == i:
                res = vout
            h.update(vout.serialize())
        if is_segwit:
            for i in range(num_vin):
                Witness.read_from(stream)
        h.update(stream.read(4))
        return res, hashlib.sha256(h.digest()).digest()

    @classmethod
    def read_from(cls, stream):
        ver = int.from_bytes(stream.read(4), "little")
        num_vin = compact.read_from(stream)
        # if num_vin is zero it is a segwit transaction
        is_segwit = num_vin == 0
        if is_segwit:
            marker = stream.read(1)
            if marker != b"\x01":
                raise TransactionError("Invalid segwit marker")
            num_vin = compact.read_from(stream)
        vin = []
        for i in range(num_vin):
            vin.append(TransactionInput.read_from(stream))
        num_vout = compact.read_from(stream)
        vout = []
        for i in range(num_vout):
            vout.append(TransactionOutput.read_from(stream))
        if is_segwit:
            for inp in vin:
                inp.witness = Witness.read_from(stream)
        locktime = int.from_bytes(stream.read(4), "little")
        return cls(version=ver, vin=vin, vout=vout, locktime=locktime)

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            h = hashlib.sha256()
            for inp in self.vin:
                h.update(bytes(reversed(inp.txid)))
                h.update(inp.vout.to_bytes(4, "little"))
            self._hash_prevouts = h.digest()
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            h = hashlib.sha256()
            for inp in self.vin:
                h.update(inp.sequence.to_bytes(4, "little"))
            self._hash_sequence = h.digest()
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            h = hashlib.sha256()
            for out in self.vout:
                h.update(out.serialize())
            self._hash_outputs = h.digest()
        return self._hash_outputs

    # Keyed on what it was computed over, because these take the spent outputs as an
    # argument rather than reading them off self: one Transaction can be asked for two
    # digests over two different sets, and each must get its own.
    def hash_amounts(self, amounts):
        key = tuple(amounts)
        if self._hash_amounts is None or self._hash_amounts[0] != key:
            self._hash_amounts = (key, hash_amounts(amounts))
        return self._hash_amounts[1]

    def hash_script_pubkeys(self, script_pubkeys):
        key = tuple(bytes(s.data) for s in script_pubkeys)
        if self._hash_script_pubkeys is None or self._hash_script_pubkeys[0] != key:
            self._hash_script_pubkeys = (key, hash_script_pubkeys(script_pubkeys))
        return self._hash_script_pubkeys[1]

    def sighash_unified(
        self,
        input_index,
        script_type,
        script_pubkeys,
        values,
        sighash,
        script_code=None,
        annex=None,
        tapleaf_hash=None,
        codeseparator_pos=None,
    ):
        """Unified opt-in signature hash, one message format for every script
        type. See doc/unified-sighash.md in Bitcoin Knots.

        script_code is required for BARE and WITNESS_V0: the scriptPubKey for a
        bare input, the redeemScript for P2SH, the witnessScript for P2WSH, and
        for P2WPKH the implied P2PKH script as in BIP143.

        tapleaf_hash and codeseparator_pos apply to TAPSCRIPT only.
        """
        if input_index < 0 or input_index >= len(self.vin):
            raise TransactionError("Invalid input index")
        if len(values) != len(self.vin) or len(script_pubkeys) != len(self.vin):
            raise TransactionError("All spent outputs are required")
        if script_type not in (0, 1, 2, 3):
            raise TransactionError("Invalid script type")
        if script_type in (0, 1) and script_code is None:
            raise TransactionError("script_code is required for this script type")
        if script_type == 3 and tapleaf_hash is None:
            raise TransactionError("tapleaf_hash is required for tapscript")
        sh, anyonecanpay = SIGHASH.check_unified(sighash, script_type)

        h = hashes.tagged_hash_init("UnifiedSighash", b"")
        # Laid out as BIP341 lays out its message, so the two can be read side by side. The epoch
        # is BIP341's, kept so a later revision has the same room to move that BIP341 left itself.
        h.update(b"\x00")
        # One byte, as BIP341 writes it and as the signature carries it: consensus reads the hash
        # type from the last byte of the signature, so a wider field could hold a value no
        # verifier would ever reconstruct.
        h.update(bytes([sighash]))
        h.update(self.version.to_bytes(4, "little"))
        # The locktime is committed to as five bytes rather than the four it occupies in a
        # transaction. Four run out on 2106-02-07, and a hardfork widening the field later
        # would otherwise have to change this message and invalidate every signature made
        # under it. The fifth byte is zero until something sets it.
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(b"\x00")
        if not anyonecanpay:
            h.update(self.hash_prevouts())
            h.update(self.hash_amounts(values))
            h.update(self.hash_script_pubkeys(script_pubkeys))
            h.update(self.hash_sequence())
        if sh not in (SIGHASH.NONE, SIGHASH.SINGLE):
            # ALL, and every value that is neither NONE nor SINGLE.
            h.update(self.hash_outputs())
        # Where BIP341 writes its spend type. It has an annex bit to pack in there and this has
        # none to pack, so the byte carries the script type alone.
        h.update(bytes([script_type]))
        if anyonecanpay:
            h.update(bytes(reversed(self.vin[input_index].txid)))
            h.update(self.vin[input_index].vout.to_bytes(4, "little"))
            h.update(values[input_index].to_bytes(8, "little"))
            h.update(script_pubkeys[input_index].serialize())
            h.update(self.vin[input_index].sequence.to_bytes(4, "little"))
        else:
            h.update(input_index.to_bytes(4, "little"))

        if script_type in (0, 1):
            h.update(script_code.serialize())
        else:
            h.update(b"\x01" if annex is not None else b"\x00")
            if annex is not None:
                h.update(hashes.sha256(compact.to_bytes(len(annex)) + annex))

        # The single output, where BIP341 puts it.
        if sh == SIGHASH.SINGLE:
            if input_index >= len(self.vout):
                raise TransactionError("SIGHASH_SINGLE with no matching output")
            h.update(hashlib.sha256(self.vout[input_index].serialize()).digest())

        if script_type == 3:
            h.update(tapleaf_hash)
            h.update(b"\x00")  # key version
            h.update(
                b"\xff\xff\xff\xff"
                if codeseparator_pos is None
                else codeseparator_pos.to_bytes(4, "little")
            )
        return h.digest()

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
        if input_index < 0 or input_index >= len(self.vin):
            raise TransactionError("Invalid input index")
        if len(values) != len(self.vin):
            raise TransactionError("All spent amounts are required")
        sh, anyonecanpay = SIGHASH.check(sighash)
        h = hashes.tagged_hash_init("TapSighash", b"\x00")
        h.update(bytes([sighash]))
        h.update(self.version.to_bytes(4, "little"))
        h.update(self.locktime.to_bytes(4, "little"))
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
            h.update(self.vin[input_index].serialize())
            h.update(values[input_index].to_bytes(8, "little"))
            h.update(script_pubkeys[input_index].serialize())
            h.update(self.vin[input_index].sequence.to_bytes(4, "little"))
        else:
            h.update(input_index.to_bytes(4, "little"))
        if annex is not None:
            h.update(hashes.sha256(compact.to_bytes(len(annex)) + annex))
        if sh == SIGHASH.SINGLE:
            h.update(self.vout[input_index].serialize())
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
        if input_index < 0 or input_index >= len(self.vin):
            raise TransactionError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        # default sighash is used only in taproot
        if sh == SIGHASH.DEFAULT:
            sh = SIGHASH.ALL
        inp = self.vin[input_index]
        zero = b"\x00" * 32  # for sighashes
        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
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
            h.update(
                hashlib.sha256(
                    hashlib.sha256(self.vout[input_index].serialize()).digest()
                ).digest()
            )
        else:
            h.update(zero)
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()

    def sighash_legacy(self, input_index, script_pubkey, sighash=SIGHASH.ALL):
        if input_index < 0 or input_index >= len(self.vin):
            raise TransactionError("Invalid input index")
        sh, anyonecanpay = SIGHASH.check(sighash)
        if sh == SIGHASH.DEFAULT:
            sh = SIGHASH.ALL
        # no corresponding output for this input, we sign 00...01
        if sh == SIGHASH.SINGLE and input_index >= len(self.vout):
            return b"\x00" * 31 + b"\x01"

        h = hashlib.sha256()
        h.update(self.version.to_bytes(4, "little"))
        # ANYONECANPAY - only one input is serialized
        if anyonecanpay:
            h.update(compact.to_bytes(1))
            h.update(self.vin[input_index].serialize(script_pubkey))
        else:
            h.update(compact.to_bytes(len(self.vin)))
            for i, inp in enumerate(self.vin):
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
            h.update(self.vout[input_index].serialize())
        elif sh == SIGHASH.ALL:
            h.update(compact.to_bytes(len(self.vout)))
            for out in self.vout:
                h.update(out.serialize())
        else:
            # shouldn't happen
            raise TransactionError("Invalid sighash")
        h.update(self.locktime.to_bytes(4, "little"))
        h.update(sighash.to_bytes(4, "little"))
        return hashlib.sha256(h.digest()).digest()


class TransactionInput(EmbitBase):
    def __init__(self, txid, vout, script_sig=None, sequence=0xFFFFFFFF, witness=None):
        if script_sig is None:
            script_sig = Script(b"")
        if witness is None:
            witness = Witness([])
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness

    @property
    def is_segwit(self):
        return not (self.witness.serialize() == b"\x00")

    def write_to(self, stream, script_sig=None, sighash=SIGHASH.ALL):
        sh, anyonecanpay = SIGHASH.check(sighash)
        if anyonecanpay or sh in [SIGHASH.SINGLE, SIGHASH.NONE]:
            sequence = 0
        else:
            sequence = self.sequence
        res = stream.write(bytes(reversed(self.txid)))
        res += stream.write(self.vout.to_bytes(4, "little"))
        if script_sig is None:
            res += stream.write(self.script_sig.serialize())
        else:
            res += stream.write(script_sig.serialize())
        res += stream.write(sequence.to_bytes(4, "little"))
        return res

    @classmethod
    def read_from(cls, stream):
        txid = bytes(reversed(stream.read(32)))
        vout = int.from_bytes(stream.read(4), "little")
        script_sig = Script.read_from(stream)
        sequence = int.from_bytes(stream.read(4), "little")
        return cls(txid, vout, script_sig, sequence)


class TransactionOutput(EmbitBase):
    def __init__(self, value, script_pubkey):
        self.value = value
        self.script_pubkey = script_pubkey

    def write_to(self, stream):
        res = stream.write(self.value.to_bytes(8, "little"))
        res += stream.write(self.script_pubkey.serialize())
        return res

    @classmethod
    def read_from(cls, stream):
        value = int.from_bytes(stream.read(8), "little")
        script_pubkey = Script.read_from(stream)
        return cls(value, script_pubkey)
