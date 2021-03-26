import sys

if sys.implementation.name == "micropython":
    import secp256k1
except:
    from ..util import secp256k1

from ..psbt import *
from collections import OrderedDict
from io import BytesIO
from .transaction import LTransaction, LTransactionOutput

class PSET(PSBT):
    MAGIC = b"pset\xff"

    def __init__(self, tx=None):
        if tx is not None:
            self.tx = tx
            self.inputs = [LInputScope() for i in range(len(tx.vin))]
            self.outputs = [LOutputScope() for i in range(len(tx.vout))]
        else:
            self.tx = LTransaction()
            self.inputs = []
            self.outputs = []
        self.unknown = {}
        self.xpubs = OrderedDict()

    def sign_with(self, root) -> int:
        """
        Signs psbt with root key (HDKey or similar).
        Returns number of signatures added to PSBT
        """
        # TODO: rebase to psbt implementation
        fingerprint = root.child(0).fingerprint
        counter = 0
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
        # TODO: super().verify()?
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

    @classmethod
    def read_from(cls, stream):
        tx = None
        unknown = {}
        xpubs = OrderedDict()
        # check magic
        if stream.read(len(cls.MAGIC)) != cls.MAGIC:
            raise ValueError("Invalid PSET magic")
        while True:
            key = read_string(stream)
            # separator
            if len(key) == 0:
                break
            value = read_string(stream)
            # tx
            if key == b"\x00":
                if tx is None:
                    tx = LTransaction.parse(value)
                else:
                    raise ValueError(
                        "Failed to parse PSBT - duplicated transaction field"
                    )
            else:
                if key in unknown:
                    raise ValueError("Duplicated key")
                unknown[key] = value

        pset = cls(tx)
        # now we can go through all the key-values and parse them
        for k in list(unknown):
            # xpub field
            if k[0] == 0x01:
                xpub = bip32.HDKey.parse(k[1:])
                xpubs[xpub] = DerivationPath.parse(unknown.pop(k))
        pset.unknown = unknown
        pset.xpubs = xpubs
        # input scopes
        for i in range(len(tx.vin)):
            pset.inputs[i] = LInputScope.read_from(stream)
        # output scopes
        for i in range(len(tx.vout)):
            pset.outputs[i] = LOutputScope.read_from(stream)
        pset.verify()
        return pset

class LInputScope(PSBTScope):
    def __init__(self, unknown: dict = {}):
        self.unknown = unknown
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = OrderedDict()
        self.sighash_type = None
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()
        self.final_scriptsig = None
        self.final_scriptwitness = None
        # liquid-specific fields:
        self.value = None
        self.value_blinding_factor = None
        self.asset = None
        self.asset_blinding_factor = None
        self.parse_unknowns()

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        # TODO: super().parse_unknowns?
        for k in list(self.unknown):
            # legacy utxo
            if k[0] == 0x00:
                if len(k) != 1:
                    raise ValueError("Invalid non-witness utxo key")
                elif self.non_witness_utxo is not None:
                    raise ValueError("Duplicated utxo value")
                else:
                    self.non_witness_utxo = LTransaction.parse(self.unknown.pop(k))
            # witness utxo
            elif k[0] == 0x01:
                if len(k) != 1:
                    raise ValueError("Invalid witness utxo key")
                elif self.witness_utxo is not None:
                    raise ValueError("Duplicated utxo value")
                else:
                    self.witness_utxo = LTransactionOutput.parse(self.unknown.pop(k))
            # partial signature
            elif k[0] == 0x02:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.partial_sigs:
                    raise ValueError("Duplicated partial sig")
                else:
                    self.partial_sigs[pub] = self.unknown.pop(k)
            # hash type
            elif k[0] == 0x03:
                if len(k) != 1:
                    raise ValueError("Invalid sighash type key")
                elif self.sighash_type is None:
                    if len(self.unknown[k]) != 4:
                        raise ValueError("Sighash type should be 4 bytes long")
                    self.sighash_type = int.from_bytes(self.unknown.pop(k), "big")
                else:
                    raise ValueError("Duplicated sighash type")
            # redeem script
            elif k[0] == 0x04:
                if len(k) != 1:
                    raise ValueError("Invalid redeem script key")
                elif self.redeem_script is None:
                    self.redeem_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated redeem script")
            # witness script
            elif k[0] == 0x05:
                if len(k) != 1:
                    raise ValueError("Invalid witness script key")
                elif self.witness_script is None:
                    self.witness_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated witness script")
            # bip32 derivation
            elif k[0] == 0x06:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.bip32_derivations:
                    raise ValueError("Duplicated derivation path")
                else:
                    self.bip32_derivations[pub] = DerivationPath.parse(
                        self.unknown.pop(k)
                    )
            # final scriptsig
            elif k[0] == 0x07:
                if len(k) != 1:
                    raise ValueError("Invalid final scriptsig key")
                elif self.final_scriptsig is None:
                    self.final_scriptsig = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated final scriptsig")
            # final script witness
            elif k[0] == 0x08:
                if len(k) != 1:
                    raise ValueError("Invalid final scriptwitness key")
                elif self.final_scriptwitness is None:
                    self.final_scriptwitness = Witness.parse(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated final scriptwitness")
            # liquid-specific fields
            elif k == b'\xfc\x08elements\x00':
                self.value = int.from_bytes(self.unknown.pop(k), 'little')
            elif k == b'\xfc\x08elements\x01':
                self.value_blinding_factor = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x02':
                self.asset = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x03':
                self.asset_blinding_factor = self.unknown.pop(k)

    def serialize(self) -> bytes:
        # TODO: super().write_to() ???
        r = b""
        if self.non_witness_utxo is not None:
            r += b"\x01\x00"
            r += ser_string(self.non_witness_utxo.serialize())
        if self.witness_utxo is not None:
            r += b"\x01\x01"
            r += ser_string(self.witness_utxo.serialize())
        for pub in self.partial_sigs:
            r += ser_string(b"\x02" + pub.serialize())
            r += ser_string(self.partial_sigs[pub])
        if self.sighash_type is not None:
            r += b"\x01\x03"
            r += ser_string(self.sighash_type.to_bytes(4, "big"))
        if self.redeem_script is not None:
            r += b"\x01\x04"
            r += self.redeem_script.serialize()  # script serialization has length
        if self.witness_script is not None:
            r += b"\x01\x05"
            r += self.witness_script.serialize()  # script serialization has length
        for pub in self.bip32_derivations:
            r += ser_string(b"\x06" + pub.serialize())
            r += ser_string(self.bip32_derivations[pub].serialize())
        if self.final_scriptsig is not None:
            r += b"\x01\x07"
            r += self.final_scriptsig.serialize()
        if self.final_scriptwitness is not None:
            r += b"\x01\x08"
            r += ser_string(self.final_scriptwitness.serialize())
        # liquid-specific keys
        if self.value is not None:
            r += ser_string(b'\xfc\x08elements\x00')
            r += ser_string(self.value.to_bytes(8, 'little'))
        if self.value_blinding_factor is not None:
            r += ser_string(b'\xfc\x08elements\x01')
            r += ser_string(self.value_blinding_factor)
        if self.asset is not None:
            r += ser_string(b'\xfc\x08elements\x02')
            r += ser_string(self.asset)
        if self.asset_blinding_factor is not None:
            r += ser_string(b'\xfc\x08elements\x03')
            r += ser_string(self.asset_blinding_factor)
        for key in self.unknown:
            r += ser_string(key)
            r += ser_string(self.unknown[key])
        # separator
        r += b"\x00"
        return r


class LOutputScope(PSBTScope):
    def __init__(self, unknown: dict = {}):
        self.unknown = unknown
        self.redeem_script = None
        self.witness_script = None
        self.bip32_derivations = OrderedDict()
        # liquid stuff
        self.value_commitment = None
        self.value_blinding_factor = None
        self.asset_commitment = None
        self.asset_blinding_factor = None
        self.range_proof = None
        self.surjection_proof = None
        self.nonce_commitment = None
        self.parse_unknowns()

    def parse_unknowns(self):
        # go through all the unknowns and parse them
        # TODO: super().parse_unknowns()
        for k in list(self.unknown):
            # redeem script
            if k[0] == 0x00:
                if len(k) != 1:
                    raise ValueError("Invalid redeem script key")
                elif self.redeem_script is None:
                    self.redeem_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated redeem script")
            # witness script
            elif k[0] == 0x01:
                if len(k) != 1:
                    raise ValueError("Invalid witness script key")
                elif self.witness_script is None:
                    self.witness_script = Script(self.unknown.pop(k))
                else:
                    raise ValueError("Duplicated witness script")
            # bip32 derivation
            elif k[0] == 0x02:
                pub = ec.PublicKey.parse(k[1:])
                if pub in self.bip32_derivations:
                    raise ValueError("Duplicated derivation path")
                else:
                    self.bip32_derivations[pub] = DerivationPath.parse(
                        self.unknown.pop(k)
                    )
            # liquid-specific fields
            elif k == b'\xfc\x08elements\x00':
                self.value_commitment = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x01':
                self.value_blinding_factor = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x02':
                self.asset_commitment = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x03':
                self.asset_blinding_factor = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x04':
                # not sure if it's a range proof or not...
                self.range_proof = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x05':
                self.surjection_proof = self.unknown.pop(k)
            elif k == b'\xfc\x08elements\x07':
                self.nonce_commitment = self.unknown.pop(k)


    def serialize(self) -> bytes:
        # TODO: super.write_to()
        r = b""
        if self.redeem_script is not None:
            r += b"\x01\x00"
            r += self.redeem_script.serialize()  # script serialization has length
        if self.witness_script is not None:
            r += b"\x01\x01"
            r += self.witness_script.serialize()  # script serialization has length
        for pub in self.bip32_derivations:
            r += ser_string(b"\x02" + pub.serialize())
            r += ser_string(self.bip32_derivations[pub].serialize())
        # liquid-specific keys
        if self.value_commitment is not None:
            r += ser_string(b'\xfc\x08elements\x00')
            r += ser_string(self.value_commitment)
        if self.value_blinding_factor is not None:
            r += ser_string(b'\xfc\x08elements\x01')
            r += ser_string(self.value_blinding_factor)
        if self.asset_commitment is not None:
            r += ser_string(b'\xfc\x08elements\x02')
            r += ser_string(self.asset_commitment)
        if self.asset_blinding_factor is not None:
            r += ser_string(b'\xfc\x08elements\x03')
            r += ser_string(self.asset_blinding_factor)
        if self.nonce_commitment is not None:
            r += ser_string(b'\xfc\x08elements\x07')
            r += ser_string(self.nonce_commitment)
        # for some reason keys 04 and 05 are serialized after 07
        if self.range_proof is not None:
            r += ser_string(b'\xfc\x08elements\x04')
            r += ser_string(self.range_proof)
        if self.surjection_proof is not None:
            r += ser_string(b'\xfc\x08elements\x05')
            r += ser_string(self.surjection_proof)
        # unknown
        for key in self.unknown:
            r += ser_string(key)
            r += ser_string(self.unknown[key])
        # separator
        r += b"\x00"
        return r
