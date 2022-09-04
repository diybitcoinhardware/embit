import hashlib
import hmac
import sys

from binascii import hexlify, unhexlify
from io import BytesIO
from typing import Tuple

from . import base58, ec, script
from .base import EmbitError
from .bip32 import HDKey
from .networks import NETWORKS
from .script import OPCODES
from .transaction import Transaction
if sys.implementation.name == "micropython":
    import secp256k1
else:
    from .util import secp256k1


"""
    BIP-47: https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki
"""

class BIP47Exception(Exception):
    pass


def get_payment_code(root: HDKey, coin: int = 0, account: int = 0) -> str:
    """
        Generates the recipient's BIP-47 shareable payment code (version 1)
        for the input root private key.
    """
    bip47_child = root.derive("m/47'/{}'/{}'".format(coin, account))

    buf = BytesIO()
    buf.write(b'\x01')      # bip47 version
    buf.write(b'\x00')      # Bitmessage; always zero
    buf.write(bip47_child.get_public_key().serialize())
    buf.write(bip47_child.chain_code)
    buf.write(b'\00' * 13)  # bytes reserved for future expansion

    return base58.encode_check(b'\x47' + buf.getvalue())


def get_derived_payment_code_node(payment_code: str, derivation_index: int) -> HDKey:
    """Returns the nth derived child for the payment_code"""
    raw_payment_code = base58.decode_check(payment_code)

    # 81-byte payment code format:
    #   0x47 0x01 0x00 (sign) (32-byte pubkey) (32-byte chain code) (13 0x00 bytes)
    pubkey = ec.PublicKey.from_string(hexlify(raw_payment_code[3:36]))
    chain_code = raw_payment_code[36:68]
    root = HDKey(key=pubkey, chain_code=chain_code)
    return root.derive([derivation_index])


def get_notification_address(payment_code: str, script_type: str = "p2pkh", network: str = NETWORKS["main"]) -> str:
    """Returns the BIP-47 notification address associated with the given payment_code"""
    # Get the 0th public key derived from the payment_code
    pubkey = get_derived_payment_code_node(payment_code, derivation_index=0).get_public_key()

    # TODO: Should we limit to just p2pkh?
    if script_type == "p2pkh":
        return script.p2pkh(pubkey).address(network)
    elif script_type == "p2wpkh":
        return script.p2wpkh(pubkey).address(network)
    else:
        raise EmbitError("Unsupported script_type: " + script_type)


def get_payment_address(payer_root: HDKey, recipient_payment_code: str, index: int, coin: int = 0, account: int = 0, network: dict = NETWORKS["main"], script_type: str = "p2wpkh") -> str:
    """Called by the payer, generates the nth payment address between the payer and recipient"""
    # Alice selects the 0th private key derived from her payment code ("a")
    payer_key = payer_root.derive("m/47'/{}'/{}'/0".format(coin, account))
    a = payer_key.secret

    # Alice selects the next unused public key derived from Bob's payment code, starting from zero ("B", where B = bG)
    recipient_payment_code_node = get_derived_payment_code_node(recipient_payment_code, derivation_index=index)
    B = recipient_payment_code_node.get_public_key()

    # Alice calculates a secret point (S = aB)
    S = B._xonly()
    secp256k1.ec_pubkey_tweak_mul(S, a)

    # Alice calculates a scalar shared secret using the x value of S (s = SHA256(Sx))
    shared_secret = hashlib.sha256(secp256k1.ec_pubkey_serialize(S)[1:33]).digest()

    # If the value of s is not in the secp256k1 group, Alice MUST increment the index used to derive Bob's public key and try again.
    if not secp256k1.ec_seckey_verify(shared_secret):
        # TODO: Is this a sufficient test???
        raise BIP47Exception("Shared secret was not valid for index {}. Try again with the next index value.".format(index))

    # Alice uses the scalar shared secret to calculate the ephemeral public key used to generate the P2PKH address for this transaction (B' = B + sG)
    shared_pubkey = secp256k1.ec_pubkey_create(shared_secret)
    pub = secp256k1.ec_pubkey_combine(B._point, shared_pubkey)
    shared_node = HDKey(key=ec.PublicKey.parse(secp256k1.ec_pubkey_serialize(pub)), chain_code=recipient_payment_code_node.chain_code)

    if script_type == "p2pkh":
        return script.p2pkh(shared_node).address(network=network)
    elif script_type == "p2wpkh":
        return script.p2wpkh(shared_node).address(network=network)
    elif script_type == "p2sh-p2wpkh":
        return script.p2sh(script.p2wpkh(shared_node)).address(network=network)
    else:
        raise EmbitError("Unsupported script_type: " + script_type)


def get_receive_address(recipient_root: HDKey, payer_payment_code: str, index: int, coin: int = 0, account: int = 0, network: dict = NETWORKS["main"], script_type: str = "p2wpkh") -> Tuple[str, ec.PrivateKey]:
    """Called by the recipient, generates the nth receive address between the payer and recipient.
    
        Returns the payment address and its associated private key."""

    # Using the 0th public key derived from Alice's payment code...
    payer_payment_code_node = get_derived_payment_code_node(payer_payment_code, derivation_index=0)
    B = payer_payment_code_node.get_public_key()

    # ...Bob calculates the nth shared secret with Alice
    recipient_key = recipient_root.derive("m/47'/{}'/{}'/{}".format(coin, account, index))
    a = recipient_key.secret

    # Bob calculates a secret point (S = aB)
    S = B._xonly()
    secp256k1.ec_pubkey_tweak_mul(S, a)

    # Bob calculates a scalar shared secret using the x value of S (s = SHA256(Sx))
    shared_secret = hashlib.sha256(secp256k1.ec_pubkey_serialize(S)[1:33]).digest()

    # If the value of s is not in the secp256k1 group, increment the index and try again.
    if not secp256k1.ec_seckey_verify(shared_secret):
        # TODO: Is this a sufficient test???
        raise BIP47Exception("Shared secret was not valid for index {}. Try again with the next index value.".format(index))

    # Bob uses the scalar shared secret to calculate the ephemeral public key used to generate the P2PKH address for this transaction (B' = B + sG)
    shared_pubkey = secp256k1.ec_pubkey_create(shared_secret)
    pub = secp256k1.ec_pubkey_combine(recipient_key.get_public_key()._point, shared_pubkey)
    shared_node = HDKey(key=ec.PublicKey.parse(secp256k1.ec_pubkey_serialize(pub)), chain_code=payer_payment_code_node.chain_code)

    if script_type == "p2pkh":
        receive_address = script.p2pkh(shared_node).address(network=network)
    elif script_type == "p2wpkh":
        receive_address = script.p2wpkh(shared_node).address(network=network)
    elif script_type == "p2sh-p2wpkh":
        receive_address = script.p2sh(script.p2wpkh(shared_node)).address(network=network)
    else:
        raise EmbitError("Unsupported script_type: " + script_type)
    
    # Bob calculates the private key for each ephemeral address as: b' = b + s
    prv_key = secp256k1.ec_privkey_add(recipient_key.secret, shared_secret)
    spending_key = ec.PrivateKey(secret=prv_key)

    return (receive_address, spending_key)


def blinding_function(private_key: str, secret_point: HDKey, utxo_outpoint: str, payload: str):
    """Reversible blind/unblind function: blinds plaintext payloads and unblinds blinded payloads"""
    S = secret_point._xonly()
    secp256k1.ec_pubkey_tweak_mul(S, private_key)

    # Calculate a 64 byte blinding factor (s = HMAC-SHA512(x, o))
    #   "x" is the x value of the secret point
    #   "o" is the outpoint being spent by the designated input
    x = secp256k1.ec_pubkey_serialize(S)[1:33]
    o = utxo_outpoint
    s = unhexlify(hmac.new(unhexlify(o), x, hashlib.sha512).hexdigest())

    # Replace the x (pubkey) value with x' (x' = x XOR (first 32 bytes of s))
    # Replace the chain code with c' (c' = c XOR (last 32 bytes of s))
    # payment code: 0x01 0x00 (sign) (32-byte pubkey) (32-byte chain code) (13 0x00 bytes)
    x_prime = b''.join([(a ^ b).to_bytes(1, byteorder='little') for (a,b) in zip(payload[3:35], s[:32])])
    c_prime = b''.join([(a ^ b).to_bytes(1, byteorder='little') for (a,b) in zip(payload[35:67], s[-32:])])
    return payload[0:3] + x_prime + c_prime + payload[-13:]


def get_blinded_payment_code(payer_payment_code: str, input_utxo_private_key: ec.PrivateKey, input_utxo_outpoint: str, recipient_payment_code: str):
    """Called by the payer, returns the blinded payload for the payer's notification tx
        that is sent to the recipient while spending the input_utxo. The blinded payload
        should be inserted as OP_RETURN data."""
    # TODO: method signature was made to easily match the BIP-47 test vector data, but
    # isn't necessarily what might be ideal for real-world usage.

    # Alice selects the private key ("a") corresponding to the designated pubkey
    a = input_utxo_private_key.secret

    # Alice selects the public key associated with Bob's notification address (B, where B = bG)
    B = get_derived_payment_code_node(recipient_payment_code, derivation_index=0).get_public_key()

    # Alice serializes her payment code in binary form
    payment_code = base58.decode_check(payer_payment_code)[1:]  # omit the 0x47 leading byte

    # Blind the payment code
    raw_blinded_payload = blinding_function(a, B, utxo_outpoint=input_utxo_outpoint[:72], payload=payment_code)
    return hexlify(raw_blinded_payload).decode()


def get_payment_code_from_notification_tx(tx: Transaction, recipient_root: HDKey, coin: int = 0, account: int = 0, network: dict = NETWORKS["main"]) -> str:
    """If the tx is a BIP-47 notification tx for the recipient,
        return the new payer's embedded payment_code, else None"""
    # Notification txs have one output sent to the recipient's notification addr
    # and another containing the payer's payment code in an OP_RETURN payload.
    if len(tx.vout) < 2:
        return False
    
    recipient_payment_code = get_payment_code(recipient_root, coin, account)
    
    matches_notification_addr = False
    payload = None
    for vout in tx.vout:
        # Notification txs include a dust payment to the recipient's notification address
        if vout.script_pubkey.script_type() is not None and vout.script_pubkey.address(network=network) == get_notification_address(recipient_payment_code, network=network):
            matches_notification_addr = True
            continue

        # Payer's payment code will be in an OP_RETURN w/exactly 80 bytes of data
        data = vout.script_pubkey.data
        if data is not None and len(data) == 83 and data[0] == OPCODES.OP_RETURN and data[1] == OPCODES.OP_PUSHDATA1 and data[2] == 80:
            # data = OP_RETURN OP_PUSHDATA1 (len of data) <data>
            payload = data[3:]

            if payload[0] != 1:
                # Only version 1 currently supported
                payload = None
            continue

    if not matches_notification_addr or payload is None:
        return None
    
    # Bob selects the designated pubkey ("A")
    # (the first tx input that exposes a pubkey in scriptsig or witness)
    for vin in tx.vin:
        if not vin.is_segwit:
            # data = (1byte len of sig) <sig> (1byte len of pubkey) <pubkey>
            sig_len = vin.script_sig.data[0]
            A = ec.PublicKey.from_string(hexlify(vin.script_sig.data[sig_len + 2:]))
            break

        else:
            # Witness should have [sig, pubkey]
            A = ec.PublicKey.from_string(hexlify(vin.witness.items[1]))
            break

    if not A or len(A.serialize()) != 33:
        return None
    
    # Bob selects the private key associated with his notification address (0th child)
    recipient_notification_node = recipient_root.derive("m/47'/{}'/{}'/0".format(coin, account))
    b = recipient_notification_node.secret

    utxo_outpoint = vin.to_string()[:72]  # TODO: Is there a better way to get the outpoint?

    # Unblind the payload using the reversible `blinding_function`.
    raw_unblinded_payload = blinding_function(b, A, utxo_outpoint=utxo_outpoint, payload=payload)
    return base58.encode_check(b'\x47' + raw_unblinded_payload)


"""
    TODO: Method to create notification transaction, etc.
"""