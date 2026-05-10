import hashlib
import hmac
import sys

from binascii import hexlify, unhexlify
from io import BytesIO
from . import base58, ec, script
from .bip32 import HDKey
from .networks import NETWORKS
from .script import OPCODES
from .transaction import Transaction
if sys.implementation.name == "micropython":
    import secp256k1  # pragma: no cover
else:
    from .util import secp256k1


"""
    BIP-47: https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki
"""

class BIP47Exception(EmbitError):
    pass


def _validate_payment_code(raw: bytes):
    """Validates the 81-byte BIP-47 v1 canonical payment code (with 0x47 prefix).
        Raises BIP47Exception on any mismatch.

        Layout: 0x47 <version:1> <features:1> <sign:1> <x:32> <chain_code:32> <13 zeros>
            * total length must be 81.
            * prefix byte must be 0x47.
            * version byte must be 0x01 (v1).
            * features byte is the now-defunct Bitmessage notification flag; intentionally not validated.
            * last 13 bytes must all be zero in v1.
    """
    if len(raw) != 81:
        raise BIP47Exception("Invalid payment code: expected 81 bytes, got {}".format(len(raw)))
    if raw[0] != 0x47:
        raise BIP47Exception("Invalid payment code: expected 0x47 prefix, got 0x{:02x}".format(raw[0]))
    if raw[1] != 0x01:
        raise BIP47Exception("Invalid payment code: unsupported version {} (only v1 is supported)".format(raw[1]))
    try:
        ec.PublicKey.parse(raw[3:36])
    except Exception:
        raise BIP47Exception("Invalid payment code: x-coordinate is not a valid secp256k1 point")
    if raw[-13:] != b'\x00' * 13:
        raise BIP47Exception("Invalid payment code: 13 trailing bytes must be zero in v1")


def get_payment_code(root: HDKey, coin: int = 0, account: int = 0) -> str:
    """
        Generates the recipient's BIP-47 shareable payment code (version 1)
        for the input root private key.
    """
    bip47_child = root.derive("m/47'/{}'/{}'".format(coin, account))

    # Build the canonical 81-byte payment code directly.
    buf = BytesIO()
    buf.write(b'\x47')      # BIP-47 protocol prefix
    buf.write(b'\x01')      # version
    buf.write(b'\x00')      # features byte; Bitmessage notification flag (bit 0, defunct) intentionally not set
    buf.write(bip47_child.get_public_key().serialize())
    buf.write(bip47_child.chain_code)
    buf.write(b'\00' * 13)  # bytes reserved for future expansion

    return base58.encode_check(buf.getvalue())


def get_derived_payment_code_node(payment_code: str, derivation_index: int) -> HDKey:
    """Returns the nth derived child for the payment_code"""
    raw_payment_code = base58.decode_check(payment_code)
    _validate_payment_code(raw_payment_code)

    pubkey = ec.PublicKey.parse(raw_payment_code[3:36])
    chain_code = raw_payment_code[36:68]
    root = HDKey(key=pubkey, chain_code=chain_code)
    return root.derive([derivation_index])


def get_notification_address(payment_code: str, network: dict = NETWORKS["main"]) -> str:
    """
        Returns the BIP-47 notification address associated with the given payment_code.
        Per the spec, this is always a p2pkh address.
    """
    # Get the 0th public key derived from the payment_code
    pubkey = get_derived_payment_code_node(payment_code, derivation_index=0).get_public_key()
    return script.p2pkh(pubkey).address(network)


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
        raise BIP47Exception("Unsupported script_type: " + script_type)


def get_receive_address(recipient_root: HDKey, payer_payment_code: str, index: int, coin: int = 0, account: int = 0, network: dict = NETWORKS["main"], script_type: str = "p2wpkh") -> tuple:
    """Called by the recipient, generates the nth receive address between the payer and recipient.

        Returns a 2-tuple `(payment_address: str, spending_key: ec.PrivateKey)`.
    """

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
        raise BIP47Exception("Unsupported script_type: " + script_type)

    # Bob calculates the private key for each ephemeral address as: b' = b + s
    prv_key = secp256k1.ec_privkey_add(recipient_key.secret, shared_secret)
    spending_key = ec.PrivateKey(secret=prv_key)

    return (receive_address, spending_key)


def blinding_function(private_key: bytes, counterparty_pubkey: ec.PublicKey, utxo_outpoint: str, payload: bytes) -> bytes:
    """Reversible blind/unblind function: blinds plaintext payloads and unblinds blinded payloads"""
    # Compute the "secret point" S = private_key · counterparty_pubkey (an ECDH
    # shared point); its x-coordinate seeds the blinding factor below.
    S = counterparty_pubkey._xonly()
    secp256k1.ec_pubkey_tweak_mul(S, private_key)

    # Calculate a 64-byte blinding factor s = HMAC-SHA512(key=o, msg=x).
    # Note: BIP-47 prose contradicts itself (sender side says "HMAC-SHA512(o, x)",
    # recipient side says "HMAC-SHA512(x, o)") but reference test vectors and
    # every known implementation use key=o, msg=x.
    #   "x" is the x value of the secret point S
    #   "o" is the outpoint being spent by the designated input
    x = secp256k1.ec_pubkey_serialize(S)[1:33]
    o = utxo_outpoint
    s = hmac.new(key=unhexlify(o), msg=x, digestmod=hashlib.sha512).digest()

    # Replace the x (pubkey) value with x' (x' = x XOR (first 32 bytes of s))
    # Replace the chain code with c' (c' = c XOR (last 32 bytes of s))
    # payment code: 0x01 0x00 (sign) (32-byte pubkey) (32-byte chain code) (13 0x00 bytes)
    x_prime = bytes(a ^ b for (a, b) in zip(payload[3:35], s[:32]))
    c_prime = bytes(a ^ b for (a, b) in zip(payload[35:67], s[-32:]))
    return payload[0:3] + x_prime + c_prime + payload[-13:]


def get_blinded_payment_code(payer_payment_code: str, input_utxo_private_key: ec.PrivateKey, input_utxo_outpoint: str, recipient_payment_code: str) -> str:
    """
        Called by the payer, returns the blinded payload for the payer's notification tx
        that is sent to the recipient while spending the input_utxo. The blinded payload
        should be inserted as OP_RETURN data.

        `input_utxo_outpoint` must be the 36-byte outpoint as a 72-char hex string
        (32-byte txid in reversed/little-endian byte order, then 4-byte vout in
        little-endian). Anything else raises BIP47Exception; silent truncation
        would produce a payload the recipient cannot unblind.
    """
    if len(input_utxo_outpoint) != 72:
        raise BIP47Exception(
            "input_utxo_outpoint must be exactly 72 hex chars (36 bytes); got {}".format(len(input_utxo_outpoint))
        )

    # Alice selects the private key ("a") corresponding to the designated pubkey
    a = input_utxo_private_key.secret

    # Alice selects the public key associated with Bob's notification address (B, where B = bG)
    B = get_derived_payment_code_node(recipient_payment_code, derivation_index=0).get_public_key()

    # Alice serializes her payment code in binary form
    payment_code = base58.decode_check(payer_payment_code)[1:]  # omit the 0x47 leading byte

    # Blind the payment code
    raw_blinded_payload = blinding_function(a, B, utxo_outpoint=input_utxo_outpoint, payload=payment_code)
    return hexlify(raw_blinded_payload).decode()


def get_payment_code_from_notification_tx(tx: Transaction, recipient_root: HDKey, coin: int = 0, account: int = 0, network: dict = NETWORKS["main"]):
    """
        If the tx is a BIP-47 notification tx for the recipient, return the new payer's
        embedded payment_code as a `str`, else `None`.
    """
    # Notification txs have one output sent to the recipient's notification addr
    # and another containing the payer's payment code in an OP_RETURN payload.
    if len(tx.vout) < 2:
        return None
    
    recipient_payment_code = get_payment_code(recipient_root, coin, account)
    
    matches_notification_addr = False
    payload = None
    for vout in tx.vout:
        # Notification txs include a dust payment to the recipient's notification address
        if vout.script_pubkey.script_type() is not None and vout.script_pubkey.address(network=network) == get_notification_address(recipient_payment_code, network=network):
            matches_notification_addr = True
            continue

        # Payer's blinded payment code will be in an OP_RETURN w/exactly 80 bytes of data
        #   data = OP_RETURN OP_PUSHDATA1 (len of payload) <payload>
        data = vout.script_pubkey.data
        if data is not None and len(data) == 83 and data[0] == OPCODES.OP_RETURN and data[1] == OPCODES.OP_PUSHDATA1 and data[2] == 80:
            candidate_payload = data[3:]
            # Only v1 is currently supported. Assign only on a supported version
            # so a later unsupported-version OP_RETURN can't clobber a valid
            # payload found earlier in the loop.
            if candidate_payload[0] == 1:
                payload = candidate_payload
            continue

    if not matches_notification_addr or payload is None:
        return None
    
    # Bob selects the designated pubkey ("A"): the first input that exposes a 33-byte
    # compressed pubkey in scriptsig (P2PKH) or witness (P2WPKH). Other script types
    # (P2SH, P2WSH, P2TR, etc.) don't expose a bare pubkey at the canonical position and
    # are skipped per BIP-47 v1.
    A = None
    designated_vin = None
    for vin in tx.vin:
        try:
            if not vin.is_segwit:
                # script_sig: (1byte len of sig) <sig> (1byte len of pubkey) <pubkey>
                sig_len = vin.script_sig.data[0]
                candidate = ec.PublicKey.parse(vin.script_sig.data[sig_len + 2:])
            else:
                # Witness should have [sig, pubkey]
                candidate = ec.PublicKey.parse(vin.witness.items[1])
        except Exception:
            continue

        if len(candidate.serialize()) == 33:
            A = candidate
            designated_vin = vin
            break

    if A is None:
        return None

    # Bob selects the private key associated with his notification address (0th child)
    recipient_notification_node = recipient_root.derive("m/47'/{}'/{}'/0".format(coin, account))
    b = recipient_notification_node.secret

    # Build the 36-byte outpoint as hex: 32-byte txid in reversed (little-endian)
    # byte order, followed by the 4-byte vout index in little-endian.
    utxo_outpoint = (bytes(reversed(designated_vin.txid)) + designated_vin.vout.to_bytes(4, "little")).hex()

    # Unblind the payload using the reversible `blinding_function`.
    raw_unblinded_payload = blinding_function(b, A, utxo_outpoint=utxo_outpoint, payload=payload)

    # Re-attach the 0x47 BIP-47 protocol prefix that was stripped from the OP_RETURN payload
    # to form the canonical 81-byte payment code, then validate.
    raw_payment_code = b'\x47' + raw_unblinded_payload

    # Per spec, an invalid payload (wrong shape, off-curve x-coordinate, etc.) must be silently ignored.
    try:
        _validate_payment_code(raw_payment_code)
    except BIP47Exception:
        return None

    return base58.encode_check(raw_payment_code)
