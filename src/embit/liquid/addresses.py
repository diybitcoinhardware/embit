from .. import bech32, ec, script, base58
from . import blech32
from .networks import NETWORKS

def address(script, blinding_key=None, network=NETWORKS['liquidv1']):
    """
    Returns liquid address from scriptpubkey and blinding key.
    Confidential if blinding key is set, unconfidential otherwise.
    """
    if script.data == b"":
        return "Fee"
    if script.script_type() == "p2sh":
        data = script.data[2:-1]
        if blinding_key is None:
            return base58.encode_check(network["p2sh"]+data)
        else:
            return base58.encode_check(network["bp2sh"]+blinding_key.sec()+data)
    else:
        data = script.data
        ver = data[0]
        # FIXME: should be one of OP_N
        if ver > 0:
            ver = ver % 0x50
        if blinding_key is None:
            return bech32.encode(network["bech32"], ver, data[2:])
        else:
            return blech32.encode(network["blech32"], ver, blinding_key.sec() + data[2:])

def addr_decode(addr):
    """
    Decodes a liquid address and returns scriptpubkey and blinding pubkey.
    If unconfidential address is used - blinding pubkey will be None
    """
    if addr == "Fee":
        return script.Script(), None
    # check if bech32:
    if addr.split("1")[0].lower() in [net.get("blech32") for net in NETWORKS.values()]:
        addr = addr.lower()
        hrp = addr.split("1")[0]
        ver, data = blech32.decode(hrp, addr)
        data = bytes(data)
        pub = ec.PublicKey.parse(data[:33])
        pubhash = data[33:]
        sc = script.Script(b"\x00"+bytes([len(pubhash)])+pubhash)
    elif addr.split("1")[0].lower() in [net.get("bech32") for net in NETWORKS.values()]:
        hrp = addr.split("1")[0]
        ver, data = bech32.decode(hrp, addr)
        pub = None
        sc = script.Script(b"\x00"+bytes([len(data)])+bytes(data))
    else:
        data = base58.decode_check(addr)
        if data[:2] in [net.get("bp2sh") for net in NETWORKS.values()]:
            pub = ec.PublicKey.parse(data[2:35])
            sc = script.Script(b"\xa9\x14"+data[35:]+b"\x87")
        elif data[:1] in [net.get("p2sh") for net in NETWORKS.values()]:
            pub = None
            sc = script.Script(b"\xa9\x14"+data[1:]+b"\x87")
        else:
            raise RuntimeError("Invalid address")
    return sc, pub

def detect_network(addr):
    """Detects what networks the address belongs to"""
    # check if it's bech32
    for net in NETWORKS.values():
        if addr.lower().startswith(net.get("bech32")):
            return net
        if "blech32" in net and addr.lower().startswith(net.get("blech32")):
            return net
    # if not - it's base58
    data = base58.decode_check(addr)
    for net in NETWORKS.values():
        if data[:2] in [net.get("bp2sh"), net.get("p2sh")]:
            return net

def to_unconfidential(addr):
    """
    Converts address from confidential to unconfidential.
    Returns the same address if already unconfidential.
    """
    sc, pub = addr_decode(addr)
    if pub is None:
        return addr
    net = detect_network(addr)
    return address(sc, network=net)
