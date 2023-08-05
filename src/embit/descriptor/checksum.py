from .errors import DescriptorError


def polymod(c: int, val: int) -> int:
    c0 = c >> 35
    c = ((c & 0x7FFFFFFFF) << 5) ^ val
    if c0 & 1:
        c ^= 0xF5DEE51989
    if c0 & 2:
        c ^= 0xA9FDCA3312
    if c0 & 4:
        c ^= 0x1BAB10E32D
    if c0 & 8:
        c ^= 0x3706B1677A
    if c0 & 16:
        c ^= 0x644D626FFD
    return c


def checksum(desc: str) -> str:
    """Calculate checksum of desciptor string"""
    INPUT_CHARSET = (
        "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVW"
        'XYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ '
    )
    CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            raise DescriptorError("Invalid character '%s' in the input string" % ch)
        c = polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = polymod(c, cls)
            cls = 0
            clscount = 0
    if clscount > 0:
        c = polymod(c, cls)
    for j in range(0, 8):
        c = polymod(c, 0)
    c ^= 1

    ret = [CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31] for j in range(0, 8)]
    return "".join(ret)


def add_checksum(desc: str) -> str:
    """Add checksum to descriptor string"""
    if "#" in desc:
        desc = desc.split("#")[0]
    return desc + "#" + checksum(desc)
