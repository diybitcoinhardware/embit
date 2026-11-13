import sys

# imported modules sorted to match `ls tests/`, for ease-of-maintenance

from .test_base58 import *
from .test_bech32 import *
from .test_bip32 import *
from .test_bip39 import *
from .test_bip85 import *
from .test_descriptor import *
from .test_ecc import *
from .test_finalizer import *
from .test_liquid import *
from .test_parsing import ParsingTest as ParsingTest
from .test_psbt import *
from .test_psbt_versions import *
from .test_psbtview import *
from .test_psetview import *
from .test_script import *
from .test_slip39 import *
from .test_taproot import *
from .test_taptree import *

if sys.implementation.name != "micropython":
    from .test_bindings import *
    from .test_ecdh import *
    from .test_psbtV2 import *
    from .test_ripemd160 import *
    from .test_threading import *
