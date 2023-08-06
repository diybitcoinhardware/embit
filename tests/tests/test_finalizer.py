from unittest import TestCase
from embit.descriptor import Descriptor
from embit.finalizer import finalize_psbt
from embit.psbt import PSBT
from .data.finalizer import DATA


class FinalizerTest(TestCase):
    def test_finalize(self):
        """
        Test we can finalize signed psbt with different tx types
        and finalization of unsigned txs returns None
        """
        for dstr, psbts in DATA.items():
            desc = Descriptor.from_string(dstr)
            expected_tx = None
            unsigned = None
            for b64psbt, expected in psbts.items():
                psbt = PSBT.from_string(b64psbt)
                res = finalize_psbt(psbt)
                if res is None:
                    self.assertEqual(expected, None)
                    unsigned = psbt
                else:
                    self.assertEqual(str(res), expected)
                    expected_tx = res
                if None not in [expected_tx, unsigned]:
                    # sign with descriptor and finalize
                    unsigned.sign_with(desc)
                    self.assertEqual(expected_tx, finalize_psbt(unsigned))
