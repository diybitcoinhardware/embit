from unittest import TestCase
from embit.psbtview import PSBTView
from embit.psbt import PSBT, InputScope
from embit import bip32, bip39
from binascii import a2b_base64, b2a_base64
from io import BytesIO

ROOT = bip32.HDKey.from_seed(bip39.mnemonic_to_seed("toy fault beef holiday later unit boring merge shield detail scrap negative"))
PSBTS = [
    # native segwit single key, 3 inputs 4 outputs, version is None
    "cHNidP8BAP0NAQIAAAADzs+bdp5MDPJOynM/GVqxv0TxNfN65lYTcGjA8cD2NQABAAAAAP3////1a2FpOvW/FfVn5ct5op0HWQPcF4A4CiD1PuhzM0hvrQAAAAAA/f///2MhMb9J3pwquctpXFlr8LsbwD92XoSKkuwvoNt5prEyAQAAAAD9////BJ5YYgIAAAAAFgAUVE9NQrxzbpzaj8DvSA4+Vfb3S8+Aw8kBAAAAACIAILUTol87mgHQEKeZJcuNUJjXFfUupwaSGuS7QTdBQ1TW5pWYAAAAAAAWABSyijJ33ycsST0veZC7xCcjMLvGnoCWmAAAAAAAFgAUfwP8SJ6OrkWYgi79Rmtboh4vb6AAAAAAAAEAcQIAAAABuN9N7UQtW4/kL7p6GZ+7mJBDtdrC/DLvjimTOlG61vwAAAAAAP7///8CZnl3IwEAAAAWABTW7Yti5UnKO3zm7e0HWxgroI9k8YCWmAAAAAAAFgAUCCFopyBBzsmGQ+okmceR7NCUMRkAAAAAAQEfgJaYAAAAAAAWABQIIWinIEHOyYZD6iSZx5Hs0JQxGSIGAqmBsz9+uSoKzzc3UJKj73Z/nJbAJO8qGivBThNWuQtcGCYUvcRUAACAAQAAgAAAAIAAAAAAAgAAAAABAH0CAAAAAWMhMb9J3pwquctpXFlr8LsbwD92XoSKkuwvoNt5prEyAAAAAAD9////AoCWmAAAAAAAFgAUmt3MvhOm8evmqSbslu0VMw4ajTRcLDEBAAAAACIAIAzATi9Gij9I+WDMngJmvUJUfdBpvUc5SHXeB2kErkrHAAAAAAEBH4CWmAAAAAAAFgAUmt3MvhOm8evmqSbslu0VMw4ajTQiBgOBjOkF2dUPQVfZDgvAq1AJnIyXnxIndmAv9CatqeHP9hgmFL3EVAAAgAEAAIAAAACAAAAAAAEAAAAAAQB9AgAAAAG4303tRC1bj+QvunoZn7uYkEO12sL8Mu+OKZM6UbrW/AEAAAAA/f///wKAw8kBAAAAACIAIFwqEzbsUSf+/PC7SPfqGuy75tAydrgFkmv8DAEW6eNi5hwsBAAAAAAWABT9hflT6IkrLKaHS+x3zqee7ExP/AAAAAABAR/mHCwEAAAAABYAFP2F+VPoiSsspodL7HfOp57sTE/8IgYC420o3I+pkBOSVZyER/NTtZTLtP1iIKPdZK99ilI9UDoYJhS9xFQAAIABAACAAAAAgAEAAAAAAAAAAAAAIgICfM8IJ5ATUtpeuQOLpQbXkqvhs5mriKEpWLHod5vWAo4YJhS9xFQAAIABAACAAAAAgAEAAAACAAAAACICAujQqWO9vOEDwyUZqbeseGADN99ME/YWtJJTjW9/ag25GCYUvcRUAACAAQAAgAAAAIAAAAAAAwAAAAA=",
    # same transaction, version = 2
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQMBBQEEAfsEAgAAAAABAHECAAAAAbjfTe1ELVuP5C+6ehmfu5iQQ7Xawvwy744pkzpRutb8AAAAAAD+////AmZ5dyMBAAAAFgAU1u2LYuVJyjt85u3tB1sYK6CPZPGAlpgAAAAAABYAFAghaKcgQc7JhkPqJJnHkezQlDEZAAAAAAEBH4CWmAAAAAAAFgAUCCFopyBBzsmGQ+okmceR7NCUMRkiBgKpgbM/frkqCs83N1CSo+92f5yWwCTvKhorwU4TVrkLXBgmFL3EVAAAgAEAAIAAAACAAAAAAAIAAAABDiDOz5t2nkwM8k7Kcz8ZWrG/RPE183rmVhNwaMDxwPY1AAEPBAEAAAABEAT9////AAEAfQIAAAABYyExv0nenCq5y2lcWWvwuxvAP3ZehIqS7C+g23mmsTIAAAAAAP3///8CgJaYAAAAAAAWABSa3cy+E6bx6+apJuyW7RUzDhqNNFwsMQEAAAAAIgAgDMBOL0aKP0j5YMyeAma9QlR90Gm9RzlIdd4HaQSuSscAAAAAAQEfgJaYAAAAAAAWABSa3cy+E6bx6+apJuyW7RUzDhqNNCIGA4GM6QXZ1Q9BV9kOC8CrUAmcjJefEid2YC/0Jq2p4c/2GCYUvcRUAACAAQAAgAAAAIAAAAAAAQAAAAEOIPVrYWk69b8V9Wfly3minQdZA9wXgDgKIPU+6HMzSG+tAQ8EAAAAAAEQBP3///8AAQB9AgAAAAG4303tRC1bj+QvunoZn7uYkEO12sL8Mu+OKZM6UbrW/AEAAAAA/f///wKAw8kBAAAAACIAIFwqEzbsUSf+/PC7SPfqGuy75tAydrgFkmv8DAEW6eNi5hwsBAAAAAAWABT9hflT6IkrLKaHS+x3zqee7ExP/AAAAAABAR/mHCwEAAAAABYAFP2F+VPoiSsspodL7HfOp57sTE/8IgYC420o3I+pkBOSVZyER/NTtZTLtP1iIKPdZK99ilI9UDoYJhS9xFQAAIABAACAAAAAgAEAAAAAAAAAAQ4gYyExv0nenCq5y2lcWWvwuxvAP3ZehIqS7C+g23mmsTIBDwQBAAAAARAE/f///wABAwieWGICAAAAAAEEFgAUVE9NQrxzbpzaj8DvSA4+Vfb3S88AAQMIgMPJAQAAAAABBCIAILUTol87mgHQEKeZJcuNUJjXFfUupwaSGuS7QTdBQ1TWACICAnzPCCeQE1LaXrkDi6UG15Kr4bOZq4ihKVix6Heb1gKOGCYUvcRUAACAAQAAgAAAAIABAAAAAgAAAAEDCOaVmAAAAAAAAQQWABSyijJ33ycsST0veZC7xCcjMLvGngAiAgLo0KljvbzhA8MlGam3rHhgAzffTBP2FrSSU41vf2oNuRgmFL3EVAAAgAEAAIAAAACAAAAAAAMAAAABAwiAlpgAAAAAAAEEFgAUfwP8SJ6OrkWYgi79Rmtboh4vb6AA",
    # nested segwit, 3 inp 3 outs
    "cHNidP8BAOMCAAAAAxTKkAuekd781k0dtVGHQB6rfsnXbOoRI8nCZaODOTuKAQAAAAD9////GzrJPRcrKOpTM/UuJtU9BHoPOauuwOwTbze8A98e9jkAAAAAAP3///8zUYet5YsLr1JURBtw6y1J+aOIFUYppSUF98NMQ0SGqAEAAAAA/f///wPA4eQAAAAAABYAFDi4Qvb/any4sD/j++An4QeQyZ8ZABu3AAAAAAAWABSZhIQZ8nU642HEO2Ad58HNlLuNX0LFLQAAAAAAF6kUmyPIidm0uYu4R4cd4G/ePLv/KL6HAAAAAAABAHICAAAAAc7Pm3aeTAzyTspzPxlasb9E8TXzeuZWE3BowPHA9jUAAAAAAAD+////Alji3iIBAAAAFgAUhtwMeBRjJ59uRi16BF//sCuKaQ+AlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwAAAAABASCAlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwEEFgAUlGEc5+39qmo7NT7GrA6unMA28sciBgObyQ41qMrOxju4XxzMINIB1ZGui3QjZEVfIZ7WGJnS2xgmFL3EMQAAgAEAAIAAAACAAAAAAAAAAAAAAQByAgAAAAGhyWgevahbYnWS3rmRhpZign4sGaq4mOdM4D8UKs2q1AAAAAAA/v///wKAlpgAAAAAABepFPAAkmx/dRJAKf+Lw49LAzeIh975h/JabSkBAAAAFgAUfWxZ1njvA0Yr7QVYEme4CDHh7qMAAAAAAQEggJaYAAAAAAAXqRTwAJJsf3USQCn/i8OPSwM3iIfe+YcBBBYAFM6hs2GlOxZSDUae67LI3aiHb3G/IgYCtyN18tSmyoFClQl6Fa87TtEnrMZH6NJoRooWChmuHd0YJhS9xDEAAIABAACAAAAAgAAAAAABAAAAAAEAcgIAAAABV2MIaeVqMWANJDD2CUpsLwzV+Kbyg5cpQYob80WZZSMAAAAAAP7///8C8lptKQEAAAAWABTXvwQx1pNX7/TEGt2BYOIovqhL4ICWmAAAAAAAF6kU9x5iJ+lOE1CyDvzfZ+6pFjHKnviHAAAAAAEBIICWmAAAAAAAF6kU9x5iJ+lOE1CyDvzfZ+6pFjHKnviHAQQWABQ5QbIFFdKLyxFSNm1hZ8S/28cjGSIGAz0meCzo95/qUlBrj9hp+T8hPjVPMIsYK7uTj4iq+Wl6GCYUvcQxAACAAQAAgAAAAIAAAAAAAgAAAAAAAAEAFgAUvQVfGjGkvg8XROgHZhlqhzm/ZOkiAgJXWxh/KFZ6O5bcwrw6M8BwIWtYoHYbrU7JqNOgbTtwxBgmFL3EMQAAgAEAAIAAAACAAQAAAAAAAAAA",
    # same psbt, version = 2
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQMBBQEDAfsEAgAAAAABAHICAAAAAc7Pm3aeTAzyTspzPxlasb9E8TXzeuZWE3BowPHA9jUAAAAAAAD+////Alji3iIBAAAAFgAUhtwMeBRjJ59uRi16BF//sCuKaQ+AlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwAAAAABASCAlpgAAAAAABepFF/+tUQewdyL8GiqX8J+muPiFo88hwEEFgAUlGEc5+39qmo7NT7GrA6unMA28sciBgObyQ41qMrOxju4XxzMINIB1ZGui3QjZEVfIZ7WGJnS2xgmFL3EMQAAgAEAAIAAAACAAAAAAAAAAAABDiAUypALnpHe/NZNHbVRh0Aeq37J12zqESPJwmWjgzk7igEPBAEAAAABEAT9////AAEAcgIAAAABocloHr2oW2J1kt65kYaWYoJ+LBmquJjnTOA/FCrNqtQAAAAAAP7///8CgJaYAAAAAAAXqRTwAJJsf3USQCn/i8OPSwM3iIfe+YfyWm0pAQAAABYAFH1sWdZ47wNGK+0FWBJnuAgx4e6jAAAAAAEBIICWmAAAAAAAF6kU8ACSbH91EkAp/4vDj0sDN4iH3vmHAQQWABTOobNhpTsWUg1GnuuyyN2oh29xvyIGArcjdfLUpsqBQpUJehWvO07RJ6zGR+jSaEaKFgoZrh3dGCYUvcQxAACAAQAAgAAAAIAAAAAAAQAAAAEOIBs6yT0XKyjqUzP1LibVPQR6DzmrrsDsE283vAPfHvY5AQ8EAAAAAAEQBP3///8AAQByAgAAAAFXYwhp5WoxYA0kMPYJSmwvDNX4pvKDlylBihvzRZllIwAAAAAA/v///wLyWm0pAQAAABYAFNe/BDHWk1fv9MQa3YFg4ii+qEvggJaYAAAAAAAXqRT3HmIn6U4TULIO/N9n7qkWMcqe+IcAAAAAAQEggJaYAAAAAAAXqRT3HmIn6U4TULIO/N9n7qkWMcqe+IcBBBYAFDlBsgUV0ovLEVI2bWFnxL/bxyMZIgYDPSZ4LOj3n+pSUGuP2Gn5PyE+NU8wixgru5OPiKr5aXoYJhS9xDEAAIABAACAAAAAgAAAAAACAAAAAQ4gM1GHreWLC69SVEQbcOstSfmjiBVGKaUlBffDTENEhqgBDwQBAAAAARAE/f///wABAwjA4eQAAAAAAAEEFgAUOLhC9v9qfLiwP+P74CfhB5DJnxkAAQMIABu3AAAAAAABBBYAFJmEhBnydTrjYcQ7YB3nwc2Uu41fAAEAFgAUvQVfGjGkvg8XROgHZhlqhzm/ZOkiAgJXWxh/KFZ6O5bcwrw6M8BwIWtYoHYbrU7JqNOgbTtwxBgmFL3EMQAAgAEAAIAAAACAAQAAAAAAAAABAwhCxS0AAAAAAAEEF6kUmyPIidm0uYu4R4cd4G/ePLv/KL6HAA==",
    # legacy

    # 1-of-2 multisig
]

class PSBTTest(TestCase):
    def test_scopes(self):
        """Tests that PSBT and PSBTView result in the same scopes and other constants"""
        for compress in [True, False]:
            for b64 in PSBTS:
                psbt = PSBT.from_string(b64, compress=compress)
                stream = BytesIO(a2b_base64(b64))
                psbtv = PSBTView.view(stream, compress=compress)
                self.assertEqual(len(psbt.inputs), psbtv.num_inputs)
                self.assertEqual(len(psbt.outputs), psbtv.num_outputs)
                self.assertEqual(psbt.version, psbtv.version)
                if psbt.version != 2:
                    self.assertTrue(psbtv.tx_offset > 0)
                # check something left when seek to n-1
                psbtv.seek_to_scope(psbtv.num_inputs+psbtv.num_outputs-1)
                self.assertEqual(len(stream.read(1)), 1)
                # check nothing left in the stream when seeking to the end
                psbtv.seek_to_scope(psbtv.num_inputs+psbtv.num_outputs)
                self.assertEqual(stream.read(1), b"")
                # check that all scopes are the same in psbt and psbtv
                # check random input scope first
                idx = len(psbt.inputs)//2
                self.assertEqual(psbt.inputs[idx].serialize(), psbtv.input(idx).serialize())
                # check input scopes sequentially
                for i, inp in enumerate(psbt.inputs):
                    self.assertEqual(inp.serialize(), psbtv.input(i).serialize())
                    self.assertEqual(inp.vin.serialize(), psbtv.vin(i).serialize())
                # check random output scope
                idx = len(psbt.outputs)//2
                self.assertEqual(psbt.outputs[idx].serialize(), psbtv.output(idx).serialize())
                # check input scopes sequentially
                for i, out in enumerate(psbt.outputs):
                    self.assertEqual(out.serialize(), psbtv.output(i).serialize())
                    self.assertEqual(out.vout.serialize(), psbtv.vout(i).serialize())
                self.assertEqual(psbt.tx_version, psbtv.tx_version)
                self.assertEqual(psbt.locktime, psbtv.locktime)


    def test_sign(self):
        for compress in [True, False]:
            for b64 in PSBTS:
                psbt = PSBT.from_string(b64, compress=compress)
                stream = BytesIO(a2b_base64(b64))
                psbtv = PSBTView.view(stream, compress=compress)

                csigs1 = psbt.sign_with(ROOT)
                sigs_stream = BytesIO()
                csigs2 = psbtv.sign_with(ROOT, sigs_stream)
                self.assertEqual(csigs1, csigs2)
                sigs_stream.seek(0)
                # check all sigs
                signed_inputs = [InputScope.read_from(sigs_stream) for i in range(psbtv.num_inputs)]
                self.assertEqual(len(signed_inputs), len(psbt.inputs))
                for i, inp in enumerate(signed_inputs):
                    inp2 = psbt.inputs[i]
                    self.assertEqual(inp.partial_sigs, inp2.partial_sigs)
                # check serialization with signatures
                sigs_stream.seek(0)
                ser = BytesIO()
                psbtv.write_to(ser, extra_input_streams=[sigs_stream])
                self.assertEqual(ser.getvalue(), psbt.serialize())
