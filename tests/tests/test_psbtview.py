from unittest import TestCase
from embit.psbtview import PSBTView
from embit.psbt import PSBT, InputScope
from embit import bip32, bip39
from binascii import a2b_base64, b2a_base64
from io import BytesIO

ROOT = bip32.HDKey.from_seed(bip39.mnemonic_to_seed("toy fault beef holiday later unit boring merge shield detail scrap negative"))
# tprv8ZgxMBicQKsPeDhmZay7WoN2W9gkmZNv4bkPRgCsaqKAnafo2YkpmJFQUAv34PTdYciNteTu8A1tvDUBsusThseGfiPkdFAniazFzxRd8xv

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
    "cHNidP8BAMMCAAAAA/8CS6+D7pDNQd/uwrrbG8k78U9QFdzV559ZhQ1EVYGEAAAAAAD+////70WX911pnoWryXdRJlFlGJyuuh5NKwXkaz76h/meNogAAAAAAP7///+O9uy981BmAPPPKXis8gBJNmx+Q0cVhuVe2RaQJdI1BwAAAAAA/v///wJAeH0BAAAAABYAFPSXFN4nngE2GMROpImI5XRxRkCXP0lMAAAAAAAWABTpOJ/mb2jdP898bWAmZuD7Njn/awAAAAAAAQB0AgAAAAGCo1OTQLigQvL2iP3OK/kA4+1Mwv2Y4ErI0Zl4E5j3SQAAAAAA/v///wKAlpgAAAAAABl2qRQhggw2j7lZq5FRG/W8Wxtq9pwcbYis/eXoSQAAAAAWABT0gC7h3PBRXI9jFN868mhubmC+2gAAAAAiBgNoW2ak4dJxu2tMB1xKJ8i0IZ1upTKHilgX2NDjWlH58gwmFL3EAAAAAAEAAAAAAQB0AgAAAAGnjGh1Fuk1Y5dz4QE9r+3oEUfuAiK9MGm3tjnPkXvShgAAAAAA/v///wKAlpgAAAAAABl2qRSz5j68l/pmSGDdCy8X1hM5LcUaxYisFOboSQAAAAAWABTh9XHu7fEdxJ2bqU/DGbrfvU42UAAAAAAiBgNYvS1u+b8fq7DcmL63qHttHinxbZLp9rhbOnmyBUCeTwwmFL3EAAAAAAIAAAAAAQB0AgAAAAFgB75i+OT1O7SqGBsTmTajlxpDsnLc/iwxwfbvr6jLVwAAAAAA/v///wKAlpgAAAAAABl2qRQBEqxvaLOlc1lLiadG5yQ5bilaRYisxf7yQwAAAAAWABTCShfxLkJyJ3/wjVLDRtChyK5v1QAAAAAiBgMmekh8kmFBB8c2g+PQLCgSuginKK+UJuxobtdRZ4FAiAwmFL3EAAAAAAAAAAAAACICAvjQsARdPkCfLoeR/ysMrMfEKmvRZ7guQexDh5x6Tpj7EGMusisAAACAAQAAgAEAAIAA",
    # same, psbt version 2
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQMBBQECAfsEAgAAAAABAHQCAAAAAYKjU5NAuKBC8vaI/c4r+QDj7UzC/ZjgSsjRmXgTmPdJAAAAAAD+////AoCWmAAAAAAAGXapFCGCDDaPuVmrkVEb9bxbG2r2nBxtiKz95ehJAAAAABYAFPSALuHc8FFcj2MU3zryaG5uYL7aAAAAACIGA2hbZqTh0nG7a0wHXEonyLQhnW6lMoeKWBfY0ONaUfnyDCYUvcQAAAAAAQAAAAEOIP8CS6+D7pDNQd/uwrrbG8k78U9QFdzV559ZhQ1EVYGEAQ8EAAAAAAEQBP7///8AAQB0AgAAAAGnjGh1Fuk1Y5dz4QE9r+3oEUfuAiK9MGm3tjnPkXvShgAAAAAA/v///wKAlpgAAAAAABl2qRSz5j68l/pmSGDdCy8X1hM5LcUaxYisFOboSQAAAAAWABTh9XHu7fEdxJ2bqU/DGbrfvU42UAAAAAAiBgNYvS1u+b8fq7DcmL63qHttHinxbZLp9rhbOnmyBUCeTwwmFL3EAAAAAAIAAAABDiDvRZf3XWmehavJd1EmUWUYnK66Hk0rBeRrPvqH+Z42iAEPBAAAAAABEAT+////AAEAdAIAAAABYAe+Yvjk9Tu0qhgbE5k2o5caQ7Jy3P4sMcH276+oy1cAAAAAAP7///8CgJaYAAAAAAAZdqkUARKsb2izpXNZS4mnRuckOW4pWkWIrMX+8kMAAAAAFgAUwkoX8S5Ccid/8I1Sw0bQociub9UAAAAAIgYDJnpIfJJhQQfHNoPj0CwoEroIpyivlCbsaG7XUWeBQIgMJhS9xAAAAAAAAAAAAQ4gjvbsvfNQZgDzzyl4rPIASTZsfkNHFYblXtkWkCXSNQcBDwQAAAAAARAE/v///wABAwhAeH0BAAAAAAEEFgAU9JcU3ieeATYYxE6kiYjldHFGQJcAIgIC+NCwBF0+QJ8uh5H/Kwysx8Qqa9FnuC5B7EOHnHpOmPsQYy6yKwAAAIABAACAAQAAgAEDCD9JTAAAAAAAAQQWABTpOJ/mb2jdP898bWAmZuD7Njn/awA=",
    # 1-of-2 multisig
    "cHNidP8BAMMCAAAAA+9Fl/ddaZ6Fq8l3USZRZRicrroeTSsF5Gs++of5njaIAAAAAAD+/////wJLr4PukM1B3+7CutsbyTvxT1AV3NXnn1mFDURVgYQAAAAAAP7///+O9uy981BmAPPPKXis8gBJNmx+Q0cVhuVe2RaQJdI1BwAAAAAA/v///wI/SUwAAAAAABYAFCcLXGMkxtEHdt09w5nGGub5dJ8JQHh9AQAAAAAWABT0lxTeJ54BNhjETqSJiOV0cUZAlwAAAAAAAQB0AgAAAAGnjGh1Fuk1Y5dz4QE9r+3oEUfuAiK9MGm3tjnPkXvShgAAAAAA/v///wKAlpgAAAAAABl2qRSz5j68l/pmSGDdCy8X1hM5LcUaxYisFOboSQAAAAAWABTh9XHu7fEdxJ2bqU/DGbrfvU42UAAAAAAiBgNYvS1u+b8fq7DcmL63qHttHinxbZLp9rhbOnmyBUCeTwwmFL3EAAAAAAIAAAAAAQB0AgAAAAGCo1OTQLigQvL2iP3OK/kA4+1Mwv2Y4ErI0Zl4E5j3SQAAAAAA/v///wKAlpgAAAAAABl2qRQhggw2j7lZq5FRG/W8Wxtq9pwcbYis/eXoSQAAAAAWABT0gC7h3PBRXI9jFN868mhubmC+2gAAAAAiBgNoW2ak4dJxu2tMB1xKJ8i0IZ1upTKHilgX2NDjWlH58gwmFL3EAAAAAAEAAAAAAQB0AgAAAAFgB75i+OT1O7SqGBsTmTajlxpDsnLc/iwxwfbvr6jLVwAAAAAA/v///wKAlpgAAAAAABl2qRQBEqxvaLOlc1lLiadG5yQ5bilaRYisxf7yQwAAAAAWABTCShfxLkJyJ3/wjVLDRtChyK5v1QAAAAAiBgMmekh8kmFBB8c2g+PQLCgSuginKK+UJuxobtdRZ4FAiAwmFL3EAAAAAAAAAAAAIgICv+hNVXqScnRDcCJsJcq35scU0SsSp08WNnVklPIs/DkQYy6yKwAAAIABAACAAwAAgAAA",
    # same, version 2
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQMBBQECAfsEAgAAAAABAHQCAAAAAaeMaHUW6TVjl3PhAT2v7egRR+4CIr0wabe2Oc+Re9KGAAAAAAD+////AoCWmAAAAAAAGXapFLPmPryX+mZIYN0LLxfWEzktxRrFiKwU5uhJAAAAABYAFOH1ce7t8R3EnZupT8MZut+9TjZQAAAAACIGA1i9LW75vx+rsNyYvreoe20eKfFtkun2uFs6ebIFQJ5PDCYUvcQAAAAAAgAAAAEOIO9Fl/ddaZ6Fq8l3USZRZRicrroeTSsF5Gs++of5njaIAQ8EAAAAAAEQBP7///8AAQB0AgAAAAGCo1OTQLigQvL2iP3OK/kA4+1Mwv2Y4ErI0Zl4E5j3SQAAAAAA/v///wKAlpgAAAAAABl2qRQhggw2j7lZq5FRG/W8Wxtq9pwcbYis/eXoSQAAAAAWABT0gC7h3PBRXI9jFN868mhubmC+2gAAAAAiBgNoW2ak4dJxu2tMB1xKJ8i0IZ1upTKHilgX2NDjWlH58gwmFL3EAAAAAAEAAAABDiD/Akuvg+6QzUHf7sK62xvJO/FPUBXc1eefWYUNRFWBhAEPBAAAAAABEAT+////AAEAdAIAAAABYAe+Yvjk9Tu0qhgbE5k2o5caQ7Jy3P4sMcH276+oy1cAAAAAAP7///8CgJaYAAAAAAAZdqkUARKsb2izpXNZS4mnRuckOW4pWkWIrMX+8kMAAAAAFgAUwkoX8S5Ccid/8I1Sw0bQociub9UAAAAAIgYDJnpIfJJhQQfHNoPj0CwoEroIpyivlCbsaG7XUWeBQIgMJhS9xAAAAAAAAAAAAQ4gjvbsvfNQZgDzzyl4rPIASTZsfkNHFYblXtkWkCXSNQcBDwQAAAAAARAE/v///wAiAgK/6E1VepJydENwImwlyrfmxxTRKxKnTxY2dWSU8iz8ORBjLrIrAAAAgAEAAIADAACAAQMIP0lMAAAAAAABBBYAFCcLXGMkxtEHdt09w5nGGub5dJ8JAAEDCEB4fQEAAAAAAQQWABT0lxTeJ54BNhjETqSJiOV0cUZAlwA=",
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
        """Test if we can sign psbtview and get the same as from signing psbt"""
        for compress in [True, False]:
            for b64 in PSBTS:
                psbt = PSBT.from_string(b64, compress=compress)
                stream = BytesIO(a2b_base64(b64))
                psbtv = PSBTView.view(stream, compress=compress)

                # incomplete psbtview
                xpsbt = PSBT.from_string(b64, compress=compress)
                # remove derivations and other important data from original
                for sc in xpsbt.inputs:
                    sc.bip32_derivations = {}
                    sc.witness_script = None
                    sc.redeem_script = None

                xstream = BytesIO(xpsbt.serialize())
                xpsbtv = PSBTView.view(xstream, compress=compress)

                csigs1 = psbt.sign_with(ROOT)
                sigs_stream2 = BytesIO()
                csigs2 = psbtv.sign_with(ROOT, sigs_stream2)
                # signing incomplete psbtview
                sigs_stream3 = BytesIO()
                csigs3 = 0
                for i in range(xpsbtv.num_inputs):
                    csigs3 += xpsbtv.sign_input(i, ROOT, sigs_stream3, extra_scope_data=psbt.inputs[i])
                    # add separator
                    sigs_stream3.write(b"\x00")

                self.assertEqual(csigs1, csigs2)
                self.assertEqual(csigs1, csigs3)
                for sigs_stream in [sigs_stream2, sigs_stream3]:
                    sigs_stream.seek(0)
                    # check all sigs
                    signed_inputs = [InputScope.read_from(sigs_stream) for i in range(len(psbt.inputs))]
                    self.assertEqual(len(signed_inputs), len(psbt.inputs))
                    for i, inp in enumerate(signed_inputs):
                        inp2 = psbt.inputs[i]
                        self.assertEqual(inp.partial_sigs, inp2.partial_sigs)
                    # check serialization with signatures
                    sigs_stream.seek(0)
                ser = BytesIO()
                psbtv.write_to(ser, extra_input_streams=[sigs_stream2])
                self.assertEqual(ser.getvalue(), psbt.serialize())

                # check compress reduces the size of psbt
                sigs_stream2.seek(0)
                ser2 = BytesIO()
                psbtv.write_to(ser2, extra_input_streams=[sigs_stream2], compress=True)
                self.assertTrue(len(ser2.getvalue()) < len(ser.getvalue()))
