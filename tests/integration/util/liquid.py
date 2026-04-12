import os

from .bitcoin import Bitcoind


class Elementsd(Bitcoind):
    rpcport = 18998
    port = 18999
    rpcuser = "liquid"
    rpcpassword = "secret"
    name = "Elements Core"

    @property
    def datadir(self):
        return os.path.join(self._temp_dir(), "data", "elements")

    @property
    def binary(self):
        return os.path.join(self._temp_dir(), "binaries", "elementsd")

    @property
    def cmd(self):
        return (
            f"{self.binary}"
            f" -datadir={self.datadir}"
            f" -chain=elreg"
            f" -fallbackfee=0.000001"
            f" -rpcuser={self.rpcuser}"
            f" -rpcpassword={self.rpcpassword}"
            f" -rpcport={self.rpcport}"
            f" -port={self.port}"
            f" -validatepegin=0"
            f" -con_blocksubsidy=5000000000"
        )

    def get_coins(self):
        # create default wallet
        if "" not in self.rpc.listwallets():
            # createwallet(name, disable_private_keys,
            #   blank, passphrase, avoid_reuse, descriptors)
            self.rpc.createwallet("", False, False, "", False, True)
        self.mine(101)
        assert self.rpc.getbalance(wallet="").get("bitcoin", 0) > 0


daemon = Elementsd()
