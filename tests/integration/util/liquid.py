import os
from .bitcoin import Bitcoind


class Elementsd(Bitcoind):
    datadir = os.path.abspath("./chain/elements")
    rpcport = 18998
    port = 18999
    rpcuser = "liquid"
    rpcpassword = "secret"
    name = "Elements Core"
    binary = "elementsd"

    @property
    def cmd(self):
        return f"{self.binary} -datadir={self.datadir} -chain=elreg -fallbackfee=0.000001 -rpcuser={self.rpcuser} -rpcpassword={self.rpcpassword} -rpcport={self.rpcport} -port={self.port} -validatepegin=0 -initialfreecoins=2100000000000000"

    def get_coins(self):
        # create default wallet
        if "" not in self.rpc.listwallets():
            self.rpc.createwallet("")
        self.rpc.rescanblockchain(wallet="")
        self.mine(10)
        balance = self.rpc.getbalance(wallet="")
        addr = self.rpc.getnewaddress(wallet="")
        self.rpc.sendtoaddress(addr, balance["bitcoin"] // 2)
        self.mine(1)
        assert self.rpc.getbalance(wallet="").get("bitcoin", 0) > 0


daemon = Elementsd()
