import subprocess
import os
import time
import signal
import shutil
from .rpc import BitcoinRPC

class Bitcoind:
    datadir = os.path.abspath("./chain/bitcoin")
    rpcport = 18778
    port = 18779
    rpcuser = "bitcoin"
    rpcpassword = "secret"
    name = "Bitcoin Core"
    retry_count = 10
    binary = "bitcoind"

    def __init__(self):
        self._rpc = None
        self._address = None

    @property
    def address(self):
        if self._address is None:
            self._address = self.rpc.getnewaddress(wallet="")
        return self._address

    @property
    def cmd(self):
        return f"{self.binary} -datadir={self.datadir} -regtest -fallbackfee=0.0001 -rpcuser={self.rpcuser} -rpcpassword={self.rpcpassword} -rpcport={self.rpcport} -port={self.port}"

    @property
    def rpc(self):
        if self._rpc is None:
            self._rpc = BitcoinRPC(self.rpcuser, self.rpcpassword, port=self.rpcport)
        return self._rpc

    def wallet(self, wname=""):
        return self.rpc.wallet(wname)

    def start(self):
        print(f"Starting {self.name} in regtest mode with datadir {self.datadir}")
        try:
            shutil.rmtree(self.datadir)
        except:
            pass
        try:
            os.makedirs(self.datadir)
        except:
            pass
        self.proc = subprocess.Popen(self.cmd,
                                stdout=subprocess.PIPE,
                                shell=True, preexec_fn=os.setsid)
        time.sleep(1)
        self.get_coins()

    def get_coins(self):
        # create default wallet
        if "" not in self.rpc.listwallets():
            self.rpc.createwallet("")
        self.mine(101)
        assert self.rpc.getbalance(wallet="") > 0

    def mine(self, n=1):
        self.rpc.generatetoaddress(n, self.address)

    def stop(self):
        print(f"Shutting down {self.name}")
        os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)  # Send the signal to all the process groups
        time.sleep(3)
        for i in range(self.retry_count):
            try:
                # shutil.rmtree(self.datadir)
                return
            except Exception as e:
                print(f"Exception: {e}")
                print(f"Retrying in 1 second... {i}/{retry_count}")
                time.sleep(1)

daemon = Bitcoind()