import logging
import os
import shutil
import subprocess
import time

import shlex

from .rpc import BitcoinRPC

logger = logging.getLogger(__name__)


class Bitcoind:
    rpcport = 18778
    port = 18779
    rpcuser = "bitcoin"
    rpcpassword = "secret"
    name = "Bitcoin Core"

    def __init__(self):
        self._rpc = None
        self._address = None
        self.proc = None

    @staticmethod
    def _temp_dir() -> str:
        d = os.environ.get("EMBIT_TEMP_DIR")
        if not d:
            raise RuntimeError(
                "EMBIT_TEMP_DIR is not set. Run `uv run poe integration-tests`.",
            )
        return d

    @property
    def datadir(self):
        return os.path.join(self._temp_dir(), "data", "bitcoin", "chain")

    @property
    def binary(self):
        return os.path.join(self._temp_dir(), "binaries", "bitcoind")

    @property
    def address(self):
        if self._address is None:
            self._address = self.rpc.getnewaddress(wallet="")
        return self._address

    @property
    def cmd(self):
        return (
            f"{self.binary} -datadir={self.datadir} -regtest "
            f"-fallbackfee=0.0001 -rpcuser={self.rpcuser} "
            f"-rpcpassword={self.rpcpassword} -rpcport={self.rpcport} "
            f"-port={self.port}"
        )

    @property
    def rpc(self):
        if self._rpc is None:
            self._rpc = BitcoinRPC(self.rpcuser, self.rpcpassword, port=self.rpcport)
        return self._rpc

    def wallet(self, wname=""):
        return self.rpc.wallet(wname)

    def start(self):
        logger.info(
            "starting name=%s datadir=%s rpcport=%s",
            self.name,
            self.datadir,
            self.rpcport,
        )
        try:
            shutil.rmtree(self.datadir)
        except OSError:
            pass
        try:
            os.makedirs(self.datadir)
        except OSError:
            pass

        self.proc = subprocess.Popen(
            shlex.split(self.cmd),
            start_new_session=True,
        )
        self._wait_for_rpc()
        self.get_coins()

    def _wait_for_rpc(self, timeout=30):
        """Poll RPC until it responds or timeout."""
        for _ in range(timeout * 2):
            try:
                self.rpc.getblockchaininfo()
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError(f"{self.name} RPC not ready after {timeout}s")

    def get_coins(self):
        # create default wallet
        if "" not in self.rpc.listwallets():
            # createwallet(name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors)
            self.rpc.createwallet("", False, False, "", False, True)
        self.mine(101)
        assert self.rpc.getbalance(wallet="") > 0

    def mine(self, n=1):
        self.rpc.generatetoaddress(n, self.address)

    def stop(self):
        logger.info("stopping name=%s", self.name)
        try:
            self.rpc.stop()
        except Exception as e:
            logger.warning(
                "rpc_stop_failed name=%s error=%s",
                self.name,
                e,
            )
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            logger.warning(
                "daemon_stop_timeout name=%s killing=yes",
                self.name,
            )
            self.proc.kill()
            self.proc.wait(timeout=30)


daemon = Bitcoind()
