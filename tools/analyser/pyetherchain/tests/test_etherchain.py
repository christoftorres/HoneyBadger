import unittest

from pyetherchain.pyetherchain import EtherChain
import ethereum_input_decoder


class EtherchainAccountTest(unittest.TestCase):

    def setUp(self):
        self.etherchain = EtherChain()

    def test_tx_pending(self):
        self.assertIn("recordsTotal", self.etherchain.transactions_pending(start=0, length=1).keys())

    def test_txs(self):
        self.assertIn("recordsTotal", self.etherchain.transactions(start=0, length=1).keys())
        # yeah super lazy :p

    def test_blocks(self):
        self.assertIn("recordsTotal", self.etherchain.blocks(start=0, length=1).keys())
        # we'll test content later

    def test_accounts(self):
        self.assertIn("recordsTotal", self.etherchain.accounts(start=0, length=1).keys())

    def test_contracts(self):
        self.assertIn("processed",self.etherchain.contracts(start=0, length=1).keys())
