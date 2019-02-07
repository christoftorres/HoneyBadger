#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# github.com/tintinweb
#
from pyetherchain.pyetherchain import *
import logging

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logging.basicConfig(format='[%(filename)s - %(funcName)20s() ][%(levelname)8s] %(message)s',
                        level=logging.INFO)
    logger.setLevel(logging.INFO)
    ##
    ## Testing
    ##

    e = EtherChain()
    ac = e.account("0x6090A6e47849629b7245Dfa1Ca21D94cd15878Ef")
    print(ac)
    print(ac.source)
    print(ac.history())
    print(ac.swarm_hash)
    print(ac.transactions())

    print(e.charts.market_cap())

    print(e.hardforks())
    print(e.transactions_pending())

    contract = e.account("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
    print("constructor: %s" % contract.abi.describe_constructor(contract.constructor_args))
    for tx in contract.transactions(direction="in", length=10000)["data"]:
        tx_obj = e.transaction(tx["parenthash"])[0]
        print("transaction: [IN] <== %s : %s" % (tx_obj["hash"], contract.abi.describe_input(Utils.str_to_bytes(tx_obj["input"]))))

    # api directly
    e = EtherChainApi()
    print(e.get_transaction("c98061e6e1c9a293f57d59d53f4e171bb62afe3e5b6264e9a770406a81fb1f07"))
    print(e.get_transactions_pending())
    print(e.get_transactions())
    print(e.get_blocks())
    print(e.get_accounts())
    print(e.get_hardforks())
    # print e.get_correlations()
    # print e.get_stats_price_btc()
    print(e.get_account_transactions("0x1104e154efa21ff3ca5da097f8906cd56b1e7d86"))
    try:
        print(e.get_account_abi("0x1104e154efa21ff3ca5da097f8906cd56b1e7d86"))
        print(e.get_account_source(("0x1104e154efa21ff3ca5da097f8906cd56b1e7d86")))
    except Exception as e:
        pass