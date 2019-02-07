#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# github.com/tintinweb
#
"""

Python Interface to EtherChain.org

Interfaces
* EtherChainAccount - interface to account/contract addresses
* EtherChainTransaction - interface to transactions
* EtherChain - interface to general discovery/exploration/browsing api on etherchain
* EtherChainCharts - interface to statistics and charting features

Backend
* UserAgent - error correcting user agent for api interface
* EtherChainApi - main api interface

Experimental
* Contract
* AbiFunction
* EtherChainApi - backend api class


"""
import code
import sys
import requests
import re
import time
import datetime
import json
try:
     # Python 2.6-2.7
    from HTMLParser import HTMLParser
    html = HTMLParser()
except ImportError:
    # Python 3
    import html

from ethereum_input_decoder import ContractAbi, Utils

import logging

logger = logging.getLogger(__name__)


class UserAgent(object):
    """
    User-Agent handling retries and errors ...
    """

    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36"

    def __init__(self, baseurl, retry=1, retrydelay=6000, proxies={}):
        self.baseurl, self.retry, self.retrydelay, self.proxies = baseurl, retry, retrydelay, proxies
        self.session = None
        self.initialize()

    def initialize(self):
        self.session = requests.session()
        self.session.headers.update({"user-agent":self.UA})

    def get(self, path, params={}, headers={}, proxies={}):
        new_headers = self.session.headers.copy()
        new_headers.update(headers)

        proxies = proxies or self.proxies
        _e = None

        for _ in range(self.retry):
            try:
                time.sleep(5)
                resp = self.session.get("%s%s%s"%(self.baseurl, "/" if not path.startswith("/") else "", path),
                                         params=params, headers=new_headers, proxies=proxies)
                if resp.status_code != 200:
                    raise Exception("Unexpected Status Code: %s!=200" % resp.status_code)
                return resp
            except Exception as e:
                logger.exception(e)
                _e = e
            logger.warning("Retrying in %d seconds..." % self.retrydelay)
            time.sleep(self.retrydelay)
        raise _e

    def post(self, path, params={}, headers={}):
        new_headers = self.session.headers.copy()
        new_headers.update(headers)

        _e = None

        for _ in range(self.retry):
            try:
                resp = self.session.post("%s%s%s"%(self.baseurl, "/" if not path.startswith("/") else "", path),
                                        params=params, headers=new_headers)
                if resp.status_code != 200:
                    raise Exception("Unexpected Status Code: %s!=200" % resp.status_code)
                return resp
            except Exception as e:
                logger.exception(e)
                _e = e
            logger.warning("Retrying in %d seconds..." % self.retrydelay)
            time.sleep(self.retrydelay)
        raise _e


class EtherChainApi(object):
    """
    Base EtherChain Api implementation
    """

    def __init__(self, baseurl="https://www.etherchain.org", retry=5, retrydelay=8, proxies={}):
        self.session = UserAgent(baseurl=baseurl, retry=retry, retrydelay=retrydelay, proxies=proxies)

    def get_transaction(self, tx):
        return self.session.get("/api/tx/%s" % tx).json()

    def get_block(self, block):
        return self.session.get("/api/block/%s" % block).json()

    def get_account(self, address):
        return self.session.get("/api/account/%s" % address).json()

    def get_account_history(self, account):
        return self.session.get("/account/%s/history" % account).json()

    def _extract_text_from_html(self, s):
        return re.sub('<[^<]+?>', '', s).strip()
        #return ''.join(re.findall(r">(.+?)</", s)) if ">" in s and "</" in s else s

    def _extract_hexstr_from_html_attrib(self, s):
        return ''.join(re.findall(r".+/([^']+)'", s)) if ">" in s and "</" in s else s

    def _get_pageable_data(self, path, start=0, length=10):
        params = {
            "start": start,
            "length": length,
        }
        resp = self.session.get(path, params=params).json()
        # cleanup HTML from response
        for item in resp['data']:
            keys = item.keys()
            for san_k in set(keys).intersection({"account", "blocknumber", "type", "direction", "number","miner"}):
                item[san_k] = self._extract_text_from_html(item[san_k])
            for san_k in set(keys).intersection(("parenthash", "from", "to", "address","hash")):
                item[san_k] = self._extract_hexstr_from_html_attrib(item[san_k])
        return resp

    def get_account_transactions(self, account, start=0, length=10):
        return self._get_pageable_data("/account/%s/txs" % account, start=start, length=length)

    def get_transactions_pending(self, start=0, length=10):
        return self._get_pageable_data("/txs/pending/data", start=start, length=length)

    def get_transactions(self, start=0, length=10):
        return self._get_pageable_data("/txs/data", start=start, length=length)

    def get_blocks(self, start=0, length=10):
        return self._get_pageable_data("/blocks/data", start=start, length=length)

    def get_accounts(self, start=0, length=10, _type=None):
        if not _type:
            return self._get_pageable_data("/accounts/data", start=start, length=length)
        ret = {"data":[]}
        while True:
            resp = self._get_pageable_data("/accounts/data", start=start, length=length)
            for acc in resp["data"]:
                if acc["type"].lower() == _type:
                    ret["data"].append(EtherChainAccount(acc["address"]))
                    if len(ret["data"]) >= length:
                        ret["processed"] = start+1
                        return ret
                start += 1
            # BUG - we somehow need to also return the amount of skipped entries


    def _parse_tbodies(self, data):
        tbodies = []
        for tbody in re.findall(r"<tbody.*?>(.+?)</tbody>", data):
            rows = []
            for tr in re.findall(r"<tr.*?>(.+?)</tr>", tbody):
                rows.append(re.findall(r"<td.*?>(.+?)</td>", tr))
            tbodies.append(rows)
        return tbodies

    def get_hardforks(self):
        rows = self._parse_tbodies(self.session.get("/hardForks").text)[0]  # only use first tbody
        result = []
        for col in rows:
            result.append({'name': self._extract_text_from_html( col[0]),
                      'on_roadmap': True if "yes" in col[1].lower() else False,
                      'date': self._extract_text_from_html(col[2]),
                      'block': int(self._extract_text_from_html(col[3]))})
        return result

    def get_correlations(self, x=None, y=None, startDate=None, endDate=None):
        if startDate is None:
            # default 1 year
            startDate = datetime.datetime.date(datetime.datetime.now()-datetime.timedelta(days=365)).isoformat()
        if endDate is None:
            endDate = datetime.datetime.date(datetime.datetime.now()).isoformat()
        params = {
            'x': x if x is not None else 'AVG_BLOCK_UTIL',
            'y': y if y is not None else 'AVG_BLOCK_UTIL',
            'startDate': startDate,
            'endDate': endDate,
        }
        return self.session.post("/correlations/data", params=params).json()

    # Economy
    def get_stats_total_ether_supply(self):
        return self.session.get("/charts/totalEtherSupply/data").json()

    def get_stats_market_cap(self):
        return self.session.get("/charts/marketCap/data").json()

    def get_stats_price_usd(self):
        return self.session.get("/charts/priceUSD/data").json()

    def get_stats_price_btc(self):
        return self.session.get("/charts/priceBTC/data").json()

    def get_stats_transactions_per_day(self):
        return self.session.get("/charts/transactionsPerDay/data").json()

    def get_stats_block_gas_usage(self):
        return self.session.get("/charts/blockGasUsage/data").json()

    def get_stats_total_gas_usage(self):
        return self.session.get("/charts/totalGasUsage/data").json()

    def get_stats_average_block_utilization(self):
        return self.session.get("/charts/averageBlockUtilization/data").json()

    # Mining
    def get_stats_hashrate(self):
        return self.session.get("/charts/hashrate/data").json()

    def get_stats_mining_reward(self):
        return self.session.get("/charts/miningReward/data").json()

    def get_stats_block_mining_reward(self):
        return self.session.get("/charts/blockMiningReward/data").json()

    def get_stats_uncle_mining_reward(self):
        return self.session.get("/charts/uncleMiningReward/data").json()

    def get_stats_fee_mining_reward(self):
        return self.session.get("/charts/feeMiningReward/data").json()

    def get_stats_distinct_miners(self):
        return self.session.get("/charts/distinctMiners/data").json()

    def get_stats_mining_revenue(self):
        return self.session.get("/charts/miningRevenue/data").json()

    def get_stats_top_miner_30d(self):
        return self.session.get("/charts/miner/data").json()

    def get_stats_top_miner_24h(self):
        return self.session.get("/charts/topMiners/data").json()

    # Network statistics
    def get_stats_blocks_per_day(self):
        return self.session.get("/charts/blocksPerDay/data").json()

    def get_stats_uncles_per_day(self):
        return self.session.get("/charts/unclesPerDay/data").json()

    def get_stats_block_time(self):
        return self.session.get("/charts/blockTime/data").json()

    def get_stats_difficulty(self):
        return self.session.get("/charts/difficulty/data").json()

    def get_stats_block_size(self):
        return self.session.get("/charts/blockSize/data").json()

    def get_stats_block_gas_limit(self):
        return self.session.get("/charts/blockGasLimit/data").json()

    def get_stats_new_accounts(self):
        return self.session.get("/charts/newAccounts/data").json()

    def get_stats_total_accounts(self):
        return self.session.get("/charts/totalAccounts/data").json()

    # Code

    def _extract_account_info_from_code_tag(self, tagid, s):
        return html.unescape(''.join(
            re.findall(r'<code id=\"%s\">(.+?)</code>' % tagid, s, re.DOTALL | re.MULTILINE)))

    def _extract_compiler_settings(self, s):
        # <div class="row"><div class="col-3">Contract Name:</div><div class="col-9">Hourglass</div></div>
        return {html.unescape(k).strip(":"):html.unescape(v) for k,v in re.findall(r'<div class="row"><div class="col-3">([^<]+)</div><div class="col-9">([^<]+)</div></div>',s, re.DOTALL | re.MULTILINE)}

    def get_account_abi(self, account):
        # <code id="abi">[
        return json.loads(self._extract_account_info_from_code_tag("abi", self.session.get("/account/%s" % account).text))

    def get_account_swarm_hash(self, account):
        return self._extract_account_info_from_code_tag("swarmHash", self.session.get("/account/%s" % account).text)

    def get_account_source(self, account):
        return self._extract_account_info_from_code_tag("source", self.session.get("/account/%s" % account).text)

    def get_account_bytecode(self, account):
        return self._extract_account_info_from_code_tag("contractCode", self.session.get("/account/%s" % account).text)

    def get_account_constructor_args(self, account):
        return self._extract_account_info_from_code_tag("constructorArgs", self.session.get("/account/%s" % account).text)


class DictLikeInterface(object):

    def __getitem__(self, i):
        e = self.data[i]  # enable lazy loading
        return e if not callable(e) else e()

    def __len__(self):
        return len(self.data)

    def __str__(self):
        return str(self.data)

    def __repr__(self):
        return self.__str__()

    def get(self, k, default=None):
        try:
            return self[k]
        except KeyError:
            return default

    def keys(self):
        return self.data.keys()

    def values(self):
        return self.data.values()

class EtherChainTransaction(DictLikeInterface):
    """
    Interface class of an EtherChain Transactions
    """

    def __init__(self, tx, api=None):
        self.tx = tx

        self.api = api or EtherChainApi()

        self.data = None

    def __str__(self):
        self.data = self._get()
        return super().__str__()

    def __repr__(self):
        self.data = self._get()
        return super().__repr__()

    def __getitem__(self, item):
        try:
            return super().__getitem__(item)
        except (KeyError, AttributeError, TypeError):
            self.data = self._get()
            return self.data[item]

    def _get(self):
        return self.api.get_transaction(self.tx)


class EtherChainAccount(DictLikeInterface):
    """
    Interface class of an EtherChain account/contract
    """

    TX_TYPE_ALL = 1
    TX_TYPE_INCOMING = 2
    TX_TYPE_OUTGOING = 3
    TX_TYPE_CREATE = 4
    TX_TYPE_CREATION = 5

    def __init__(self, address, api=None):
        self.address = address
        #self.abi, self.swarm_hash, self.source, self.code, self.constructor_args = None, None, None, None, None

        self.api = api or EtherChainApi()

        # prepare lazy loading
        self.data = None
        # lazy loading funcs

    def __getattr__(self, item):
        if item in ("abi", "swarm_hash", "source", "code", "constructor_args", "compiler_settings"):
            self._get_extra_info()  # creates attributes
        return self.__getattribute__(item)

    def __str__(self):
        self.data = self._get()
        return super().__str__()

    def __repr__(self):
        self.data = self._get()
        return super().__repr__()

    def __getitem__(self, item):
        try:
            return super().__getitem__(item)
        except (AttributeError, KeyError, TypeError):
            self.data = self._get()
            return self.data[item]

    def keys(self):
        self.data = self.data or self._get()
        return self.data.keys()

    def values(self):
        self.data = self.data or self._get()
        return self.data.values()

    def _get(self):
        return self.api.get_account(self.address)

    def history(self):
        return self.api.get_account_history(self.address)

    def transactions(self, start=0, length=10, direction=None):
        txs = self.api.get_account_transactions(account=self.address, start=start, length=length)
        if not direction:
            return txs

        if direction.lower()=="in":
            txs["data"] = [tx for tx in txs['data'] if "in" in tx["direction"].lower()]
        elif direction.lower()=="out":
            txs["data"] = [tx for tx in txs['data'] if "out" in tx["direction"].lower()]

        return txs

    def _get_extra_info(self):
        s = self.api.session.get("/account/%s" % self.address).text

        try:
            self.abi = ContractAbi(json.loads(self.api._extract_account_info_from_code_tag("abi", s)))
        except ValueError:
            self.abi = None
            logger.debug("could not retrieve contract abi; maybe its just not a contract")
        try:
            self.swarm_hash = self.api._extract_account_info_from_code_tag("swarmHash", s)
        except ValueError:
            self.swarm_hash = None
            logger.debug("could not retrieve swarm hash")
        try:
            self.source = self.api._extract_account_info_from_code_tag("source", s)
        except ValueError:
            self.soruce = None
            logger.debug("could not retrieve contract source code")
        try:
            self.code = self.api._extract_account_info_from_code_tag("contractCode", s)
        except ValueError:
            self.code = None
            logger.debug("could not retrieve contract bytecode")
        try:
            self.constructor_args = self.api._extract_account_info_from_code_tag("constructorArgs", s)
        except ValueError:
            self.constructor_args = None
            logger.debug("could not retrieve contract constructor args")
        try:
            self.compiler_settings = self.api._extract_compiler_settings(s)
        except ValueError:
            self.compiler_settings = None
            logger.debug("could not retrieve contract compiler settings")

    def set_abi(self, json_abi):
        self.abi = ContractAbi(json_abi)

    def describe_constructor(self):
        return self.abi.describe_constructor(Utils.str_to_bytes(self.constructor_args))

    def describe_transactions(self, length=10000):
        reslt = []
        for tx in self.transactions(direction="in", length=length)["data"]:
            tx_obj = EtherChainTransaction(tx["parenthash"], api=self.api)[0]
            reslt.append((tx_obj["hash"], self.abi.describe_input(Utils.str_to_bytes(tx_obj["input"]))))
        return reslt

    def describe_contract(self, nr_of_transactions_to_include=0):
        header = """//***********************************************************
//
// created with pyetherchain.EtherChainAccount(address).describe_contract()
// see: https://github.com/tintinweb/pyetherchain
//
// Date:     %s
//
// Name:     %s
// Address:  %s
// Swarm:    %s
//
//
// Constructor Args: %s
//
//
// Transactions %s: %s
//
//***************************
""" % (time.ctime(),
       self["name"],
       self["address"],
       self.swarm_hash,
       self.describe_constructor(),
       "(last %d)" % nr_of_transactions_to_include if nr_of_transactions_to_include else "",
       "\n//     " + "\n//     ".join(("[IN] %s : %s" % (txhash, txdata) for txhash, txdata in
                                               self.describe_transactions(
                                                   nr_of_transactions_to_include))) if nr_of_transactions_to_include else "<disabled>")

        return "%s%s" % (header, self.source)


class EtherChain(object):
    """
    Interface to EtherChain Browsing featuers
    """

    def __init__(self, api=None, proxies={}):
        self.api = api or EtherChainApi(proxies=proxies)

        self.charts = EtherChainCharts(api=self.api)

    def transactions_pending(self, start=0, length=10):
        return self.api.get_transactions_pending(start=start, length=length)

    def transactions(self, start=0, length=10):
        return self.api.get_transactions(start=start, length=length)

    def blocks(self, start=0, length=10):
        return self.api.get_blocks(start=start, length=length)

    def accounts(self, start=0, length=10):
        return self.api.get_accounts(start=start, length=length)

    def contracts(self, start=0, length=10):
        return self.api.get_accounts(start=start, length=length, _type="contract")

    def hardforks(self):
        return self.api.get_hardforks()

    def account(self, address):
        return EtherChainAccount(address, api=self.api)

    def transaction(self, tx):
        return EtherChainTransaction(tx, api=self.api)


class EtherChainCharts(object):
    """
    Interface to EtherChain Charts
    """

    def __init__(self, api=None):
        self.api = api or EtherChainApi()

    def correlations(self, x=None, y=None, startDate=None, endDate=None):
        return self.api.get_correlations(x=x, y=y, startDate=startDate, endDate=endDate)

    def total_ether_supply(self):
        return self.api.get_stats_total_ether_supply()

    def market_cap(self):
        return self.api.get_stats_market_cap()

    def price_usd(self):
        return self.api.get_stats_price_usd()

    def price_btc(self):
        return self.api.get_stats_price_btc()

    def transactions_per_day(self):
        return self.api.get_stats_transactions_per_day()

    def block_gas_usage(self):
        return self.api.get_stats_block_gas_usage()

    def total_gas_usage(self):
        return self.api.get_stats_total_gas_usage()

    def average_block_utilization(self):
        return self.api.get_stats_average_block_utilization()

    def hashrate(self):
        return self.api.get_stats_hashrate()

    def mining_reward(self):
        return self.api.get_stats_mining_reward()

    def block_mining_reward(self):
        return self.api.get_stats_block_mining_reward()

    def uncle_mining_reward(self):
        return self.api.get_stats_uncle_mining_reward()

    def fee_mining_reward(self):
        return self.api.get_stats_fee_mining_reward()

    def distinct_miners(self):
        return self.api.get_stats_distinct_miners()

    def mining_revenue(self):
        return self.api.get_stats_mining_revenue()

    def top_miner_30d(self):
        return self.api.get_stats_top_miner_30d()

    def top_miner_24h(self):
        return self.api.get_stats_top_miner_24h()

    def blocks_per_day(self):
        return self.api.get_stats_blocks_per_day()

    def uncles_per_day(self):
        return self.api.get_stats_uncles_per_day()

    def block_time(self):
        return self.api.get_block_time()

    def difficulty(self):
        return self.api.get_stats_difficulty()

    def block_size(self):
        return self.api.get_stats_block_size()

    def block_gas_limit(self):
        return self.api.get_stats_block_gas_limit()

    def new_accounts(self):
        return self.api.get_stats_new_accounts()

    def total_accounts(self):
        return self.api.get_stats_total_accounts()


def interact():
    banner = """
==================================================================

      pyetherchain - cli

==================================================================

Welcome to pyetherchain - the python interface to etherchain.org.
Here's a quick help to get you started :)

Available Classes
* EtherChain - interface to general discovery/exploration/browsing api on etherchain
* EtherChainAccount - interface to account/contract addresses
* EtherChainTransaction - interface to transactions
* EtherChainCharts - interface to statistics and charting features
* EtherChainApi - remote communication api


Available instances:
* etherchain - is an instance of EtherChain() - the main entry point
* api - is an instance of the back-end api connector

* logger - is the module logger instance


Examples:

    etherchain
    etherchain.account("ab7c74abc0c4d48d1bdad5dcb26153fc8780f83e")
    etherchain.account("ab7c74abc0c4d48d1bdad5dcb26153fc8780f83e").describe_contract(nr_of_transactions_to_include=10)
    etherchain.account("ab7c74abc0c4d48d1bdad5dcb26153fc8780f83e").transactions()
    etherchain.transaction("d8df011e6112e2855717a46a16975a3b467bbb69f6db0a26ad6e0803f376dae9")

    etherchain.transactions(start=0, length=10)
    etherchain.transactions_pending(start=0, length=10)
    etherchain.blocks(start=0, length=10)

    etherchain.charts   # access the charts api
    etherchain.charts.price_usd()

    exit() or ctr+c (multiple times) to quit.

"""

    # setup Environment
    #  spawn default connection, share api connection


    api = EtherChainApi()
    etherchain = EtherChain(api=api)

    if len(sys.argv)>2 and sys.argv[1] == "-c":
        print (eval(" ".join(sys.argv[2:]), locals()))
    else:
        try:
            import readline
        except ImportError:
            logger.warning("Module readline not available.")
        else:
            import rlcompleter
            readline.parse_and_bind("tab: complete")
            readline.set_completer(rlcompleter.Completer(locals()).complete)

        code.interact(banner=banner, local=locals())


def main():
    logging.basicConfig(format='[%(filename)s - %(funcName)20s() ][%(levelname)8s] %(message)s',
                        level=logging.INFO)
    logger.setLevel(logging.DEBUG)
    interact()


if __name__ == "__main__":
    main()
    exit()
