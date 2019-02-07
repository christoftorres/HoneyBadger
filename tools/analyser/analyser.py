#!/usr/bin/env python2

import re
import os
import csv
import json
import time
import pymongo
import datetime
import requests

from pymongo import MongoClient
from HTMLParser import HTMLParser
from pyetherchain.pyetherchain import EtherChain
from pyetherchain.pyetherchain import EtherChainApi

DEBUG_MODE = False
KEYWORDS = ["scam", "honeypot", "honey-pot", "honey pot", "honey trap", "honey", "trap", "fraud"]

etherchain = EtherChain()
etherchain_api = EtherChainApi()
prices = etherchain_api.get_stats_price_usd()

def get_one_eth_to_usd(timestamp):
    one_eth_to_usd = prices[-1]["value"]
    for index, price in enumerate(prices):
        if index < len(prices)-1:
            if prices[index]["time"] <= timestamp and timestamp <= prices[index+1]["time"]:
                one_eth_to_usd = prices[index]["value"]
                break
    return one_eth_to_usd

def analyse_honeypot(contract_address, report, collection):
    if not DEBUG_MODE:
        if collection.find({'contract': contract_address}).count() != 0:
            print("Contract has already been analysed...")
            return

    attack_methods = report["attack_methods"]
    cashout_methods = report["cashout_methods"]

    if DEBUG_MODE:
        print("Attack methods: "+str(attack_methods))

    contract = etherchain.account(contract_address)
    # Etherchain.org has a limit of 10,000 transactions
    transactions = contract.transactions(start=0, length=10000)

    if DEBUG_MODE:
        print("Number of transactions: "+str(len(transactions["data"])))

    accounts = {}
    creator        = None
    deployed       = None
    first_attacked = None
    cashed_out     = None
    suicidal       = False
    balance        = 0

    first_investor = None
    for transaction in reversed(transactions["data"]):
        if transaction["failed"]:
            continue

        if contract_address.lower().startswith(transaction["from"].lower().replace("...", "")):
            balance -= float(transaction["value"].replace("ETH", "").replace("<", ""))
        if contract_address.lower().startswith(transaction["to"].lower().replace("...", "")):
            balance += float(transaction["value"].replace("ETH", "").replace("<", ""))

        if contract_address.lower().startswith(transaction["from"].lower().replace("...", "")):
            transaction["from"] = contract_address.lower()
        if not transaction["from"] in accounts:
            account = {}
            account["received"]     = 0.0
            account["received_usd"] = 0.0
            account["spent"]        = 0.0
            account["spent_usd"]    = 0.0
            account["fees"]         = 0.0
            account["fees_usd"]     = 0.0
            account["label"]        = None
            account["transactions"] = []
            accounts[transaction["from"]] = account

        if contract_address.lower().startswith(transaction["to"].lower().replace("...", "")):
            transaction["to"] = contract_address.lower()
        if not transaction["to"] in accounts:
            account = {}
            account["received"]     = 0.0
            account["received_usd"] = 0.0
            account["spent"]        = 0.0
            account["spent_usd"]    = 0.0
            account["fees"]         = 0.0
            account["fees_usd"]     = 0.0
            account["label"]        = None
            account["transactions"] = []
            accounts[transaction["to"]] = account

        date_string = etherchain_api.get_block(transaction["blocknumber"])["time"].replace("T", " ").replace(".000Z", "")
        timestamp = int(time.mktime(datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S").timetuple()))
        one_eth_to_usd = float(get_one_eth_to_usd(timestamp))

        value = float(transaction["value"].replace("ETH", "").replace("<", ""))
        fee = float(transaction["fee"].replace("ETH", "").replace("<", ""))

        accounts[transaction["to"]]["received"] += value
        accounts[transaction["to"]]["received_usd"] += value * one_eth_to_usd
        accounts[transaction["from"]]["spent"] += value
        accounts[transaction["from"]]["spent_usd"] += value * one_eth_to_usd
        accounts[transaction["from"]]["fees"] += fee
        accounts[transaction["from"]]["fees_usd"] += fee * one_eth_to_usd

        if transaction["type"] == "create":
            creator = transaction["from"]
            deployed = etherchain_api.get_block(transaction["blocknumber"])["time"].replace("T", " ").replace(".000Z", "")
            if not accounts[transaction["to"]]["label"]:
                accounts[transaction["to"]]["label"] = "contract"
            if not accounts[transaction["from"]]["label"]:
                accounts[transaction["from"]]["label"] = "attacker"

        # Check if contract commited suicide
        if transaction["type"] == "suicide":
            suicidal = True

        # Check if attacker cashed out
        if contract_address.lower().startswith(transaction["from"].lower().replace("...", "")) and float(transaction["value"].replace("ETH", "").replace("<", "")) > 0 and accounts[transaction["to"].lower()]["label"] == "attacker":
            cashed_out = etherchain_api.get_block(transaction["blocknumber"])["time"].replace("T", " ").replace(".000Z", "")

        if not first_investor and float(transaction["value"].replace("ETH", "")) > 0 and transaction["from"] != contract_address:
            first_investor = transaction["from"]
            if not accounts[transaction["from"]]["label"]:
                accounts[transaction["from"]]["label"] = "attacker"

        if not transaction["parenthash"] in accounts[transaction["from"]]["transactions"]:
            accounts[transaction["from"]]["transactions"].append(transaction["parenthash"])
        if not transaction["parenthash"] in accounts[transaction["to"]]["transactions"]:
            accounts[transaction["to"]]["transactions"].append(transaction["parenthash"])

    for address in accounts:
        if not contract_address.lower().startswith(address.lower().replace("...", "")):
            if not accounts[address]["label"]:
                if accounts[address]["received"] > accounts[address]["spent"]:
                    accounts[address]["label"] = "attacker"
                elif accounts[address]["received"] == 0 and accounts[address]["spent"] > 0:
                    accounts[address]["label"] = "victim"
            for parenthash in accounts[address]["transactions"]:
                transaction = etherchain_api.get_transaction(parenthash)[0]
                if not transaction["failed"]:
                    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
                    response = requests.get("https://www.etherchain.org/tx/"+parenthash+"/parityTrace", headers=headers)
                    #time.sleep(1)
                    if response.status_code == 200:
                        parser = HTMLParser()
                        match = re.compile("<tr><th>Trace</th><td><pre>(.+?)</pre></td></tr>").findall(parser.unescape(response.text).replace('\n', ' ').replace('\r', ''))
                        if len(match) > 0:
                            trace = json.loads(match[0])
                            for call in trace:
                                input = ""
                                if "input" in call["action"]:
                                    input = call["action"]["input"]
                                    # Check if the address executed the attack method
                                    if address != creator and address != first_investor and len(attack_methods) == 0 or any([True for attack_method in attack_methods if not attack_method and not input or attack_method and input.startswith(attack_method)]):
                                        # Check if the address tried to cashout
                                        if any([True for cashout_method in cashout_methods if any([True for hash in accounts[address]["transactions"] if etherchain_api.get_transaction(hash)[0]["input"].startswith(cashout_method.replace("0x", ""))])]):
                                            # Check if the address potentially lost the money
                                            if accounts[address]["received"] < accounts[address]["spent"]:
                                                if not accounts[address]["label"]:
                                                    accounts[address]["label"] = "victim"
                                                if accounts[address]["label"] and accounts[address]["label"] == "attacker":
                                                    accounts[address]["label"] = "both"
                                                if address != creator and not first_attacked:
                                                    first_attacked = transaction["time"].replace("T", " ").replace(".000Z", "")
                    if accounts[address]["label"] == "victim" and not first_attacked and address != creator:
                        first_attacked = transaction["time"].replace("T", " ").replace(".000Z", "")

    if DEBUG_MODE:
        f = open(contract_address+'.dot', 'w')
        f.write('digraph liquidity_flow {\n')
        f.write('rankdir = LR;\n')
        f.write('size = "240"\n')
        f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];\n')
    attackers = []
    victims   = []
    both      = []
    for address in accounts:
        if DEBUG_MODE:
            if not contract_address.lower().startswith(address.lower().replace("...", "")):
                f.write('"In: '+address+'" -> "'+contract_address+'" [color="green" label=" '+str(accounts[address]["spent"])+'"];\n')
                f.write('"'+contract_address+'" -> "Out: '+address+'" [color="red" label=" '+str(accounts[address]["received"])+'"];\n')
        if accounts[address]["label"] == "attacker":
            if not address in attackers:
                attackers.append(address)
        if accounts[address]["label"] == "victim":
            if not address in victims:
                victims.append(address)
        if accounts[address]["label"] == "both":
            if not address in both:
                both.append(address)
    if DEBUG_MODE:
        f.write('}\n')
        f.close()

    if DEBUG_MODE:
        if attackers and victims:
            print("=================================")
            print("     !!! Attack Detected !!!     ")
            print("=================================")
        else:
            print("=================================")
            print("   !!! No Attack Detected !!!    ")
            print("=================================")

    validation = {}

    validation["attackers"] = []
    if DEBUG_MODE:
        print("Attacker(s):")
        print("---------------------------------")
    for address in attackers:
        attacker = {}
        attacker["address"]      = address
        attacker["invested_eth"] = accounts[address]["spent"]
        attacker["invested_usd"] = accounts[address]["spent_usd"]
        attacker["costs_eth"]    = accounts[address]["fees"]
        attacker["costs_usd"]    = accounts[address]["fees_usd"]
        attacker["profit_eth"]   = accounts[address]["received"]-(accounts[address]["spent"]+accounts[address]["fees"])
        attacker["profit_usd"]   = accounts[address]["received_usd"]-(accounts[address]["spent_usd"]+accounts[address]["fees_usd"])
        validation["attackers"].append(attacker)
        if DEBUG_MODE:
            print(address+" \t Invested: "+str(attacker["invested_eth"])+" ETH ("+str(attacker["invested_usd"])+" USD) \t Costs: "+str(attacker["costs_eth"])+" ETH ("+str(attacker["costs_usd"])+" USD) \t Profit: "+str(attacker["profit_eth"])+" ETH ("+str(attacker["profit_usd"])+" USD)")
    if DEBUG_MODE:
        print("---------------------------------")

    validation["victims"] = []
    if DEBUG_MODE:
        print("Victim(s):")
        print("---------------------------------")
    for address in victims:
        victim = {}
        victim["address"]      = address
        victim["invested_eth"] = accounts[address]["spent"]
        victim["invested_usd"] = accounts[address]["spent_usd"]
        victim["costs_eth"]    = accounts[address]["fees"]
        victim["costs_usd"]    = accounts[address]["fees_usd"]
        victim["profit_eth"]   = accounts[address]["received"]-(accounts[address]["spent"]+accounts[address]["fees"])
        victim["profit_usd"]   = accounts[address]["received_usd"]-(accounts[address]["spent_usd"]+accounts[address]["fees_usd"])
        validation["victims"].append(victim)
        if DEBUG_MODE:
            print(address+" \t Invested: "+str(victim["invested_eth"])+" ETH ("+str(victim["invested_usd"])+" USD) \t Costs: "+str(victim["costs_eth"])+" ETH ("+str(victim["costs_usd"])+" USD) \t Profit: "+str(victim["profit_eth"])+" ETH ("+str(victim["profit_usd"])+" USD)")
    if DEBUG_MODE:
        print("---------------------------------")

    validation["attacker_and_victim"] = []
    if DEBUG_MODE:
        print("Attacker and Victim:")
        print("---------------------------------")
    for address in both:
        attacker_and_victim = {}
        attacker_and_victim["address"]      = address
        attacker_and_victim["invested_eth"] = accounts[address]["spent"]
        attacker_and_victim["invested_usd"] = accounts[address]["spent_usd"]
        attacker_and_victim["costs_eth"]    = accounts[address]["fees"]
        attacker_and_victim["costs_usd"]    = accounts[address]["fees_usd"]
        attacker_and_victim["profit_eth"]   = accounts[address]["received"]-(accounts[address]["spent"]+accounts[address]["fees"])
        attacker_and_victim["profit_usd"]   = accounts[address]["received_usd"]-(accounts[address]["spent_usd"]+accounts[address]["fees_usd"])
        validation["attacker_and_victim"].append(attacker_and_victim)
        if DEBUG_MODE:
            print(address+" \t Invested: "+str(attacker_and_victim["invested_eth"])+" ETH ("+str(attacker_and_victim["invested_usd"])+" USD) \t Costs: "+str(attacker_and_victim["costs_eth"])+" ETH ("+str(attacker_and_victim["costs_usd"])+" USD) \t Profit: "+str(attacker_and_victim["profit_eth"])+" ETH ("+str(attacker_and_victim["profit_usd"])+" USD)")
    if DEBUG_MODE:
        print("---------------------------------")

    if DEBUG_MODE:
        print("Time analysis:")
        print("---------------------------------")
        print("Deployed: "+str(deployed)+" \t First attacked: "+str(first_attacked)+" \t Cashed out: "+str(cashed_out)+" \t " + ("(Suicided)" if suicidal else ""))
    time_analysis = {}
    if deployed:
        time_analysis["deployed"] = int(time.mktime(datetime.datetime.strptime(deployed, "%Y-%m-%d %H:%M:%S").timetuple()))
    else:
        time_analysis["deployed"] = 0
    if first_attacked:
        time_analysis["first_attacked"] = int(time.mktime(datetime.datetime.strptime(first_attacked, "%Y-%m-%d %H:%M:%S").timetuple()))
    else:
        time_analysis["first_attacked"] = 0
    if cashed_out:
        time_analysis["cashed_out"] = int(time.mktime(datetime.datetime.strptime(cashed_out, "%Y-%m-%d %H:%M:%S").timetuple()))
    else:
        time_analysis["cashed_out"] = 0
    validation["time_analysis"] = time_analysis
    validation["suicidal"] = suicidal

    validation["comments"] = {}

    validation["comments"]["etherscan"] = []
    response = requests.get("https://disqus.com/embed/comments/?base=default&f=etherscan&t_i=Etherscan_"+contract_address.lower()+"_Comments&t_u=http%3A%2F%2Fetherscan.io%2Faddress%2F"+contract_address.lower())
    if response.status_code == 200:
        match = re.compile("<script type=\"text/json\" id=\"disqus-threadData\">(.+?)</script>").findall(response.text)
        if len(match) > 0:
            disqus = json.loads(match[0])
            if DEBUG_MODE:
                print("---------------------------------")
                print("Comments from Etherscan: "+str(len(disqus["response"]["posts"])))
                print("---------------------------------")
            for i in range(len(disqus["response"]["posts"])):
                if True:
                #if any([True for keyword in KEYWORDS if keyword in disqus["response"]["posts"][i]["raw_message"].lower()]):
                    comment = {}
                    comment["created"] = int(time.mktime(datetime.datetime.strptime(disqus["response"]["posts"][i]["createdAt"].replace("T", " ").replace(".000Z", ""), "%Y-%m-%d %H:%M:%S").timetuple()))
                    comment["message"] = disqus["response"]["posts"][i]["raw_message"]
                    validation["comments"]["etherscan"].append(comment)
                    if DEBUG_MODE:
                        print(disqus["response"]["posts"][i]["createdAt"].replace("T", " ").replace(".000Z", "")+' "'+disqus["response"]["posts"][i]["raw_message"]+'"')
            if DEBUG_MODE:
                print("---------------------------------")

    validation["comments"]["etherchain"] = []


    response = requests.get("https://www.etherchain.org/account/"+contract_address.replace("0x", ""))
    if response.status_code == 200:
        matches = re.compile("<h5 class=\"text-muted d-none d-md-block\">(.+?)</h5>").findall(response.text)
        if matches:
            response = requests.get("https://disqus.com/embed/comments/?base=default&f=etherchain&t_u=https://www.etherchain.org/account/"+matches[0].replace("0x", "")+"&t_d=Account%20"+matches[0]+"%20-%20etherchain.org%20-%20The%20Ethereum%20Blockchain%20Explorer&t_t=Account%20"+matches[0]+"%20-%20etherchain.org%20-%20The%20Ethereum%20Blockchain%20Explorer&s_o=default")
            if response.status_code == 200:
                match = re.compile("<script type=\"text/json\" id=\"disqus-threadData\">(.+?)</script>").findall(response.text)
                if len(match) > 0:
                    disqus = json.loads(match[0])
                    if DEBUG_MODE:
                        print("Comments from Etherchain: "+str(len(disqus["response"]["posts"])))
                        print("---------------------------------")
                    for i in range(len(disqus["response"]["posts"])):
                        if True:
                        #if any([True for keyword in KEYWORDS if keyword in disqus["response"]["posts"][i]["raw_message"].lower()]):
                            comment = {}
                            comment["created"] = int(time.mktime(datetime.datetime.strptime(disqus["response"]["posts"][i]["createdAt"].replace("T", " ").replace(".000Z", ""), "%Y-%m-%d %H:%M:%S").timetuple()))
                            comment["message"] = disqus["response"]["posts"][i]["raw_message"]
                            validation["comments"]["etherchain"].append(comment)
                            if DEBUG_MODE:
                                print(disqus["response"]["posts"][i]["createdAt"].replace("T", " ").replace(".000Z", "")+' "'+disqus["response"]["posts"][i]["raw_message"]+'"')
                    if DEBUG_MODE:
                        print("---------------------------------")

    if attackers and victims:
        validation["successful"] = True
    else:
        validation["successful"] = False

    validation["transactions"] = len(transactions["data"])
    validation["contract"] = contract_address
    validation["honeypot_techniques"] = []
    validation["balance"] = balance

    if report["balance_disorder"]:
        validation["honeypot_techniques"].append("balance_disorder")
    if report["inheritance_disorder"]:
        validation["honeypot_techniques"].append("inheritance_disorder")
    if report["skip_empty_string_literal"]:
        validation["honeypot_techniques"].append("skip_empty_string_literal")
    if report["type_deduction_overflow"]:
        validation["honeypot_techniques"].append("type_deduction_overflow")
    if report["uninitialised_struct"]:
        validation["honeypot_techniques"].append("uninitialised_struct")
    if report["hidden_state_update"]:
        validation["honeypot_techniques"].append("hidden_state_update")
    if report["hidden_transfer"]:
        validation["honeypot_techniques"].append("hidden_transfer")
    if report["straw_man_contract"]:
        validation["honeypot_techniques"].append("straw_man_contract")

    if not DEBUG_MODE:
        collection.insert_one(validation)
        # Indexing...
        if 'contract' not in collection.index_information():
            collection.create_index('contract', unique=True)
            collection.create_index('transactions')
            collection.create_index('successful')
            collection.create_index('comments')
            collection.create_index('attackers')
            collection.create_index('victims')
            collection.create_index('attacker_and_victim')
            collection.create_index('honeypot_techniques')
            collection.create_index('suicidal')
            collection.create_index('time_analysis')
            collection.create_index('balance')

if __name__ == "__main__":
    analysis_collection = MongoClient('127.0.0.1', 27017)['honeybadger']['analysis']
    for (dirpath, dirnames, filenames) in os.walk("../../results/evaluation"):
        for filename in filenames:
            if filename.endswith(".csv"):
                print("Analysing '"+filename+"'")
                with open(dirpath+"/"+filename, 'rb') as csvfile:
                    reader = csv.reader(csvfile, delimiter=',')
                    for row in reader:
                        if row[1] == "Yes" and row[2] == 'TRUE':
                            print("Analysing contract: "+row[0])
                            with open("../../results/reports/"+row[0]+".json") as file:
                                report = json.load(file)
                                try:
                                    analyse_honeypot(row[0], report, analysis_collection)
                                except:
                                    print("Error analysing contract: "+row[0])
