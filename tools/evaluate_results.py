#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import json
import pymongo
import os.path
import traceback
import math

from collections import Counter

from pymongo import MongoClient
from html.parser import HTMLParser

FOLDER = "results"

MONGO_HOST      = '127.0.0.1'
MONGO_PORT      = 27017
DATABASE        = 'honeybadger'
COLLECTION      = 'contracts'

def mean(x):
    return sum(x) / len(x)

def median(x):
    sorted_x = sorted(x)
    length_n = len(x)
    middle = length_n // 2
    if length_n % 2 == 0:
        median_even = (sorted_x[middle - 1] + sorted_x[middle]) / 2
        return(median_even)
    else:
        return(sorted_x[middle])

def variance(x):
     n = len(x)
     x_bar = mean(x)
     return(round(sum((x_i - x_bar)**2 for x_i in x) / (n - 1), 2))

def standard_deviation(x):
     return(math.sqrt(variance(x)))

global total
global vulnearable
global time
global paths
global min_paths
global max_paths
global nr_contracts
global coverage
global timeouts

global money_flows
global balance_disorders
global hidden_transfers
global inheritance_disorders
global uninitialised_structs
global type_deduction_overflows
global skip_empty_string_literals
global hidden_state_updates
global straw_man_contracts

global list_of_money_flows
global list_of_balance_disorders
global list_of_hidden_transfers
global list_of_inheritance_disorders
global list_of_uninitialised_structs
global list_of_type_deduction_overflows
global list_of_skip_empty_string_literals
global list_of_hidden_state_updates
global list_of_straw_man_contracts

total        = 0
vulnearable  = 0
time         = 0.0
time_array   = []
paths        = 0
min_paths    = 0
max_paths    = 0
paths_array  = []
nr_contracts = 0
coverage     = 0.0
timeouts     = 0

money_flows                = 0
balance_disorders          = 0
hidden_transfers           = 0
inheritance_disorders      = 0
uninitialised_structs      = 0
type_deduction_overflows   = 0
skip_empty_string_literals = 0
hidden_state_updates       = 0
straw_man_contracts        = 0

list_of_money_flows                = set()
list_of_balance_disorders          = set()
list_of_hidden_transfers           = set()
list_of_inheritance_disorders      = set()
list_of_uninitialised_structs      = set()
list_of_type_deduction_overflows   = set()
list_of_skip_empty_string_literals = set()
list_of_hidden_state_updates       = set()
list_of_straw_man_contracts        = set()

addresses = set()

def evaluate_contract(contract):
    global total
    global vulnearable
    global time
    global time_array
    global paths
    global min_paths
    global max_paths
    global nr_contracts
    global coverage
    global timeouts
    global paths_array

    global money_flows
    global balance_disorders
    global hidden_transfers
    global inheritance_disorders
    global uninitialised_structs
    global type_deduction_overflows
    global skip_empty_string_literals
    global hidden_state_updates
    global straw_man_contracts

    global list_of_money_flows
    global list_of_balance_disorders
    global list_of_hidden_transfers
    global list_of_inheritance_disorders
    global list_of_uninitialised_structs
    global list_of_type_deduction_overflows
    global list_of_skip_empty_string_literals
    global list_of_hidden_state_updates
    global list_of_straw_man_contracts

    global money_flow
    global balance_disorder
    global hidden_transfer
    global inheritance_disorder
    global uninitialised_struct
    global type_deduction_overflow
    global skip_empty_string_literal
    global hidden_state_update
    global straw_man_contract

    global timeout

    if contract["money_flow"] != False:
        money_flow = True
    if contract["balance_disorder"] != False:
        balance_disorder = True
    if contract["hidden_transfer"] != False:
        hidden_transfer = True
    if contract["inheritance_disorder"] != False:
        inheritance_disorder = True
    if contract["uninitialised_struct"] != False:
        uninitialised_struct = True
    if contract["type_deduction_overflow"] != False:
        type_deduction_overflow = True
    if contract["skip_empty_string_literal"] != False:
        skip_empty_string_literal = True
    if contract["hidden_state_update"] != False:
        hidden_state_update = True
    if contract["straw_man_contract"] != False:
        straw_man_contract = True

    if contract["timeout"] != False:
        timeout = True

    if contract["execution_time"] != "":
        time += float(contract["execution_time"])
        time_array.append(round(float(contract["execution_time"])))
    paths += int(contract["execution_paths"])
    paths_array.append(int(contract["execution_paths"]))
    coverage += float(contract["evm_code_coverage"])
    nr_contracts += 1
    if min_paths == 0 or int(contract["execution_paths"]) < min_paths:
        min_paths = int(contract["execution_paths"])
    if max_paths == 0 or int(contract["execution_paths"]) > max_paths:
        max_paths = int(contract["execution_paths"])

print("Evaluating results...")

for file in os.listdir(os.path.join("..", FOLDER)):
    if file.endswith(".json"):
        total += 1
        try:
            data = json.load(open(os.path.join(os.path.join("..", FOLDER), file)))

            global money_flow
            global balance_disorder
            global hidden_transfer
            global inheritance_disorder
            global uninitialised_struct
            global type_deduction_overflow
            global skip_empty_string_literal
            global hidden_state_update
            global straw_man_contract

            global timeout

            money_flow                = False
            balance_disorder          = False
            hidden_transfer           = False
            inheritance_disorder      = False
            uninitialised_struct      = False
            type_deduction_overflow   = False
            skip_empty_string_literal = False
            hidden_state_update       = False
            straw_man_contract        = False

            timeout = False

            if not "evm_code_coverage" in data:
                for contract in data:
                    evaluate_contract(data[contract])
            else:
                evaluate_contract(data)

            address = file.split('.')[0]

            if money_flow:
                money_flows += 1
                list_of_money_flows.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if balance_disorder:
                balance_disorders += 1
                list_of_balance_disorders.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if hidden_transfer:
                hidden_transfers += 1
                list_of_hidden_transfers.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if inheritance_disorder:
                inheritance_disorders += 1
                list_of_inheritance_disorders.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if uninitialised_struct:
                uninitialised_structs += 1
                list_of_uninitialised_structs.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if type_deduction_overflow:
                type_deduction_overflows += 1
                list_of_type_deduction_overflows.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if skip_empty_string_literal:
                skip_empty_string_literals += 1
                list_of_skip_empty_string_literals.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if hidden_state_update:
                hidden_state_updates += 1
                list_of_hidden_state_updates.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))
            if straw_man_contract:
                straw_man_contracts += 1
                list_of_straw_man_contracts.add(address)
                #print(os.path.join(os.path.join("..", FOLDER), file))

            if balance_disorder or hidden_transfer or inheritance_disorder or uninitialised_struct or type_deduction_overflow or skip_empty_string_literal or hidden_state_update or straw_man_contract:
                vulnearable += 1
                addresses.add(address)

            if timeout:
                timeouts += 1
        except Exception as e:
            print(" --> Exception in: "+os.path.join(os.path.join("..", FOLDER), file))
            print("Reason: "+str(e))
            traceback.print_exc()

print("Number of analyzed contracts: "+str(total))
print("Total execution time: "+str(time)+" seconds, avg: "+str(float(time)/float(nr_contracts))+" seconds")
data = Counter(time_array)
print("Execution time mode: "+str(data.most_common(1)))
print("Execution time median: "+str(median(time_array)))
print("Execution time variance: "+str(variance(time_array)))
print("Execution time standard deviation: "+str(standard_deviation(time_array)))
print("Average code coverage: "+str(float(coverage)/float(nr_contracts))+"%")
print("Number of explored paths: "+str(paths)+", min: "+str(min_paths)+", max: "+str(max_paths)+", avg: "+str(float(paths)/float(nr_contracts)))
data = Counter(paths_array)
print("Number of explored paths mode: "+str(data.most_common(1)))
print("Number of explored paths median: "+str(median(paths_array)))
print("Number of vulnearable contracts: "+str(vulnearable))
print("Number of timeouts: "+str(timeouts))
print("=====================================================================")
print("Number of unique money flows: "+str(money_flows)+" ("+str(float(money_flows)/float(total)*100)+"%)")
print("Number of unique balance disorders: "+str(balance_disorders)+" ("+str(float(balance_disorders)/float(total)*100)+"%)")
print("Number of unique inheritance disorders: "+str(inheritance_disorders)+" ("+str(float(inheritance_disorders)/float(total)*100)+"%)")
print("Number of unique skip empty string literals: "+str(skip_empty_string_literals)+" ("+str(float(skip_empty_string_literals)/float(total)*100)+"%)")
print("Number of unique type deduction overflows: "+str(type_deduction_overflows)+" ("+str(float(type_deduction_overflows)/float(total)*100)+"%)")
print("Number of unique uninitialised structs: "+str(uninitialised_structs)+" ("+str(float(uninitialised_structs)/float(total)*100)+"%)")
print("Number of unique hidden state updates: "+str(hidden_state_updates)+" ("+str(float(hidden_state_updates)/float(total)*100)+"%)")
print("Number of unique hidden transfers: "+str(hidden_transfers)+" ("+str(float(hidden_transfers)/float(total)*100)+"%)")
print("Number of unique straw man contracts: "+str(straw_man_contracts)+" ("+str(float(straw_man_contracts)/float(total)*100)+"%)")
print("=====================================================================")

collection = MongoClient(MONGO_HOST, MONGO_PORT)[DATABASE][COLLECTION]

########################################################################

list_of_bytecode_addresses = set()

list_of_bytecode_money_flows = set()
list_of_bytecode_balance_disorders = set()
list_of_bytecode_hidden_transfers = set()
list_of_bytecode_inheritance_disorders = set()
list_of_bytecode_uninitialised_structs = set()
list_of_bytecode_type_deduction_overflows = set()
list_of_bytecode_skip_empty_string_literals = set()
list_of_bytecode_hidden_state_updates = set()
list_of_bytecode_straw_man_contracts = set()

cursor = collection.find()
for contract in cursor:
    if contract["address"] in addresses:
        list_of_bytecode_addresses.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_money_flows:
        list_of_bytecode_money_flows.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_balance_disorders:
        list_of_bytecode_balance_disorders.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_hidden_transfers:
        list_of_bytecode_hidden_transfers.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_inheritance_disorders:
        list_of_bytecode_inheritance_disorders.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_uninitialised_structs:
        list_of_bytecode_uninitialised_structs.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_type_deduction_overflows:
        list_of_bytecode_type_deduction_overflows.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_skip_empty_string_literals:
        list_of_bytecode_skip_empty_string_literals.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_hidden_state_updates:
        list_of_bytecode_hidden_state_updates.add(contract["byteCode"].encode('utf-8'))

    if contract["address"] in list_of_straw_man_contracts:
        list_of_bytecode_straw_man_contracts.add(contract["byteCode"].encode('utf-8'))

if len(addresses) != len(list_of_bytecode_addresses):
    print("Error")
if len(list_of_money_flows) != len(list_of_bytecode_money_flows):
    print("Error")
if len(list_of_balance_disorders) != len(list_of_bytecode_balance_disorders):
    print("Error")
if len(list_of_hidden_transfers) != len(list_of_bytecode_hidden_transfers):
    print("Error")
if len(list_of_inheritance_disorders) != len(list_of_bytecode_inheritance_disorders):
    print("Error")
if len(list_of_uninitialised_structs) != len(list_of_bytecode_uninitialised_structs):
    print("Error")
if len(list_of_type_deduction_overflows) != len(list_of_bytecode_type_deduction_overflows):
    print("Error")
if len(list_of_skip_empty_string_literals) != len(list_of_bytecode_skip_empty_string_literals):
    print("Error")
if len(list_of_hidden_state_updates) != len(list_of_bytecode_hidden_state_updates):
    print("Error")
if len(list_of_straw_man_contracts) != len(list_of_bytecode_straw_man_contracts):
    print("Error")

overall_addresses                  = 0
overall_money_flows                = 0
overall_balance_disorders          = 0
overall_hidden_transfers           = 0
overall_inheritance_disorders      = 0
overall_uninitialised_structs      = 0
overall_type_deduction_overflows   = 0
overall_skip_empty_string_literals = 0
overall_hidden_state_updates       = 0
overall_straw_man_contracts        = 0

cursor = collection.find()
for contract in cursor:
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_addresses:
        overall_addresses += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_money_flows:
        overall_money_flows += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_balance_disorders:
        overall_balance_disorders += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_hidden_transfers:
        overall_hidden_transfers += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_inheritance_disorders:
        overall_inheritance_disorders += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_uninitialised_structs:
        overall_uninitialised_structs += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_type_deduction_overflows:
        overall_type_deduction_overflows += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_skip_empty_string_literals:
        overall_skip_empty_string_literals += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_hidden_state_updates:
        overall_hidden_state_updates += 1
    if contract["byteCode"].encode('utf-8') in list_of_bytecode_straw_man_contracts:
        overall_straw_man_contracts += 1

print("Number of overall vulnerable contracts: "+str(overall_addresses))

print("Number of overall money flows: "+str(overall_money_flows))
print("Number of overall balance disorders: "+str(overall_balance_disorders))
print("Number of overall inheritance disorders: "+str(overall_inheritance_disorders))
print("Number of overall skip empty string literals: "+str(overall_skip_empty_string_literals))
print("Number of overall type deduction overflows: "+str(overall_type_deduction_overflows))
print("Number of overall uninitialised structs: "+str(overall_uninitialised_structs))
print("Number of overall hidden state updates: "+str(overall_hidden_state_updates))
print("Number of overall hidden transfers: "+str(overall_hidden_transfers))
print("Number of overall straw man contracts: "+str(overall_straw_man_contracts))

file = open("balance_disorder_contracts.txt", "w")
for address in list_of_balance_disorders:
    file.write(address+"\n")
file.close()
file = open("hidden_transfer_contracts.txt", "w")
for address in list_of_hidden_transfers:
    file.write(address+"\n")
file.close()
file = open("inheritance_disorder_contracts.txt", "w")
for address in list_of_inheritance_disorders:
    file.write(address+"\n")
file.close()
file = open("uninitialised_struct_contracts.txt", "w")
for address in list_of_uninitialised_structs:
    file.write(address+"\n")
file.close()
file = open("type_deduction_overflow_contracts.txt", "w")
for address in list_of_type_deduction_overflows:
    file.write(address+"\n")
file.close()
file = open("skip_empty_string_literal_contracts.txt", "w")
for address in list_of_skip_empty_string_literals:
    file.write(address+"\n")
file.close()
file = open("hidden_state_update_contracts.txt", "w")
for address in list_of_hidden_state_updates:
    file.write(address+"\n")
file.close()
file = open("straw_man_contracts.txt", "w")
for address in list_of_straw_man_contracts:
    file.write(address+"\n")
file.close()
