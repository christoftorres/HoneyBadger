#!/usr/bin/env python2

import os
import json
import shlex
import shutil
import subprocess

global min_code_coverage
min_code_coverage = 99.0
global_timeout = 1800
loop_limit = 10

if __name__ == '__main__':
    print("")
    print("                Testing HoneyBadger")
    FNULL = open(os.devnull, 'w')
    os.mkdir('results')
    print("=======================================================")


    print("Testing 'CryptoRoulette.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/CryptoRoulette.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/CryptoRoulette.json', 'r') as f:
            results = json.load(f)
            print("Code coverage: "+results["CryptoRoulette"]["evm_code_coverage"])
            print("Execution time: "+results["CryptoRoulette"]["execution_time"])
            if (float(results["CryptoRoulette"]["evm_code_coverage"]) >= min_code_coverage
            and results["CryptoRoulette"]["money_flow"]
            and not results["CryptoRoulette"]["balance_disorder"]
            and not results["CryptoRoulette"]["hidden_transfer"]
            and not results["CryptoRoulette"]["inheritance_disorder"]
            and results["CryptoRoulette"]["uninitialised_struct"]
            and not results["CryptoRoulette"]["type_deduction_overflow"]
            and not results["CryptoRoulette"]["skip_empty_string_literal"]
            and not results["CryptoRoulette"]["hidden_state_update"]
            and not results["CryptoRoulette"]["straw_man_contract"]):
                print("\033[92mPASSED\033[0m")
            else:
                print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'Gift_1_Eth.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/Gift_1_Eth.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/Gift_1_Eth.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["Gift_1_ETH"]["evm_code_coverage"])
        print("Execution time: "+results["Gift_1_ETH"]["execution_time"])
        if (float(results["Gift_1_ETH"]["evm_code_coverage"]) >= min_code_coverage
        and results["Gift_1_ETH"]["money_flow"]
        and not results["Gift_1_ETH"]["balance_disorder"]
        and not results["Gift_1_ETH"]["hidden_transfer"]
        and not results["Gift_1_ETH"]["inheritance_disorder"]
        and not results["Gift_1_ETH"]["uninitialised_struct"]
        and not results["Gift_1_ETH"]["type_deduction_overflow"]
        and not results["Gift_1_ETH"]["skip_empty_string_literal"]
        and results["Gift_1_ETH"]["hidden_state_update"]
        and not results["Gift_1_ETH"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'MultiplicatorX3.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/MultiplicatorX3.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/MultiplicatorX3.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["MultiplicatorX3"]["evm_code_coverage"])
        print("Execution time: "+results["MultiplicatorX3"]["execution_time"])
        if (float(results["MultiplicatorX3"]["evm_code_coverage"]) >= min_code_coverage
        and results["MultiplicatorX3"]["money_flow"]
        and results["MultiplicatorX3"]["balance_disorder"]
        and not results["MultiplicatorX3"]["hidden_transfer"]
        and not results["MultiplicatorX3"]["inheritance_disorder"]
        and not results["MultiplicatorX3"]["uninitialised_struct"]
        and not results["MultiplicatorX3"]["type_deduction_overflow"]
        and not results["MultiplicatorX3"]["skip_empty_string_literal"]
        and not results["MultiplicatorX3"]["hidden_state_update"]
        and not results["MultiplicatorX3"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'PrivateBank.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/PrivateBank.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/PrivateBank.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["Private_Bank"]["evm_code_coverage"])
        print("Execution time: "+results["Private_Bank"]["execution_time"])
        if (float(results["Private_Bank"]["evm_code_coverage"]) >= min_code_coverage
        and results["Private_Bank"]["money_flow"]
        and not results["Private_Bank"]["balance_disorder"]
        and not results["Private_Bank"]["hidden_transfer"]
        and not results["Private_Bank"]["inheritance_disorder"]
        and not results["Private_Bank"]["uninitialised_struct"]
        and not results["Private_Bank"]["type_deduction_overflow"]
        and not results["Private_Bank"]["skip_empty_string_literal"]
        and not results["Private_Bank"]["hidden_state_update"]
        and results["Private_Bank"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'Test1.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/Test1.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/Test1.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["Test1"]["evm_code_coverage"])
        print("Execution time: "+results["Test1"]["execution_time"])
        if (float(results["Test1"]["evm_code_coverage"]) >= min_code_coverage
        and results["Test1"]["money_flow"]
        and not results["Test1"]["balance_disorder"]
        and not results["Test1"]["hidden_transfer"]
        and not results["Test1"]["inheritance_disorder"]
        and not results["Test1"]["uninitialised_struct"]
        and results["Test1"]["type_deduction_overflow"]
        and not results["Test1"]["skip_empty_string_literal"]
        and not results["Test1"]["hidden_state_update"]
        and not results["Test1"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'TestBank.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/TestBank.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/TestBank.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["TestBank"]["evm_code_coverage"])
        print("Execution time: "+results["TestBank"]["execution_time"])
        if (float(results["TestBank"]["evm_code_coverage"]) >= min_code_coverage
        and results["TestBank"]["money_flow"]
        and not results["TestBank"]["balance_disorder"]
        and not results["TestBank"]["hidden_transfer"]
        and results["TestBank"]["inheritance_disorder"]
        and not results["TestBank"]["uninitialised_struct"]
        and not results["TestBank"]["type_deduction_overflow"]
        and not results["TestBank"]["skip_empty_string_literal"]
        and not results["TestBank"]["hidden_state_update"]
        and not results["TestBank"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'TestToken.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/TestToken.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/TestToken.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["TestToken"]["evm_code_coverage"])
        print("Execution time: "+results["TestToken"]["execution_time"])
        if (float(results["TestToken"]["evm_code_coverage"]) >= min_code_coverage
        and results["TestToken"]["money_flow"]
        and not results["TestToken"]["balance_disorder"]
        and results["TestToken"]["hidden_transfer"]
        and not results["TestToken"]["inheritance_disorder"]
        and not results["TestToken"]["uninitialised_struct"]
        and not results["TestToken"]["type_deduction_overflow"]
        and not results["TestToken"]["skip_empty_string_literal"]
        and not results["TestToken"]["hidden_state_update"]
        and not results["TestToken"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'WhaleGiveaway1.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/WhaleGiveaway1.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/WhaleGiveaway1.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["WhaleGiveaway1"]["evm_code_coverage"])
        print("Execution time: "+results["WhaleGiveaway1"]["execution_time"])
        if (float(results["WhaleGiveaway1"]["evm_code_coverage"]) >= min_code_coverage
        and results["WhaleGiveaway1"]["money_flow"]
        and not results["WhaleGiveaway1"]["balance_disorder"]
        and results["WhaleGiveaway1"]["hidden_transfer"]
        and not results["WhaleGiveaway1"]["inheritance_disorder"]
        and not results["WhaleGiveaway1"]["uninitialised_struct"]
        and not results["WhaleGiveaway1"]["type_deduction_overflow"]
        and not results["WhaleGiveaway1"]["skip_empty_string_literal"]
        and not results["WhaleGiveaway1"]["hidden_state_update"]
        and not results["WhaleGiveaway1"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'firstTest.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/firstTest.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/firstTest.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["firstTest"]["evm_code_coverage"])
        print("Execution time: "+results["firstTest"]["execution_time"])
        if (float(results["firstTest"]["evm_code_coverage"]) >= min_code_coverage
        and results["firstTest"]["money_flow"]
        and not results["firstTest"]["balance_disorder"]
        and not results["firstTest"]["hidden_transfer"]
        and not results["firstTest"]["inheritance_disorder"]
        and not results["firstTest"]["uninitialised_struct"]
        and not results["firstTest"]["type_deduction_overflow"]
        and not results["firstTest"]["skip_empty_string_literal"]
        and not results["firstTest"]["hidden_state_update"]
        and results["firstTest"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'DividendDistributor.bin'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/DividendDistributor.bin -b -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/DividendDistributor.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["evm_code_coverage"])
        print("Execution time: "+results["execution_time"])
        if (float(results["evm_code_coverage"]) >= min_code_coverage
        and results["money_flow"]
        and not results["balance_disorder"]
        and not results["hidden_transfer"]
        and not results["inheritance_disorder"]
        and not results["uninitialised_struct"]
        and not results["type_deduction_overflow"]
        and results["skip_empty_string_literal"]
        and not results["hidden_state_update"]
        and not results["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'For_Test.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/For_Test.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/For_Test.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["For_Test"]["evm_code_coverage"])
        print("Execution time: "+results["For_Test"]["execution_time"])
        if (float(results["For_Test"]["evm_code_coverage"]) >= min_code_coverage
        and results["For_Test"]["money_flow"]
        and not results["For_Test"]["balance_disorder"]
        and not results["For_Test"]["hidden_transfer"]
        and not results["For_Test"]["inheritance_disorder"]
        and not results["For_Test"]["uninitialised_struct"]
        and results["For_Test"]["type_deduction_overflow"]
        and not results["For_Test"]["skip_empty_string_literal"]
        and not results["For_Test"]["hidden_state_update"]
        and not results["For_Test"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'KingOfTheHill.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/KingOfTheHill.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/KingOfTheHill.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["KingOfTheHill"]["evm_code_coverage"])
        print("Execution time: "+results["KingOfTheHill"]["execution_time"])
        if (float(results["KingOfTheHill"]["evm_code_coverage"]) >= min_code_coverage
        and results["KingOfTheHill"]["money_flow"]
        and not results["KingOfTheHill"]["balance_disorder"]
        and not results["KingOfTheHill"]["hidden_transfer"]
        and results["KingOfTheHill"]["inheritance_disorder"]
        and not results["KingOfTheHill"]["uninitialised_struct"]
        and not results["KingOfTheHill"]["type_deduction_overflow"]
        and not results["KingOfTheHill"]["skip_empty_string_literal"]
        and not results["KingOfTheHill"]["hidden_state_update"]
        and not results["KingOfTheHill"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'NEW_YEARS_GIFT.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/NEW_YEARS_GIFT.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/NEW_YEARS_GIFT.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["NEW_YEARS_GIFT"]["evm_code_coverage"])
        print("Execution time: "+results["NEW_YEARS_GIFT"]["execution_time"])
        if (float(results["NEW_YEARS_GIFT"]["evm_code_coverage"]) >= min_code_coverage
        and results["NEW_YEARS_GIFT"]["money_flow"]
        and not results["NEW_YEARS_GIFT"]["balance_disorder"]
        and not results["NEW_YEARS_GIFT"]["hidden_transfer"]
        and not results["NEW_YEARS_GIFT"]["inheritance_disorder"]
        and not results["NEW_YEARS_GIFT"]["uninitialised_struct"]
        and not results["NEW_YEARS_GIFT"]["type_deduction_overflow"]
        and not results["NEW_YEARS_GIFT"]["skip_empty_string_literal"]
        and results["NEW_YEARS_GIFT"]["hidden_state_update"]
        and not results["NEW_YEARS_GIFT"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'OpenAddressLottery.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/OpenAddressLottery.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/OpenAddressLottery.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["OpenAddressLottery"]["evm_code_coverage"])
        print("Execution time: "+results["OpenAddressLottery"]["execution_time"])
        if (float(results["OpenAddressLottery"]["evm_code_coverage"]) >= min_code_coverage
        and results["OpenAddressLottery"]["money_flow"]
        and not results["OpenAddressLottery"]["balance_disorder"]
        and not results["OpenAddressLottery"]["hidden_transfer"]
        and not results["OpenAddressLottery"]["inheritance_disorder"]
        and results["OpenAddressLottery"]["uninitialised_struct"]
        and not results["OpenAddressLottery"]["type_deduction_overflow"]
        and not results["OpenAddressLottery"]["skip_empty_string_literal"]
        and not results["OpenAddressLottery"]["hidden_state_update"]
        and not results["OpenAddressLottery"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'PINCODE.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/PINCODE.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/PINCODE.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["PinCodeEtherStorage"]["evm_code_coverage"])
        print("Execution time: "+results["PinCodeEtherStorage"]["execution_time"])
        if (float(results["PinCodeEtherStorage"]["evm_code_coverage"]) >= min_code_coverage
        and results["PinCodeEtherStorage"]["money_flow"]
        and results["PinCodeEtherStorage"]["balance_disorder"]
        and not results["PinCodeEtherStorage"]["hidden_transfer"]
        and not results["PinCodeEtherStorage"]["inheritance_disorder"]
        and not results["PinCodeEtherStorage"]["uninitialised_struct"]
        and not results["PinCodeEtherStorage"]["type_deduction_overflow"]
        and not results["PinCodeEtherStorage"]["skip_empty_string_literal"]
        and not results["PinCodeEtherStorage"]["hidden_state_update"]
        and not results["PinCodeEtherStorage"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'RichestTakeAll.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/RichestTakeAll.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/RichestTakeAll.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["RichestTakeAll"]["evm_code_coverage"])
        print("Execution time: "+results["RichestTakeAll"]["execution_time"])
        if (float(results["RichestTakeAll"]["evm_code_coverage"]) >= min_code_coverage
        and results["RichestTakeAll"]["money_flow"]
        and not results["RichestTakeAll"]["balance_disorder"]
        and not results["RichestTakeAll"]["hidden_transfer"]
        and results["RichestTakeAll"]["inheritance_disorder"]
        and not results["RichestTakeAll"]["uninitialised_struct"]
        and not results["RichestTakeAll"]["type_deduction_overflow"]
        and not results["RichestTakeAll"]["skip_empty_string_literal"]
        and not results["RichestTakeAll"]["hidden_state_update"]
        and not results["RichestTakeAll"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'ICO_Hold.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/ICO_Hold.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/ICO_Hold.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["ICO_Hold"]["evm_code_coverage"])
        print("Execution time: "+results["ICO_Hold"]["execution_time"])
        if (float(results["ICO_Hold"]["evm_code_coverage"]) >= min_code_coverage
        and results["ICO_Hold"]["money_flow"]
        and not results["ICO_Hold"]["balance_disorder"]
        and not results["ICO_Hold"]["hidden_transfer"]
        and results["ICO_Hold"]["inheritance_disorder"]
        and not results["ICO_Hold"]["uninitialised_struct"]
        and not results["ICO_Hold"]["type_deduction_overflow"]
        and not results["ICO_Hold"]["skip_empty_string_literal"]
        and not results["ICO_Hold"]["hidden_state_update"]
        and not results["ICO_Hold"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'TransferReg.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/TransferReg.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/TransferReg.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["TransferReg"]["evm_code_coverage"])
        print("Execution time: "+results["TransferReg"]["execution_time"])
        if (float(results["TransferReg"]["evm_code_coverage"]) >= min_code_coverage
        and results["TransferReg"]["money_flow"]
        and not results["TransferReg"]["balance_disorder"]
        and not results["TransferReg"]["hidden_transfer"]
        and not results["TransferReg"]["inheritance_disorder"]
        and not results["TransferReg"]["uninitialised_struct"]
        and not results["TransferReg"]["type_deduction_overflow"]
        and not results["TransferReg"]["skip_empty_string_literal"]
        and not results["TransferReg"]["hidden_state_update"]
        and results["TransferReg"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'testBank2.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/testBank2.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/testBank2.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["testBank"]["evm_code_coverage"])
        print("Execution time: "+results["testBank"]["execution_time"])
        if (float(results["testBank"]["evm_code_coverage"]) >= min_code_coverage
        and results["testBank"]["money_flow"]
        and not results["testBank"]["balance_disorder"]
        and not results["testBank"]["hidden_transfer"]
        and not results["testBank"]["inheritance_disorder"]
        and not results["testBank"]["uninitialised_struct"]
        and not results["testBank"]["type_deduction_overflow"]
        and not results["testBank"]["skip_empty_string_literal"]
        and not results["testBank"]["hidden_state_update"]
        and results["testBank"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'GuessNumber.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/GuessNumber.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/GuessNumber.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["GuessNumber"]["evm_code_coverage"])
        print("Execution time: "+results["GuessNumber"]["execution_time"])
        if (float(results["GuessNumber"]["evm_code_coverage"]) >= min_code_coverage
        and results["GuessNumber"]["money_flow"]
        and not results["GuessNumber"]["balance_disorder"]
        and not results["GuessNumber"]["hidden_transfer"]
        and not results["GuessNumber"]["inheritance_disorder"]
        and results["GuessNumber"]["uninitialised_struct"]
        and not results["GuessNumber"]["type_deduction_overflow"]
        and not results["GuessNumber"]["skip_empty_string_literal"]
        and not results["GuessNumber"]["hidden_state_update"]
        and not results["GuessNumber"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'G_GAME.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/G_GAME.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/G_GAME.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["G_GAME"]["evm_code_coverage"])
        print("Execution time: "+results["G_GAME"]["execution_time"])
        if (float(results["G_GAME"]["evm_code_coverage"]) >= min_code_coverage
        and results["G_GAME"]["money_flow"]
        and not results["G_GAME"]["balance_disorder"]
        and not results["G_GAME"]["hidden_transfer"]
        and not results["G_GAME"]["inheritance_disorder"]
        and not results["G_GAME"]["uninitialised_struct"]
        and not results["G_GAME"]["type_deduction_overflow"]
        and not results["G_GAME"]["skip_empty_string_literal"]
        and results["G_GAME"]["hidden_state_update"]
        and not results["G_GAME"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'IFYKRYGE.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/IFYKRYGE.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/IFYKRYGE.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["IFYKRYGE"]["evm_code_coverage"])
        print("Execution time: "+results["IFYKRYGE"]["execution_time"])
        if (float(results["IFYKRYGE"]["evm_code_coverage"]) >= min_code_coverage
        and results["IFYKRYGE"]["money_flow"]
        and not results["IFYKRYGE"]["balance_disorder"]
        and not results["IFYKRYGE"]["hidden_transfer"]
        and not results["IFYKRYGE"]["inheritance_disorder"]
        and not results["IFYKRYGE"]["uninitialised_struct"]
        and not results["IFYKRYGE"]["type_deduction_overflow"]
        and not results["IFYKRYGE"]["skip_empty_string_literal"]
        and results["IFYKRYGE"]["hidden_state_update"]
        and not results["IFYKRYGE"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'EtherBet.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/EtherBet.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/EtherBet.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["EtherBet"]["evm_code_coverage"])
        print("Execution time: "+results["EtherBet"]["execution_time"])
        if (float(results["EtherBet"]["evm_code_coverage"]) >= min_code_coverage
        and results["EtherBet"]["money_flow"]
        and not results["EtherBet"]["balance_disorder"]
        and not results["EtherBet"]["hidden_transfer"]
        and not results["EtherBet"]["inheritance_disorder"]
        and not results["EtherBet"]["uninitialised_struct"]
        and not results["EtherBet"]["type_deduction_overflow"]
        and not results["EtherBet"]["skip_empty_string_literal"]
        and results["EtherBet"]["hidden_state_update"]
        and not results["EtherBet"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'TerrionFund.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/TerrionFund.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/TerrionFund.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["TerrionFund"]["evm_code_coverage"])
        print("Execution time: "+results["TerrionFund"]["execution_time"])
        if (float(results["TerrionFund"]["evm_code_coverage"]) >= min_code_coverage
        and results["TerrionFund"]["money_flow"]
        and not results["TerrionFund"]["balance_disorder"]
        and not results["TerrionFund"]["hidden_transfer"]
        and results["TerrionFund"]["inheritance_disorder"]
        and not results["TerrionFund"]["uninitialised_struct"]
        and not results["TerrionFund"]["type_deduction_overflow"]
        and not results["TerrionFund"]["skip_empty_string_literal"]
        and not results["TerrionFund"]["hidden_state_update"]
        and not results["TerrionFund"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")
    print("-------------------------------------------------------")


    print("Testing 'TrustFund.sol'...")
    p = subprocess.Popen(shlex.split("python honeybadger.py -s ../honeypots/TrustFund.sol -j -glt "+str(global_timeout)+" -ll "+str(loop_limit)), stdout=subprocess.PIPE, stderr=FNULL)
    if "======= error =======" in p.communicate()[0]:
        print("\033[91m!!! FAILED !!!\033[0m")
    else:
        with open('results/TrustFund.json', 'r') as f:
            results = json.load(f)
        print("Code coverage: "+results["TrustFund"]["evm_code_coverage"])
        print("Execution time: "+results["TrustFund"]["execution_time"])
        if (float(results["TrustFund"]["evm_code_coverage"]) >= min_code_coverage
        and results["TrustFund"]["money_flow"]
        and not results["TrustFund"]["balance_disorder"]
        and not results["TrustFund"]["hidden_transfer"]
        and not results["TrustFund"]["inheritance_disorder"]
        and not results["TrustFund"]["uninitialised_struct"]
        and not results["TrustFund"]["type_deduction_overflow"]
        and not results["TrustFund"]["skip_empty_string_literal"]
        and not results["TrustFund"]["hidden_state_update"]
        and results["TrustFund"]["straw_man_contract"]):
            print("\033[92mPASSED\033[0m")
        else:
            print("\033[91m!!! FAILED !!!\033[0m")


    print("=======================================================")
    shutil.rmtree('results')
    print("Finished testing.")
