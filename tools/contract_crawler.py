#!/usr/bin/python3
# -*- coding: utf-8 -*-

import queue
import threading
import pymongo
import datetime

from web3 import Web3, HTTPProvider
from pymongo import MongoClient

#web3 = Web3(HTTPProvider("http://localhost:8545"))
web3 = Web3(HTTPProvider("https://mainnet.infura.io/:8545"))

latestBlock = web3.eth.getBlock('latest')
exitFlag = 0

def init():
    if web3.eth.syncing == False:
        print('Ethereum blockchain is up-to-date.')
        print('Latest block: '+str(latestBlock.number)+' ('+datetime.datetime.fromtimestamp(int(latestBlock.timestamp)).strftime('%d-%m-%Y %H:%M:%S')+')\n')
    else:
        print('Ethereum blockchain is currently syncing...')
        print('Latest block: '+str(latestBlock.number)+' ('+datetime.datetime.fromtimestamp(int(latestBlock.timestamp)).strftime('%d-%m-%Y %H:%M:%S')+')\n')

class searchThread(threading.Thread):
   def __init__(self, threadID, queue, collection):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.queue = queue
      self.collection = collection
   def run(self):
      searchContract(self.queue, self.collection)

def searchContract(queue, collection):
    while not exitFlag:
        queueLock.acquire()
        if not queue.empty():
            blockNumber = queue.get()
            queueLock.release()
            print('Searching block '+str(blockNumber)+' for contracts...')
            block = web3.eth.getBlock(blockNumber, True)
            if block and block.transactions:
                for transaction in block.transactions:
                    if not transaction.to:
                        receipt = web3.eth.getTransactionReceipt(transaction.hash)
                        print('Contract found: '+receipt['contractAddress'])
                        if collection.count_documents({'address': receipt['contractAddress'].lower()}) == 0:
                            transaction_input = transaction['input'].replace("0x", "")
                            contract_code = web3.eth.getCode(receipt['contractAddress'], transaction['blockNumber']).hex().replace("0x", "")
                            # Uncomment this line if you want to skip zombie contracts
                            #if len(transaction_input) == 0 and len(contract_code) == 0:
                            #    print('Contract '+receipt['contractAddress']+' is empty...')
                            #    continue
                            contract = {}
                            contract['address'] = receipt['contractAddress'].lower()
                            contract['transactionHash'] = transaction['hash'].hex().lower()
                            contract['blockNumber'] = transaction['blockNumber']
                            contract['timestamp'] = block.timestamp
                            contract['creator'] = transaction['from'].lower()
                            contract['input'] = transaction_input
                            contract['byteCode'] = contract_code
                            collection.insert_one(contract)
                            # Indexing...
                            if 'address' not in collection.index_information():
                                collection.create_index('address', unique=True)
                                collection.create_index('transactionHash', unique=True)
                                collection.create_index('blockNumber')
                                collection.create_index('timestamp')
                                collection.create_index('creator')
                            print('Contract '+contract['address']+' has been successfully added.')
                        else:
                            print('Contract '+receipt['contractAddress']+' already exists...')
        else:
            queueLock.release()

if __name__ == "__main__":
    init()

    queueLock = threading.Lock()
    blockQueue = queue.Queue()

    # Create new threads
    threads = []
    threadID = 1
    collection = MongoClient('127.0.0.1', 27017)['honeybadger']['contracts']
    for i in range(100):
        thread = searchThread(threadID, blockQueue, collection)
        thread.start()
        threads.append(thread)
        threadID += 1

    startBlockNumber = 6400000
    #cursor = MongoClient('127.0.0.1', 27017)['honeybadger']['contracts'].find().sort('blockNumber', pymongo.DESCENDING).limit(1)
    #for contract in cursor:
    #    startBlockNumber = contract['blockNumber']
    endBlockNumber = max(startBlockNumber, 6500000)

    # Fill the queue with block numbers
    queueLock.acquire()
    for i in range(startBlockNumber, endBlockNumber+1):
        blockQueue.put(i)
    queueLock.release()

    print('Searching for contracts within blocks '+str(startBlockNumber)+' and '+str(endBlockNumber)+'\n')

    # Wait for queue to empty
    while not blockQueue.empty():
        pass

    # Notify threads it's time to exit
    exitFlag = 1

    # Wait for all threads to complete
    for t in threads:
       t.join()

    print('\nDone')
