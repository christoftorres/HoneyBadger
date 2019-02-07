#!/usr/bin/python
# -*- coding: utf-8 -*-

import queue
import threading
import pymongo
import os
import operator

from pymongo import MongoClient

NR_OF_THREADS   = 100
MONGO_HOST      = "127.0.0.1"
MONGO_PORT      = 27017
DATABASE        = "honeybadger"
COLLECTION      = "contracts"
CONTRACT_FOLDER = "contracts"

exitFlag = 0

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
            contract = queue.get()
            queueLock.release()
            file_path = CONTRACT_FOLDER+"/"+str(contract["address"])+".bin"
            # Write bytecode to file
            writeLock.acquire()
            file = open(file_path, "w")
            file.write(contract["byteCode"])
            file.close()
            writeLock.release()
        else:
            queueLock.release()

if __name__ == "__main__":

    queueLock = threading.Lock()
    writeLock = threading.Lock()

    contractQueue = queue.Queue()

    # Create new threads
    threads = []
    threadID = 0
    for i in range(NR_OF_THREADS):
        contractCollection = MongoClient(MONGO_HOST, MONGO_PORT)[DATABASE][COLLECTION]
        thread = searchThread(threadID, contractQueue, contractCollection)
        thread.start()
        threads.append(thread)
        threadID += 1

    contractCollection = MongoClient(MONGO_HOST, MONGO_PORT)[DATABASE][COLLECTION]
    cursor = contractCollection.find()
    print("Total number of smart contracts: "+str(contractCollection.count_documents({})))

    uniques = set()
    contracts = []
    distinct_bytecode = {}
    distinct_deployer = {}
    for contract in cursor:
        if not contract["creator"] in distinct_deployer:
            distinct_deployer[contract["creator"]] = 1
        else:
            distinct_deployer[contract["creator"]] += 1
        if not contract["byteCode"].encode("utf-8") in uniques:
            uniques.add(contract["byteCode"].encode("utf-8"))
            contracts.append(contract)
            distinct_bytecode[contract["byteCode"].encode("utf-8")] = 1
        else:
            distinct_bytecode[contract["byteCode"].encode("utf-8")] += 1
    print("Total number of smart contracts that are distinct: "+str(len(uniques))+" ("+str(len(contracts))+")")
    print(str(len(distinct_bytecode)))
    sorted_by_value = sorted(distinct_bytecode.items(), key=lambda kv: kv[1])
    print(sorted_by_value[-1])
    print(str(len(distinct_deployer)))
    sorted_by_value = sorted(distinct_deployer.items(), key=lambda kv: kv[1])
    print(sorted_by_value[-1])

    # Fill the queue with contracts
    queueLock.acquire()
    print("Filling queue with contracts...")
    for i in range(len(contracts)):
        contractQueue.put(contracts[i])
    queueLock.release()

    print("Queue contains "+str(contractQueue.qsize())+" contracts...")

    # Wait for queue to empty
    while not contractQueue.empty():
        pass

    # Notify threads it's time to exit
    exitFlag = 1

    # Wait for all threads to complete
    for t in threads:
       t.join()

    print('\nDone')
