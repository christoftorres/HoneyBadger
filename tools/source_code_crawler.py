#!/usr/bin/python
# -*- coding: utf-8 -*-

import queue
import threading
import cfscrape
import re
import os
import time
import traceback
import html

from html.parser import HTMLParser

exitFlag = 0

retries = 0
timeout = 1 # seconds
wait    = 2 # seconds

ETHERSCAN_URL = 'https://etherscan.io/address/'
FOLDER = 'straw_man_contract'

class searchThread(threading.Thread):
   def __init__(self, threadID, queue, scraper, parser):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.queue = queue
      self.scraper = scraper
      self.parser = parser
   def run(self):
      searchContract(self.queue, self.scraper, self.parser)

def searchContract(queue, scraper, parser):
    while not exitFlag:
        queueLock.acquire()
        if not queue.empty():
            contract = queue.get()
            queueLock.release()
            print('Searching contract '+str(contract)+'...')
            success = False
            webpage = ""
            tries = 0
            while (not success and tries <= retries):
                try:
                    time.sleep(wait)
                    webpage = scraper.get(ETHERSCAN_URL+str(contract)).content.decode('utf-8')
                    sourceCode = re.compile("<pre class='js-sourcecopyarea' id='editor' style='.+?'>([\s\S]+?)</pre>", re.MULTILINE).findall(webpage)[0]
                    writeLock.acquire()
                    file = open('../datasets/source_code/'+str(FOLDER)+'/'+str(contract)+'.sol', 'w')
                    file.write(html.unescape(sourceCode))
                    file.close()
                    writeLock.release()
                    success = True
                except Exception as e:
                    if "Request Throttled" in webpage:
                        print("Request throttled contract address "+contract)
                    else:
                        print("Unexpected error at contract address "+contract+": "+str(e))
                        #traceback.print_exc()
                    tries += 1
                    if (tries < retries):
                        print("Retrying in "+str(int(timeout))+" sec... ("+str(tries)+" of "+str(retries)+" retries)")
                        time.sleep(tries * timeout)
                    else:
                        print('Error: contract source code '+contract+' could not be downloaded.')
                    pass
                if (success):
                    print('Contract source code '+contract+' has been successfully downloaded.')
        else:
            queueLock.release()

if __name__ == "__main__":
    queueLock = threading.Lock()
    q = queue.Queue()

    writeLock = threading.Lock()

    # Create new threads
    threads = []
    threadID = 1
    for i in range(5):
        scraper = cfscrape.CloudflareScraper()
        parser = HTMLParser()
        thread = searchThread(threadID, q, scraper, parser)
        thread.start()
        threads.append(thread)
        threadID += 1

    # Fill the queue with contract addresses
    queueLock.acquire()
    with open('straw_man_contracts.txt', 'r') as lines:
        for line in lines:
            address = line.replace('\n', ' ').replace('\r', '').replace(' ', '')
            exists = os.path.isfile('../datasets/source_code/'+str(FOLDER)+'/'+str(address)+'.sol')
            if not exists:
                q.put(address)
    queueLock.release()

    print('Searching for '+str(q.qsize())+' contracts...\n')

    # Wait for queue to empty
    while not q.empty():
        pass

    # Notify threads it's time to exit
    exitFlag = 1

    # Wait for all threads to complete
    for t in threads:
       t.join()

    print('\nDone')
