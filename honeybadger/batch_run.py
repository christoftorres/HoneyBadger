#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import shlex
import os
import Queue
import threading
import multiprocessing

exitFlag = 0
BYTECODE = True

class honeybadgerThread(threading.Thread):
   def __init__(self, threadID, queue):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.queue = queue
   def run(self):
      runHoneybadger(self.queue)

def runHoneybadger(queue):
    while not exitFlag:
        queueLock.acquire()
        if not queue.empty():
            contract = queue.get()
            queueLock.release()
            print('Running Honeybadger on contract: '+str(contract).split('/')[-1])
            cmd = ''
            if BYTECODE:
                cmd = 'python honeybadger.py -s '+str(contract)+' -b -j'
            else:
                cmd = 'python honeybadger.py -s '+str(contract)+' -j'
            subprocess.call(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print('Running contract '+str(contract).split('/')[-1])+' finished.'
        else:
            queueLock.release()

if __name__ == "__main__":

    queueLock = threading.Lock()
    queue = Queue.Queue()

    # Create new threads
    threads = []
    threadID = 1
    #for i in range(multiprocessing.cpu_count()):
    for i in range(1):
        thread = honeybadgerThread(threadID, queue)
        thread.start()
        threads.append(thread)
        threadID += 1

    # Fill the queue with contracts
    queueLock.acquire()
    for file in os.listdir(os.path.join("..", "contracts")):
        if BYTECODE and file.endswith(".bin") or not BYTECODE and file.endswith(".sol"):
            #print(os.path.join(os.path.join("..", "contracts"), file))
            queue.put(os.path.join(os.path.join("..", "contracts"), file))
    queueLock.release()

    print('Verifying: '+str(queue.qsize())+'\n')

    # Wait for queue to empty
    while not queue.empty():
        pass

    # Notify threads it's time to exit
    exitFlag = 1

    # Wait for all threads to complete
    for t in threads:
       t.join()

    print('\nDone')
