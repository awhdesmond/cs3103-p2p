# p2pclient.py
# ------------
# The P2P main program. Calls P2P server in a daemonic thread? 
# Wraps around the P2P client

import sys
import os
import socket
import time
import threading

from peer import Peer
from p2pserver import P2PServer
from p2pclient import P2PClient

# CONSTANTS
CLIENT_ROOT_PATH = "./p2pvar/"

class P2PMain(object):

    def __init__(self, ip_addr):
        # Create base directory to store files and chunks
        if not os.path.exists(CLIENT_ROOT_PATH):
            os.makedirs(CLIENT_ROOT_PATH)

        self.p2p_server = P2PServer(ip_addr)
        self.p2p_client = P2PClient()

    def _setup(self):
        t = threading.Thread(target=self.p2p_server.run)
        t.start()        
        
        time.sleep(2)
        
        self.p2p_client.setup()

    def run(self):
        self._setup()
        self.p2p_client.run()
        
if __name__ == "__main__":
    ip_addr = sys.argv[1]
    p2pmain = P2PMain(ip_addr)
    p2pmain.run()
