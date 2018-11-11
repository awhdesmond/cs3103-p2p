# peer.py
# -------
# Stores peer info like peer id, successor, predecessor

import sys
import os
import utils

class Peer(object):

    def __init__(self, ip_addr, external_port):
        self.peer_id       = utils.generate_peerid()
        self.ip_addr       = ip_addr
        self.external_port = external_port
        self.successor     = {"id": None, "ip_addr": None, "port": None}
        self.predecessor   = {"id": None, "ip_addr": None, "port": None}

        # self.next_successor = {"id": None, "ip_addr": None}
        print("My peer_id is: %d" % (self.peer_id,))

    def print_info(self):
        print("Peer Information:")
        print("Peer Id:", self.peer_id)
        
        print("Successor id:", self.successor["id"])
        print("Successor ip address:", self.successor["ip_addr"])
        print("Successor port:", self.successor["port"])
        
        print("Predecessor id:", self.predecessor["id"])
        print("Predecessor ip address:", self.predecessor["ip_addr"])
        print("Predecessor port:", self.predecessor["port"])