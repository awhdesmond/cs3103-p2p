# peer.py
# -------
# Stores peer info like peer id, successor, predecessor

import sys
import os
import utils

class Peer(object):

    def __init__(self):
        self.peer_id        = utils.generate_peerid()
        self.successor      = {"id": None, "ip_addr": None} 
        self.predecessor    = {"id": None, "ip_addr": None}
        print("My peer_id is: %d" % (self.peer_id,))

    def print_info(self):
        print("Peer Information:")
        print("Peer Id:", self.peer_id)
        print("Successor id:", self.successor["id"])
        print("Successor ip address:", self.successor["ip_addr"])
        print("Predecessor id:", self.predecessor["id"])
        print("Predecessor ip address:", self.predecessor["ip_addr"])