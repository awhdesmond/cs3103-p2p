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

