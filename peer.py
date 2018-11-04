# peer.py
# -------
# Stores peer info like peer id, successor, predecessor

import sys
import os
import utils

class Peer(object):

    def __init__(self):
        self.peer_id        = utils.generate_peerid()
        self.successor      = None # {id, ip_addr}
        self.next_successor = None # {id, ip_addr}
        self.predecessor    = None # {id, ip_addr}


