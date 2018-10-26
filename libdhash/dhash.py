# dhash.py
# ------------
# DHT that relies on Chord lookup service

from libchord import libchord

class Dhash(object):

    def __init__(self, peerid):
        self.peerid = peerid
        self.chord  = libchord.ChordService(peerid)

    def put(self, key, data):
        # 1. Chord will look for correct node to store
        # 2. Store the data in that node 
        # (the target node will then duplicate the data in successor and predecessor)
        
        # target_node_id = self.chord.lookup(key)


        pass

    def get(self, key):
        # 1. Chord will look for correct node to retrieve
        # 2. Retrieve data from the target node
        pass

    def handle_put_request(self, key, data):
        # 1. Store the data in ownself
        # 2. Send put request to own successor and predecessor
        pass

    def handle_get_request(self, key):
        # 1. Retrieve the data. 
        # 1.1 If data not available then return NOT FOUND
        pass
