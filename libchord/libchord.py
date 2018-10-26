# libchord.py
# ------------
# Provide functions that implement the Chord 
# protocol lookup service


class ChordService(object):

    def __init__(self, peerid):
        self.peerid      = peerid
        self.successor   = None
        self.predecessor = None
    
    def lookup(self, key):
        """ lookup(key) -> node_id
        """
        pass

    def node_join(self):
        pass
    
    def run_stablisation(self):
        pass


