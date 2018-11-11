# libchord.py
# ------------
# Provide functions that implement the Chord 
# protocol lookup service
from random import randrange
from apscheduler.schedulers.background import BackgroundScheduler

from libprotocol import libp2pproto
from libprotocol.libp2pproto import P2PRequestPacket, P2PResponsePacket, send_p2p_tcp_packet

STABILISATION_INTERVAL = 10

class Chord(object):

    def __init__(self, peer):
        self.peer = peer
        self.scheduler = BackgroundScheduler()
    
    def enter_p2p_network(self, peer_ip_port):
        if len(peer_ip_port) == 0:
            # First node has no peers
            pass
        else:
            peer_ip_addr, peer_port = peer_ip_port[randrange(len(peer_ip_port))]
            print("Joining P2P Network...")
            print("Chosen peer_ip addr: ", peer_ip_addr, "\tport: ", peer_port)

            req_packet = P2PRequestPacket(libp2pproto.GET_NEIGHBOURS_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
            res_packet = send_p2p_tcp_packet(peer_ip_addr, peer_port, req_packet)
            data = res_packet.data[0].split(" ")
            self.peer.predecessor["id"]      = int(data[0])
            self.peer.predecessor["ip_addr"] = data[1]
            self.peer.predecessor["port"]    = data[2]

            self.peer.successor["id"]      = int(data[3])
            self.peer.successor["ip_addr"] = data[4]
            self.peer.successor["port"]    = data[5]

            print("Informing my predecessor to add me as its successor")
            inform_packet = P2PRequestPacket(libp2pproto.INFORM_PREDECESSOR_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
            send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"], inform_packet)

            print("Informing my successor to add me as its predecessor")
            inform_packet = P2PRequestPacket(libp2pproto.INFORM_SUCCESSOR_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
            send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)

        self.scheduler.add_job(self._stabilisation, 'interval', seconds=STABILISATION_INTERVAL)
        self.scheduler.start()
        return

    
    def _stabilisation(self):
        if not self.peer.successor["id"]:
            #Genesis node. No Stabilisation needed
            return

        stab_packet = P2PRequestPacket(libp2pproto.QUERY_SUCCESSOR_FOR_PREDECESSOR_OP_WORD, [])
        res_packet = send_p2p_tcp_packet(self.peer.successor["ip_addr"],self.peer.successor["port"], stab_packet)
        
        if res_packet is not None:
            data = res_packet.data[0].split(" ")
            successor_predecessor_peer_id = int(data[0])

            if successor_predecessor_peer_id != self.peer.peer_id:
                # Oh, you have a new predecessor, let me add that as my successor
                self.peer.successor["id"]        = int(data[0])
                self.peer.successor["ip_addr"]   = data[1]
                self.peer.successor["port"] = data[2]
                inform_packet = P2PRequestPacket(libp2pproto.INFORM_SUCCESSOR_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
                send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)
            else:
                # There is no change
                pass


    def get_neighbours(self, new_peer_id, new_peer_ip_address, new_peer_port):
        if not self.peer.successor["id"]:
            # I AM YOUR PREDECESSOR -- only one node in network
            self.peer.successor  ["id"]      = new_peer_id
            self.peer.successor  ["ip_addr"] = new_peer_ip_address
            self.peer.successor  ["port"]    = new_peer_port
            self.peer.predecessor["id"]      = new_peer_id
            self.peer.predecessor["ip_addr"] = new_peer_ip_address
            self.peer.predecessor["port"]    = new_peer_port

            data = "%d %s %d %d %s %d" % (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                          self.peer.peer_id, self.peer.ip_addr, self.peer.external_port)
            return data            
        
        if new_peer_id > self.peer.predecessor["id"] and new_peer_id < self.peer.peer_id:
            data = "%d %s %d %d %s %d" % (self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"],
                                          self.peer.peer_id, self.peer.ip_addr, self.peer.external_port)
            
            self.peer.predecessor["id"]      = new_peer_id
            self.peer.predecessor["ip_addr"] = new_peer_ip_address
            self.peer.predecessor["port"]    = new_peer_port

            return data

        if new_peer_id < self.peer.successor["id"] and new_peer_id > self.peer.peer_id:
            data = "%d %s %d %d %s %d" % (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                          self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])

            self.peer.successor["id"] = new_peer_id
            self.peer.successor["ip_addr"] = new_peer_ip_address
            self.peer.successor  ["port"]    = new_peer_port
    
            return data

        if new_peer_id > self.peer.peer_id and new_peer_id > self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = "%d %s %d %d %s %d" % (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                              self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])
 
                self.peer.successor["id"]      = new_peer_id
                self.peer.successor["ip_addr"] = new_peer_ip_address
                self.peer.successor["port"]    = new_peer_port

                return data
            else:
                # print("Recursively ask my successor")
                req_packet = P2PRequestPacket(libp2pproto.GET_NEIGHBOURS_OP_WORD, [new_peer_id, new_peer_ip_address, new_peer_port])
                res_pkt = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], req_packet)
                return res_pkt.data

        if new_peer_id < self.peer.peer_id and new_peer_id < self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = "%d %s %d %d %s %d" % (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                              self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])

                self.peer.successor["id"]      = new_peer_id
                self.peer.successor["ip_addr"] = new_peer_ip_address
                self.peer.successor["port"]    = new_peer_port

                return data
            else:
                # print("Recursively ask my successor")
                req_packet = P2PRequestPacket(libp2pproto.GET_NEIGHBOURS_OP_WORD, [new_peer_id, new_peer_ip_address, new_peer_port])
                res_pkt = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], req_packet)
                return res_pkt.data

    