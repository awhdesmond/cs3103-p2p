# libchord.py
# ------------
# Provide functions that implement the Chord 
# protocol lookup service
from random import randrange
from apscheduler.schedulers.background import BackgroundScheduler
import socket

from libprotocol import libp2pproto, libp2pdns
from libprotocol.libp2pproto import P2PRequestPacket, P2PResponsePacket, send_p2p_tcp_packet

STABILISATION_INTERVAL = 10

class Chord(object):

    def __init__(self, peer):
        self.peer = peer
        self.scheduler = BackgroundScheduler()

    def enter_p2p_network(self, peers_ip_port_list):
        if len(peers_ip_port_list) == 0:
            # First node has no peers
            pass
        else:
            rand_index = randrange(len(peers_ip_port_list))
            peer_id, peer_ip_addr, peer_port = peers_ip_port_list[rand_index]
            print("Joining P2P Network...")
            print("Chosen peer_ip addr: ", peer_ip_addr, "\tport: ", peer_port)

            req_packet = P2PRequestPacket(libp2pproto.GET_NEIGHBOURS_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
            try:
                res_packet = send_p2p_tcp_packet(peer_ip_addr, peer_port, req_packet)
                data = res_packet.data[0].split(" ")
                self.peer.predecessor["id"]      = int(data[0])
                self.peer.predecessor["ip_addr"] = data[1]
                self.peer.predecessor["port"]    = int(data[2])

                self.peer.successor["id"]      = int(data[3])
                self.peer.successor["ip_addr"] = data[4]
                self.peer.successor["port"]    = int(data[5])

                # handle case where there are at least 3 nodes in the network
                if int(data[6]) != -1:
                    self.peer.next_successor["id"] = int(data[6])
                    self.peer.next_successor["ip_addr"] = data[7]
                    self.peer.next_successor["port"] = int(data[8])

                    print("Informing my predecessor's predecessor to add me as its next successor")
                    inform_packet = P2PRequestPacket(libp2pproto.INFORM_PREDECESSOR_PREDECESSOR_OP_WORD,
                                                     [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
                    send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"], inform_packet)

                print("Informing my predecessor to add me as its successor and my successor as its next successor")
                inform_packet = P2PRequestPacket(libp2pproto.INFORM_PREDECESSOR_OP_WORD,
                                                 [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                                  self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"]])

                send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"], inform_packet)

                print("Informing my successor to add me as its predecessor")
                inform_packet = P2PRequestPacket(libp2pproto.INFORM_SUCCESSOR_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
                send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)

            # Handle when node has left the network
            except socket.error as e:
                if e.errno == 111:
                    libp2pdns.send_dns_remove_entry(peer_id)
                    del peers_ip_port_list[rand_index]
                    self.enter_p2p_network(peers_ip_port_list)
                else:
                    raise e.strerror

        self.scheduler.add_job(self._stabilisation, 'interval', seconds=STABILISATION_INTERVAL)
        self.scheduler.start()
        return


    def _stabilisation(self):
        if not self.peer.successor["id"]:
            #Genesis node. No Stabilisation needed
            return
        print("---------------STABLISATION---------------")
        self.peer.print_info()
        print()

        stab_packet = P2PRequestPacket(libp2pproto.QUERY_SUCCESSOR_FOR_NEIGHBOURS_OP_WORD, [])
        try:
            res_packet = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], stab_packet)

            if res_packet is not None:
                data = res_packet.data[0].split(" ")
                successor_predecessor_peer_id = int(data[0])
                successor_successor_peer_id = int(data[3])

                if successor_predecessor_peer_id != self.peer.peer_id:
                    # Oh, you have a new predecessor, let me add that as my successor
                    self.peer.next_successor["id"] = self.peer.successor["id"]
                    self.peer.next_successor["ip_addr"] = self.peer.successor["ip_addr"]
                    self.peer.next_successor["port"] = self.peer.successor["port"]
                    self.peer.successor["id"]        = int(data[0])
                    self.peer.successor["ip_addr"]   = data[1]
                    self.peer.successor["port"] = int(data[2])
                    # Inform successor of new predecessor
                    inform_packet = P2PRequestPacket(libp2pproto.INFORM_SUCCESSOR_OP_WORD, [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
                    send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)

                    # Inform predecessor of new next successor
                    inform_packet = P2PRequestPacket(libp2pproto.INFORM_PREDECESSOR_OP_WORD,
                                                     [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                                      self.peer.successor["id"], self.peer.successor["ip_addr"],
                                                      self.peer.successor["port"]])
                    send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"],
                                        inform_packet)

                # Ensure that there's 3 nodes in the network.
                # If there's 2 node, then the successor's successor will be the current node
                elif successor_successor_peer_id != self.peer.peer_id:
                    if successor_successor_peer_id != self.peer.next_successor["id"]:
                        # You have a new successor, let me add that as my next successor
                        self.peer.next_successor["id"] = int(data[3])
                        self.peer.next_successor["ip_addr"] = data[4]
                        self.peer.next_successor["port"] = int(data[5])

                else:
                    self.peer.next_successor["id"] = None
                    self.peer.next_successor["ip_addr"] = None
                    self.peer.next_successor["port"] = None


        # Handle when node leaves the network
        except socket.error as e:
            if e.errno == 111:
                print("Destination node has left the network...")
                if self.peer.next_successor["id"]:
                    self.peer.successor["id"] = self.peer.next_successor["id"]
                    self.peer.successor["ip_addr"] = self.peer.next_successor["ip_addr"]
                    self.peer.successor["port"] = self.peer.next_successor["port"]

                    self.peer.next_successor["id"] = None
                    self.peer.next_successor["ip_addr"] = None
                    self.peer.next_successor["port"] = None

                    print("Informing my predecessor to add me as its successor and my successor as its next successor")
                    inform_packet = P2PRequestPacket(libp2pproto.INFORM_PREDECESSOR_OP_WORD,
                                                     [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                                      self.peer.successor["id"], self.peer.successor["ip_addr"],
                                                      self.peer.successor["port"]])

                    send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"], inform_packet)

                    print("Informing my successor to add me as its predecessor")
                    inform_packet = P2PRequestPacket(libp2pproto.INFORM_SUCCESSOR_OP_WORD,
                                                     [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port])
                    send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)

                    self._stabilisation()
                else:
                    self.peer.predecessor["id"] = None
                    self.peer.predecessor["ip_addr"] = None
                    self.peer.predecessor["port"] = None

                    self.peer.successor["id"] = None
                    self.peer.successor["ip_addr"] = None
                    self.peer.successor["port"] = None
            else:
                raise e.strerror




    def get_neighbours(self, new_peer_id, new_peer_ip_address, new_peer_port):
        if not self.peer.successor["id"]:
            # I AM YOUR PREDECESSOR -- only one node in network
            data = self._generate_data_second_node()
            self._add_second_node(new_peer_id, new_peer_ip_address, new_peer_port)

            return data

        if self.peer.predecessor["id"] < new_peer_id < self.peer.peer_id:
            data = self._generate_data_new_predecessor()
            self._add_node_to_predecessor(new_peer_id, new_peer_ip_address, new_peer_port)

            return data

        if self.peer.peer_id < new_peer_id < self.peer.successor["id"]:
            data = self._generate_data_new_successor()
            self._add_node_to_successor(new_peer_id, new_peer_ip_address, new_peer_port)

            return data

        if new_peer_id > self.peer.peer_id and new_peer_id > self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = self._generate_data_new_successor()
                self._add_node_to_successor(new_peer_id, new_peer_ip_address, new_peer_port)

                return data
            else:
                # print("Recursively ask my successor")
                req_packet = P2PRequestPacket(libp2pproto.GET_NEIGHBOURS_OP_WORD, [new_peer_id, new_peer_ip_address, new_peer_port])
                res_pkt = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], req_packet)
                return res_pkt.data[0]

        if new_peer_id < self.peer.peer_id and new_peer_id < self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = self._generate_data_new_successor()
                self._add_node_to_successor(new_peer_id, new_peer_ip_address, new_peer_port)

                return data
            else:
                # print("Recursively ask my successor")
                req_packet = P2PRequestPacket(libp2pproto.GET_NEIGHBOURS_OP_WORD, [new_peer_id, new_peer_ip_address, new_peer_port])
                res_pkt = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], req_packet)
                return res_pkt.data[0]


    def _generate_data_second_node(self):
        # When only 2 nodes in the network, there will be no 'next successor' node
        data = "%d %s %d %d %s %d %d %s %d" % \
               (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                -1, "", -1)
        return data

    def _add_second_node(self, new_peer_id, new_peer_ip_address, new_peer_port):
        self.peer.successor["id"] = new_peer_id
        self.peer.successor["ip_addr"] = new_peer_ip_address
        self.peer.successor["port"] = new_peer_port
        self.peer.predecessor["id"] = new_peer_id
        self.peer.predecessor["ip_addr"] = new_peer_ip_address
        self.peer.predecessor["port"] = new_peer_port


    def _generate_data_new_predecessor(self):
        data = "%d %s %d %d %s %d %d %s %d" % \
               (self.peer.predecessor["id"], self.peer.predecessor["ip_addr"], self.peer.predecessor["port"],
                self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])
        return data

    def _add_node_to_predecessor(self, new_peer_id, new_peer_ip_address, new_peer_port):

        self.peer.predecessor["id"] = new_peer_id
        self.peer.predecessor["ip_addr"] = new_peer_ip_address
        self.peer.predecessor["port"] = new_peer_port

        if self.peer.next_successor["id"] is None:
            self.peer.next_successor["id"] = new_peer_id
            self.peer.next_successor["ip_addr"] = new_peer_ip_address
            self.peer.next_successor["port"] = new_peer_port


    def _generate_data_new_successor(self):
        if self.peer.next_successor["id"] is None:
            data = "%d %s %d %d %s %d %d %s %d" % \
                   (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                    self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"],
                    self.peer.peer_id, self.peer.ip_addr, self.peer.external_port)
        else:
            data = "%d %s %d %d %s %d %d %s %d" % \
                   (self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                    self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"],
                    self.peer.next_successor["id"], self.peer.next_successor["ip_addr"], self.peer.next_successor["port"])
        return data

    def _add_node_to_successor(self, new_peer_id, new_peer_ip_address, new_peer_port):
        self.peer.next_successor["id"] = self.peer.successor["id"]
        self.peer.next_successor["ip_addr"] = self.peer.successor["ip_addr"]
        self.peer.next_successor["port"] = self.peer.successor["port"]

        self.peer.successor["id"] = new_peer_id
        self.peer.successor["ip_addr"] = new_peer_ip_address
        self.peer.successor["port"] = new_peer_port
