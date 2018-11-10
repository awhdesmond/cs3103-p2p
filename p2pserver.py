# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS
import binascii
import os
import socket
import types
import selectors
import utils

from random import randrange
from apscheduler.schedulers.background import BackgroundScheduler
from libprotocol import libp2puds, libp2pdns, libp2pproto

# CONSTANTS
CLIENT_UDS_PATH = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"

DNS_IP_ADDR = "192.168.2.170"
DNS_PORT = 7494
PEER_PORT = 7495
STABILISATION_INTERVAL = 10

MAX_PACKET_SIZE = 1024
UDS_SOCKET_DISPATCH_CODE = 1
TCP_SOCKET_DISPATCH_CODE = 2

STUN_SERVER_HOST = "stun1.l.google.com"
STUN_SERVER_PORT = 19302
STUN_RESP_CODE = "0101"
STUN_REQ_CODE = "0001"
STUN_MAPPED_ADDR_CODE = '0001'

class P2PServer(object):
    
    def __init__(self, peer, ip_addr):
        self.peer      = peer
        self.ip_addr   = ip_addr
        self.selector  = selectors.DefaultSelector()
        self.scheduler = BackgroundScheduler()

        # Make sure the socket does not already exist
        try:
            if not os.path.exists(CLIENT_ROOT_PATH):
                os.makedirs(CLIENT_ROOT_PATH)
            os.unlink(CLIENT_UDS_PATH)
        except OSError:
            if os.path.exists(CLIENT_UDS_PATH):
                raise

        external_ip, external_port = self._retrieve_public_ip_stun()

        self.external_port = PEER_PORT

        # TODO: UNCOMMENT THIS WHEN NAT IS NOT SYMMETRIC
        # self.ip_addr = external_ip
        # self.external_port = external_port

        self.uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds_sock.bind(CLIENT_UDS_PATH)

        self.peer_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_sock.bind(('', PEER_PORT))

    def setup(self):
        print("P2P Server Setup")

        self.uds_sock.listen()
        self.uds_sock.setblocking(False)

        self.peer_server_sock.listen()
        self.peer_server_sock.setblocking(False)

        # data is used to store whatever arbitrary data you’d like along with the socket
        self.selector.register(self.uds_sock, selectors.EVENT_READ, data=(UDS_SOCKET_DISPATCH_CODE, None))  
        self.selector.register(self.peer_server_sock, selectors.EVENT_READ, data=(TCP_SOCKET_DISPATCH_CODE, None))

    
    def _send_p2p_tcp_packet(self, dst_ip_addr, dst_port, packet):
        # This should be blocking -- easier to reason about -- TODO: make not blocking
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # try:
        tcp_socket.connect((dst_ip_addr, int(dst_port)))
        tcp_socket.sendall(packet.encode())

        # TODO: Incomplete-Packet error handling
        res = tcp_socket.recv(MAX_PACKET_SIZE)
        res_str = res.decode("utf-8")

        try:
            tcp_socket.close()
            print("-------", res_str)
            return libp2pproto.parse_string_to_res_packet(res_str)
        except ValueError as err:
            if int(str(err)) == libp2pproto.MALFORMED_PACKET_ERROR:
                raise err

        # except socket.error as e:
        #     if e.errno == 111:
        #         print("Destination node has left the network...")
        #
        #     else:
        #         raise e.strerror


    def _handle_p2p_get_neighbors(self, new_peer_id, new_peer_ip_address, new_port):
        if not self.peer.successor["id"]:
            # I AM YOUR PREDECESSOR -- only one node in network
            self.peer.successor  ["id"]      = new_peer_id
            self.peer.successor  ["ip_addr"] = new_peer_ip_address
            self.peer.successor  ["port"]    = new_port
            self.peer.predecessor["id"]      = new_peer_id
            self.peer.predecessor["ip_addr"] = new_peer_ip_address
            self.peer.predecessor["port"]    = new_port

            print("I am the genesis node")
            self.peer.print_info()

            data = "%d %s %s %d %s %s" % (self.peer.peer_id, self.ip_addr, self.external_port,
                                          self.peer.peer_id, self.ip_addr, self.external_port)
            return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])
        
        if new_peer_id > self.peer.predecessor["id"] and new_peer_id < self.peer.peer_id:
            data = "%d %s %s %d %s %s" % (self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"],
                                          self.peer.peer_id, self.ip_addr, self.external_port)
            
            self.peer.predecessor["id"]      = new_peer_id
            self.peer.predecessor["ip_addr"] = new_peer_ip_address
            self.peer.predecessor["port"]    = new_port

            print("I am the successor of: %d" % (new_peer_id,))
            self.peer.print_info()

            return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])

        if new_peer_id < self.peer.successor["id"] and new_peer_id > self.peer.peer_id:
            data = "%d %s %s %d %s %s" % (self.peer.peer_id, self.ip_addr, self.external_port,
                                          self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])

            self.peer.successor["id"] = new_peer_id
            self.peer.successor["ip_addr"] = new_peer_ip_address
            self.peer.successor  ["port"]    = new_port

            print("I am the predecessor of: %d" % (new_peer_id,))
            self.peer.print_info()
    
            return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])


        if new_peer_id > self.peer.peer_id and new_peer_id > self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = "%d %s %s %d %s %s" % (self.peer.peer_id, self.ip_addr, self.external_port,
                                              self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])
 
                self.peer.successor["id"]      = new_peer_id
                self.peer.successor["ip_addr"] = new_peer_ip_address
                self.peer.successor["port"]    = new_port

                print("I am the predecessor of: %d" % (new_peer_id,))
                self.peer.print_info()

                return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])
            else:
                print("Recursively ask my successor")
                req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, new_peer_id, new_peer_ip_address, new_port)
                res_pkt = self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], req_packet)
                return libp2pproto.construct_res_packet(res_pkt["code"], res_pkt["msg"], res_pkt["data"])
            
        if new_peer_id < self.peer.peer_id and new_peer_id < self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = "%d %s %s %d %s %s" % (self.peer.peer_id, self.ip_addr, self.external_port,
                                              self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])

                self.peer.successor["id"]      = new_peer_id
                self.peer.successor["ip_addr"] = new_peer_ip_address
                self.peer.successor["port"]    = new_port

                print("I am the predecessor of: %d" % (new_peer_id,))
                self.peer.print_info()

                return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])
            else:
                print("Recursively ask my successor")
                req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, new_peer_id, new_peer_ip_address, new_port)
                res_pkt = self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], req_packet)
                return libp2pproto.construct_res_packet(res_pkt["code"], res_pkt["msg"], res_pkt["data"])

    def _handle_p2p_inform_predecessor(self, peer_id, ip_addr, port):
        self.peer.successor["id"]      = peer_id
        self.peer.successor["ip_addr"] = ip_addr
        self.peer.successor["port"] = port
        self.peer.print_info()
        return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [])

    def _handle_p2p_inform_successor(self, peer_id, ip_addr, port):
        self.peer.predecessor["id"]      = peer_id
        self.peer.predecessor["ip_addr"] = ip_addr
        self.peer.predecessor["port"] = port
        self.peer.print_info()
        return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [])

    def _handle_p2p_query_successor_for_predecessor(self):
        data = "%d %s %s" % (self.peer.predecessor["id"], self.peer.predecessor["ip_addr"], self.peer.predecessor["port"])
        return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])

    def _process_p2p_request(self, req):
        op_word, arguments = req["op"], req["args"]
        if op_word == libp2pproto.GET_NEIGHBOURS_OP_WORD:
            peer_id = int(arguments[libp2pproto.GET_NEIGHBOURS_PEER_ID_INDEX])
            ip_addr = arguments[libp2pproto.GET_NEIGHBOURS_PEER_IP_ADDR_INDEX]
            port = arguments[libp2pproto.GET_NEIGHBOURS_PEER_PORT_INDEX]
            return self._handle_p2p_get_neighbors(peer_id, ip_addr, port)
        
        if op_word == libp2pproto.INFORM_PREDECESSOR_OP_WORD:
            peer_id = int(arguments[libp2pproto.INFORM_PREDECESSOR_PEER_ID_INDEX])
            ip_addr = arguments[libp2pproto.INFORM_PREDECESSOR_PEER_IP_ADDR_INDEX]
            port = arguments[libp2pproto.INFORM_PREDECESSOR_PEER_PORT_INDEX]
            return self._handle_p2p_inform_predecessor(peer_id, ip_addr, port)

        if op_word == libp2pproto.INFORM_SUCCESSOR_OP_WORD:
            peer_id = int(arguments[libp2pproto.INFORM_SUCCESSOR_PEER_ID_INDEX])
            ip_addr = arguments[libp2pproto.INFORM_SUCCESSOR_PEER_IP_ADDR_INDEX]
            port = arguments[libp2pproto.INFORM_SUCCESSOR_PEER_PORT_INDEX]

            return self._handle_p2p_inform_successor(peer_id, ip_addr, port)

        if op_word == libp2pproto.QUERY_SUCCESSOR_FOR_PREDECESSOR_OP_WORD:
            return self._handle_p2p_query_successor_for_predecessor()

        return libp2pproto.construct_unknown_res()

    def _stabilisation(self):
        if not self.peer.successor["id"]:
            print("Genesis node. No Stabilisation needed.")
            return

        stab_packet = libp2pproto.construct_req_packet(libp2pproto.QUERY_SUCCESSOR_FOR_PREDECESSOR_OP_WORD)
        res_packet = self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], stab_packet)
        
        if res_packet is not None:
            data = res_packet["data"][0].split(" ")
            successor_predecessor_peer_id = int(data[0])

            if successor_predecessor_peer_id != self.peer.peer_id:
                # Oh, you have a new predecessor, let me add that as my successor
                self.peer.successor["id"]        = int(data[0])
                self.peer.successor["ip_addr"]   = data[1]
                self.peer.successor["port"] = data[2]
                inform_packet = libp2pproto.construct_req_packet(libp2pproto.INFORM_SUCCESSOR_OP_WORD,
                                                                 self.peer.peer_id, self.ip_addr, self.external_port)
                self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)
            else:
                print("There is no change")

    def _handle_p2p_connection(self, key):
        socket = key.fileobj
        data = key.data[1]

        recv_data = socket.recv(MAX_PACKET_SIZE)  # Should be ready to read
        if recv_data:
            data.req_str += recv_data.decode("utf-8")
            try:
                req = libp2pproto.parse_string_to_req_packet(data.req_str)
                data.res_str = self._process_p2p_request(req)
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    data.res_str = libp2puds.construct_malformed_res()

   
    def _enter_p2p_network(self, peer_ip_port):
        if len(peer_ip_port) == 0:
            print("First node has no peers")
        else:
            peer_ip_addr, peer_port = peer_ip_port[randrange(len(peer_ip_port))]
            print("Joining P2P Network...")
            print("Chosen peer_ip addr: ", peer_ip_addr, "\tport: ", peer_port)

            req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, self.peer.peer_id,
                                                          self.ip_addr, self.external_port)
            res_packet = self._send_p2p_tcp_packet(peer_ip_addr, peer_port, req_packet)
            data = res_packet["data"][0].split(" ")
            self.peer.predecessor["id"]      = int(data[0])
            self.peer.predecessor["ip_addr"] = data[1]
            self.peer.predecessor["port"] = data[2]

            self.peer.successor["id"]        = int(data[3])
            self.peer.successor["ip_addr"]   = data[4]
            self.peer.successor["port"]   = data[5]

            # self.peer.next_successor["id"]   = int(data[4])
            # self.peer.next_successor["ip_addr"] = data[5]
            self.peer.print_info()

            print("Informing my predecessor to add me as its successor")
            inform_packet = libp2pproto.construct_req_packet(libp2pproto.INFORM_PREDECESSOR_OP_WORD,
                                                             self.peer.peer_id, self.ip_addr, self.external_port)
            self._send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"], inform_packet)

            print("Informing my successor to add me as its predecessor")
            inform_packet = libp2pproto.construct_req_packet(libp2pproto.INFORM_SUCCESSOR_OP_WORD,
                                                             self.peer.peer_id, self.ip_addr, self.external_port)
            self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor["port"], inform_packet)

        self.scheduler.add_job(self._stabilisation, 'interval', seconds=STABILISATION_INTERVAL)
        self.scheduler.start()


    def _retrieve_peer_ip_port(self):
        # TODO: handle case if DNS is not up.
        dns_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dns_server_sock.connect((DNS_IP_ADDR, DNS_PORT))

        message = libp2pdns.construct_req_packet(libp2pdns.JOIN_REQ_OP_WORD, self.peer.peer_id, self.ip_addr, self.external_port)

        dns_server_sock.sendall(message.encode())
        res = dns_server_sock.recv(MAX_PACKET_SIZE)
        try:
            res_str = res.decode("utf-8")
            peers_ip_addr_port_list = libp2pdns.parse_message_to_peer_list(res_str)
            dns_server_sock.close()
            return peers_ip_addr_port_list

        except ValueError as err:
            if int(str(err)) == libp2puds.INCOMPLETE_PACKET_ERROR:
                return [] #TODO: should re-attempt to get info again
          
    def _process_uds_request(self, req):
        op_word, arguments = req["op"], req["args"]
        if op_word == libp2puds.INIT_PEER_TABLE_OP_WORD:
            peer_ip_port = self._retrieve_peer_ip_port()
            self._enter_p2p_network(peer_ip_port)
            return libp2puds.construct_empty_ok_res()
        else:
            return libp2puds.construct_unknown_res()


    def _retrieve_public_ip_stun(self):
        # Blocking.
        stun_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stun_socket.settimeout(2)
        stun_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        stun_socket.bind(('', PEER_PORT))

        send_data = ""
        str_len = "0000"
        tranid = utils.gen_tran_id()
        str_data = ''.join([STUN_REQ_CODE, str_len, tranid, send_data])
        data = binascii.a2b_hex(str_data)

        stun_socket.sendto(data, (STUN_SERVER_HOST, STUN_SERVER_PORT))

        extenal_ip = ''
        external_port = ''
        buf = stun_socket.recv(MAX_PACKET_SIZE)
        stun_socket.close()

        msgtype = binascii.b2a_hex(buf[0:2]).decode()
        tranid_ret = binascii.b2a_hex(buf[4:20]).decode().upper()

        if msgtype == STUN_RESP_CODE and tranid_ret == tranid:
            len_message = int(binascii.b2a_hex(buf[2:4]), 16)
            base = 20

            while len_message:
                attr_type = binascii.b2a_hex(buf[base:(base + 2)]).decode()
                attr_len = int(binascii.b2a_hex(buf[(base + 2):(base + 4)]), 16)
                if attr_type == STUN_MAPPED_ADDR_CODE:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    extenal_ip = ip
                    external_port = port
                base = base + 4 + attr_len
                len_message -= (4 + attr_len)
        print("External IP: ", extenal_ip, "\t\tExternal Port: ", external_port)
        return extenal_ip, external_port


    def _handle_uds_connection(self, key):
        socket = key.fileobj
        data = key.data[1]

        recv_data = socket.recv(1024)  # Should be ready to read
        if recv_data:
            data.req_str += recv_data.decode("utf-8")
            try:
                req = libp2puds.parse_string_to_req_packet(data.req_str)
                data.res_str = self._process_uds_request(req)
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    data.res_str = libp2puds.construct_malformed_res()

    def _handle_connection(self, key, mask):
        if mask & selectors.EVENT_READ:
            dispatch_code = key.data[0]

            if dispatch_code == UDS_SOCKET_DISPATCH_CODE:
                self._handle_uds_connection(key)
            else:
                self._handle_p2p_connection(key)

        if mask & selectors.EVENT_WRITE:
            socket = key.fileobj
            data = key.data[1]
            if data.res_str:
                socket.sendall(data.res_str.encode())  # Should be ready to write

            self.selector.unregister(socket)
            socket.close()


    def _accept_socket(self, socket, dispatch_code):
        conn, addr = socket.accept()
        conn.setblocking(False)

        data = (dispatch_code, types.SimpleNamespace(addr=addr, req_str='', res_str=''))
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.selector.register(conn, events, data=data)


    def run(self):
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data[1] is None:
                    self._accept_socket(key.fileobj, key.data[0])  # key.fileobj is the socket object
                else:
                    self._handle_connection(key, mask)
