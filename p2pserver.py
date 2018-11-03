# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS

import os
import socket
import types
import p2pdns
import selectors
import utils
from random import randrange
from libprotocol import libp2puds, libp2pdns, libp2pproto

# CONSTANTS
CLIENT_UDS_PATH = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"

PEER_PORT = 8818

UDS_SOCKET_DISPATCH_CODE = 1
TCP_SOCKET_DISPATCH_CODE = 2

MAX_MSG_LEN = 1024
NODE_ID_INDEX = 0
NODE_IP_ADDR_INDEX = 1


class P2PServer(object):

    def __init__(self, peer, ip_addr):
        self.peer     = peer
        self.ip_addr  = ip_addr
        self.selector = selectors.DefaultSelector()

        # Make sure the socket does not already exist
        try:
            if not os.path.exists(CLIENT_ROOT_PATH):
                os.makedirs(CLIENT_ROOT_PATH)
            os.unlink(CLIENT_UDS_PATH)
        except OSError:
            if os.path.exists(CLIENT_UDS_PATH):
                raise

        self.uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds_sock.bind(CLIENT_UDS_PATH)

        self.peer_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_sock.bind((self.ip_addr, PEER_PORT))

    def setup(self):
        print("P2P Server Setup")

        self.uds_sock.listen()
        self.uds_sock.setblocking(False)

        self.peer_server_sock.listen()
        self.peer_server_sock.setblocking(False)

        # data is used to store whatever arbitrary data you’d like along with the socket
        self.selector.register(self.uds_sock, selectors.EVENT_READ, data=(UDS_SOCKET_DISPATCH_CODE, None))  
        self.selector.register(self.peer_server_sock, selectors.EVENT_READ, data=(TCP_SOCKET_DISPATCH_CODE, None))

        peer_ip_address = self._retrieve_peer_ip_address()
        self._enter_p2p_network(peer_ip_address)


    def _retrieve_peer_ip_address(self):
        # TODO: handle case if DNS is not up.
        dns_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dns_server_sock.connect((p2pdns.HOST, p2pdns.PORT))

        message = libp2pdns.construct_req_packet(libp2pdns.JOIN_REQ_OP_WORD, self.peer.peer_id, self.ip_addr)
        sent = dns_server_sock.sendall(message.encode())
        if sent == 0:
            raise RuntimeError("socket connection broken")

        res = dns_server_sock.recv(MAX_MSG_LEN)
        try:
            res_str = res.decode("utf-8")
            peers_ip_addr_list = libp2pdns.parse_message_to_peer_list(res_str)
            dns_server_sock.close()
            return peers_ip_addr_list
        
        except ValueError as err:
            if int(str(err)) == libp2puds.INCOMPLETE_PACKET_ERROR:
                return [] #TODO: should re-attempt to get info again


    def _send_p2p_tcp_packet(self, dst_ip_addr, packet):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect((dst_ip_addr, PEER_PORT))
        tcp_socket.sendall(packet.encode())
        tcp_socket.close()

    def _enter_p2p_network(self, peer_ip_addr_list):
        if len(peer_ip_addr_list) == 0:
            print("First node has no peers")
        else:
            chosen_peer_ip_addr = peer_ip_addr_list[randrange(len(peer_ip_addr_list))]
            print("Chosen peer ip addr: ", chosen_peer_ip_addr)
            req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, [self.peer.peer_id, self.ip_addr])
            self._send_p2p_tcp_packet(chosen_peer_ip_addr, req_packet)


    def _handle_get_neighbours(self, arguments):
        original_peer_id = int(arguments[libp2pproto.GET_NEIGHBOURS_PEER_ID_INDEX])
        original_ip_addr = arguments[libp2pproto.GET_NEIGHBOURS_PEER_IP_ADDR_INDEX]
        
        predecessor_id = self.predecessor_node[NODE_ID_INDEX]
        predecessor_ip_addr = self.predecessor_node[NODE_IP_ADDR_INDEX]
        
        successor_id = self.successor_node[NODE_ID_INDEX]
        successor_ip_addr = self.successor_node[NODE_IP_ADDR_INDEX]
        
        next_successor_id = self.next_successor_node[NODE_ID_INDEX]
        next_successor_ip_addr = self.next_successor_node[NODE_IP_ADDR_INDEX]

        if self.peer.successor:
            if self.peer.peer_id < original_peer_id < self.peer.successor["id"] \
                    or self.peer.successor["id"] < self.peer.peer_id < original_peer_id \
                    or original_peer_id < self.peer.successor["id"] < self.peer.peer_id:

                if not self.peer.next_successor["id"]:
                    next_successor_id = self.peer.peer_id
                    next_successor_ip_addr = self.ip_addr

                # Update incoming node to the network
                # self._send_p2p_tcp_packet(original_ip_addr, libp2pproto.RET_NEIGHBOURS_OP_WORD, [self.peerid, self.ip_addr,
                #                                                                              successor_id, successor_ip_addr,
                #                                                                              next_successor_id, next_successor_ip_addr])
                # # Update current node
                # self.next_successor_node = self.successor_node
                # self.successor_node = (original_peer_id, original_ip_addr)

                # # Update predecessor's next successor
                # self._send_p2p_tcp_packet(predecessor_ip_addr, libp2pproto.UPDATE_NEXT_SUCCESSOR, [original_peer_id, original_ip_addr])

                # # Update successor's predecessor
                # self._send_p2p_tcp_packet(successor_ip_addr, libp2pproto.UPDATE_PREDECESSOR, [original_peer_id, original_ip_addr])

        else:
            # case where its only the genesis node in the network
            self.successor_node = (original_peer_id, original_ip_addr)
            self.predecessor_node = (original_peer_id, original_ip_addr)
            # self._send_p2p_tcp_packet(original_ip_addr, libp2pproto.RET_NEIGHBOURS_OP_WORD, [self.peer.peer_id, self.ip_addr, self.peer.peer_id, self.ip_addr, None, None])

            
    def _handle_update_all_neighbours(self, args):
        self.predecessor_node = (utils.get_arguments(args, libp2pproto.RetNeighboursArgs.PREDECESSOR_ID.value, True),
                                 utils.get_arguments(args, libp2pproto.RetNeighboursArgs.PREDECESSOR_IP_ADDR.value))
        self.successor_node = (utils.get_arguments(args, libp2pproto.RetNeighboursArgs.SUCCESSOR_ID.value, True),
                               utils.get_arguments(args, libp2pproto.RetNeighboursArgs.SUCCESSOR_IP_ADDR.value))
        self.next_successor_node = (utils.get_arguments(args, libp2pproto.RetNeighboursArgs.NEXT_SUCCESSOR_ID.value, True),
                                    utils.get_arguments(args, libp2pproto.RetNeighboursArgs.NEXT_SUCCESSOR_IP_ADDR.value))

        print("Successor node id: ", self.successor_node[0], " Successor node ip addr: ", self.successor_node[1])
        print("Next successor node id: ", self.next_successor_node[0], " Next successor node ip addr: ", self.next_successor_node[1])
        print("Predecessor node id: ", self.predecessor_node[0], "Predecessor node ip addr: ", self.predecessor_node[1])

    def _handle_update_predecessor(self, args):
        self.predecessor_node = (utils.get_arguments(args, libp2pproto.UpdatePredecessorArgs.PREDECESSOR_ID.value, True),
                                 utils.get_arguments(args, libp2pproto.UpdatePredecessorArgs.PREDECESSOR_IP_ADDR.value))


    def _handle_update_next_successor(self, arguments):
        self.next_successor_node = (utils.get_arguments(arguments, libp2pproto.UpdateNextSuccessorArgs.NEXT_SUCCESSOR_ID.value, True),
                                    utils.get_arguments(arguments, libp2pproto.UpdateNextSuccessorArgs.NEXT_SUCCESSOR_IP_ADDR.value))


    def _process_p2p_request(self, req):
        op_word, arguments = req["op"], req["args"]
        if op_word == libp2pproto.GET_NEIGHBOURS_OP_WORD:
            return self._handle_get_neighbours(arguments)

        elif op_word == libp2pproto.RET_NEIGHBOURS_OP_WORD:
            return self._handle_update_all_neighbours(arguments)

        elif op_word == libp2pproto.UPDATE_PREDECESSOR:
            return self._handle_update_predecessor(arguments)

        elif op_word == libp2pproto.UPDATE_NEXT_SUCCESSOR:
            return self._handle_update_next_successor(arguments)

        else:
            return libp2pproto.construct_unknown_res()


    def _handle_tcp_connection(self, key):
        socket = key.fileobj
        data = key.data[1]

        recv_data = socket.recv(1024)  # Should be ready to read
        if recv_data:
            data.req_str += recv_data.decode("utf-8")
            try:
                req = libp2pproto.parse_string_to_req_packet(data.req_str)
                data.res_str = self._process_p2p_request(req)
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    data.res_str = libp2puds.construct_malformed_res()


    def _process_uds_request(self, req):
        op_word, arguments = req["op"], req["args"]
        if op_word == libp2puds.INIT_PEER_TABLE_OP_WORD:
            return libp2puds.construct_unknown_res()
        else:
            return libp2puds.construct_unknown_res()


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
                self._handle_tcp_connection(key)

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
            # self._handle_udp_packets()

            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data[1] is None:
                    self._accept_socket(key.fileobj, key.data[0])  # key.fileobj is the socket object
                else:
                    self._handle_connection(key, mask)
