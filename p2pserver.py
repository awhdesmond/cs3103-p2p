# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS

import os
import socket
import types

import selectors

from libp2puds import libp2puds

# CONSTANTS
CLIENT_UDS_PATH  = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"

PEER_ADDR = "127.0.0.1" 
PEER_PORT = 8818

UDS_SOCKET_DISPATCH_CODE = 1
TCP_SOCKET_DISPATCH_CODE = 2

class P2PServer(object):

    def __init__(self, peerid):
        self.peerid   = peerid
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
        self.peer_server_sock.bind((PEER_ADDR, PEER_PORT))

    def setup(self):
        print("P2P Server Setup")

        self.uds_sock.listen()
        self.uds_sock.setblocking(False)
        
        self.peer_server_sock.listen()
        self.peer_server_sock.setblocking(False)
        
        self.selector.register(self.uds_sock, selectors.EVENT_READ, data=(UDS_SOCKET_DISPATCH_CODE, None)) # data is used to store whatever arbitrary data you’d like along with the socket
        self.selector.register(self.peer_server_sock, selectors.EVENT_READ, data=(TCP_SOCKET_DISPATCH_CODE, None))


    def _accept_socket(self, socket, dispatch_code):
        conn, addr = socket.accept()
        conn.setblocking(False)

        data = (dispatch_code, types.SimpleNamespace(addr=addr, req_str='', res_str=''))
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.selector.register(conn, events, data=data)

    def _handle_uds_connection(self, key):
        socket = key.fileobj
        data   = key.data[1]

        recv_data = socket.recv(1024)  # Should be ready to read
        if recv_data:
            data.req_str += recv_data.decode("utf-8")
            try:
                req = libp2puds.parse_string_to_req_packet(data.req_str)
                print(req)
                data.res_str = libp2puds.construct_unknonw_res()
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    data.res_str = libp2puds.construct_malformed_res()
                    
    def _handle_tcp_connection(self, key):
        pass


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
                print(data.res_str.encode())
                socket.sendall(data.res_str.encode())  # Should be ready to write
                
            self.selector.unregister(socket)
            socket.close()

    

    def run(self):
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data[1] is None:
                    self._accept_socket(key.fileobj, key.data[0]) # key.fileobj is the socket object
                else:
                    self._handle_connection(key, mask)
                        
                    

