# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS

import os
import socket
import types

import selectors

# CONSTANTS
CLIENT_UDS_PATH  = "~/.p2pclient/uds_socket"
CLIENT_ROOT_PATH = "~/.p2pclient/"
PEER_ADDR = "127.0.0.1" 
PEER_PORT = 8818

class P2PServer(object):

    def __init__(self, peerid):
        self.peerid = peerid

        self.selector = selectors.DefaultSelector()

        # Make sure the socket does not already exist
        try:
            os.unlink(CLIENT_UDS_PATH)
        except OSError:
            if os.path.exists(CLIENT_UDS_PATH):
                raise

        self.uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds_sock.bind(CLIENT_UDS_PATH)

        self.peer_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_sock.bind((PEER_ADDR, PEER_PORT))

    def _accept_socket(self, socket):
        conn, addr = socket.accept()
        conn.setblocking(False)

        data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.selector.register(conn, events, data=data)

    def _handle_connection(self, key, mask):
        socket = key.fileobj
        data   = key.data

        if mask & selectors.EVENT_READ:
            recv_data = socket.recv(1024)  # Should be ready to read
            if recv_data:
                data.inb += recv_data
            else:
                self.selector.unregister(socket)
                socket.close()
        
        if mask & selectors.EVENT_WRITE:
            if data.inb:
                sent = socket.sendall(data.outb)  # Should be ready to write
                data.outb = data.outb[sent:]

    def setup(self):
        self.uds_sock.listen()
        self.uds_sock.setblocking(False)
        
        self.peer_server_sock.listen()
        self.peer_server_sock.setblocking(False)
        
        self.selector.register(self.uds_sock, selectors.EVENT_READ, data=None) # data is used to store whatever arbitrary data you’d like along with the socket
        self.selector.register(self.peer_server_sock, selectors.EVENT_READ, data=None)

    def run(self):
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    self._accept_socket(key.fileobj) # key.fileobj is the socket object
                else:
                    self._handle_connection(key, mask)



