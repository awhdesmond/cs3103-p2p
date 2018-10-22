# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS

import os
import sys
import socket

import selectors
import constants


class P2PServer(object):

    def __init__(self, peerid):
        self.peerid = peerid

        self.selector = selectors.DefaultSelector()

        self.uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds_sock.bind(constants.CLIENT_SOCKET_PATH)

        self.peer_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_sock.bind((constants.PEER_ADDR, constants.PEER_PORT))

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
            recv_data = sock.recv(1024)  # Should be ready to read
            if recv_data:
                data.inb += recv_data
            else:
                sel.unregister(sock)
                sock.close()
        
        if mask & selectors.EVENT_WRITE:
            if data.inb:
                
                sent = sock.sendall(data.outb)  # Should be ready to write
                data.outb = data.outb[sent:]


    def run(self):
        self.uds_sock.listen()
        self.uds_sock.setblocking(False)
        
        self.peer_server_sock.listen()
        self.peer_server_sock.setblocking(False)
        
        self.selector.register(self.uds_sock, selectors.EVENT_READ, data=None) # data is used to store whatever arbitrary data you’d like along with the socket
        self.selector.register(self.peer_server_sock, selectors.EVENT_READ, data=None)

        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    self._accept_socket(key.fileobj) # key.fileobj is the socket object
                else:
                    _handle_connection(key, mask)



