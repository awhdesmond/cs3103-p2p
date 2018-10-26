# p2pclient.py
# ------------
# The P2P client component
# Handle user interaction, controls the server
# Communicate with server via UNIX DOMAIN SOCKETS


import os
import socket

from libprotocol import libp2puds

# CONSTANTS
CLIENT_UDS_PATH  = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"

class P2PClient(object):

    def __init__(self, peerid):
        self.peerid = peerid

    def setup(self):
        print("P2P Client Setup")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(CLIENT_UDS_PATH)

        init_peer_table_req = libp2puds.construct_init_req()
        sock.sendall(init_peer_table_req.encode())

        data_string = ""
        while True: 
            data = sock.recv(1024)
            data_string = data_string + data.decode("utf-8")
            try:
                res = libp2puds.parse_string_to_res_packet(data_string)
                # print("asd")
                # print(res)
                break
            except ValueError as err:
                if int(str(err)) == libp2puds.INCOMPLETE_PACKET_ERROR:
                    continue
                else: 
                    exit(libp2puds.MALFORMED_PACKET_ERROR)
        sock.close()

    def _render_user_menu(self):
        print("Group 14 P2P Client")
        print("-------------------")
        print("1. List available files.")
        print("2. Search for a file.")
        print("3. Download a file.")
        print("4. Share a file.")
        print("5. Quit")

    def _process_user_option(self, user_option):
    
        if user_option == "1":
            pass
        elif user_option == "2":
            filename = input('Enter filename: ')
        elif user_option == "3":
            filename = input('Enter filename: ')
        elif user_option == "4":
            filepath = input('Enter filepath: ')
            # copy file from filepath to program root dir & seed
        else:
            pass

    def run(self):
        while 1:
            self._render_user_menu()
            user_option = input('Enter option: ')
            while user_option not in ["1", "2", "3", "4"]:
                user_option = input('Invalid option selected. Please try again: ')
            self._process_user_option(user_option)