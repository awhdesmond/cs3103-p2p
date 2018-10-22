# p2pclient.py
# ------------
# The P2P client component
# Handle user interaction, controls the server
# Communicate with server via UNIX DOMAIN SOCKETS


import os
import socket

# CONSTANTS
CLIENT_UDS_PATH  = "~/.p2pclient/uds_socket"
CLIENT_ROOT_PATH = "~/.p2pclient/"

class P2PClient(object):

    def __init__(self, peerid):
        self.peerid = peerid

    def _construct_uds_req(self, message):
        return b"%s\r\n" % message

    def setup(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(CLIENT_UDS_PATH)

        contact_p2pdns_msg = self._construct_uds_req("INIT_PEER_TABLE") 
        sock.sendall(contact_p2pdns_msg)

        res = ""
        content_length = None
        while True: 
            data = sock.recv(1024)
            res = res + "%s" % data
            
            if content_length is not None:
                recv_length = len("\r\n".join(res.split("\r\n")[1:]))
                if recv_length >= content_length:
                    break

            if "\r\n" in res:
                content_length = int(res.split("\r\n")[0][-1])   
        
        print(res)
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