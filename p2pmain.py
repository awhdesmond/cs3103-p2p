# p2pclient.py
# ------------
# The P2P main program. Calls P2P server in a daemonic thread? 
# Wraps around the P2P client

import sys
import os
import socket

import constants as CONTSTANTS

class P2PMain(object):

    def __init__(self):
        self.peerid      = generate_peerid()
        self.predecessor = 0
        self.successor   = 0

    def _setup(self):
        # Create base directory to store files and chunks
        if not os.path.exists(CLIENT_ROOT_PATH):
            os.makedirs(CLIENT_ROOT_PATH)

    def _render_user_menu():
        print("Group 14 P2P Client")
        print("-------------------")
        print("1. List available files.")
        print("2. Search for a file.")
        print("3. Download a file.")
        print("4. Share a file.")

    def _process_user_option(user_option):
        user_option = int(user_option)

        if user_option == 1:
            
        elif user_option == 2:
            filename = input('Enter filename: ')
        elif user_option == 3:
            filename = input('Enter filename: ')
        else:
            filename = input('Enter filename: ')

    def _start_client(self):
        while 1:
            self._render_user_menu()
            user_option = input('Enter option: ')
            while user_option not in ["1", "2", "3", "4"]:
                user_option = input('Invalid option selected. Please try again: ')
            process_user_option(user_option)


    def _start_server(self):
        pass

    def run(self):
        self._setup()
        self._start_server()
        self._start_client()

       
if __name__ == "__main__":
    p2pmain = P2PMain()
    p2pmain.run()
