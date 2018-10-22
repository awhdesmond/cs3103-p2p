#
# client.py
# ---------
# The P2P client program. 
# The P2P client is also a P2P server (which is different from the central server)
#

import sys
import os
import socket

import constants as CONTSTANTS
import create_client_socket, generate_peerid from utils

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

    def _list_files_from_central_server():
        socket = create_client_socket(CENTRAL_SERVER_URL, CENTRAL_SERVER_PORT)
        socket.sendall("GET" +  GET_ALL_FILES)
        data = socket.recv(1024)
        print(data)
        socket.close()


    def _search_file_from_central_server(filename):
        socket = create_client_socket(CENTRAL_SERVER_URL, CENTRAL_SERVER_PORT)
        socket.sendall("GET" +  GET_FILE.replace(":filename", filename))
        data = socket.recv(1024)
        print(data)
        socket.close()

    def _download_file(filename):
        # Contact DHT to get file chunks
        # download file chunk
        # seed file chunk?
        pass

    def _process_user_option(user_option):
        user_option = int(user_option)

        if user_option == 1:
            _list_files_from_central_server()
        elif user_option == 2:
            filename = input('Enter filename: ')
            _search_file_from_central_server(filename)
        else:
            filename = input('Enter filename: ')
            _download_file(filename)

    def _start_client(self):
        while 1:
            self._render_user_menu()
            user_option = input('Enter option: ')
            while user_option not in ["1", "2", "3"]:
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
