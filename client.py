#
# client.py
# ---------
# The P2P client program. 
# The P2P client is also a P2P server (which is different from the central server)
#

import sys
import os
import socket

# CONSTANTS
CLIENT_ROOT_PATH    = "~/.p2pclient/"
CENTRAL_SERVER_URL  = "127.0.0.1" 
CENTRAL_SERVER_PORT = 3000

# CENTRAL SERVER API
GET_ALL_FILES = "/files"
GET_FILE      = "/file/:filename"

def create_client_socket(host, port):
    # create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(host, port)
    return s


def list_files_from_central_server():
    socket = create_client_socket(CENTRAL_SERVER_URL, CENTRAL_SERVER_PORT)
    socket.sendall("GET" +  GET_ALL_FILES)
    data = socket.recv(1024)
    print(data)
    socket.close()


def search_file_from_central_server(filename):
    socket = create_client_socket(CENTRAL_SERVER_URL, CENTRAL_SERVER_PORT)
    socket.sendall("GET" +  GET_FILE.replace(":filename", filename))
    data = socket.recv(1024)
    print(data)
    socket.close()

def download_file(filename):
    # Contact DHT to get file chunks
    # download file chunk
    # seed file chunk?
    pass

def process_user_option(user_option):
    user_option = int(user_option)

    if user_option == 1:
        list_files_from_central_server()
    elif user_option == 2:
        filename = input('Enter filename: ')
        search_file_from_central_server(filename)
    else:
        filename = input('Enter filename: ')
        download_file(filename)

def main():
    # Create base directory to store files and chunks
    if not os.path.exists(CLIENT_ROOT_PATH):
        os.makedirs(CLIENT_ROOT_PATH)

    while 1:
        print("Group 14 P2P Client")
        print("-------------------")
        print("1. List available files.")
        print("2. Search for a file.")
        print("3. Download a file.")


        user_option = input('Enter option: ')
        while user_option not in ["1", "2", "3"]:
            user_option = input('Invalid option selected. Please try again: ')
        
        process_user_option(user_option)

if __name__ == "__main__":
    main()
