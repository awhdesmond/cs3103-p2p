# p2pclient.py
# ------------
# The P2P client component
# Handle user interaction, controls the server
# Communicate with server via UNIX DOMAIN SOCKETS


import os
import socket
import sys

from libprotocol import libp2puds
from libprotocol.libp2puds import UdsResponsePacket

# CONSTANTS
CLIENT_UDS_PATH  = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"
MAX_PACKET_SIZE = 1024

class P2PClient(object):

    def _send_uds_request(self, packet):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(CLIENT_UDS_PATH)
        sock.sendall(packet.encode_bytes())
        
        data_string = ""
        while True:
            try:
                data = sock.recv(MAX_PACKET_SIZE)
                data_string = data_string + data.decode("utf-8")
            
                # print("-------", data_string)
                res_pkt = UdsResponsePacket.parse(data_string)
                sock.close()
                return res_pkt
            except ValueError as err:
                if int(str(err)) == libp2puds.INCOMPLETE_PACKET_ERROR:
                    continue
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    raise err
        
    def setup(self):
        print("P2P CLIENT INITIALISING...")
        init_peer_table_req = libp2puds.construct_init_req()

        try:
            self._send_uds_request(init_peer_table_req)
        except ValueError as err:
            if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                exit(libp2puds.MALFORMED_PACKET_ERROR)


    def _render_user_menu(self):
        print("Group 14 P2P Client")
        print("-------------------")
        print("1. List available files.")
        print("2. Share a file.")
        print("3. Download a file.")
        print("4. Quit")

    def _process_user_option(self, user_option):
        if user_option == "1":
            list_req = libp2puds.construct_list_files_req()
            res_pkt = self._send_uds_request(list_req)
            print(list(set(res_pkt.data)))

        elif user_option == "2":
            filepath = input('Enter filepath: ')
            upload_req = libp2puds.construct_upload_file_req(os.path.basename(filepath))
            res_pkt =  self._send_uds_request(upload_req)

            if res_pkt.code == libp2puds.OK_RES_CODE:
                print("File uploaded")
            else:
                print("An error occurred")

        elif user_option == "3":
            filename = input('Enter filename: ')
            download_req = libp2puds.construct_download_file_req(filename)
            res_pkt =  self._send_uds_request(download_req)
            
            if res_pkt.code == libp2puds.OK_RES_CODE:
                file_data = res_pkt.data[0].encode()
                with open(CLIENT_ROOT_PATH + filename, "wb") as file:
                    file.write(file_data)
                print("File downloaded!")
            else:
                print("File not found")
        elif user_option == "4":
            sys.exit()            
        else:
            pass


    def run(self):
        while 1:
            self._render_user_menu()
            user_option = input('Enter option: ')
            while user_option not in ["1", "2", "3", "4"]:
                user_option = input('Invalid option selected. Please try again: ')
            self._process_user_option(user_option)