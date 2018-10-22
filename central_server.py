#
# central_server.py
# ---------
# The P2P central server program. 
# Stores a lists of available files for download
#

import sqlite3
import selectors

# CONSTANTS
HOST = '127.0.0.1'  
PORT = 8828

def create_tcp_socket():
    pass

def insert_file():
    pass

def list_all_files():
    pass

def list_single_file(filename):
    pass

def main():
    db_conn = sqlite3.connect("p2p.db")
    sel = selectors.DefaultSelector()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print('Central Server listening on: %s:%d' % (host, port))
        
        lsock.setblocking(False)
        sel.register(lsock, selectors.EVENT_READ, data=None)




if __name__ == "__main__":
    main()