# p2pdns.py
# ---------
# Serves the function of introducing existing peers 
# to new peers who want to join
# 
# Sqlite3 DB Format -- <id, peer-id, ip-address>

import sys
import os
import socket
import sqlite3

from libp2pdns import libp2pdns

HOST    = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT    = 7494         # Port to listen on (non-privileged ports are > 1023)
DB_NAME = 'p2pdns.db'

class P2PDns(object):

    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.dbconn = sqlite3.connect(DB_NAME)

    def _setup_db(self):
        query = """
            CREATE TABLE IF NOT EXISTS p2pdns (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id TEXT, ip_address TEXT)
        """
        cursor = self.dbconn.cursor()
        cursor.execute(query)
        self.dbconn.commit()
    
    def _process_join(self, new_peerid, new_ipaddr):
        # add newest peer into db
        insert_query = """
            INSERT INTO p2pdns (peer_id, ip_address) VALUES (?, ?)
        """
        cursor = self.dbconn.cursor()
        cursor.execute(insert_query, (new_peerid, new_ipaddr))
        self.dbconn.commit()
        
        # give some peers back to new peer
        select_query = """
            SELECT * FROM p2pdns WHERE peer_id<>? ORDER BY id LIMIT 5
        """
        cursor.execute(select_query, (new_peerid,))
        return list(map(lambda row: "%d,%s,%s" % (row[0], row[1], row[2]), cursor.fetchall()))


    def _process_req(self, req):
        op_word, arguments = req["op"], req["args"]
        
        if op_word == libp2pdns.JOIN_REQ_OP_WORD:
            res_data = self._process_join(arguments[0], arguments[1])
            return libp2pdns.construct_res_packet(libp2pdns.OK_RES_CODE, libp2pdns.OK_RES_MSG, res_data)
        else:
            return libp2pdns.construct_unknonw_res()    

    def _service_connection(self, conn, addr):
        print("Connected by", addr)
        data_string = ""
        while True:
            data = conn.recv(1024)
            data_string = data_string + data.decode("utf-8")
            try:
                req = libp2pdns.parse_string_to_req_packet(data_string)
                res = self._process_req(req)
                conn.sendall(res.encode())
                break
            except ValueError as err:
                if int(str(err)) == libp2pdns.INCOMPLETE_PACKET_ERROR:
                    continue
                else:
                    conn.sendall(libp2pdns.construct_malformed_res().encode())
                    break
        conn.close()

    def run(self):
        self._setup_db()
        self.server_socket.listen()
        
        print("P2P DNS Server listening on %s:%d" % (HOST, PORT))

        while 1:
            conn, addr = self.server_socket.accept()
            self._service_connection(conn, addr)
                
if __name__ == "__main__":
    p2pdns = P2PDns()
    p2pdns.run()
