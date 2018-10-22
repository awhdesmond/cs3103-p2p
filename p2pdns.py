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

import constants as CONTSTANTS

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 7494         # Port to listen on (non-privileged ports are > 1023)

class P2PDns(object):

    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.dbconn = sqlite3.connect('p2pdns.db')
    
    def _parse_req(self, req):
        return req.split(" ")[0], req.split(" ")[1:]

    def _process_join(self, new_peerid, new_ipaddr):
        # add newest peer into db
        cursor = self.dbconn.cursor()
        cursor.execute("INSERT INTO p2pdns VALUES (?, ?)", new_peerid, new_ipaddr)
        self.dbconn.commit()
        
        # give some peers back to new peer
        cursor.execute("SELECT * FROM p2pdns ORDER BY id LIMIT 5")
        return list(map(lambda row: "%d,%s,%s" % (row[0], row[1], row[2]), cursor.fetchall()))

    def _construct_res(self, op_line, res_data):
        res = op_line + "\r\n" + "\r\n"
        for line in res_data:
            res = res + line + "\r\n"
        return res

    def _process_req(self, req):
        op_word, arguments = self._parse_req(req)
        
        if op_word == "JOIN":
            ## need check for malformed packets
            if len(arguments) != 2:
                return self._construct_res("422 MALFORMED PACKET", [])    
            
            res_data = self._process_join(arguments[0], arguments[1])
            return self._construct_res("200 OK", res_data)
        else:
            return "404 OPERATION UNKNOWN"

    def _setup_db(self):
        cursor = self.dbconn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS p2pdns (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id TEXT, ip_address TEXT);")
        self.dbconn.commit()

    def run(self):
        self._setup_db()
        self.server_socket.listen()
        conn, addr = self.server_socket.accept()
        with conn:
            print("Connected by", addr)
            req = conn.recv(1024)
            res = self._process_req(req)
            conn.sendall(res)

if __name__ == "__main__":
    p2pdns = P2PDns()
    p2pdns.run()
