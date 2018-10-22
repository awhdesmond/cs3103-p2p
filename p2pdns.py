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

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 7494         # Port to listen on (non-privileged ports are > 1023)

class P2PDns(object):

    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.dbconn = sqlite3.connect('p2pdns.db')
    
    def _parse_req(self, req):
        stripped_req = req.strip()
        return stripped_req.split(" ")[0], stripped_req.split(" ")[1:]

    def _construct_res(self, op_line, res_data):
        content = ""
        for line in res_data:
            content = content + line + "\r\n"
        res = op_line + " " + str(len(content)) + "\r\n" + content
        return res

    def _process_join(self, new_peerid, new_ipaddr):
        # add newest peer into db
        cursor = self.dbconn.cursor()
        cursor.execute("INSERT INTO p2pdns (peer_id, ip_address) VALUES (?, ?)", (new_peerid, new_ipaddr))
        self.dbconn.commit()
        
        # give some peers back to new peer
        cursor.execute("SELECT * FROM p2pdns WHERE peer_id<>? ORDER BY id LIMIT 5", (new_peerid,))
        return list(map(lambda row: "%d,%s,%s" % (row[0], row[1], row[2]), cursor.fetchall()))

    
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
        
        print("P2P DNS Server listening on %s:%d" % (HOST, PORT))

        while 1:
            conn, addr = self.server_socket.accept()
            with conn:
                print("Connected by", addr)

                req = ""
                while True:
                    data = conn.recv(1024)
                    req = req + "%s" % data.decode("utf-8")         
                    if "\r\n" in req:
                        break        
                print(req)
                res = self._process_req(req)
                conn.sendall(res.encode())

if __name__ == "__main__":
    p2pdns = P2PDns()
    p2pdns.run()
