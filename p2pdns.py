# p2pdns.py
# ---------
# Serves the function of introducing existing peers 
# to new peers who want to join
# 
# Sqlite3 DB Format -- <id, peer-id, ip-address>
import signal
import sys
import os
import socket
import sqlite3

from libprotocol import libp2pdns
from libprotocol.libp2pdns import DnsRequestPacket, DnsResponsePacket 

PORT = 7494
DB_NAME = 'p2pdns.db'
MAX_MSG_LEN = 1024

class P2PDns(object):

    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('', PORT))
        self.dbconn = sqlite3.connect(DB_NAME)

    def _setup_db(self):
        query = """
            CREATE TABLE IF NOT EXISTS p2pdns (id INTEGER PRIMARY KEY AUTOINCREMENT, peer_id TEXT, ip_address TEXT, port TEXT)
        """
        cursor = self.dbconn.cursor()
        cursor.execute(query)
        self.dbconn.commit()
    
    def _process_join(self, new_peerid, new_ipaddr, new_port):
        # add newest peer into db
        insert_query = """
            INSERT INTO p2pdns (peer_id, ip_address, port) VALUES (?, ?, ?)
        """
        cursor = self.dbconn.cursor()
        cursor.execute(insert_query, (new_peerid, new_ipaddr, new_port))
        self.dbconn.commit()
        
        # give some peers back to new peer
        select_query = """
            SELECT * FROM p2pdns WHERE peer_id<>? ORDER BY id LIMIT 5
        """
        cursor.execute(select_query, (new_peerid,))
        return list(map(lambda row: "%d,%s,%s,%s" % (row[0], row[1], row[2], row[3]), cursor.fetchall()))

    def _process_remove(self, cur_peerid):
        delete_query = """
            DELETE FROM p2pdns WHERE peer_id = ?
        """
        cursor = self.dbconn.cursor()
        cursor.execute(delete_query, (cur_peerid,))
        self.dbconn.commit()


    def _process_req(self, req):
        op_word, arguments = req.op_word, req.args
        print("OP CODE: " + op_word + "\tPeer ID: " + arguments[0] + "\tIP Address: " + arguments[1] + "\tPort: " + arguments[2])
        
        if op_word == libp2pdns.JOIN_REQ_OP_WORD:
            res_data = self._process_join(arguments[0], arguments[1], arguments[2])
            return DnsResponsePacket(libp2pdns.OK_RES_CODE, libp2pdns.OK_RES_MSG, res_data)
        elif op_word == libp2pdns.DELETE_ENTRY_OP_WORD:
            self._process_remove(arguments[0])
            return DnsResponsePacket(libp2pdns.OK_RES_CODE, libp2pdns.OK_RES_MSG, [])
        else:
            return libp2pdns.construct_unknown_res()

    def _service_connection(self, conn, addr):
        # print("Connected by", addr)
        
        data_string = ""
        while True:
            data = conn.recv(MAX_MSG_LEN)
            data_string = data_string + data.decode("utf-8")
            try:
                req = DnsRequestPacket.parse(data_string) 
                res_pkt = self._process_req(req)
                conn.sendall(res_pkt.encode_bytes())
                break
            except ValueError as err:
                if int(str(err)) == libp2pdns.INCOMPLETE_PACKET_ERROR:
                    continue
                else:
                    conn.sendall(libp2pdns.construct_malformed_res().encode_bytes())
                    break
        conn.close()

    def run(self):
        self._setup_db()
        self.server_socket.listen()
        
        print("P2P DNS Server listening on port:%d" % (PORT,))

        while 1:
            conn, addr = self.server_socket.accept()
            self._service_connection(conn, addr)
                
if __name__ == "__main__":
    p2pdns = P2PDns()
    p2pdns.run()


    def handler(signum, frame):
        print('Signal handler called with signal', signum)
        p2pdns.server_socket.close()

    signal.signal(signal.SIGINT, handler)