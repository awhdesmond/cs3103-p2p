# dhash.py
# ------------
# DHT that relies on Chord lookup service

import json
import utils
import sqlite3
from libprotocol import libp2pproto
from libprotocol.libp2pproto import P2PRequestPacket, send_p2p_tcp_packet

PEER_PORT    = 7495
DB_NAME      = './p2pvar/p2pdht.db'
SELECT_QUERY = "SELECT * FROM p2pdht WHERE filename=?"

class Dhash(object):

    def __init__(self, peer):
        self.peer = peer
        self._setup_db()

    def _setup_db(self):
        query = """
            CREATE TABLE IF NOT EXISTS p2pdht (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, ip_addr_list TEXT)
        """
        
        dbconn = sqlite3.connect(DB_NAME)
        cursor = dbconn.cursor()
        cursor.execute(query)
        dbconn.commit()
        dbconn.close()

    def put(self, filename, ip_addr_port):
        if self._check_filename_responsibility(filename):
            dbconn = sqlite3.connect(DB_NAME)
            cursor = dbconn.cursor()
            cursor.execute(SELECT_QUERY, (filename,))
            db_result = cursor.fetchone()

            if db_result == None:
                insert_query = """
                    INSERT INTO p2pdht (filename, ip_addr_list) VALUES (?, ?)
                """
                cursor.execute(insert_query, (filename, json.dumps([ip_addr_port])))
            else:
                update_query = """
                    UPDATE p2pdht SET ip_addr_list=? WHERE id=?
                """
                ip_addr_list = json.loads(db_result[2])
                ip_addr_list.append(ip_addr_port)
                cursor.execute(update_query, (json.dumps(ip_addr_list), int(db_result[0])))
            dbconn.commit()
            dbconn.close()
            return True
        else:
            # Ask successor
            req_packet = P2PRequestPacket(libp2pproto.PUT_FILE_OP_WORD, [filename, ip_addr_port])
            res_packet = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor['port'], req_packet)    
            return res_packet.code == libp2pproto.OK_RES_CODE
            
    def get(self, filename):
        dbconn = sqlite3.connect(DB_NAME)
        cursor = dbconn.cursor()
        cursor.execute(SELECT_QUERY, (filename,))
        datum = cursor.fetchone()
        dbconn.close()

        if datum == None:
            if self._check_filename_responsibility(filename):
                # If I am responsible and file is not found == ggwp
                return None
            else:
                # Ask successor
                req_packet = P2PRequestPacket(libp2pproto.GET_FILE_OP_WORD, [filename])
                res_packet = send_p2p_tcp_packet(self.peer.successor["ip_addr"], self.peer.successor['port'], req_packet)
                
                if len(res_packet.data) > 0:
                    return res_packet.data[0]
                else:
                    return None
                    
                return None
        else:
            ip_addr_port_str = datum[2].replace(' ', '')
            return json.loads(ip_addr_port_str)[0]
            

    # Returns only the filename
    def get_local_keys(self):
        data = self._get_local_rows()
        return [d[1] for d in data]

    # Returns everything
    def _get_local_rows(self):
        select_query = """
            SELECT * FROM p2pdht
        """
        
        dbconn = sqlite3.connect(DB_NAME)
        cursor =dbconn.cursor()
        cursor.execute(select_query)
        data = cursor.fetchall()
        dbconn.close()
        return data

    def _check_filename_responsibility(self, filename):
        if not self.peer.successor['id']:
            return True
        
        filename_hash = utils.generate_filename_hash(filename)
        # print(filename_hash)
        # self.peer.print_info()

        return ((filename_hash > self.peer.predecessor['id'] and filename_hash <= self.peer.peer_id)
                # 60 - F(70) - 2
                or (filename_hash > self.peer.predecessor['id'] and self.peer.peer_id < self.peer.predecessor['id'])
                # filehash is smaller than all peers
                or (self.peer.peer_id < self.peer.predecessor['id'] and filename_hash < self.peer.peer_id))

    def update_responsible_keys(self):
        data = self._get_local_rows()
        
        if data is None:
            return
        
        for datum in data:
            filename = datum[1]
            if not self._check_filename_responsibility(filename):
                ip_addr_port_list = json.loads(datum[2])
                for ip_addr_port in ip_addr_port_list:
                    self.put(filename, ip_addr_port)