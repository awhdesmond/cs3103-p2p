# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS

import os
import socket
import types
import selectors
import utils
import sqlite3
import json
from random import randrange
from apscheduler.schedulers.background import BackgroundScheduler
from libprotocol import libp2puds, libp2pdns, libp2pproto

# CONSTANTS
CLIENT_UDS_PATH = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"

DNS_IP_ADDR = "192.168.2.170"
DNS_PORT = 7494
PEER_PORT = 7495
STABILISATION_INTERVAL = 10

MAX_PACKET_SIZE = 1024
UDS_SOCKET_DISPATCH_CODE = 1
TCP_SOCKET_DISPATCH_CODE = 2

DB_NAME = 'p2pdht.db'
SELECT_QUERY = "SELECT * FROM p2pdht WHERE filename=?"

class P2PServer(object):
    
    def __init__(self, peer, ip_addr):
        self.peer      = peer
        self.ip_addr   = ip_addr
        self.selector  = selectors.DefaultSelector()
        self.scheduler = BackgroundScheduler()

        # Make sure the socket does not already exist
        try:
            if not os.path.exists(CLIENT_ROOT_PATH):
                os.makedirs(CLIENT_ROOT_PATH)
            os.unlink(CLIENT_UDS_PATH)
        except OSError:
            if os.path.exists(CLIENT_UDS_PATH):
                raise

        self.uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.uds_sock.bind(CLIENT_UDS_PATH)

        self.peer_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_sock.bind(('', PEER_PORT))

    def setup(self):
        print("P2P Server Setup")

        self.uds_sock.listen()
        self.uds_sock.setblocking(False)

        self.peer_server_sock.listen()
        self.peer_server_sock.setblocking(False)

        # data is used to store whatever arbitrary data you’d like along with the socket
        self.selector.register(self.uds_sock, selectors.EVENT_READ, data=(UDS_SOCKET_DISPATCH_CODE, None))  
        self.selector.register(self.peer_server_sock, selectors.EVENT_READ, data=(TCP_SOCKET_DISPATCH_CODE, None))

    
    def _send_p2p_tcp_packet(self, dst_ip_addr, packet, recv):
        # This should be blocking -- easier to reason about -- TODO: make not blocking
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect((dst_ip_addr, PEER_PORT))
        tcp_socket.sendall(packet.encode())
        if(recv == False):
            return
        # TODO: Incomplete-Packet error handling
        res = tcp_socket.recv(MAX_PACKET_SIZE)  
        res_str = res.decode("utf-8")
        
        try:
            tcp_socket.close()
            print("-------", res_str)
            return libp2pproto.parse_string_to_res_packet(res_str)
        except ValueError as err:
            if int(str(err)) == libp2pproto.MALFORMED_PACKET_ERROR:
                raise err

    def _handle_p2p_get_neighbors(self, new_peer_id, new_peer_ip_address):
        if not self.peer.successor["id"]:
            # I AM YOUR PREDECESSOR -- only one node in network
            self.peer.successor  ["id"]      = new_peer_id
            self.peer.successor  ["ip_addr"] = new_peer_ip_address
            self.peer.predecessor["id"]      = new_peer_id
            self.peer.predecessor["ip_addr"] = new_peer_ip_address

            print("I am the genesis node")
            self.peer.print_info()

            data = "%d %s %d %s" % (self.peer.peer_id, self.ip_addr, self.peer.peer_id, self.ip_addr)
            return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])
        
        if new_peer_id > self.peer.predecessor["id"] and new_peer_id < self.peer.peer_id:
            data = "%d %s %d %s" % (self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.peer_id, self.ip_addr)
            
            self.peer.predecessor["id"]      = new_peer_id
            self.peer.predecessor["ip_addr"] = new_peer_ip_address
            
            print("I am the successor of: %d" % (new_peer_id,))
            self.peer.print_info()

            return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])

        if new_peer_id < self.peer.successor["id"] and new_peer_id > self.peer.peer_id:
            data = "%d %s %d %s" % (self.peer.peer_id, self.ip_addr, self.peer.successor["id"], self.peer.successor["ip_addr"])

            self.peer.successor["id"] = new_peer_id
            self.peer.successor["ip_addr"] = new_peer_ip_address

            print("I am the predecessor of: %d" % (new_peer_id,))
            self.peer.print_info()
    
            return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])


        if new_peer_id > self.peer.peer_id and new_peer_id > self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = "%d %s %d %s" % (self.peer.peer_id, self.ip_addr, self.peer.successor["id"], self.peer.successor["ip_addr"])
 
                self.peer.successor["id"]      = new_peer_id
                self.peer.successor["ip_addr"] = new_peer_ip_address

                print("I am the predecessor of: %d" % (new_peer_id,))
                self.peer.print_info()

                return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])
            else:
                print("Recursively ask my successor")
                req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, new_peer_id, new_peer_ip_address)
                res_pkt = self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], req_packet, True)
                return libp2pproto.construct_res_packet(res_pkt["code"], res_pkt["msg"], res_pkt["data"])
            
        if new_peer_id < self.peer.peer_id and new_peer_id < self.peer.successor["id"]:
            if self.peer.successor["id"] < self.peer.peer_id: # WRAP AROUND
                data = "%d %s %d %s" % (self.peer.peer_id, self.ip_addr, self.peer.successor["id"], self.peer.successor["ip_addr"])

                self.peer.successor["id"]      = new_peer_id
                self.peer.successor["ip_addr"] = new_peer_ip_address

                print("I am the predecessor of: %d" % (new_peer_id,))
                self.peer.print_info()

                return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])
            else:
                print("Recursively ask my successor")
                req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, new_peer_id, new_peer_ip_address)
                res_pkt = self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], req_packet, True)
                return libp2pproto.construct_res_packet(res_pkt["code"], res_pkt["msg"], res_pkt["data"])

    def _handle_p2p_inform_predecessor(self, peer_id, ip_addr):
        self.peer.successor["id"]      = peer_id
        self.peer.successor["ip_addr"] = ip_addr
        self.peer.print_info()
        return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [])

    def _handle_p2p_inform_successor(self, peer_id, ip_addr):
        self.peer.predecessor["id"]      = peer_id
        self.peer.predecessor["ip_addr"] = ip_addr
        self.peer.print_info()
        return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [])

    def _handle_p2p_query_successor_for_predecessor(self):
        data = "%d %s" % (self.peer.predecessor["id"], self.peer.predecessor["ip_addr"])
        return libp2pproto.construct_res_packet(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])

    def _process_p2p_request(self, req):
        op_word, arguments = req["op"], req["args"]
        if op_word == libp2pproto.GET_NEIGHBOURS_OP_WORD:
            peer_id = int(arguments[libp2pproto.GET_NEIGHBOURS_PEER_ID_INDEX])
            ip_addr = arguments[libp2pproto.GET_NEIGHBOURS_PEER_IP_ADDR_INDEX]
            return self._handle_p2p_get_neighbors(peer_id, ip_addr)
        
        if op_word == libp2pproto.INFORM_PREDECESSOR_OP_WORD:
            peer_id = int(arguments[libp2pproto.GET_NEIGHBOURS_PEER_ID_INDEX])
            ip_addr = arguments[libp2pproto.GET_NEIGHBOURS_PEER_IP_ADDR_INDEX]
            return self._handle_p2p_inform_predecessor(peer_id, ip_addr)

        if op_word == libp2pproto.INFORM_SUCCESSOR_OP_WORD:
            peer_id = int(arguments[libp2pproto.INFORM_SUCCESSOR_PEER_ID_INDEX])
            ip_addr = arguments[libp2pproto.INFORM_SUCCESSOR_PEER_IP_ADDR_INDEX]
            return self._handle_p2p_inform_successor(peer_id, ip_addr)

        if op_word == libp2pproto.QUERY_SUCCESSOR_FOR_PREDECESSOR_OP_WORD:
            return self._handle_p2p_query_successor_for_predecessor()

        if op_word == libp2pproto.PUT_FILE_OP_WORD:
            filename = arguments[libp2pproto.PUT_FILE_FILENAME_INDEX]
            ip_addr = arguments[libp2pproto.PUT_FILE_IP_ADDR_INDEX]
            msg_type = int(arguments[libp2pproto.PUT_FILE_MSG_TYPE_INDEX])
            return self._handle_put_request(filename, ip_addr, msg_type)

        if op_word == libp2pproto.GET_FILE_OP_WORD:
            filename = arguments[libp2pproto.GET_FILE_FILENAME_INDEX]
            ip_addr = arguments[libp2pproto.GET_FILE_IP_ADDR_INDEX]
            msg_type = int(arguments[libp2pproto.GET_FILE_MSG_TYPE_INDEX])
            return self._handle_search_request(filename, ip_addr, msg_type)
        
        if op_word == libp2pproto.LIST_FILES_OP_WORD:
            file_str = arguments[libp2pproto.LIST_FILES_FILE_STR_INDEX]
            ip_addr = arguments[libp2pproto.LIST_FILES_IP_ADDR_INDEX]
            hop_count = int(arguments[libp2pproto.LIST_FILES_HOP_COUNT_INDEX])
            return self._handle_list_request(file_str, ip_addr, hop_count)

        
        return libp2pproto.construct_unknown_res()

    def _stabilisation(self):
        if not self.peer.successor["id"]:
            print("Genesis node. No Stabilisation needed.")
            return

        stab_packet = libp2pproto.construct_req_packet(libp2pproto.QUERY_SUCCESSOR_FOR_PREDECESSOR_OP_WORD)
        res_packet = self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], stab_packet, True)
        
        if res_packet is not None:
            data = res_packet["data"][0].split(" ")
            successor_predecessor_peer_id = int(data[0])

            if successor_predecessor_peer_id != self.peer.peer_id:
                # Oh, you have a new predecessor, let me add that as my successor
                self.peer.successor["id"]        = int(data[0])
                self.peer.successor["ip_addr"]   = data[1]
                inform_packet = libp2pproto.construct_req_packet(libp2pproto.INFORM_SUCCESSOR_OP_WORD, self.peer.peer_id, self.ip_addr)
                self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], inform_packet, True)
            else:
                print("There is no change")

    def _handle_p2p_connection(self, key):
        socket = key.fileobj
        data = key.data[1]

        recv_data = socket.recv(MAX_PACKET_SIZE)  # Should be ready to read
        if recv_data:
            data.req_str += recv_data.decode("utf-8")
            try:
                req = libp2pproto.parse_string_to_req_packet(data.req_str)
                data.res_str = self._process_p2p_request(req)
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    data.res_str = libp2puds.construct_malformed_res()

   
    def _enter_p2p_network(self, peer_ip_addr_list):
        if len(peer_ip_addr_list) == 0:
            print("First node has no peers")
        else:
            chosen_peer_ip_addr = peer_ip_addr_list[randrange(len(peer_ip_addr_list))]
            print("Joining P2P Network...")
            print("Chosen peer_ip addr: ", chosen_peer_ip_addr)

            req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_NEIGHBOURS_OP_WORD, self.peer.peer_id, self.ip_addr)
            res_packet = self._send_p2p_tcp_packet(chosen_peer_ip_addr, req_packet, True)
            data = res_packet["data"][0].split(" ")
            self.peer.predecessor["id"]      = int(data[0])
            self.peer.predecessor["ip_addr"] = data[1]
            self.peer.successor["id"]        = int(data[2])
            self.peer.successor["ip_addr"]   = data[3]
            self.peer.print_info()

            print("Informing my predecessor to add me as its successor")
            inform_packet = libp2pproto.construct_req_packet(libp2pproto.INFORM_PREDECESSOR_OP_WORD, self.peer.peer_id, self.ip_addr)
            self._send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], inform_packet, True)

            print("Informing my successor to add me as its predecessor")
            inform_packet = libp2pproto.construct_req_packet(libp2pproto.INFORM_SUCCESSOR_OP_WORD, self.peer.peer_id, self.ip_addr)
            self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], inform_packet, True)

        self.scheduler.add_job(self._stabilisation, 'interval', seconds=STABILISATION_INTERVAL)
        self.scheduler.start()


    def _retrieve_peer_ip_addresses(self):
        # TODO: handle case if DNS is not up.
        dns_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dns_server_sock.connect((DNS_IP_ADDR, DNS_PORT))

        message = libp2pdns.construct_req_packet(libp2pdns.JOIN_REQ_OP_WORD, self.peer.peer_id, self.ip_addr)
        dns_server_sock.sendall(message.encode())
        res = dns_server_sock.recv(MAX_PACKET_SIZE)
        try:
            res_str = res.decode("utf-8")
            peers_ip_addr_list = libp2pdns.parse_message_to_peer_list(res_str)
            dns_server_sock.close()
            return peers_ip_addr_list

        except ValueError as err:
            if int(str(err)) == libp2puds.INCOMPLETE_PACKET_ERROR:
                return [] #TODO: should re-attempt to get info again
          
    def _process_uds_request(self, req):
        op_word, arguments = req["op"], req["args"]
        if op_word == libp2puds.INIT_PEER_TABLE_OP_WORD:
            peer_ip_addresses = self._retrieve_peer_ip_addresses()
            self._enter_p2p_network(peer_ip_addresses)
            return libp2puds.construct_empty_ok_res()
        if op_word == libp2puds.UPLOAD_FILE_OP_WORD:
            filename = arguments[libp2pproto.PUT_FILE_FILENAME_INDEX]
            ip_addr = self.ip_addr
            self._handle_put_request(filename, ip_addr, libp2pproto.REQUEST_MSG)
            return libp2puds.construct_empty_ok_res()
        if op_word == libp2puds.DOWNLOAD_FILE_OP_WORD:
            filename = arguments[libp2pproto.GET_FILE_FILENAME_INDEX]
            ip_addr = self.ip_addr
            self._handle_search_request(filename, ip_addr, libp2pproto.REQUEST_MSG)
            return libp2puds.construct_empty_ok_res()
        if op_word == libp2puds.LIST_ALL_FILES_OP_WORD:
            self._handle_list_request("None", self.ip_addr, 0)
            return libp2puds.construct_empty_ok_res()
        if op_word == libp2puds.SEARCH_FILE_OP_WORD:
            filename = arguments[libp2pproto.GET_FILE_FILENAME_INDEX]
            ip_addr = self.ip_addr
            self._handle_search_request(filename, ip_addr, libp2pproto.REQUEST_MSG)
            return libp2puds.construct_empty_ok_res()
        
        return libp2puds.construct_unknown_res()


    def _handle_uds_connection(self, key):
        socket = key.fileobj
        data = key.data[1]

        recv_data = socket.recv(1024)  # Should be ready to read
        if recv_data:
            data.req_str += recv_data.decode("utf-8")
            try:
                req = libp2puds.parse_string_to_req_packet(data.req_str)
                data.res_str = self._process_uds_request(req)
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    data.res_str = libp2puds.construct_malformed_res()

    def _handle_connection(self, key, mask):
        if mask & selectors.EVENT_READ:
            dispatch_code = key.data[0]

            if dispatch_code == UDS_SOCKET_DISPATCH_CODE:
                self._handle_uds_connection(key)
            else:
                self._handle_p2p_connection(key)

        if mask & selectors.EVENT_WRITE:
            socket = key.fileobj
            data = key.data[1]
            if data.res_str:
                socket.sendall(data.res_str.encode())  # Should be ready to write

            self.selector.unregister(socket)
            socket.close()


    def _accept_socket(self, socket, dispatch_code):
        conn, addr = socket.accept()
        conn.setblocking(False)

        data = (dispatch_code, types.SimpleNamespace(addr=addr, req_str='', res_str=''))
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.selector.register(conn, events, data=data)

    def _handle_put_request(self, filename, ip_addr, msg_type):
        if(msg_type == libp2pproto.RESPONSE_MSG):
            print("%s successfully placed" % filename)
            return libp2puds.construct_empty_ok_res()
        
        filename_hash = utils.consistent_hash(filename.encode())
        print("filenamehash: %d"%filename_hash)
        # this node is responsible
        if((filename_hash > self.peer.predecessor['id'] and filename_hash <= self.peer.peer_id)
            #filehash is larger than all peers
            or (self.peer.peer_id > self.peer.successor['id'] and filename_hash> self.peer.peer_id)
            #filehash is smaller than all peers
            or (self.peer.peer_id < self.peer.predecessor['id'] and filename_hash < self.peer.peer_id)):
            print('inserting!')
            insert_query = """
                INSERT INTO p2pdht (filename, ip_addr_list) VALUES (?, ?)
            """
            cursor = self.dbconn.cursor()
            cursor.execute(SELECT_QUERY, (filename,))
            db_result = cursor.fetchone()
            print(db_result)
            ip_addr_list = list()
            if(db_result != None):
                print(db_result[2])
                print(type(db_result[2]))
                ip_addr_list = json.loads(db_result[2])
                update_query = """
                UPDATE p2pdht SET ip_addr_list=? WHERE id=?
                """
                ip_addr_list.append(ip_addr)
                cursor.execute(update_query, (json.dumps(ip_addr_list), int(db_result[0])))
            else:
                ip_addr_list.append(ip_addr)
                cursor.execute(insert_query, (filename, json.dumps(ip_addr_list)))
            self.dbconn.commit()
            if(ip_addr == self.ip_addr):
                print("%s successfully placed" % filename)
                return 
            print('inserted! sending response')
            req_packet = libp2pproto.construct_req_packet(libp2pproto.PUT_FILE_OP_WORD, filename, ip_addr, libp2pproto.RESPONSE_MSG)
            self._send_p2p_tcp_packet(ip_addr,req_packet, True)
            print('response sent!')
            return
        # send request to next successor
        req_packet = libp2pproto.construct_req_packet(libp2pproto.PUT_FILE_OP_WORD, filename, ip_addr, libp2pproto.REQUEST_MSG)
        # TODO: error handling
        self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], req_packet, False)
        return

    def _handle_search_request(self, filename, ip_addr, msg_type):
        # handle responsible node replying to source node
        if(msg_type == libp2pproto.RESPONSE_MSG):
            if(ip_addr == '-1'):
                print("%s not found" % filename)
            else:
                print('Found %s, available at the following peers:' % filename)
                print(json.loads(ip_addr))
            return libp2puds.construct_empty_ok_res()
        filename_hash = utils.consistent_hash(filename.encode())
        if((filename_hash > self.peer.predecessor['id'] and filename_hash <= self.peer.peer_id)
            #filehash is larger than all peers
            or (self.peer.peer_id > self.peer.successor['id'] and filename_hash> self.peer.peer_id)
            #filehash is smaller than all peers
            or (self.peer.peer_id < self.peer.predecessor['id'] and filename_hash < self.peer.peer_id)):
            print('at responsible node')
            cursor = self.dbconn.cursor()
            cursor.execute(SELECT_QUERY, (filename,))
            datum = cursor.fetchone()
            if(datum == None):
                print('file not found')
                if(ip_addr == self.ip_addr):
                    print('file not found on source node')
                    return
                err_packet = libp2pproto.construct_req_packet(libp2pproto.GET_FILE_OP_WORD,filename,'-1',libp2pproto.RESPONSE_MSG)
                self._send_p2p_tcp_packet(ip_addr, err_packet, False)
                return
            ip_addr_str = datum[2].replace(' ', '')
            print(datum[2])
            if(ip_addr == self.ip_addr):
                if(ip_addr == None):
                    print("%s not found" % filename)
                else:
                    print('Found %s, available at the following peers:' % filename)
                    print(json.loads(ip_addr_str))
                return
            req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_FILE_OP_WORD,filename,ip_addr_str,libp2pproto.RESPONSE_MSG)
            print('file found, sending response')
            self._send_p2p_tcp_packet(ip_addr, req_packet, True)
            print('sent!!')
            return 
        # send request to next successor
        req_packet = libp2pproto.construct_req_packet(libp2pproto.GET_FILE_OP_WORD, filename, ip_addr, libp2pproto.REQUEST_MSG)
        print('SENDING PACKET: %s' %req_packet)
        # TODO: error handling
        self._send_p2p_tcp_packet(self.peer.successor["ip_addr"], req_packet, False)
        return

    def _handle_list_request(self, files_str, ip_addr, hop_count):
        if(hop_count != 0 and ip_addr == self.ip_addr):
            print('terminating')
            if(files_str != 'None'):
                print('FILES AVAILABLE:')
                files = json.loads(files_str)
                for datum in files:
                    print(datum)
            else:
                print('No Files Found')
            return libp2puds.construct_empty_ok_res()
        
        select_query = "SELECT * FROM p2pdht"
        cursor = self.dbconn.cursor()
        cursor.execute(select_query)
        data = cursor.fetchall()
        if(len(data) != 0):
            files = list()
            for datum in data:
                files.append(datum[1])
            if(files_str != 'None'):
                file_list = json.loads(files_str)
                file_list.extend(files)
            files_str = json.dumps(files).replace(' ', '')

        hop_count += 1
        req_packet = libp2pproto.construct_req_packet(libp2pproto.LIST_FILES_OP_WORD, files_str, ip_addr, hop_count)
        self._send_p2p_tcp_packet(self.peer.successor['ip_addr'], req_packet, False)
        return libp2puds.construct_empty_ok_res()



    def _setup_db(self):
        query = """
            CREATE TABLE IF NOT EXISTS p2pdht (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT,  ip_addr_list TEXT)
        """
        cursor = self.dbconn.cursor()
        cursor.execute(query)
        self.dbconn.commit()
        
    def run(self):
        self.dbconn = sqlite3.connect(DB_NAME)
        self._setup_db()
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data[1] is None:
                    self._accept_socket(key.fileobj, key.data[0])  # key.fileobj is the socket object
                else:
                    self._handle_connection(key, mask)
