# p2pserver.py
# ------------
# The P2P server component
# Handle sharing, downloading, DHT queries
# Communicate with client via UNIX DOMAIN SOCKETS
import binascii
import os
import socket
import types
import utils
import json

import threading
from utils import generate_chunks_filename, get_file_chunk_byte, remove_chunk_suffix, get_chunk_number_from_filename

from peer import Peer

from libdhash.dhash import Dhash
from libchord.chord import Chord

from libprotocol import libp2pproto, libp2puds, libp2pdns
from libprotocol.libp2puds import UdsRequestPacket, UdsResponsePacket
from libprotocol.libp2pproto import P2PRequestPacket, P2PResponsePacket, send_p2p_tcp_packet
from libprotocol.libp2pdns import DnsRequestPacket, DnsResponsePacket


# CONSTANTS
CLIENT_UDS_PATH = "./p2pvar/uds_socket"
CLIENT_ROOT_PATH = "./p2pvar/"

DNS_IP_ADDR = "192.168.2.170"
DNS_PORT = 7494
PEER_PORT = 7495

MAX_PACKET_SIZE = 1024

STUN_SERVER_HOST = "stun1.l.google.com"
STUN_SERVER_PORT = 19302
STUN_RESP_CODE = "0101"
STUN_REQ_CODE = "0001"
STUN_MAPPED_ADDR_CODE = '0001'

class P2PServer(object):
    
    def __init__(self, ip_addr, dns_ip_addr):
        self.ip_addr       = ip_addr
        self.external_port = PEER_PORT
        self.dns_ip_addr = dns_ip_addr

        external_ip, external_port = self._retrieve_public_ip_stun()
        # TODO: UNCOMMENT THIS WHEN NAT IS NOT SYMMETRIC
        # self.ip_addr = external_ip
        # self.external_port = external_port

        self.peer  = Peer(self.ip_addr, self.external_port) 
        self.chord = Chord(self.peer)
        self.dhash = Dhash(self.peer)
            
    def uds_socket_worker(self):
        # Make sure the socket does not already exist
        try:
            if not os.path.exists(CLIENT_ROOT_PATH):
                os.makedirs(CLIENT_ROOT_PATH)
            os.unlink(CLIENT_UDS_PATH)
        except OSError:
            if os.path.exists(CLIENT_UDS_PATH):
                raise

        uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        uds_sock.bind(CLIENT_UDS_PATH)
        uds_sock.listen()
        
        while True:
            conn, addr = uds_sock.accept()
            conn_thread = threading.Thread(target=self._handle_uds_connection, args=(conn,))
            conn_thread.start()

    def p2p_socket_worker(self):
        peer_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_server_sock.bind(('', PEER_PORT))
        peer_server_sock.listen()
        
        while True:
            conn, addr = peer_server_sock.accept()
            conn_thread = threading.Thread(target=self._handle_p2p_connection, args=(conn,))
            conn_thread.start()
                
    def run(self):
        uds_server_thread = threading.Thread(name='UDS SERVER THREAD', target=self.uds_socket_worker)
        p2p_server_thread = threading.Thread(name='P2P SERVER THREAD', target=self.p2p_socket_worker)
        uds_server_thread.start()
        p2p_server_thread.start()

        while 1:
            pass

    def _handle_uds_connection(self, conn):
        data_string = ""
        while True:
            try:
                data_bytes = conn.recv(MAX_PACKET_SIZE)
                data_string = data_string + data_bytes.decode("utf-8")
                
                # print("-------", data.req_str)
                req_pkt = UdsRequestPacket.parse(data_string)
                res_pkt = self._process_uds_request(req_pkt)
                
                conn.sendall(res_pkt.encode_bytes())
                conn.close()
                break
            except ValueError as err:
                if int(str(err)) == libp2puds.MALFORMED_PACKET_ERROR:
                    malform_res = libp2puds.construct_malformed_res()
                    conn.sendall(malform_res.encode_bytes())
                

    def _handle_p2p_connection(self, socket):
        data_string = ""
        while True:
            try:
                data_bytes = socket.recv(MAX_PACKET_SIZE)
                data_string = data_string + data_bytes.decode("utf-8")
                
                # print("-------", data.req_str)
                req_pkt = P2PRequestPacket.parse(data_string)
                res_pkt = self._process_p2p_request(req_pkt)
                
                socket.sendall(res_pkt.encode_bytes())
                socket.close()
                break
            except ValueError as err:
                if int(str(err)) == libp2pproto.MALFORMED_PACKET_ERROR:
                    malform_res = libp2pproto.construct_malformed_res()
                    socket.sendall(malform_res.encode_bytes())

    ##
    ## UDS
    ##
    def _process_uds_request(self, req_pkt):
        op_word, args = req_pkt.op_word, req_pkt.args 
        #print(op_word, args)

        if op_word == libp2puds.INIT_PEER_TABLE_OP_WORD:
            self._enter_p2p_network()
            return libp2puds.construct_empty_ok_res()

        if op_word == libp2puds.UPLOAD_FILE_OP_WORD:
            filename = args[libp2pproto.PUT_FILE_FILENAME_INDEX]
            return self._handle_upload_file_request(filename)
            
        if op_word == libp2puds.DOWNLOAD_FILE_OP_WORD:
            filename = args[libp2pproto.GET_FILE_FILENAME_INDEX]
            return self._handle_download_file_request(filename)
        
        if op_word == libp2puds.LIST_ALL_FILES_OP_WORD:
            return self._handle_list_files_request()
        
        return libp2puds.construct_unknown_res()


    def _retrieve_peer_ip_port(self):
        # TODO: handle case if DNS is not up.
        dns_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dns_client_sock.connect((self.dns_ip_addr, DNS_PORT))
        message = DnsRequestPacket(libp2pdns.JOIN_REQ_OP_WORD, [self.peer.peer_id, self.ip_addr, self.external_port])
        dns_client_sock.sendall(message.encode_bytes())

        data_string = ""
        while True:
            try:
                data = dns_client_sock.recv(MAX_PACKET_SIZE)
                data_string = data_string + data.decode("utf-8")

                # print("-------", data_string)
                peers_ip_addr_port_list = libp2pdns.parse_message_to_peer_list(data_string)
                dns_client_sock.close()
                return peers_ip_addr_port_list
            except ValueError as err:
                if int(str(err)) == libp2puds.INCOMPLETE_PACKET_ERROR:
                    continue

    def _enter_p2p_network(self):
        peers_ip_port_list = self._retrieve_peer_ip_port()
        self.chord.enter_p2p_network(peers_ip_port_list)

    def _handle_upload_file_request(self, filename):
        ip_addr_port = self.ip_addr + ':' + str(self.external_port)
        
        for chunk_name in generate_chunks_filename(filename):
            print("Uploading:", chunk_name)
            success = self.dhash.put(chunk_name, ip_addr_port)

        return libp2puds.construct_empty_ok_res()

    def _handle_download_file_request(self, filename):
        overall_bytes = b""

        for chunk_name in generate_chunks_filename(filename):
            ip_addr_port = self.dhash.get(chunk_name)
        
            if ip_addr_port == None:
                return libp2puds.construct_unknown_res()
            else:
                ip_addr, port = ip_addr_port.split(":")[0], int(ip_addr_port.split(":")[1])
                print("Download source of %s is: %s" % (chunk_name, ip_addr_port))

                if ip_addr == self.ip_addr:
                    real_filename = remove_chunk_suffix(chunk_name)
                    chunk_number = get_chunk_number_from_filename(chunk_name)
                    byte_data = get_file_chunk_byte(real_filename, chunk_number)
                    overall_bytes = overall_bytes + byte_data
                else:
                    req_packet = P2PRequestPacket(libp2pproto.DOWNLOAD_FILE_OP_WORD, [chunk_name])
                    res_pkt = send_p2p_tcp_packet(self.peer.successor['ip_addr'], self.peer.successor['port'], req_packet)
                    
                    if len(res_pkt.data) > 0:
                        overall_bytes = overall_bytes + res_pkt.data[0].encode()
    
        return UdsResponsePacket(libp2puds.OK_RES_CODE, libp2puds.OK_RES_MSG, [overall_bytes.decode()])
    
    def _handle_list_files_request(self):
        data = self.dhash.get_local_keys()
        if self.peer.successor['id']:
            req_packet = P2PRequestPacket(libp2pproto.LIST_FILES_OP_WORD, [self.ip_addr])
            res_pkt = send_p2p_tcp_packet(self.peer.successor['ip_addr'], self.peer.successor['port'], req_packet)
            data = res_pkt.data + self.dhash.get_local_keys()
        
        data = [remove_chunk_suffix(f) for f in data] 
        return UdsResponsePacket(libp2puds.OK_RES_CODE, libp2puds.OK_RES_MSG, data)
    
    ##
    ## P2P
    ##
    def _process_p2p_request(self, req_pkt):
        op_word, args = req_pkt.op_word, req_pkt.args
        # print(op_word, args)

        if op_word == libp2pproto.GET_NEIGHBOURS_OP_WORD:
            peer_id = int(args[libp2pproto.GET_NEIGHBOURS_PEER_ID_INDEX])
            ip_addr = args[libp2pproto.GET_NEIGHBOURS_PEER_IP_ADDR_INDEX]
            port = int(args[libp2pproto.GET_NEIGHBOURS_PEER_PORT_INDEX])
            return self._handle_p2p_get_neighbors(peer_id, ip_addr, port)

        if op_word == libp2pproto.INFORM_PREDECESSOR_PREDECESSOR_OP_WORD:
            peer_id = int(args[libp2pproto.INFORM_PREDECESSOR_PEER_ID_INDEX])
            ip_addr = args[libp2pproto.INFORM_PREDECESSOR_PEER_IP_ADDR_INDEX]
            port = int(args[libp2pproto.INFORM_PREDECESSOR_PEER_PORT_INDEX])

            inform_packet = P2PRequestPacket(libp2pproto.INFORM_PREDECESSOR_OP_WORD,
                                             [self.peer.peer_id, self.peer.ip_addr, self.peer.external_port,
                                              peer_id, ip_addr, port])
            return send_p2p_tcp_packet(self.peer.predecessor["ip_addr"], self.peer.predecessor["port"], inform_packet)

        if op_word == libp2pproto.INFORM_PREDECESSOR_OP_WORD:
            peer_id = int(args[libp2pproto.INFORM_PREDECESSOR_PEER_ID_INDEX])
            ip_addr = args[libp2pproto.INFORM_PREDECESSOR_PEER_IP_ADDR_INDEX]
            port = int(args[libp2pproto.INFORM_PREDECESSOR_PEER_PORT_INDEX])

            next_successor_peer_id = int(args[libp2pproto.INFORM_PREDECESSOR_SUCCESSOR_PEER_ID_INDEX])
            next_successor_ip_addr = args[libp2pproto.INFORM_PREDECESSOR_SUCCESSOR_PEER_IP_ADDR_INDEX]
            next_successor_port = int(args[libp2pproto.INFORM_PREDECESSOR_SUCCESSOR_PEER_PORT_INDEX])

            return self._handle_p2p_inform_predecessor(peer_id, ip_addr, port,
                                                       next_successor_peer_id, next_successor_ip_addr, next_successor_port)

        if op_word == libp2pproto.INFORM_SUCCESSOR_OP_WORD:
            peer_id = int(args[libp2pproto.INFORM_SUCCESSOR_PEER_ID_INDEX])
            ip_addr = args[libp2pproto.INFORM_SUCCESSOR_PEER_IP_ADDR_INDEX]
            port = int(args[libp2pproto.INFORM_SUCCESSOR_PEER_PORT_INDEX])
            return self._handle_p2p_inform_successor(peer_id, ip_addr, port)

        if op_word == libp2pproto.QUERY_SUCCESSOR_FOR_NEIGHBOURS_OP_WORD:
            return self._handle_p2p_query_successor_for_neighbours()

        if op_word == libp2pproto.PUT_FILE_OP_WORD:
            filename = args[libp2pproto.PUT_FILE_FILENAME_INDEX]
            ip_addr_port = args[libp2pproto.PUT_FILE_IP_ADDR_PORT_INDEX]
            return self._handle_p2p_put_request(filename, ip_addr_port)

        if op_word == libp2pproto.GET_FILE_OP_WORD:
            filename = args[libp2pproto.GET_FILE_FILENAME_INDEX]
            return self._handle_p2p_get_request(filename)
        
        if op_word == libp2pproto.LIST_FILES_OP_WORD:
            ip_addr = args[libp2pproto.LIST_FILES_IP_ADDR_INDEX]
            return self._handle_p2p_list_request(ip_addr)

        if op_word == libp2pproto.DOWNLOAD_FILE_OP_WORD:
            filename = args[libp2pproto.DOWNLOAD_FILE_FILENAME_INDEX]
            return self._handle_p2p_download_request(filename)

        return libp2pproto.construct_unknown_res()
    

    def _handle_p2p_get_neighbors(self, new_peer_id, new_peer_ip_address, new_peer_port):
        data = self.chord.get_neighbours(new_peer_id, new_peer_ip_address, new_peer_port)
        print("GET NEIGHBOURS: ", data)
        return P2PResponsePacket(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])

    def _handle_p2p_inform_predecessor(self, peer_id, ip_addr, port,
                                       next_successor_peer_id, next_successor_ip_addr, next_successor_port):
        self.peer.successor["id"]      = peer_id
        self.peer.successor["ip_addr"] = ip_addr
        self.peer.successor["port"] = port

        # ignore case where only 2 nodes in the network
        if self.peer.peer_id == next_successor_peer_id:
            pass
        else:
            self.peer.next_successor["id"] = next_successor_peer_id
            self.peer.next_successor["ip_addr"] = next_successor_ip_addr
            self.peer.next_successor["port"] = next_successor_port

        self.dhash.update_responsible_keys()
        
        return libp2pproto.construct_empty_ok_res()

    def _handle_p2p_inform_successor(self, peer_id, ip_addr, port):
        self.peer.predecessor["id"]      = peer_id
        self.peer.predecessor["ip_addr"] = ip_addr
        self.peer.predecessor["port"] = port
        self.dhash.update_responsible_keys()
        
        return libp2pproto.construct_empty_ok_res()

    def _handle_p2p_query_successor_for_neighbours(self):
        data = "%d %s %s %d %s %s" % \
               (self.peer.predecessor["id"], self.peer.predecessor["ip_addr"], self.peer.predecessor["port"],
                self.peer.successor["id"], self.peer.successor["ip_addr"], self.peer.successor["port"])

        return P2PResponsePacket(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [data])

    def _handle_p2p_put_request(self, filename, ip_addr_port):
        success = self.dhash.put(filename, ip_addr_port)
        if success:
            return libp2pproto.construct_empty_ok_res()
        else:
            return libp2pproto.construct_error_res()

    def _handle_p2p_get_request(self, filename):
        ip_addr_port = self.dhash.get(filename)
        if ip_addr_port == None:
            return libp2pproto.construct_fnf_res()
        else:
            return P2PResponsePacket(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [ip_addr_port])

    def _handle_p2p_list_request(self, ip_addr):
        successor_data = []
        if self.peer.successor["ip_addr"] != ip_addr:
            req_packet = P2PRequestPacket(libp2pproto.LIST_FILES_OP_WORD, [ip_addr])
            res_pkt = send_p2p_tcp_packet(self.peer.successor['ip_addr'], self.peer.successor['port'], req_packet)
            successor_data = res_pkt.data

        successor_data = successor_data + self.dhash.get_local_keys()
        return P2PResponsePacket(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, successor_data)


    def _handle_p2p_download_request(self, filename):
        real_filename = remove_chunk_suffix(filename)
        chunk_number = get_chunk_number_from_filename(filename)
        byte_data = get_file_chunk_byte(real_filename, chunk_number)
        return P2PResponsePacket(libp2pproto.OK_RES_CODE, libp2pproto.OK_RES_MSG, [byte_data.decode()])


    ##
    ## STUN
    ##

    def _retrieve_public_ip_stun(self):
        # Blocking.
        stun_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        stun_socket.settimeout(2)
        stun_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        stun_socket.bind(('', PEER_PORT))

        send_data = ""
        str_len = "0000"
        tranid = utils.gen_tran_id()
        str_data = ''.join([STUN_REQ_CODE, str_len, tranid, send_data])
        data = binascii.a2b_hex(str_data)

        stun_socket.sendto(data, (STUN_SERVER_HOST, STUN_SERVER_PORT))

        extenal_ip = ''
        external_port = ''
        buf = stun_socket.recv(MAX_PACKET_SIZE)
        stun_socket.close()

        msgtype = binascii.b2a_hex(buf[0:2]).decode()
        tranid_ret = binascii.b2a_hex(buf[4:20]).decode().upper()

        if msgtype == STUN_RESP_CODE and tranid_ret == tranid:
            len_message = int(binascii.b2a_hex(buf[2:4]), 16)
            base = 20

            while len_message:
                attr_type = binascii.b2a_hex(buf[base:(base + 2)]).decode()
                attr_len = int(binascii.b2a_hex(buf[(base + 2):(base + 4)]), 16)
                if attr_type == STUN_MAPPED_ADDR_CODE:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(buf[base + 11:base + 12]), 16))
                    ])
                    extenal_ip = ip
                    external_port = port
                base = base + 4 + attr_len
                len_message -= (4 + attr_len)
        
        print("External IP: ", extenal_ip, "\t\tExternal Port: ", external_port)
        return extenal_ip, external_port


    