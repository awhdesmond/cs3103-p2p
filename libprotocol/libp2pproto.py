# libp2pproto.py
# --------------
# Processing and helper code for P2P node <-> P2P node
# communication

import utils
import socket

MALFORMED_PACKET_ERROR  = 1
INCOMPLETE_PACKET_ERROR = 2
REQUEST_MSG = 1
RESPONSE_MSG = 2

PUT_FILE_OP_WORD = "PUT"
PUT_FILE_FILENAME_INDEX = 0
PUT_FILE_IP_ADDR_PORT_INDEX = 1

GET_FILE_OP_WORD = "GET"
GET_FILE_FILENAME_INDEX = 0

LIST_FILES_OP_WORD = "LIST"
LIST_FILES_IP_ADDR_INDEX = 0

GET_NEIGHBOURS_OP_WORD = "GET_NEIGHBOURS"
GET_NEIGHBOURS_PEER_ID_INDEX = 0
GET_NEIGHBOURS_PEER_IP_ADDR_INDEX = 1
GET_NEIGHBOURS_PEER_PORT_INDEX = 2

INFORM_SUCCESSOR_OP_WORD = "INFORM_SUCCESSOR"
INFORM_SUCCESSOR_PEER_ID_INDEX = 0
INFORM_SUCCESSOR_PEER_IP_ADDR_INDEX = 1
INFORM_SUCCESSOR_PEER_PORT_INDEX = 2

INFORM_PREDECESSOR_OP_WORD = "INFORM_PREDECESSOR"
INFORM_PREDECESSOR_PEER_ID_INDEX = 0
INFORM_PREDECESSOR_PEER_IP_ADDR_INDEX = 1
INFORM_PREDECESSOR_PEER_PORT_INDEX = 2
INFORM_PREDECESSOR_SUCCESSOR_PEER_ID_INDEX = 3
INFORM_PREDECESSOR_SUCCESSOR_PEER_IP_ADDR_INDEX = 4
INFORM_PREDECESSOR_SUCCESSOR_PEER_PORT_INDEX = 5

INFORM_PREDECESSOR_PREDECESSOR_OP_WORD = "INFORM_PREDECESSOR_PREDECESSOR"
INFORM_PREDECESSOR_PREDECESSOR_PEER_ID_INDEX = 0
INFORM_PREDECESSOR_PREDECESSOR_PEER_IP_ADDR_INDEX = 1
INFORM_PREDECESSOR_PREDECESSOR_PEER_PORT_INDEX = 2

QUERY_SUCCESSOR_FOR_NEIGHBOURS_OP_WORD = "QUERY_SUCCESSOR_FOR_NEIGHBOURS"
QUERY_SUCCESSOR_FOR_NEIGHBOURS_PEER_ID_INDEX = 0
QUERY_SUCCESSOR_FOR_NEIGHBOURS_PEER_IP_ADDR_INDEX = 1

DOWNLOAD_FILE_OP_WORD = "DOWNLOAD_FILE"
DOWNLOAD_FILE_FILENAME_INDEX = 0

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

IN_PROGRESS_CODE = 202
IN_PROGRESS_MESSAGE = "OPERATION IN PROGRESS"

FILE_NOT_FOUND_CODE = 404
FILE_NOT_FOUND_MSG  = "FILE NOT FOUND"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

ERROR_RES_CODE = 500
ERROR_RES_MSG  = "ERROR"

UNKNOWN_RES_CODE = 600
UNKOWN_RES_MSG  = "UNKNOW OPERATION"


class P2PRequestPacket(object):
    delimeter = "\r\n"

    @staticmethod
    def parse(string):
        if P2PRequestPacket.delimeter in string:
            tokens = string.strip().split(" ")

            if len(tokens) <= 0:
                raise ValueError(MALFORMED_PACKET_ERROR)

            return P2PRequestPacket(tokens[0], tokens[1:])
        else:
            raise ValueError(INCOMPLETE_PACKET_ERROR)


    def __init__(self, op_word, args):
        self.op_word = op_word
        self.args = args

    def stringify(self):
        return self.op_word.strip() + " " \
                + " ".join([str(a) for a in self.args]) \
                + P2PRequestPacket.delimeter

    def encode_bytes(self):
        return self.stringify().encode()


class P2PResponsePacket(object):
    delimeter = "\r\n"

    @staticmethod
    def parse(string):
        if P2PResponsePacket.delimeter in string:
            status_line = string.split(P2PResponsePacket.delimeter)[0] 
            status_tokens = status_line.split(" ")
            if len(status_tokens) < 3: 
                # CHECK MALFORM STATUS LINE
                raise ValueError(MALFORMED_PACKET_ERROR)
            
            datalines = utils.remove_empty_string_from_arr(string.split(P2PResponsePacket.delimeter)[1:])
            num_data_bytes = int(status_line.split(" ")[-1])
            if len(string[string.index(P2PResponsePacket.delimeter) + 2:]) == num_data_bytes: 
                ## OK HERE
                code = int(status_tokens[0])
                msg = status_tokens[1:-1]
                data = list(map(lambda x: x.strip(), datalines))
                return  P2PResponsePacket(code, msg, data)
            elif len(datalines) < num_data_bytes: 
                ## still got more to receive
                raise ValueError(INCOMPLETE_PACKET_ERROR)
            else: 
                # data do not match data length
                raise ValueError(MALFORMED_PACKET_ERROR) 
        else:
            ## still got more to receive
            raise ValueError(INCOMPLETE_PACKET_ERROR)


    def __init__(self, code, msg, data):
        self.code = code
        self.msg  = msg
        self.data = data

    def stringify(self):
        datalines = ""
        for item_line in self.data:
            datalines = datalines + item_line + P2PResponsePacket.delimeter

        data_bytes_len = len(datalines.encode())
        status_line = "%d %s %d%s" % (self.code, self.msg, data_bytes_len, P2PResponsePacket.delimeter)
        return status_line + datalines

    def encode_bytes(self):
        return self.stringify().encode()


## Construct Response Packets
def construct_empty_ok_res():
    return P2PResponsePacket(OK_RES_CODE, OK_RES_MSG, [])

def construct_error_res():
    return P2PResponsePacket(ERROR_RES_CODE, ERROR_RES_MSG, [])

def construct_fnf_res():
    return P2PResponsePacket(FILE_NOT_FOUND_CODE, FILE_NOT_FOUND_MSG, [])

def construct_malformed_res():
    return P2PResponsePacket(MALFORMED_RES_CODE, MALFORMED_RES_MSG, [])

def construct_unknown_res():
    return P2PResponsePacket(UNKNOWN_RES_CODE, UNKNOWN_RES_MSG, [])


## Send TCP Packets
def send_p2p_tcp_packet(dst_ip_addr, dst_port, packet):
    # This should be blocking -- easier to reason about -- TODO: make not blocking
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((dst_ip_addr, int(dst_port)))
    tcp_socket.sendall(packet.encode_bytes())

    data_string = ""
    while True:
        try:
            data = tcp_socket.recv(1024)
            data_string = data_string + data.decode("utf-8")
            
            # print("-------", data_string)
            res_pkt = P2PResponsePacket.parse(data_string)
            tcp_socket.close()
            return res_pkt
        except ValueError as err:
            if int(str(err)) == INCOMPLETE_PACKET_ERROR:
                continue
            if int(str(err)) == MALFORMED_PACKET_ERROR:
                raise err