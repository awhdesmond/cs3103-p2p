# libp2pproto.py
# --------------
# Processing and helper code for P2P node <-> P2P node
# communication

import utils
from enum import Enum

MALFORMED_PACKET_ERROR  = 1
INCOMPLETE_PACKET_ERROR = 2

PUT_FILE_OP_WORD = "PUT"
GET_FILE_OP_WORD = "GET"

GET_NEIGHBOURS_OP_WORD = "GET_NEIGHBOURS"
GET_NEIGHBOURS_PEER_ID_INDEX = 0
GET_NEIGHBOURS_PEER_IP_ADDR_INDEX = 1

INFORM_SUCCESSOR_OP_WORD = "INFORM_SUCCESSOR"
INFORM_SUCCESSOR_PEER_ID_INDEX = 0
INFORM_SUCCESSOR_PEER_IP_ADDR_INDEX = 1

INFORM_PREDECESSOR_OP_WORD = "INFORM_PREDECESSOR"
INFORM_PREDECESSOR_PEER_ID_INDEX = 0
INFORM_PREDECESSOR_PEER_IP_ADDR_INDEX = 1

QUERY_SUCCESSOR_FOR_PREDECESSOR_OP_WORD = "QUERY_SUCCESSOR_FOR_PREDECESSOR" 
QUERY_SUCCESSOR_FOR_PREDECESSOR_PEER_ID_INDEX = 0
QUERY_SUCCESSOR_FOR_PREDECESSOR_PEER_IP_ADDR_INDEX = 1

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

UNKNOWN_RES_CODE = 404
UNKNOWN_RES_MSG  = "OPERATION UNKNOWN"

FILE_NOT_FOUND_CODE = 404
FILE_NOT_FOUND_MSG  = "FILE NOT FOUND"

class GetNeighboursDataArgs(Enum):
    PREDECESSOR_ID = 0
    PREDECESSOR_IP_ADDR = 1
    SUCCESSOR_ID = 2
    SUCCESSOR_IP_ADDR = 3

def parse_string_to_req_packet(string):
    if "\r\n" in string:
        tokens = string.strip().split(" ")

        if len(tokens) <= 0:
            raise ValueError(MALFORMED_PACKET_ERROR)

        return {
            "op": tokens[0],
            "args": tokens[1:]
        }
    else:
        raise ValueError(INCOMPLETE_PACKET_ERROR)

def parse_string_to_res_packet(string):
    if "\r\n" in string:

        status_line = string.split("\r\n")[0] 
        status_tokens = status_line.split(" ")
        if len(status_tokens) < 3: # CHECK MALFORM STATUS LINE
            raise ValueError(MALFORMED_PACKET_ERROR)
        
        datalines = utils.remove_empty_string_from_arr(string.split("\r\n")[1:])
        num_data_bytes = int(status_line.split(" ")[-1])
        if len(string[string.index("\r\n") + 2:]) == num_data_bytes: 
            ## OK HERE
            return {
                "code": int(status_line.split(" ")[0]),
                "msg": status_line.split(" ")[1:-1],
                "data": list(map(lambda x: x.strip(), datalines))
            }
        elif len(datalines) < num_data_bytes: 
            ## still got more to receive
            raise ValueError(INCOMPLETE_PACKET_ERROR)
        else: 
            # data do not match data length
            raise ValueError(MALFORMED_PACKET_ERROR) 
    else:
        ## still got more to receive
        raise ValueError(INCOMPLETE_PACKET_ERROR)

def construct_req_packet(op_word, *args):
    return op_word + " " + " ".join([str(a) for a in list(args)]) + " " + "\r\n"

def construct_res_packet(code, message, data):
    datalines = ""
    for item_line in data:
        datalines = datalines + item_line + "\r\n"

    data_bytes_len = len(datalines.encode())
    status_line = "%d %s %d\r\n" % (code, message, data_bytes_len)
    return status_line + datalines

def construct_malformed_res():
    return construct_res_packet(MALFORMED_RES_CODE, MALFORMED_RES_MSG, [])

def construct_unknown_res():
    return construct_res_packet(UNKNOWN_RES_CODE, UNKNOWN_RES_MSG, [])

def construct_file_not_found_res():
    return construct_res_packet(FILE_NOT_FOUND_CODE, FILE_NOT_FOUND_MSG, [])

