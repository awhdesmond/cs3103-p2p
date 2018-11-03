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

RET_NEIGHBOURS_OP_WORD = "RET_NEIGHBOURS"
UPDATE_NEXT_SUCCESSOR = "UPDATE_NEXT_SUCCESSOR"
UPDATE_PREDECESSOR = "UPDATE_PREDECESSOR"

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

UNKNOWN_RES_CODE = 404
UNKNOWN_RES_MSG  = "OPERATION UNKNOWN"

FILE_NOT_FOUND_CODE = 404
FILE_NOT_FOUND_MSG  = "FILE NOT FOUND"

class GetNeighboursArgs(Enum):
    PREDECESSOR_ID = 0
    PREDECESSOR_IP_ADDR = 1
    SUCCESSOR_ID = 2
    SUCCESSOR_IP_ADDR = 3
    NEXT_SUCCESSOR_ID = 4
    NEXT_SUCCESSOR_IP_ADDR = 5

class RetNeighboursArgs(Enum):
    PREDECESSOR_ID = 0
    PREDECESSOR_IP_ADDR = 1
    SUCCESSOR_ID = 2
    SUCCESSOR_IP_ADDR = 3
    NEXT_SUCCESSOR_ID = 4
    NEXT_SUCCESSOR_IP_ADDR = 5

class UpdateNextSuccessorArgs(Enum):
    NEXT_SUCCESSOR_ID = 0
    NEXT_SUCCESSOR_IP_ADDR = 1

class UpdatePredecessorArgs(Enum):
    PREDECESSOR_ID = 0
    PREDECESSOR_IP_ADDR = 1


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
    pass

def construct_req_packet(op_word, arguments):
    args = []
    for arg in arguments:
        if arg:
            args.append(str(arg))
        else:
            args.append('-1')
    return op_word + ' ' + ' '.join(args) + '\r\n'

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

