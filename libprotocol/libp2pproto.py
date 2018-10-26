# libp2pproto.py
# --------------
# Processing and helper code for P2P node <-> P2P node
# communication

import utils

MALFORMED_PACKET_ERROR  = 1
INCOMPLETE_PACKET_ERROR = 2

PUT_FILE_OP_WORD = "PUT"
GET_FILE_OP_WORD = "GET"

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

UNKNOWN_RES_CODE = 404
UNKNOWN_RES_MSG  = "OPERATION UNKNOWN"

FILE_NOT_FOUND_CODE = 404
FILE_NOT_FOUND_MSG  = "FILE NOT FOUND"

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
    pass

def construct_res_packet(code, message, data):
    pass

def construct_malformed_res():
    return construct_res_packet(MALFORMED_RES_CODE, MALFORMED_RES_MSG, [])

def construct_unknonw_res():
    return construct_res_packet(UNKNOWN_RES_CODE, UNKNOWN_RES_MSG, [])

def construct_file_not_found_res():
    return construct_res_packet(FILE_NOT_FOUND_CODE, FILE_NOT_FOUND_MSG, [])

