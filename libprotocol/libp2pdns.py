MALFORMED_PACKET_ERROR  = 1
INCOMPLETE_PACKET_ERROR = 2

JOIN_REQ_OP_WORD = "JOIN"

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

UNKNOWN_RES_CODE = 404
UNKNOWN_RES_MSG  = "OPERATION UNKNOWN"

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

## Construct Response Packets
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

def parse_message_to_peer_list(string):
    if "\r\n" in string:
        peers = string.split("\r\n")
        header_info = peers[0]
        peer_list = []
        for peer_index in range(1, len(peers) - 1): # to len(peers) - 1 here because of final \r\n in list
            peer_info = peers[peer_index].split(",")
            index = peer_info[0]
            peer_id = peer_info[1]
            ip_addr = peer_info[2]
            peer_list.append(ip_addr)
        return peer_list

    else:
        raise ValueError(INCOMPLETE_PACKET_ERROR)
