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

def construct_unknonw_res():
    return construct_res_packet(UNKNOWN_RES_CODE, UNKNOWN_RES_MSG, [])

