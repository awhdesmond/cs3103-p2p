import utils

MALFORMED_PACKET_ERROR  = 1
INCOMPLETE_PACKET_ERROR = 2

INIT_PEER_TABLE_OP_WORD = "INIT_PEER_TABLE"
LIST_ALL_FILES_OP_WORD  = "LIST_ALL_FILES"
SEARCH_FILE_OP_WORD     = "SEARCH"
DOWNLOAD_FILE_OP_WORD   = "DOWNLOAD"
UPLOAD_FILE_OP_WORD     = "UPLOAD"

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

UNKNOWN_RES_CODE = 404
UNKNOWN_RES_MSG  = "OPERATION UNKNOWN"

## PARSE REQUEST
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

## PARSE RESPONSE
def parse_string_to_res_packet(string):
    if "\r\n" in string:

        status_line = string.split("\r\n")[0] 
        status_tokens = status_line.split(" ")
        if len(status_tokens) < 3: # CHECK MALFORM STATUS LINE
            raise ValueError(MALFORMED_PACKET_ERROR)
        
        datalines = utils.remove_empty_string_from_arr(string.split("\r\n")[1:])
        num_data_bytes = int(status_line.split(" ")[-1])
        if len(datalines) == num_data_bytes: 
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

## Construct Request Packets
def construct_req_packet(op_word, arguments):
    return op_word.strip() + " " + " ".join(arguments) + "\r\n"

def construct_init_req():
    return construct_req_packet(INIT_PEER_TABLE_OP_WORD, ())

def construct_list_files_req():
    return construct_req_packet(LIST_ALL_FILES_OP_WORD, ())

def construct_search_file_req(filename):
    return construct_req_packet(SEARCH_FILE_OP_WORD, (filename,))

def construct_download_file_req(filename):
    return construct_req_packet(DOWNLOAD_FILE_OP_WORD, (filename,))

def construct_upload_file_req(filename):
    return construct_req_packet(UPLOAD_FILE_OP_WORD, (filename,))

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
