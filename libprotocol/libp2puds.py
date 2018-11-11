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

ERROR_RES_CODE = 500
ERROR_RES_MSG = "ERROR OCCURRED"

class UdsRequestPacket(object):
    delimeter = "\r\n"

    @staticmethod
    def parse(string):
        if UdsRequestPacket.delimeter in string:
            tokens = string.strip().split(" ")

            if len(tokens) <= 0:
                raise ValueError(MALFORMED_PACKET_ERROR)

            return UdsRequestPacket(tokens[0], tokens[1:])
        else:
            raise ValueError(INCOMPLETE_PACKET_ERROR)

    def __init__(self, op_word, args):
        self.op_word = op_word
        self.args    = args

    def stringify(self):
        return self.op_word.strip() + " " \
                + " ".join([str(a) for a in self.args]) \
                + UdsRequestPacket.delimeter

    def encode_bytes(self):
        return self.stringify().encode()


class UdsResponsePacket(object):
    delimeter = "\r\n"

    @staticmethod
    def parse(string):
        if UdsResponsePacket.delimeter in string:
            status_line = string.split(UdsResponsePacket.delimeter)[0] 
            status_tokens = status_line.split(" ")
            if len(status_tokens) < 3: # CHECK MALFORM STATUS LINE
                raise ValueError(MALFORMED_PACKET_ERROR)
            
            datalines = utils.remove_empty_string_from_arr(string.split(UdsResponsePacket.delimeter)[1:])
            num_data_bytes = int(status_line.split(" ")[-1])
            if len(string[string.index(UdsResponsePacket.delimeter) + 2:]) == num_data_bytes: 
                ## OK HERE
                code = int(status_tokens[0])
                msg = status_tokens[1:-1]
                data = list(map(lambda x: x.strip(), datalines))
                return  UdsResponsePacket(code, msg, data)

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
            datalines = datalines + item_line + UdsResponsePacket.delimeter

        data_bytes_len = len(datalines.encode())
        status_line = "%d %s %d%s" % (self.code, self.msg, data_bytes_len, UdsResponsePacket.delimeter)
        return status_line + datalines

    def encode_bytes(self):
        return self.stringify().encode()

## Construct Request Packets
def construct_init_req():
    return UdsRequestPacket(INIT_PEER_TABLE_OP_WORD, [])

def construct_list_files_req():
    return UdsRequestPacket(LIST_ALL_FILES_OP_WORD, [])
    
def construct_search_file_req(filename):
    return UdsRequestPacket(SEARCH_FILE_OP_WORD, [filename])

def construct_download_file_req(filename):
    return UdsRequestPacket(DOWNLOAD_FILE_OP_WORD, [filename])
    
def construct_upload_file_req(filename):
    return UdsRequestPacket(UPLOAD_FILE_OP_WORD, [filename])
    
## Construct Response Packets
def construct_empty_ok_res():
    return UdsResponsePacket(OK_RES_CODE, OK_RES_MSG, [])

def construct_empty_error_res():
    return UdsResponsePacket(ERROR_RES_CODE, ERROR_RES_MSG, [])

def construct_malformed_res():
    return UdsResponsePacket(MALFORMED_RES_CODE, MALFORMED_RES_MSG, [])

def construct_unknown_res():
    return UdsResponsePacket(UNKNOWN_RES_CODE, UNKNOWN_RES_MSG, [])