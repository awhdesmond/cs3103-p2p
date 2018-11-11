MALFORMED_PACKET_ERROR  = 1
INCOMPLETE_PACKET_ERROR = 2

JOIN_REQ_OP_WORD = "JOIN"

OK_RES_CODE = 200
OK_RES_MSG  = "OK"

MALFORMED_RES_CODE = 422
MALFORMED_RES_MSG  = "MALFORMED"

UNKNOWN_RES_CODE = 404
UNKNOWN_RES_MSG  = "OPERATION UNKNOWN"

class DnsRequestPacket(object):
    delimeter = "\r\n"

    @staticmethod
    def parse(string):
        if DnsRequestPacket.delimeter in string:
            tokens = string.strip().split(" ")

            if len(tokens) <= 0:
                raise ValueError(MALFORMED_PACKET_ERROR)

            return DnsRequestPacket(tokens[0], tokens[1:])
        else:
            raise ValueError(INCOMPLETE_PACKET_ERROR)

    def __init__(self, op_word, args):
        self.op_word = op_word
        self.args = args

    def stringify(self):
        return self.op_word.strip() + " " \
                + " ".join([str(a) for a in self.args]) \
                + DnsRequestPacket.delimeter

    def encode_bytes(self):
        return self.stringify().encode()

class DnsResponsePacket(object):
    delimeter = "\r\n"

    @staticmethod
    def parse(string):
        if DnsResponsePacket.delimeter in string:
            status_line = string.split(DnsResponsePacket.delimeter)[0] 
            status_tokens = status_line.split(" ")
            if len(status_tokens) < 3: # CHECK MALFORM STATUS LINE
                raise ValueError(MALFORMED_PACKET_ERROR)
            
            datalines = utils.remove_empty_string_from_arr(string.split(DnsResponsePacket.delimeter)[1:])
            num_data_bytes = int(status_line.split(" ")[-1])
            if len(string[string.index(DnsResponsePacket.delimeter) + 2:]) == num_data_bytes: 
                ## OK HERE
                code = int(status_tokens[0])
                msg = status_tokens[1:-1]
                data = list(map(lambda x: x.strip(), datalines))
                return  DnsResponsePacket(code, msg, data)
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
        self.code           = code
        self.msg            = msg
        self.data           = data

    def stringify(self):
        datalines = ""
        for item_line in self.data:
            datalines = datalines + item_line + DnsResponsePacket.delimeter

        data_bytes_len = len(datalines.encode())
        status_line = "%d %s %d%s" % (self.code, self.msg, data_bytes_len, DnsResponsePacket.delimeter)
        return status_line + datalines

    def encode_bytes(self):
        return self.stringify().encode()

## Construct Response Packets
def construct_malformed_res():
    return DnsResponsePacket(MALFORMED_RES_CODE, MALFORMED_RES_MSG, [])

def construct_unknown_res():
    return DnsResponsePacket(UNKNOWN_RES_CODE, UNKNOWN_RES_MSG, [])

def parse_message_to_peer_list(string):
    if "\r\n" in string:
        peers = string.split("\r\n")
        
        header_info = peers[0]
        peer_list   = []
        
        for peer_index in range(1, len(peers) - 1): # to len(peers) - 1 here because of final \r\n in list
            peer_info = peers[peer_index].split(",")
            ip_addr = peer_info[2]
            port = peer_info[3]
            peer_list.append((ip_addr, port))
        return peer_list

    else:
        raise ValueError(INCOMPLETE_PACKET_ERROR)
