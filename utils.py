import hashlib
import datetime
import socket
import random
import math
from functools import reduce

# PEERING CONSTANTS
M_EXPONENT = 10
N_CHUNKS = 10

##
## Hashing
##
def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def consistent_hash(string):
    hash_object = hashlib.sha1(string)
    hex_dig = hash_object.hexdigest()

    bits_arr = tobits(hex_dig)[-M_EXPONENT:]
    binary_exp = 0
    key = 1
    for bit in bits_arr[::-1]:
        key = key + bit * (2 ** binary_exp)
        binary_exp = binary_exp + 1

    return key

def generate_filename_hash(filename):
    return consistent_hash(filename.encode())

def generate_peerid():
    currrent_time_str = str(datetime.datetime.now()).encode()
    return consistent_hash(currrent_time_str)

##
## File Handling
##
def generate_chunks_filename(filename):
    return [(filename + "-cs3103-chunk%d" % i) for i in range(0, N_CHUNKS)]

def get_file_chunk_byte(filename, chunk):
    file = open(filename, 'rb')
    data = file.read()
    
    chunk_size = len(data) / 10
    if chunk_size < 1:
        if chunk == 0:
            return data
        else:
            return b""
    
    chunk_size = math.floor(chunk_size)
    if chunk < N_CHUNKS - 1:
        return data[chunk * chunk_size: chunk * chunk_size + chunk_size]
    else:
        return data[chunk * chunk_size:]



def remove_empty_string_from_arr(arr):
    return list(filter(lambda x: x != '', arr))

def get_arguments(args, index, is_int=False):
    if args[index] == "-1":
        return None
    else:
        return int(args[index]) if is_int else args[index]

def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for _ in range(32))
    return a
