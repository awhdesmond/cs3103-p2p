import hashlib
import datetime
import socket
import random
from functools import reduce

# PEERING CONSTANTS
M_EXPONENT = 10


def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def create_client_socket(host, port):
    # create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(host, port)
    return s


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
    return consistent_hash(filename)


def generate_peerid():
    currrent_time_str = str(datetime.datetime.now()).encode()
    return consistent_hash(currrent_time_str)


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
