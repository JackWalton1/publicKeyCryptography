import random
import hashlib
from ast import literal_eval
import re
from itertools import chain
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_hash(input):
    string_secret = str(input)
    val_bytes = bytearray(hashlib.sha256(string_secret.encode('utf-8')).digest())
    return bytes(val_bytes[0:3]).hex()

# input1 = "njsdjcn31rnjdsvan53tn6gnfwdv"
# input2 = "nbajifgnqjivbwiepnvj445tg98bn wdcvfwvwv"
past_hashes = {0: generate_hash(0)}
input = 1
 
# use a dictionary to compare the current hashes
def find_collision(dictionary, i):
    result_hash = []
    while(len(result_hash) == 0):
        past_hashes.__setitem__(i, generate_hash(i))
        rev_dict = {}
        for key, value in dictionary.items():
            rev_dict.setdefault(value, set()).add(key)
        result_hash = [key for key, values in rev_dict.items() if len(values) > 1]
        if(len(result_hash)>0):
            result_inputs = set(chain.from_iterable(values for key, values in rev_dict.items() if len(values) > 1))
        else:
            i = i +1

    print(len(dictionary))
    return (result_hash, result_inputs)

start = time.time()
answer = find_collision(past_hashes, input)
end = time.time()
print(answer)
print(end - start)
