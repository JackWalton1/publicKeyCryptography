import random
import hashlib
from ast import literal_eval
import re

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
BLOCK_SIZE = 16 # Bytes
"""
Task I. Implement Diffie Hellman Key Exchange
"""

class Person:
    def __init__(self, name, p, g, message):
        self.name = name
        self.p = p
        self.g = g
        self.rand_num = random.randint(1, 2**31 - 1)
        self.message = message
        self.pub_key_mine = 0
        self.pub_key_yours = 0
        self.secret = 0
        self.pkey = 0

def generate_key(person):
    person.pub_key_mine = pow(person.g, person.rand_num, person.p) 
    return

def send_pubkey(sender, reciever):
    reciever.pub_key_yours = sender.pub_key_mine
    return

def generate_secret(person):
    person.secret = pow(person.pub_key_yours, person.rand_num, person.p)
    return 

def generate_pkey(person):
    string_secret = str(person.secret)
    val_bytes = bytearray(hashlib.sha256(string_secret.encode('utf-8')).digest())
    person.pkey = bytes(val_bytes[:16])
    return
       
def hexToInt(hex):
    pattern = re.compile(r'\s+')
    hex = re.sub(pattern, '', hex)
    res = literal_eval("0x"+hex)
    return res


def main():
    # Diffie Hellman Key Exchange
    p = """B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371"""
    g = """A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5"""

    g = hexToInt(g)
    p = hexToInt(p)

    alice = Person('Alice', p, 1, "Hi Bob!")
    bob = Person('Bob', p, 1, "Hi Alice!")
    # add mallory to the key exchange, sets g to 1 
    mallory = Person('Mallory', p, 1, "ψ(｀∇´)ψ")
    # mallory generates her public key with tampered g
    generate_key(mallory)

    # alice and bob generates their public keys with tampered g
    generate_key(alice)
    generate_key(bob)

    send_pubkey(alice, bob)
    send_pubkey(bob, alice)


    generate_secret(alice)
    generate_secret(bob)
    # mallory generates her secret without ever having recieved/generated a public key, because the keys are the same
    mallory.pub_key_yours = mallory.pub_key_mine
    generate_secret(mallory)

    generate_pkey(alice)
    generate_pkey(bob)
    #now she has the private key
    generate_pkey(mallory)

    if (alice.pkey == bob.pkey):
        print("Same! - Key: ", alice.pkey, "(", len(alice.pkey), " bytes )")
    else:
        print("Different :( - Alice: ", alice.pkey, " Bob: ", bob.pkey)

    iv = get_random_bytes(16)
    cipher = AES.new(alice.pkey, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(bytes(alice.message.encode('utf-8')), 16))
    """ mallory grabs the ciphertext of alice's message"""
    decipher = AES.new(bob.pkey, AES.MODE_CBC, iv)
    message = decipher.decrypt(ciphertext)
    print(str(unpad(message, 16)))

    cipher = AES.new(bob.pkey, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(bytes(bob.message.encode('utf-8')), 16))
    """mallory grabs the ciphertext of bob's message"""
    decipher = AES.new(mallory.pkey, AES.MODE_CBC, iv)
    message = decipher.decrypt(ciphertext)
    print(str(unpad(message, 16)))

main()