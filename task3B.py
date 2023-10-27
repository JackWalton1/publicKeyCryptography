import re
from ast import literal_eval
from Crypto.Util import number
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# c’ = F(c)
# (c* 1^e) mod n
prime_length = 2048
bobs_message = "Hello Alice!"
# mallorys_message = "ψ(｀∇´)ψ"

e = 65537

def messageToInt(message):
    s = message.encode('utf-8')
    hex = s.hex()
    pattern = re.compile(r'\s+')
    hex = re.sub(pattern, '', hex)
    res = literal_eval("0x"+hex)
    return res

mIntBobs = messageToInt(bobs_message)
p_alice = number.getPrime(prime_length)
q_alice = number.getPrime(prime_length)
n_alice = p_alice * q_alice
phi_alice = (p_alice-1) * (q_alice-1)

# mIntMallorys = messageToInt(mallorys_message)

def generate_ciphertext(m_Int, e, n):
    ciphertext = pow(m_Int, e, n)
    return ciphertext

bobsCiphertext = generate_ciphertext(mIntBobs, e, n_alice)
"""mallory takes the ciphertext and does some predictable operation on it"""
malloriedCiphertext = pow(bobsCiphertext, e, n_alice)
# mallorysCiphertext = generate_ciphertext(mIntMallorys, e, n_alice)

# def calculate_pkey(e, phi):
#     j = 0
#     d = 0
#     while (d==0):
#         if (j * e) % phi == 1:
#             d = j
#         j += 1
#     return d

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(e, phi):
    # Calculate the modular multiplicative inverse of e modulo phi
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("The modular inverse does not exist")
    else:
        return x % phi

# mallory can calculate pkey "d"
d = modinv(e, phi_alice)

def generate_secret(c, d, n):
    return pow(c, d, n) 

def generate_pkey(s):
    string_secret = str(s)
    val_bytes = bytearray(hashlib.sha256(string_secret.encode('utf-8')).digest())
    return bytes(val_bytes[:16])

iv = get_random_bytes(16)
"""mallory replaces the ciphertext with the predictable ciphertext she generated"""
bobs_pkey = generate_pkey(generate_secret(malloriedCiphertext, d, n_alice))
cipher = AES.new(bobs_pkey, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(bytes(bobs_message.encode('utf-8')), 16))
mallory_pkey = generate_pkey(generate_secret(malloriedCiphertext, d, n_alice))
"""mallory deciphers the message"""
decipher = AES.new(mallory_pkey, AES.MODE_CBC, iv)
message = decipher.decrypt(ciphertext)
print(str(unpad(message, 16)))
