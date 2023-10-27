import re
from ast import literal_eval
from Crypto.Util import number

prime_length = 2048
bobs_message = "Hello Alice!"
e = 65537

def messageToInt(message):
    s = message.encode('utf-8')
    hex = s.hex()
    pattern = re.compile(r'\s+')
    hex = re.sub(pattern, '', hex)
    res = literal_eval("0x"+hex)
    return res

mInt = messageToInt(bobs_message)
p_alice = number.getPrime(prime_length)
q_alice = number.getPrime(prime_length)
n_alice = p_alice * q_alice
phi_alice = (p_alice-1) * (q_alice-1)

def generate_ciphertext(m_Int, e, n):
    ciphertext = pow(m_Int, e, n)
    return ciphertext

ciphertext = generate_ciphertext(mInt, e, n_alice)

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

# d = calculate_pkey(e, phi_alice)
d = modinv(e, phi_alice)

def decrypt(ciphertext, d, n):
    message = pow(ciphertext, d, n)
    return message

print(d)


messageAsInt = decrypt(ciphertext, d, n_alice)
messageAsHex = hex(messageAsInt)
byte_string = bytes.fromhex(messageAsHex[2:])            
result = byte_string.decode('utf-8')

# print(mInt)
# print(e)
# print(phi_alice)
print(result)
