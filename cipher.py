import secrets
import hashlib

# TODO: Improvements
# One time pad?? generate key based on current one somehow have it be same for client and server
# Generate same random number for client and server xor it repeating for length of msg along with key

# assue msg is 512 bits or less
def encode(key, msg):
    if len(key) > 56:
        print("Error: Key must be <= 56 bytes (448 bits) long")
    padKey = key + b'\x00' * (56 - len(key))
    padMsg = msg + b'\x00' * (56 - len(msg))

    salt = secrets.token_bytes(8)
    keyHash = hashlib.sha256(salt)
    keyHash.update(padKey)
    encMsg = xor_byte(keyHash.digest(), padMsg)
    return salt, encMsg

def decode(salt, key, ecMsg):
    padKey = key + b'\x00' * (56 - len(key))
    keyHash = hashlib.sha256(salt)
    keyHash.update(padKey)
    msg = xor_byte(keyHash.digest(), ecMsg)
    return msg

def xor_byte(strA, strB):
    return bytes([a ^ b for a, b in zip(strA, strB)])


k = b'\x0b' * 56
data = b"Hi There"
s, encRes = encode(k,data)
print(encRes.hex())
decres = decode(s, k, encRes)
print(decres)