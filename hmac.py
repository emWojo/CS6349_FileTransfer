import hashlib
import base64

# SHA256(k' xor opad || SHA256(k' xor ipad || m))
# msgs of size 512 bits
# REF: https://blog.titanwolf.in/a?ID=01650-20b33297-cbf3-4c8e-a0dc-360bc32acc01
# Assume key and msg are byte strings
def hmac_256(key, msg):
    #ipad = 00110110 repeating till packet length
    ipad = b'\x36' * 64
    #opad = 01011100 repeating till packet length
    opad = b'\x5c' * 64
    #Pad key with 0 at end if len < 512 bits
    if len(key) > 64:
        print("Error: Key must be <= 64 bytes (512 bits) long")
    padKey = key + b'\x00' * (64 - len(key))

    # XOR key with ipad to generate ipadkey
    ipadKey = xor_byte(padKey, ipad)
    # append msg to ipadkey and hash
    inHash = hashlib.sha256(ipadKey)
    inHash.update(msg)
    # XOR key with opad to generate opadKey
    opadKey = xor_byte(padKey, opad)
    # append hash to opadkey and hash
    outHash = hashlib.sha256(opadKey)
    outHash.update(inHash.digest())
    return outHash.digest()

def xor_byte(strA, strB):
    return bytes([a ^ b for a, b in zip(strA, strB)])


k = b'\x0b' * 20
data = b"Hi There"
result = hmac_256(k, data)
print(result.hex())