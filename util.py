import hashlib

def hmac_256(key, msg):
    #ipad = 00110110 repeating till packet length
    ipad = b'\x36' * 64
    #opad = 01011100 repeating till packet length
    opad = b'\x5c' * 64
    #Pad key with 0 at end if len < 512 bits
    if len(key) > 64:
        print("Error: Key must be <= 64 bytes (512 bits) long")
    padMsg = msg + b'\x00' * (64 - len(msg))
    padKey = key + b'\x00' * (64 - len(key))

    # XOR key with ipad to generate ipadkey
    ipadKey = xor_byte(padKey, ipad)
    # append msg to ipadkey and hash
    inHash = hashlib.sha256(ipadKey)
    inHash.update(padMsg)
    # XOR key with opad to generate opadKey
    opadKey = xor_byte(padKey, opad)
    # append hash to opadkey and hash
    outHash = hashlib.sha256(opadKey)
    outHash.update(inHash.digest())
    return outHash.digest()

def encode(key, msg):
    if len(key) > 64:
        print("Error: Key must be <= 64 bytes (512 bits) long")
    if len(msg) > 32:
        print("Error: Msg must be <= 32 bytes (256 bits) long")
    padKey = key + b'\x00' * (64 - len(key))
    padMsg = msg + b'\x00' * (64 - len(msg))

    keyHash = hashlib.sha256(padKey)
    encMsg = xor_byte(keyHash.digest(), padMsg)
    return encMsg

def decode(key, ecMsg):
    padKey = key + b'\x00' * (64 - len(key))
    keyHash = hashlib.sha256(padKey)
    msg = xor_byte(keyHash.digest(), ecMsg)
    return msg

def xor_byte(strA, strB):
    return bytes([a ^ b for a, b in zip(strA, strB)])
