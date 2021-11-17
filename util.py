import hashlib
import secrets

def getDecMsg(rMsg, conKey, intKey, mode, IV):
    checkMsg = rMsg[:32]
    encMsg = rMsg[32:]
    hashMsg = hmac_256(intKey, encMsg)

    if checkMsg == hashMsg:
        msg = decode(conKey,encMsg, mode, IV)
        fInd = int.from_bytes(msg[:2], 'big')
        fId = msg[2:6]
        return fInd, fId, msg[6:]
    else:
        return -1, None, None

def getDataMsg(fInd, fId, fData, conKey, intKey, IV):
    # 2 Byte Index, 4 Byte File Id, 58 byte file data = 64 Bytes
    fIndByte = fInd.to_bytes(2, 'big')

    msg = b"".join([fIndByte, fId, fData])

    return getSendMsg(msg, conKey, intKey, 0, IV)

def getExitMsg(conKey, intKey, IV):
    # 2 Byte Index, 4 Byte F, 1 Byte message Type, 57 byte pad = 64 Bytes
    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    fId = b'\xff\xff\xff\xff'

    mType = b'\x0f'

    msg = b"".join([fIndByte, fId, mType])

    IV = secrets.token_bytes(32)

    return getSendMsg(msg, conKey, intKey, 1, IV)


def getEndMsg(fId, conKey, intKey, IV):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 57 byte pad = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    mType = b"\x11"

    msg = b"".join([fIndByte, fId, mType])

    return getSendMsg(msg, conKey, intKey, 0, IV)

def getStartAckMsg(fId, aInd, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 2 Byte Ack Index, 55 byte pad = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    mType = b"\x00"

    aIndByte = aInd.to_bytes(2, 'big')

    msg = b"".join([fIndByte, fId, mType, aIndByte])

    IV = secrets.token_bytes(32)

    return getSendMsg(msg, conKey, intKey, 1, IV)

def getAckMsg(fId, aInd, conKey, intKey, IV):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 2 Byte Ack Index, 55 byte pad = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    mType = b"\x00"

    aIndByte = aInd.to_bytes(2, 'big')

    msg = b"".join([fIndByte, fId, mType, aIndByte])

    return getSendMsg(msg, conKey, intKey, 0, IV)

def getStartMsg(fLength, fName, op, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 4 Byte File Length, 53 Byte File Name = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    fId = secrets.token_bytes(4)

    #Upload 
    mType = b"\x01"
    if op == 1:
        #Download
        mType = b"\x10"

    fLengthByte = fLength.to_bytes(4, 'big')
    
    msg = b"".join([fIndByte, fId, mType, fLengthByte, bytes(fName, 'ascii')])

    IV = secrets.token_bytes(32)

    return getSendMsg(msg, conKey, intKey, 1, IV), fId

def getSendMsg(msg, conKey, intKey, mode, IV):
    encMsg = encode(conKey, msg, mode, IV)
    hashMsg = hmac_256(intKey, encMsg)
    return b"".join([hashMsg, encMsg])

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

# TODO: Use keystream for xor
"""
IV 32 byte, K 32 byte, SHA(64 byte) = 32 bytes
START MSG: 32 byte enc msg, 32 byte IV 
ACK MSG: For start include IV
ACK MSG: Stream....
DATA MSG: 32 bye enc msg, 32 byte hash

c1 = p1 XOR SHA(K, IV)
c2 = p2 XOR SHA(K, c1)
.
.
cn = pn XOR SHA(K, cn-1)
"""
def encode(key, msg, mode, IV):
    if len(key) > 32:
        print("Error: Key must be <= 32 bytes (128 bits) long")
    if len(msg) > 64:
        print("Error: Msg must be <= 64 bytes (256 bits) long")
    if mode == 1: #Gen 1 Key (Start MSG)
        padKey = key + b'\x00' * (32 - len(key))
        digCon = xor_byte(padKey, (IV+IV))
        dig = hashlib.sha256(digCon)
        padMsg = msg + b'\x00' * (32 - len(msg))
        encMsg = xor_byte(dig.digest(), padMsg)
        return encMsg + IV
    else: #Gen 2 Key
        padKey = key + b'\x00' * (32 - len(key))
        digCon = xor_byte(padKey, (IV+IV))
        dig = hashlib.sha256(digCon)
        padMsg = msg + b'\x00' * (64 - len(msg))
        padMsgH = padMsg[:32]
        padMsgL = padMsg[32:]
        encMsgH = xor_byte(dig.digest(), padMsgH)
        digCon = xor_byte(padKey, (encMsgH+encMsgH))
        dig = hashlib.sha256(digCon)
        encMsgL = xor_byte(dig.digest(), padMsgL)
        return encMsgH + encMsgL
    
# TODO: Use Keysream for xor
"""
p1 = c1 XOR SHA(K, IV)
p2 = c2 XOR SHA(K, c1)
.
.
pn = cn XOR SHA(K, cn-1)
"""
def decode(key, ecMsg, mode, IV):
    if mode == 1: #Gen 1 Key (Start MSG)
        padKey = key + b'\x00' * (32 - len(key))
        ecMsgH = ecMsg[:32]
        IV = ecMsg[32:]
        digCon = xor_byte(padKey, (IV+IV))
        dig = hashlib.sha256(digCon)
        msg = xor_byte(dig.digest(), ecMsgH)
        return msg
    else: #Gen 2 Key
        padKey = key + b'\x00' * (32 - len(key))
        ecMsgH = ecMsg[:32]
        ecMsgL = ecMsg[32:]
        digCon = xor_byte(padKey, (IV+IV))
        dig = hashlib.sha256(digCon)
        msgH = xor_byte(dig.digest(), ecMsgH)
        digCon = xor_byte(padKey, (ecMsgH+ecMsgH))
        dig = hashlib.sha256(digCon)
        msgL = xor_byte(dig.digest(), ecMsgL)
        return msgH + msgL

def xor_byte(strA, strB):
    return bytes([a ^ b for a, b in zip(strA, strB)])
