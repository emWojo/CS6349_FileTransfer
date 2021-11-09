import hashlib
import secrets
import math

def getDecMsg(rMsg, conKey, intKey):
    checkMsg = rMsg[:32]
    encMsg = rMsg[32:]
    hashMsg = hmac_256(intKey, encMsg)

    if checkMsg == hashMsg:
        msg = decode(conKey,encMsg)
        fInd = int.from_bytes(msg[:2], 'big')
        fId = msg[2:6]
        return fInd, fId, msg[6:]
    else:
        return -1, None, None

def getErrMsg(err, fId, eInd, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 2 byte err Ind, 4 byte err Type, 51 byte pad = 64 Bytes
    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    mType = b"\xff"

    eType = 0
    eTypeByte = eType.to_bytes(4, 'big')

    msg = b"".join([fIndByte, fId, mType, eInd, eTypeByte])

    return getSendMsg(msg, conKey, intKey)


def getDataMsg(fInd, fId, fData, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 58 byte file data = 64 Bytes
    fIndByte = fInd.to_bytes(2, 'big')

    msg = b"".join([fIndByte, fId, fData])

    return getSendMsg(msg, conKey, intKey)

def getExitMsg(conKey, intKey):
    # 2 Byte Index, 4 Byte F, 1 Byte message Type, 57 byte pad = 64 Bytes
    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    fId = b'\xff\xff\xff\xff'

    mType = b'\x0f'

    msg = b"".join([fIndByte, fId, mType])

    return getSendMsg(msg, conKey, intKey)


def getEndMsg(fId, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 57 byte pad = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    mType = b"\x11"

    msg = b"".join([fIndByte, fId, mType])

    return getSendMsg(msg, conKey, intKey)

def getAckMsg(fId, aInd, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 2 Byte Ack Index, 55 byte pad = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    mType = b"\x00"

    aIndByte = aInd.to_bytes(2, 'big')

    msg = b"".join([fIndByte, fId, mType, aIndByte])

    return getSendMsg(msg, conKey, intKey)

def getStartMsg(fLength, fName, op, conKey, intKey):
    # 2 Byte Index, 4 Byte File Id, 1 Byte message Type, 2 Byte Segement Number, 55 Byte File Name = 64 Bytes

    fInd = 0
    fIndByte = fInd.to_bytes(2, 'big')

    fId = secrets.token_bytes(4)

    #Upload 
    mType = b"\x01"
    if op == 1:
        #Download
        mType = b"\x10"

    fSegs = math.ceil(fLength/58)
    fSegsByte = fSegs.to_bytes(2, 'big')
    
    msg = b"".join([fIndByte, fId, mType, fSegsByte, bytes(fName, 'ascii')])

    return getSendMsg(msg, conKey, intKey), fId

def getSendMsg(msg, conKey, intKey):
    encMsg = encode(conKey, msg)
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

def encode(key, msg):
    if len(key) > 64:
        print("Error: Key must be <= 64 bytes (512 bits) long")
    if len(msg) > 64:
        print("Error: Msg must be <= 64 bytes (256 bits) long")
    padKey = key + b'\x00' * (64 - len(key))
    padMsg = msg + b'\x00' * (64 - len(msg))

    encMsg = xor_byte(padKey, padMsg)
    return encMsg

def decode(key, ecMsg):
    padKey = key + b'\x00' * (64 - len(key))
    msg = xor_byte(padKey, ecMsg)
    return msg

def xor_byte(strA, strB):
    return bytes([a ^ b for a, b in zip(strA, strB)])
