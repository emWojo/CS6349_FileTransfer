import hashlib
import secrets
import binascii
import time
import rsa

def getChalMsg():
    ts = int(time.time())
    ts_bytes = ts.to_bytes(4, 'big')
    nonce = secrets.token_bytes(64)
    return ts_bytes+nonce

def signChalMsg(msg, pKey):
    return sign_sha256(msg, pKey)

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
    if len(key) > 64:
        print("Error: Key must be <= 64 bytes (128 bits) long")
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

# sign mssage msg with key using sha256
def sign_sha256(msg, key):
    return rsa.sign(msg, key, 'SHA-256')

# verify signed mssage msg with signature using key and sha256
def verify_sha256(msg, signature, key):
    try:
        return rsa.verify(msg, signature, key) == 'SHA-256'
    except:
        return False

def xor_byte(strA, strB):
    return bytes([a ^ b for a, b in zip(strA, strB)])

def get_dh_prime(num):
    p = primes[num]['p']
    g = primes[num]['g']
    return p,g

def get_dh_secAndpub(p, g):
    sec = int(binascii.hexlify(secrets.token_bytes(32)), base=16)
    pub = pow(g,sec,p)
    return sec, pub

def get_dh_shared(pub, a, p):
    safePrime = False
    if 2 <= pub and pub <= p - 2:
        if pow(pub, (p - 1) // 2, p) == 1:
	        return pow(pub, a, p)
    return -1

primes = {
	1536: { 
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
	"g": 2
	},
	2048: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
	"g": 2
	},
	3072: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
	"g": 2
	},
	4096: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
	"g": 2
	},
	6144: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
	"g": 2
	},
	8192: {
	"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF,
	"g": 2
	}
}
