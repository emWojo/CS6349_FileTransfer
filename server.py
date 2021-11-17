import socket
import util
import math
import secrets
import rsa

HOST = '0.0.0.0'
PORT = 6265

print("Server Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(60)

# load private key for the server
with open('keys/privkey.pem', 'rb') as file:
    privKey = rsa.PrivateKey.load_pkcs1(file.read())

#TODO: AUTH and KEY GEN Goes HERE
ci = b'\x0b' * 64 #Client Integrity
ca = b'\x0c' * 32 #Client Auth
si = b'\x0d' * 64 #Server Integrity
sa = b'\x0e' * 32 #Server Auth
k = [ci,ca,si,sa]
#k = ci

# Constants
fStore = "serverStore\\"
DEBUG = False

# Place Holders
conFlag = False
state = 0 # 0-Start 1-Upload 2-Download 3-End

f = None # File Upload/Download Buffer
fSegs = 0 # Tracks how many file segs to rcv
fLength = 0


ind = 0 # Track last accurate seg index
cache = {} # Store file before sending
ID = -1 # Place holder for file id
tmpI = None #Place holder for tracking number segs in file

cIV = None
sIV = None

while True:
    conn, addr = s.accept()

    conFlag = True
    while conFlag:
        # Decode a Message
        data = conn.recv(1460)
        while len(data) >= 96:
            fInd = fId = msg = None
            if state == 0:
                cIV = data[32:64]
                fInd, fId, msg = util.getDecMsg(data[:96], k[1], k[0], 1, cIV)
                data = data[96:]
            else:
                tcIV = data[64:96]
                fInd, fId, msg = util.getDecMsg(data[:96], k[1], k[0], 0, cIV)
                cIV = tcIV
                data = data[96:]
            
            # Generate Appropriate Response
            if state == 0:
                if DEBUG:
                    print("start mode")
                # Check Message Integrity
                if fInd == -1:
                    break
                mType = msg[0:1]

                if mType == b'\x01':
                    #Set up for upload    
                    state = 1
                    fLength = int.from_bytes(msg[1:5], 'big')
                    fSegs = math.ceil(fLength/58)
                    fName = msg[5:].decode('ascii').strip("\x00")
                    ID = fId
                    ind = 0
                    f = open(fStore+fName, "wb")

                    #Ack the start message
                    sendMsg = util.getStartAckMsg(fId, fInd, k[3], k[2])
                    sIV = sendMsg[32:64]
                    conn.send(sendMsg)
                elif mType == b'\x10':
                    #Set up for download
                    state = 2
                    fName = msg[3:].decode('ascii').strip("\x00")

                    #Open File
                    try:
                        f = open(fStore+fName, 'rb')
                    except IOError as e:
                        print(e)
                        continue
                    
                    #File in Bytes
                    contents = f.read()
                    fLength = len(contents)
                    #Dict mapping indices to encoded file portions
                    cache = {}
                    #Tracking most recent acked segment
                    ind = 0

                    #Prep start message
                    sendMsg, ID = util.getStartMsg(fLength, fName, 1,k[3], k[2])
                    sIV = sendMsg[32:64]
                    conn.send(sendMsg)

                    #Cache File
                    tmpI = 1
                    while len(contents) > 0:
                        interMsg = util.getDataMsg(tmpI, ID, contents[:58], k[3], k[2], sIV)
                        sIV = interMsg[64:96]
                        cache[tmpI] = interMsg
                        contents = contents[58:]
                        tmpI+=1
                                    
                elif mType == b'\x0f':
                    state = 3
                    conn.close()
                    conFlag = False
                    if DEBUG:
                        print("exit")
                else:
                    state = 0
            elif state == 1:
                if DEBUG:
                    print("upload")
                # Check Message Integrity
                if fInd == -1 or fId != ID or ind+1 != fInd:
                    sendMsg = util.getAckMsg(fId, ind, k[3], k[2], sIV)
                    sIV = sendMsg[64:96]
                    conn.send(sendMsg)
                    break

                #Remove 0 Pad on last msg
                if fInd == fSegs:
                    padLen = ((fSegs*58) - fLength)
                    msg =  msg[:len(msg)-padLen]

                # Write File
                ind = fInd
                f.write(msg)

                # Send Ack for 15 msgs
                if len(data) == 0:
                    sendMsg = util.getAckMsg(fId, ind, k[3], k[2], sIV)
                    sIV = sendMsg[64:96]
                    conn.send(sendMsg)

                # Finished writing file
                if fInd == fSegs:
                    if DEBUG:
                        print("upload finished")
                    f.close()

                    #Set up for end
                    state = 0
                    sendMsg = util.getEndMsg(fId, k[3], k[2], sIV)
                    conn.send(sendMsg)
            elif state == 2:
                if DEBUG:
                    print("download")

                # Check Message Integrity
                # ACK Msg
                if fInd != -1 and fId == ID and msg[0:1] == b'\x00':
                    aInd = int.from_bytes(msg[1:3], 'big')
                    if aInd > ind:
                        ind = aInd
                # END Msg
                elif fInd != -1 and fId == ID and msg[0:1] == b'\x11':
                        if DEBUG:
                            print("download Finished")
                        state = 0
                        break
                
                # Send Next Part of File
                sendMsg = b''
                for i in range(ind+1, min(tmpI, ind+16)):
                    sendMsg += cache[i]
                conn.send(sendMsg)
            else:
                conn.close()
                conFlag = False
                if DEBUG:
                    print("exit")
            
    conn.close()
    print ('client disconnected')
    exit()