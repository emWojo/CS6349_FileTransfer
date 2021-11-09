import socket
import util
import math
import secrets

HOST = '0.0.0.0'
PORT = 6265

print("Server Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)

#TODO: AUTH and KEY GEN Goes HERE
ci = b'\x0b' * 64 #Client Integrity
ca = b'\x0c' * 64 #Client Auth
si = b'\x0d' * 64 #Server Integrity
sa = b'\x0e' * 64 #Server Auth
k = [ci,ca,si,sa]
#k = ci

# Constants
fStore = "serverStore\\"

# Place Holders
conFlag = False
state = 0 # 0-Start 1-Upload 2-Download 3-End

f = None # File Upload/Download Buffer
fSegs = 0 # Tracks how many file segs to rcv

ind = 0 # Track last accurate seg index
ID = -1 # Place holder for file id

while True:
    conn, addr = s.accept()
    conFlag = True
    while conFlag:
        # Decode a Message
        data = conn.recv(1460)
        while len(data) >= 96:
            fInd, fId, msg = util.getDecMsg(data[:96], k[1], k[0])
            data = data[96:]
            
            # Generate Appropriate Response
            if state == 0:
                print("start mode")
                # Check Message Integrity
                if fInd == -1:
                    break
                mType = msg[0:1]

                if mType == b'\x01':
                    #Set up for upload    
                    state = 1
                    fSegs = int.from_bytes(msg[1:3], 'big')
                    fName = msg[3:].decode('ascii').strip("\x00")
                    ID = fId
                    cache = {}
                    f = open(fStore+fName, "wb")

                    #Ack the start message
                    sendMsg = util.getAckMsg(fId, fInd, k[3], k[2])
                    conn.send(sendMsg)
                elif mType == b'\x10':
                    #Set up for download
                    state = 2
                    fName = msg[3:].decode('ascii').strip("\x00")
                    ID = fId
                    f = open(fStore+fName, "rb")

                    #Ack the start message
                    sendMsg = util.getAckMsg(fId, fInd, k[3], k[2])
                    conn.send(sendMsg)
                elif mType == b'\x0f':
                    state = 3
                    conn.close()
                    conFlag = False
                    print("exit")
                else:
                    state = 0
            elif state == 1:
                print("upload")
                # Check Message Integrity
                if fInd == -1 or fId != ID or ind+1 != fInd:
                    sendMsg = util.getAckMsg(fId, ind, k[3], k[2])
                    conn.send(sendMsg)
                    break

                # Write File
                ind = fInd
                f.write(msg)

                # Finished writing file
                if fInd == fSegs:
                    print("upload finished")
                    f.close()

                    #Set up for end
                    state = 0
                    sendMsg = util.getEndMsg(fId, k[3], k[2])
                    conn.send(sendMsg)
            elif state == 2:
                print("download")
            else:
                conn.close()
                conFlag = False
                print("exit")
            
    conn.close()
    print ('client disconnected')