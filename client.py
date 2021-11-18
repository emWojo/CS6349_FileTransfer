import socket
import util
import rsa
import math
import time

HOST = '127.0.0.1'
PORT = 6265
DEBUG = False

print("Client Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.settimeout(30)

# Constants
usage = "Usage:\n\thelp\n\tupload \"[file]\"\n\tdownload \"[file]\"\n\texit"
fStore = "clientStore\\"

# Place Holders
f = None #File Upload/Download Buffer
cIV = None
sIV = None
k = []

# Authenticate Server
with open('keys/pubkey.pem', 'rb') as file:
    pubKey = rsa.PublicKey.load_pkcs1(file.read())

while True:
    try:
        #challenge
        msg = util.getChalMsg()
        s.send(msg)

        #confirm
        data = s.recv(1460)
        ver = util.verify_sha256(msg, data, pubKey)
        if ver == False:
            print("Could Not Verify Server")
            time.sleep(60)
            continue

        # Get DH Key
        #agree on prime
        prime = 2048
        msg = prime.to_bytes(4, 'big')
        s.send(msg)

        #get server pubkey send pubkey
        data = s.recv(1460)
        sPub_bytes = data[:256]
        sign = data[256:]
        sPub = int.from_bytes(sPub_bytes, 'big')
        ver = util.verify_sha256(sPub_bytes, sign, pubKey)
        if ver == False:
            print("Could Not Verify Server pubKey")
            time.sleep(60)
            continue
        p,g = util.get_dh_prime(prime)
        sec,pub = util.get_dh_secAndpub(p, g)
        pub_bytes = pub.to_bytes(256, 'big')
        s.send(pub_bytes)
        
        share = util.get_dh_shared(sPub, sec, p)
        if share == -1:
            print("Server Public Key Bad Prime")
            time.sleep(60)
            continue
        share_byte = share.to_bytes(256, 'big')
        k = [share_byte[:64],share_byte[64:128],share_byte[128:192],share_byte[192:]]
        break
    except socket.timeout as e:
        time.sleep(60)
        continue
        print("reauthenticate")
    
s.settimeout(1)
print("Program Started")
print(usage)
while True:
    inp = input("\n>> ").split()
    if inp[0] == "help":
        print(usage)
    elif inp[0] == "upload":
        s.settimeout(1)
        fName = inp[1]
        if len(fName) > 53:
            print("File name cannot be > 53 bytes in length")
            continue
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

        if fLength > 3801030:
            print("File size cannot be larger than 3,801,030 bytes")

        print("Upload",fStore+inp[1],"Starting...")

        # Prep Start Msg
        sendMsg, fId = util.getStartMsg(fLength, fName, 0,k[1], k[0])
        cIV = sendMsg[32:64]

        # Write file to cache
        tmpI = 1
        while len(contents) > 0:
            interMsg = util.getDataMsg(tmpI, fId, contents[:58], k[1], k[0], cIV)
            cIV = interMsg[64:96]
            cache[tmpI] = interMsg
            contents = contents[58:]
            tmpI+=1

        # Send Start Msg
        s.send(sendMsg)

        # Wait for Ack for Start Msg
        while True:
            try:
                data = s.recv(1460)
                sIV = data[32:64]
                rInd, rId, msg = util.getDecMsg(data, k[3], k[2], 1, sIV)
                if rInd == 0 and rId == fId and msg[0:1] == b'\x00' and msg[1:3] == b'\x00\x00':
                    break
            except socket.timeout as e:
                s.send(sendMsg)
                print("send start")
        
        #Wait for Ack for Upload Msgs
        while True:
            sendMsg = b''
            for i in range(ind+1, min(tmpI, ind+16)):
                sendMsg += cache[i]
            s.send(sendMsg)

            try: 
                data = s.recv(1460)
                tsIV = data[64:96]
                rInd, rId, msg = util.getDecMsg(data, k[3], k[2], 0, sIV)
                sIV = tsIV
                #Ack Message
                if rInd != -1 and rId == fId and msg[0:1] == b'\x00':
                    aInd = int.from_bytes(msg[1:3], 'big')
                    if aInd > ind:
                        ind = aInd
                #End Message
                elif rInd != -1 and rId == fId and msg[0:1] == b'\x11':
                    print("Upload Finished")
                    break
            except socket.timeout as e:
                continue
            
    elif inp[0] == "download":    
        s.settimeout(1)  
        fName = inp[1]
        if len(fName) > 53:
            print("File name cannot be > 53 bytes in length")
            continue
        
        try:
            f = open(fStore+fName, 'wb')
        except IOError as e:
            print(e)
            continue

        # Track last received file segment
        ind = 0
        fLength = None
        fSegs = None

        print("Download",fStore+inp[1],"Starting...")

        # Prep Start Msg
        sendMsg, fId = util.getStartMsg(0, fName, 1,k[1], k[0])
        cIV = sendMsg[32:64]
        s.send(sendMsg)

        # Wait for Start Msg
        while True:
            try:
                data = s.recv(1460)
                sIV = data[32:64]
                rInd, fId, msg = util.getDecMsg(data, k[3], k[2], 1, sIV)
                if rInd == 0 and msg[0:1] == b'\x10':
                    fLength = int.from_bytes(msg[1:5], 'big')
                    fSegs = math.ceil(fLength/58)
                    break
            except socket.timeout as e:
                s.send(sendMsg)
                print("send start")

        sendMsg = util.getAckMsg(fId, ind, k[1], k[0], cIV)
        cIV = sendMsg[64:96]
        s.send(sendMsg)

        s.settimeout(360)

        # Wait for Data
        flag = True
        while flag:
            data = s.recv(1460)
            s.settimeout(1)
            while len(data) >= 96:
                tsIV = data[64:96]
                rInd, rId, msg = util.getDecMsg(data[:96], k[3], k[2], 0, sIV)
                sIV = tsIV
                data = data[96:]

                #If file is bad ack index of last received file that was good
                if rInd == -1 or rId != fId or ind+1 != rInd:
                    sendMsg = util.getAckMsg(fId, ind, k[1], k[0], cIV)
                    cIV = sendMsg[64:96]
                    s.send(sendMsg)
                    break

                #Remove 0 Pad on last msg
                if rInd == fSegs:
                    padLen = ((fSegs*58) - fLength)
                    msg =  msg[:len(msg)-padLen]

                # Write File
                ind = rInd
                f.write(msg)

                # Send Ack for 15 msgs
                if len(data) == 0:
                    sendMsg = util.getAckMsg(fId, ind, k[1], k[0], cIV)
                    cIV = sendMsg[64:96]
                    s.send(sendMsg)

                # Finished writing file
                if rInd == fSegs:
                    state = 0
                    print("Download Finished")
                    f.close()
                    #Set up for end
                    sendMsg = util.getEndMsg(fId, k[1], k[0], cIV)
                    s.send(sendMsg)
                    flag = False
                    break
    elif inp[0] == "exit":
        print("Program Exiting...")
        break
    else:
        print("Error: Unrecognized command")
        print(usage)

sendMsg = util.getExitMsg(k[1], k[0], cIV)
s.send(sendMsg)
s.close()

