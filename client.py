import socket
import util

HOST = '127.0.0.1'
PORT = 6265
DEBUG_MODE = True

print("Client Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.settimeout(1)

#TODO: AUTH and KEY GEN Goes HERE
ci = b'\x0b' * 64 #Client Integrity
ca = b'\x0c' * 64 #Client Auth
si = b'\x0d' * 64 #Server Integrity
sa = b'\x0e' * 64 #Server Auth
k = [ci,ca,si,sa]
#k = ci

# Constants
usage = "Usage:\n\thelp\n\tupload \"[file]\"\n\tdownload \"[file]\"\n\texit"
fStore = "clientStore\\"

# Place Holders
f = None #File Upload/Download Buffer

print("Program Started")
print(usage)
while True:
    inp = input("\n>> ").split()
    if inp[0] == "help":
        print(usage)
    elif inp[0] == "upload":
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
        cIV = None
        sIV = None
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
                if rId == fId and msg[0:1] == b'\x00':
                    aInd = int.from_bytes(msg[1:3], 'big')
                    if aInd > ind:
                        ind = aInd
                #End Message
                elif rId == fId and msg[0:1] == b'\x11':
                    print("Upload Finished")
                    break
            except socket.timeout as e:
                continue
            
    elif inp[0] == "download":
        print("Download",fstore+inp[1],"Starting...")
    elif inp[0] == "exit":
        print("Program Exiting...")
        break
    else:
        print("Error: Unrecognized command")
        print(usage)

sendMsg = util.getExitMsg(k[1], k[0], cIV)
s.send(sendMsg)
s.close()

