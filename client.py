import socket
import util
import math

#TODO: SOCKET PREP
HOST = '127.0.0.1'
PORT = 6265
DEBUG_MODE = True

print("Client Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

#TODO: AUTH and KEY GEN Goes HERE
ci = b'\x0b' * 64 #Client Integrity
ca = b'\x0c' * 64 #Client Auth
si = b'\x0d' * 64 #Server Integrity
sa = b'\x0e' * 64 #Server Auth
k = [ci,ca,si,sa]
#k = ci

#TODO: FILE UPLOAD/DOWNLOAD HANDLING
# Constants
usage = "Usage:\n\thelp\n\tupload \"[file]\"\n\tdownload \"[file]\"\n\texit"
fstore = "clientStore\\"
# Place Holders
f = None #File Upload/Download Buffer

print("Program Started")
print(usage)
while True:
    inp = input("\n>> ").split()
    if inp[0] == "help":
        print(usage)
    elif inp[0] == "upload":
        print("Upload",fstore+inp[1],"Starting...")
        try:
            f = open(fstore+inp[1], 'rb')
        except IOError as e:
            print(e)
            continue
        contents = f.read()
        length = len(contents)
        ind = 0
        flag = b"up"
        indByte = ind.to_bytes(4, 'big')
        name = b"test.txt"
        rounds = math.ceil(length/28)
        roundsByte = rounds.to_bytes(4, 'big')
        msg = b"".join([indByte, flag, roundsByte, name])

        encMsg = util.encode(k[1], msg)
        hashMsg = util.hmac_256(k[0], encMsg)
        sendMsg = b"".join([hashMsg, encMsg])
        s.send(sendMsg)

        while length > 0:
            data = s.recv(4096)

            checkMsg = data[:32]
            encMsg = data[32:]
            hashMsg = util.hmac_256(k[2], encMsg)

            if(checkMsg == hashMsg):
                print("good integ")
                msg = util.decode(k[3],encMsg)
                ind = int.from_bytes(msg[:4], 'big')
                ind += 1
                indByte = ind.to_bytes(4, 'big')
            else:
                print("bad integ")

            msg = indByte + contents[:28]
            contents = contents[28:]
            length = len(contents)

            encMsg = util.encode(k[1], msg)
            hashMsg = util.hmac_256(k[0], encMsg)
            sendMsg = b"".join([hashMsg, encMsg])
            s.send(sendMsg)
    elif inp[0] == "download":
        print("Download",fstore+inp[1],"Starting...")
    elif inp[0] == "exit":
        print("Program Exiting...")
        break
    else:
        print("Error: Unrecognized command")
        print(usage)
s.close()

