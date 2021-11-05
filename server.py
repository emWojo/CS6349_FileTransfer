import socket
import util

HOST = '0.0.0.0'
PORT = 6265

print("Server Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)

# 0-No Mode 1-Upload 2-Download
state = 0
ind = None
rounds = None
f = None
k = b'\x0b' * 64

while True:
    conn, addr = s.accept()
    while True:

        data = conn.recv(4096)
        checkMsg = data[:32]
        encMsg = data[32:]
        hashMsg = util.hmac_256(k, encMsg)

        if(checkMsg == hashMsg):
            print("good integ")
            msg = util.decode(k,encMsg)
            print(msg)
            print(len(msg))
            ind = int.from_bytes(msg[:4], 'big')
            ind += 1
            outFlag = b'ak'
            indByte = ind.to_bytes(4, 'big')

            newMsg = b"".join([indByte, outFlag])
            encMsg = util.encode(k, newMsg)
            hashMsg = util.hmac_256(k, encMsg)
            sendMsg = b"".join([hashMsg, encMsg])
            conn.send(sendMsg)
        else:
            print("bad integ")
            outFlag = b'ak'
            errInd = 0
            indByte = errInd.to_bytes(4, 'big')

            newMsg = b"".join([indByte, outFlag])
            encMsg = util.encode(k, newMsg)
            hashMsg = util.hmac_256(k, encMsg)
            sendMsg = b"".join([hashMsg, encMsg])
            conn.send(sendMsg)
        if state == 0:
            print("no mode")
            rounds = int.from_bytes(msg[6:10], 'big')
            flag = msg[4:6]
            print(flag)
            if flag == b'up':
                state = 1
                f = open("sample.txt", "wb")
            elif flag == b'dn':
                state = 2
            else:
                state = 0
        elif state == 1:
            print("upload")
            print(msg)
            bytes = msg[4:]
            f.write(bytes)
            if ind == rounds*2+1:
                print("upload finished")
                f.close()
                state = 0
        else:
            print("download")
    conn.close()
    print ('client disconnected')





