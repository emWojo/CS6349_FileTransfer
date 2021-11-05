import socket
import util
import math


HOST = '127.0.0.1'
PORT = 6265
DEBUG_MODE = True

print("Client Running")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

with open('test.txt', 'rb') as f:
    contents = f.read()

k = b'\x0b' * 64
length = len(contents)
ind = 0
flag = b"up"
indByte = ind.to_bytes(4, 'big')
name = b"test.txt"
rounds = math.ceil(length/28)
roundsByte = rounds.to_bytes(4, 'big')
msg = b"".join([indByte, flag, roundsByte, name])

encMsg = util.encode(k, msg)
hashMsg = util.hmac_256(k, encMsg)
sendMsg = b"".join([hashMsg, encMsg])
s.send(sendMsg)

while length > 0:
    data = s.recv(4096)

    checkMsg = data[:32]
    encMsg = data[32:]
    hashMsg = util.hmac_256(k, encMsg)

    if(checkMsg == hashMsg):
        print("good integ")
        msg = util.decode(k,encMsg)
        ind = int.from_bytes(msg[:4], 'big')
        ind += 1
        indByte = ind.to_bytes(4, 'big')
    else:
        print("bad integ")

    msg = indByte + contents[:28]
    contents = contents[28:]
    length = len(contents)

    encMsg = util.encode(k, msg)
    hashMsg = util.hmac_256(k, encMsg)
    sendMsg = b"".join([hashMsg, encMsg])
    s.send(sendMsg)


s.close()

